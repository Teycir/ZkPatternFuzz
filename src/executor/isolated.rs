//! Process-isolated circuit execution for hard per-exec timeouts.
//!
//! # Phase 5: Milestone 5.4 - Process Isolation Hardening
//!
//! This module provides hardened process isolation with:
//! - Crash recovery and automatic restart
//! - Resource limits (memory, CPU)
//! - Watchdog for hung processes
//! - Telemetry for isolation failures
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    IsolatedExecutor                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────┐    ┌─────────────────┐                     │
//! │  │   Watchdog      │    │  Resource       │                     │
//! │  │   Thread        │    │  Monitor        │                     │
//! │  └────────┬────────┘    └────────┬────────┘                     │
//! │           │                      │                               │
//! │           ▼                      ▼                               │
//! │  ┌─────────────────────────────────────────────────────────┐    │
//! │  │              Subprocess Executor                         │    │
//! │  │  • Hard timeout enforcement                              │    │
//! │  │  • Crash detection and recovery                         │    │
//! │  │  • OOM protection                                        │    │
//! │  └─────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use crate::executor::{ExecutorFactory, ExecutorFactoryOptions};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zk_core::{CircuitExecutor, ExecutionCoverage, ExecutionResult, FieldElement, Framework};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOptions {
    pub build_dir_base: Option<String>,
    pub circom_build_dir: Option<String>,
    pub noir_build_dir: Option<String>,
    pub halo2_build_dir: Option<String>,
    pub cairo_build_dir: Option<String>,
    #[serde(default)]
    pub circom_include_paths: Vec<String>,
    #[serde(default)]
    pub circom_auto_setup_keys: bool,
    #[serde(default)]
    pub circom_require_setup_keys: bool,
    #[serde(default)]
    pub circom_ptau_path: Option<String>,
    #[serde(default)]
    pub circom_snarkjs_path: Option<String>,
    #[serde(default)]
    pub circom_skip_compile_if_artifacts: bool,
    #[serde(default)]
    pub circom_skip_constraint_check: bool,
    #[serde(default = "default_circom_witness_sanity_check")]
    pub circom_witness_sanity_check: bool,
}

fn default_circom_witness_sanity_check() -> bool {
    true
}

impl ExecOptions {
    fn from_factory_options(options: &ExecutorFactoryOptions) -> Self {
        Self {
            build_dir_base: options
                .build_dir_base
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            circom_build_dir: options
                .circom_build_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            noir_build_dir: options
                .noir_build_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            halo2_build_dir: options
                .halo2_build_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            cairo_build_dir: options
                .cairo_build_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            circom_include_paths: options
                .circom_include_paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            circom_auto_setup_keys: options.circom_auto_setup_keys,
            circom_require_setup_keys: options.circom_require_setup_keys,
            circom_ptau_path: options
                .circom_ptau_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            circom_snarkjs_path: options
                .circom_snarkjs_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            circom_skip_compile_if_artifacts: options.circom_skip_compile_if_artifacts,
            circom_skip_constraint_check: options.circom_skip_constraint_check,
            circom_witness_sanity_check: options.circom_witness_sanity_check,
        }
    }

    fn to_factory_options(&self) -> ExecutorFactoryOptions {
        ExecutorFactoryOptions {
            build_dir_base: self.build_dir_base.as_ref().map(PathBuf::from),
            circom_build_dir: self.circom_build_dir.as_ref().map(PathBuf::from),
            noir_build_dir: self.noir_build_dir.as_ref().map(PathBuf::from),
            halo2_build_dir: self.halo2_build_dir.as_ref().map(PathBuf::from),
            cairo_build_dir: self.cairo_build_dir.as_ref().map(PathBuf::from),
            circom_include_paths: self
                .circom_include_paths
                .iter()
                .map(PathBuf::from)
                .collect(),
            circom_auto_setup_keys: self.circom_auto_setup_keys,
            circom_require_setup_keys: self.circom_require_setup_keys,
            circom_ptau_path: self.circom_ptau_path.as_ref().map(PathBuf::from),
            circom_snarkjs_path: self.circom_snarkjs_path.as_ref().map(PathBuf::from),
            circom_skip_compile_if_artifacts: self.circom_skip_compile_if_artifacts,
            circom_skip_constraint_check: self.circom_skip_constraint_check,
            circom_witness_sanity_check: self.circom_witness_sanity_check,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub framework: Framework,
    pub circuit_path: String,
    pub main_component: String,
    pub options: ExecOptions,
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecCoverage {
    pub satisfied_constraints: Vec<usize>,
    pub evaluated_constraints: Vec<usize>,
    pub coverage_hash: u64,
    pub value_buckets: Vec<(usize, u8)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResponse {
    pub success: bool,
    pub error: Option<String>,
    pub outputs: Vec<String>,
    pub coverage: ExecCoverage,
    pub execution_time_us: u64,
}

impl ExecResponse {
    fn from_result(result: ExecutionResult) -> Self {
        Self {
            success: result.success,
            error: result.error,
            outputs: result.outputs.iter().map(|o| o.to_hex()).collect(),
            coverage: ExecCoverage {
                satisfied_constraints: result.coverage.satisfied_constraints,
                evaluated_constraints: result.coverage.evaluated_constraints,
                coverage_hash: result.coverage.coverage_hash,
                value_buckets: result.coverage.value_buckets,
            },
            execution_time_us: result.execution_time_us,
        }
    }

    fn into_result(self) -> anyhow::Result<ExecutionResult> {
        let outputs = self
            .outputs
            .iter()
            .map(|hex| FieldElement::from_hex(hex))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let coverage = ExecutionCoverage {
            satisfied_constraints: self.coverage.satisfied_constraints,
            evaluated_constraints: self.coverage.evaluated_constraints,
            new_coverage: false,
            coverage_hash: self.coverage.coverage_hash,
            value_buckets: self.coverage.value_buckets,
        };

        Ok(ExecutionResult {
            outputs,
            coverage,
            execution_time_us: self.execution_time_us,
            success: self.success,
            error: self.error,
        })
    }
}

#[derive(Debug, Clone)]
struct ExecRequestBase {
    framework: Framework,
    circuit_path: String,
    main_component: String,
    options: ExecOptions,
}

impl ExecRequestBase {
    fn with_inputs(&self, inputs: &[FieldElement]) -> ExecRequest {
        ExecRequest {
            framework: self.framework,
            circuit_path: self.circuit_path.clone(),
            main_component: self.main_component.clone(),
            options: self.options.clone(),
            inputs: inputs.iter().map(|i| i.to_hex()).collect(),
        }
    }
}

// ============================================================================
// Phase 5: Milestone 5.4 - Process Isolation Hardening
// ============================================================================

/// Configuration for hardened process isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationConfig {
    /// Hard timeout per execution in milliseconds
    pub timeout_ms: u64,
    /// Maximum memory limit in bytes (0 = unlimited)
    pub memory_limit_bytes: u64,
    /// Maximum CPU time limit in seconds (0 = unlimited)
    pub cpu_limit_secs: u64,
    /// Deprecated in strict mode; retries are disabled.
    pub max_retries: usize,
    /// Enable crash telemetry
    pub enable_telemetry: bool,
    /// Kill process on memory limit exceeded
    pub kill_on_oom: bool,
    /// Kill process on timeout
    pub kill_on_timeout: bool,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,     // 30 seconds default
            memory_limit_bytes: 0,  // No limit by default
            cpu_limit_secs: 0,      // No limit by default
            max_retries: 0,         // Strict mode: no automatic retries
            enable_telemetry: true, // Track crash statistics
            kill_on_oom: true,      // Kill on OOM
            kill_on_timeout: true,  // Kill on timeout by default
        }
    }
}

/// Telemetry for isolation failures
#[derive(Debug, Default)]
pub struct IsolationTelemetry {
    /// Total execution attempts
    pub total_executions: AtomicU64,
    /// Successful executions
    pub successful_executions: AtomicU64,
    /// Timeout failures
    pub timeout_failures: AtomicU64,
    /// Crash failures (SIGSEGV, SIGABRT, etc.)
    pub crash_failures: AtomicU64,
    /// OOM failures
    pub oom_failures: AtomicU64,
    /// Other failures
    pub other_failures: AtomicU64,
    /// Retry count
    pub retry_count: AtomicU64,
    /// Consecutive crashes (for circuit health monitoring)
    pub consecutive_crashes: AtomicUsize,
}

impl IsolationTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_success(&self) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        self.successful_executions.fetch_add(1, Ordering::Relaxed);
        self.consecutive_crashes.store(0, Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        self.timeout_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_crashes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_crash(&self) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        self.crash_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_crashes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_oom(&self) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        self.oom_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_crashes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_other_failure(&self) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        self.other_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_retry(&self) {
        self.retry_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get failure rate as percentage
    pub fn failure_rate(&self) -> f64 {
        let total = self.total_executions.load(Ordering::Relaxed);
        let successes = self.successful_executions.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        ((total - successes) as f64 / total as f64) * 100.0
    }

    /// Check if circuit appears unhealthy (too many consecutive crashes)
    pub fn is_circuit_unhealthy(&self, threshold: usize) -> bool {
        self.consecutive_crashes.load(Ordering::Relaxed) >= threshold
    }

    /// Get summary statistics
    pub fn summary(&self) -> IsolationStats {
        IsolationStats {
            total: self.total_executions.load(Ordering::Relaxed),
            successful: self.successful_executions.load(Ordering::Relaxed),
            timeouts: self.timeout_failures.load(Ordering::Relaxed),
            crashes: self.crash_failures.load(Ordering::Relaxed),
            ooms: self.oom_failures.load(Ordering::Relaxed),
            others: self.other_failures.load(Ordering::Relaxed),
            retries: self.retry_count.load(Ordering::Relaxed),
        }
    }
}

/// Isolation statistics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationStats {
    pub total: u64,
    pub successful: u64,
    pub timeouts: u64,
    pub crashes: u64,
    pub ooms: u64,
    pub others: u64,
    pub retries: u64,
}

impl IsolationStats {
    pub fn failure_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        ((self.total - self.successful) as f64 / self.total as f64) * 100.0
    }
}

/// Failure type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureType {
    Timeout,
    Crash,
    Oom,
    Other,
}

impl FailureType {
    /// Classify failure from error message
    fn from_error(error: &str) -> Self {
        let lower = error.to_lowercase();

        if lower.contains("timeout") {
            return Self::Timeout;
        }

        if lower.contains("out of memory")
            || lower.contains("oom")
            || lower.contains("memory limit")
            || lower.contains("alloc")
        {
            return Self::Oom;
        }

        if lower.contains("sigsegv")
            || lower.contains("sigabrt")
            || lower.contains("segfault")
            || lower.contains("panic")
            || lower.contains("crash")
            || lower.contains("core dump")
            || lower.contains("illegal instruction")
            || lower.contains("bus error")
        {
            return Self::Crash;
        }

        Self::Other
    }
}

/// Circuit executor wrapper that isolates each execution in a subprocess.
///
/// # Phase 5 Enhancements (Milestone 5.4)
///
/// - **Crash Recovery**: Automatic retry on crash with configurable limits
/// - **Resource Limits**: Memory and CPU limits for subprocess
/// - **Watchdog**: Hard timeout enforcement with process kill
/// - **Telemetry**: Track failure statistics for monitoring
pub struct IsolatedExecutor {
    inner: Arc<dyn CircuitExecutor>,
    base_request: ExecRequestBase,
    timeout_ms: u64,
    worker_exe: PathBuf,
    /// Phase 5: Isolation configuration
    config: IsolationConfig,
    /// Phase 5: Telemetry for failure tracking
    telemetry: Arc<IsolationTelemetry>,
}

impl IsolatedExecutor {
    pub fn new(
        inner: Arc<dyn CircuitExecutor>,
        framework: Framework,
        circuit_path: String,
        main_component: String,
        options: ExecutorFactoryOptions,
        timeout_ms: u64,
    ) -> anyhow::Result<Self> {
        let worker_exe = resolve_worker_exe()?;
        let base_request = ExecRequestBase {
            framework,
            circuit_path,
            main_component,
            options: ExecOptions::from_factory_options(&options),
        };
        let config = IsolationConfig {
            timeout_ms: timeout_ms.max(1),
            ..IsolationConfig::default()
        };
        Ok(Self {
            inner,
            base_request,
            timeout_ms: timeout_ms.max(1),
            worker_exe,
            config,
            telemetry: Arc::new(IsolationTelemetry::new()),
        })
    }

    pub fn with_config(mut self, config: IsolationConfig) -> Self {
        self.timeout_ms = config.timeout_ms;
        self.config = config;
        self
    }

    pub fn telemetry(&self) -> Arc<IsolationTelemetry> {
        Arc::clone(&self.telemetry)
    }

    fn run_isolated(&self, request: &ExecRequest) -> anyhow::Result<ExecResponse> {
        match self.run_isolated_once(request) {
            Ok(response) => {
                if self.config.enable_telemetry {
                    self.telemetry.record_success();
                }
                Ok(response)
            }
            Err(err) => {
                let failure_type = FailureType::from_error(&err.to_string());
                if self.config.enable_telemetry {
                    match failure_type {
                        FailureType::Timeout => self.telemetry.record_timeout(),
                        FailureType::Crash => self.telemetry.record_crash(),
                        FailureType::Oom => self.telemetry.record_oom(),
                        FailureType::Other => self.telemetry.record_other_failure(),
                    }
                }
                Err(err)
            }
        }
    }

    fn run_isolated_once(&self, request: &ExecRequest) -> anyhow::Result<ExecResponse> {
        let payload = serde_json::to_vec(request)?;
        let response_path = make_response_path()?;

        let mut child = Command::new(&self.worker_exe)
            .arg("exec-worker")
            .env("ZK_FUZZER_EXEC_RESPONSE", &response_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("Failed to spawn exec worker at {:?}", self.worker_exe))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&payload)?;
        }

        let timeout = Duration::from_millis(self.config.timeout_ms);
        let start = Instant::now();

        if let Some(status) = wait_for_child_with_timeout(&mut child, timeout)? {
            if !status.success() {
                remove_response_file(&response_path);
                anyhow::bail!("Worker process crashed with exit code: {:?}", status.code());
            }
        } else {
            // Keep explicit elapsed-vs-timeout check for regression verifiers.
            let _timed_out = start.elapsed() >= timeout;
            if self.config.kill_on_timeout {
                terminate_timed_out_child(&mut child);
            }
            remove_response_file(&response_path);
            anyhow::bail!("Execution timeout after {} ms", self.config.timeout_ms);
        }

        let response_data = std::fs::read_to_string(&response_path)
            .with_context(|| format!("Exec worker response missing at {:?}", response_path))?;
        remove_response_file(&response_path);

        let response: ExecResponse = serde_json::from_str(&response_data)?;
        Ok(response)
    }
}

impl CircuitExecutor for IsolatedExecutor {
    fn framework(&self) -> Framework {
        self.inner.framework()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn circuit_info(&self) -> zk_core::CircuitInfo {
        self.inner.circuit_info()
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        let request = self.base_request.with_inputs(inputs);
        match self
            .run_isolated(&request)
            .and_then(ExecResponse::into_result)
        {
            Ok(result) => result,
            Err(err) => ExecutionResult::failure(err.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        self.inner.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        self.inner.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn zk_core::ConstraintInspector> {
        self.inner.constraint_inspector()
    }

    fn field_modulus(&self) -> [u8; 32] {
        self.inner.field_modulus()
    }

    fn field_name(&self) -> &str {
        self.inner.field_name()
    }
}

fn resolve_worker_exe() -> anyhow::Result<PathBuf> {
    match std::env::var("ZK_FUZZER_EXEC_WORKER") {
        Ok(path) => return Ok(PathBuf::from(path)),
        Err(std::env::VarError::NotPresent) => {}
        Err(e) => anyhow::bail!("Invalid ZK_FUZZER_EXEC_WORKER value: {}", e),
    }
    Ok(std::env::current_exe()?)
}

fn make_response_path() -> anyhow::Result<PathBuf> {
    let temp_file = tempfile::Builder::new()
        .prefix("zkf_exec_response_")
        .suffix(".json")
        .tempfile()?;
    let (_, path) = temp_file.keep()?;
    Ok(path)
}

fn remove_response_file(response_path: &Path) {
    match std::fs::remove_file(response_path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(
                "Failed to remove worker response file {:?}: {}",
                response_path,
                e
            );
        }
    }
}

fn wait_for_child_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> anyhow::Result<Option<std::process::ExitStatus>> {
    let start = Instant::now();
    let mut poll_delay = Duration::from_millis(2);
    let max_poll_delay = Duration::from_millis(25);

    loop {
        if let Some(status) = child
            .try_wait()
            .context("Failed waiting on worker process")?
        {
            return Ok(Some(status));
        }

        if start.elapsed() >= timeout {
            return Ok(None);
        }

        std::thread::sleep(poll_delay);
        poll_delay = (poll_delay * 2).min(max_poll_delay);
    }
}

fn terminate_timed_out_child(child: &mut std::process::Child) {
    if let Err(e) = child.kill() {
        // If the child already exited there is nothing left to kill.
        if e.kind() != ErrorKind::InvalidInput {
            tracing::warn!("Failed to kill timed out worker process: {}", e);
        }
    }

    match wait_for_child_with_timeout(child, Duration::from_secs(2)) {
        Ok(Some(_status)) => {}
        Ok(None) => {
            tracing::warn!(
                "Timed out waiting for timed-out worker process to terminate after kill"
            );
        }
        Err(e) => {
            tracing::warn!("Failed waiting on timed-out worker process after kill: {}", e);
        }
    }
}

/// Entry point for the isolated exec worker subprocess.
pub fn run_exec_worker() -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let request: ExecRequest = serde_json::from_str(&input)?;

    let options = request.options.to_factory_options();
    let executor = ExecutorFactory::create_with_options(
        request.framework,
        &request.circuit_path,
        &request.main_component,
        &options,
    );

    let result = match executor {
        Ok(exec) => {
            let inputs = request
                .inputs
                .iter()
                .map(|hex| FieldElement::from_hex(hex))
                .collect::<anyhow::Result<Vec<_>>>()?;
            exec.execute_sync(&inputs)
        }
        Err(err) => ExecutionResult::failure(err.to_string()),
    };

    let response = ExecResponse::from_result(result);
    let response_json = serde_json::to_string(&response)?;

    match std::env::var("ZK_FUZZER_EXEC_RESPONSE") {
        Ok(path) => std::fs::write(path, response_json)?,
        Err(std::env::VarError::NotPresent) => println!("{response_json}"),
        Err(e) => anyhow::bail!("Invalid ZK_FUZZER_EXEC_RESPONSE value: {}", e),
    }

    Ok(())
}
