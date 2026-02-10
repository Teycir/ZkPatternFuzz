//! Process-isolated circuit execution for hard per-exec timeouts.

use crate::executor::{ExecutorFactory, ExecutorFactoryOptions};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
    pub circom_ptau_path: Option<String>,
    #[serde(default)]
    pub circom_snarkjs_path: Option<String>,
    #[serde(default)]
    pub circom_skip_compile_if_artifacts: bool,
    pub strict_backend: bool,
    pub mark_fallback: bool,
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
            circom_ptau_path: options
                .circom_ptau_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            circom_snarkjs_path: options
                .circom_snarkjs_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            circom_skip_compile_if_artifacts: options.circom_skip_compile_if_artifacts,
            strict_backend: options.strict_backend,
            mark_fallback: options.mark_fallback,
        }
    }

    fn to_factory_options(&self) -> ExecutorFactoryOptions {
        let mut options = ExecutorFactoryOptions::default();
        options.build_dir_base = self.build_dir_base.as_ref().map(PathBuf::from);
        options.circom_build_dir = self.circom_build_dir.as_ref().map(PathBuf::from);
        options.noir_build_dir = self.noir_build_dir.as_ref().map(PathBuf::from);
        options.halo2_build_dir = self.halo2_build_dir.as_ref().map(PathBuf::from);
        options.cairo_build_dir = self.cairo_build_dir.as_ref().map(PathBuf::from);
        options.circom_include_paths = self
            .circom_include_paths
            .iter()
            .map(PathBuf::from)
            .collect();
        options.circom_auto_setup_keys = self.circom_auto_setup_keys;
        options.circom_ptau_path = self.circom_ptau_path.as_ref().map(PathBuf::from);
        options.circom_snarkjs_path = self.circom_snarkjs_path.as_ref().map(PathBuf::from);
        options.circom_skip_compile_if_artifacts = self.circom_skip_compile_if_artifacts;
        options.strict_backend = self.strict_backend;
        options.mark_fallback = self.mark_fallback;
        options
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

    fn to_result(self) -> anyhow::Result<ExecutionResult> {
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

/// Circuit executor wrapper that isolates each execution in a subprocess.
pub struct IsolatedExecutor {
    inner: Arc<dyn CircuitExecutor>,
    base_request: ExecRequestBase,
    timeout_ms: u64,
    worker_exe: PathBuf,
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
        Ok(Self {
            inner,
            base_request,
            timeout_ms: timeout_ms.max(1),
            worker_exe,
        })
    }

    fn run_isolated(&self, request: &ExecRequest) -> anyhow::Result<ExecResponse> {
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

        let timeout = Duration::from_millis(self.timeout_ms);
        let start = Instant::now();

        loop {
            if let Some(_status) = child.try_wait()? {
                break;
            }

            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_file(&response_path);
                anyhow::bail!("Execution timeout after {} ms", self.timeout_ms);
            }

            thread::sleep(Duration::from_millis(5));
        }

        let response_data = std::fs::read_to_string(&response_path)
            .with_context(|| format!("Exec worker response missing at {:?}", response_path))?;
        let _ = std::fs::remove_file(&response_path);

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

    fn is_mock(&self) -> bool {
        self.inner.is_mock()
    }

    fn is_fallback_mock(&self) -> bool {
        self.inner.is_fallback_mock()
    }

    fn circuit_info(&self) -> zk_core::CircuitInfo {
        self.inner.circuit_info()
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        let request = self.base_request.with_inputs(inputs);
        match self
            .run_isolated(&request)
            .and_then(|resp| resp.to_result())
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
    if let Ok(path) = std::env::var("ZK_FUZZER_EXEC_WORKER") {
        return Ok(PathBuf::from(path));
    }
    Ok(std::env::current_exe()?)
}

fn make_response_path() -> anyhow::Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let pid = std::process::id();
    let filename = format!("zkf_exec_response_{}_{}.json", pid, now.as_nanos());
    Ok(std::env::temp_dir().join(filename))
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

    if let Ok(path) = std::env::var("ZK_FUZZER_EXEC_RESPONSE") {
        std::fs::write(path, response_json)?;
    } else {
        println!("{response_json}");
    }

    Ok(())
}
