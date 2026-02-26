use anyhow::Context;
use chrono::Utc;
use clap::{ArgAction, Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[path = "zkpatternfuzz/checkenv.rs"]
mod checkenv;
#[path = "zkpatternfuzz/zkpatternfuzz_env.rs"]
mod zkpatternfuzz_env;
#[path = "zkpatternfuzz/zkpatternfuzz_readiness.rs"]
mod zkpatternfuzz_readiness;

use checkenv::CheckEnv;
use zkpatternfuzz_env::{expand_env_placeholders, has_unresolved_env_placeholder};
use zkpatternfuzz_readiness::{ensure_local_runtime_requirements, preflight_template_paths};

const SCAN_RUN_ROOT_ENV: &str = "ZKF_SCAN_RUN_ROOT";
const SCAN_OUTPUT_ROOT_ENV: &str = "ZKF_SCAN_OUTPUT_ROOT";
const RUN_SIGNAL_DIR_ENV: &str = "ZKF_RUN_SIGNAL_DIR";
const BUILD_CACHE_DIR_ENV: &str = "ZKF_BUILD_CACHE_DIR";
const SHARED_BUILD_CACHE_DIR_ENV: &str = "ZKF_SHARED_BUILD_CACHE_DIR";
const HALO2_EXTERNAL_TIMEOUT_ENV: &str = "ZK_FUZZER_HALO2_EXTERNAL_TIMEOUT_SECS";
const HALO2_MIN_EXTERNAL_TIMEOUT_ENV: &str = "ZK_FUZZER_HALO2_MIN_EXTERNAL_TIMEOUT_SECS";
const HALO2_CARGO_RUN_BIN_ENV: &str = "ZK_FUZZER_HALO2_CARGO_RUN_BIN";
const HALO2_USE_HOST_CARGO_HOME_ENV: &str = "ZK_FUZZER_HALO2_USE_HOST_CARGO_HOME";
const HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV: &str = "ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES";
const HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV: &str = "ZK_FUZZER_HALO2_TOOLCHAIN_CASCADE_LIMIT";
const HALO2_DEFAULT_BATCH_TIMEOUT_ENV: &str = "ZKF_HALO2_DEFAULT_TIMEOUT_SECS";
const CAIRO_EXTERNAL_TIMEOUT_ENV: &str = "ZK_FUZZER_CAIRO_EXTERNAL_TIMEOUT_SECS";
const SCARB_DOWNLOAD_TIMEOUT_ENV: &str = "ZK_FUZZER_SCARB_DOWNLOAD_TIMEOUT_SECS";
const HIGH_CONFIDENCE_MIN_ORACLES_ENV: &str = "ZKF_HIGH_CONFIDENCE_MIN_ORACLES";
const DEFAULT_BATCH_JOBS_ENV: &str = "ZKF_ZKPATTERNFUZZ_DEFAULT_JOBS";
const DEFAULT_BATCH_WORKERS_ENV: &str = "ZKF_ZKPATTERNFUZZ_DEFAULT_WORKERS";
const DEFAULT_BATCH_ITERATIONS_ENV: &str = "ZKF_ZKPATTERNFUZZ_DEFAULT_ITERATIONS";
const DEFAULT_BATCH_TIMEOUT_ENV: &str = "ZKF_ZKPATTERNFUZZ_DEFAULT_TIMEOUT_SECS";
const MEMORY_GUARD_ENABLED_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_GUARD_ENABLED";
const MEMORY_GUARD_RESERVED_MB_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_RESERVED_MB";
const MEMORY_GUARD_MB_PER_TEMPLATE_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_MB_PER_TEMPLATE";
const MEMORY_GUARD_MB_PER_WORKER_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_MB_PER_WORKER";
const MEMORY_GUARD_LAUNCH_FLOOR_MB_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_LAUNCH_FLOOR_MB";
const MEMORY_GUARD_WAIT_SECS_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_WAIT_SECS";
const MEMORY_GUARD_POLL_MS_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_POLL_MS";
const DETECTION_STAGE_TIMEOUT_ENV: &str = "ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS";
const PROOF_STAGE_TIMEOUT_ENV: &str = "ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS";
const STUCK_STEP_WARN_SECS_ENV: &str = "ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS";
const DEFAULT_HIGH_CONFIDENCE_MIN_ORACLES: usize = 2;
const DEFAULT_BATCH_TIMEOUT_SECS: u64 = 1_800;
const DEFAULT_HALO2_BATCH_TIMEOUT_SECS: u64 = 3_600;
const DEFAULT_STUCK_STEP_WARN_SECS: u64 = 60;
const DEFAULT_MEMORY_GUARD_RESERVED_MB: u64 = 4_096;
const DEFAULT_MEMORY_GUARD_MB_PER_TEMPLATE: u64 = 768;
const DEFAULT_MEMORY_GUARD_MB_PER_WORKER: u64 = 1_536;
const DEFAULT_MEMORY_GUARD_LAUNCH_FLOOR_MB: u64 = 2_048;
const DEFAULT_MEMORY_GUARD_WAIT_SECS: u64 = 180;
const DEFAULT_MEMORY_GUARD_POLL_MS: u64 = 1_000;
const DEFAULT_REGISTRY_PATH: &str = "targets/fuzzer_registry.yaml";
const DEV_REGISTRY_PATH: &str = "targets/fuzzer_registry.dev.yaml";
const PROD_REGISTRY_PATH: &str = "targets/fuzzer_registry.prod.yaml";
const PROOF_STAGE_NOT_STARTED_REASON_CODE: &str = "proof_stage_not_started";
const MAX_PIPE_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const PIPE_CAPTURE_TRUNCATED_NOTICE: &str =
    "\n[zkpatternfuzz] command output truncated to 8 MiB per stream\n";
static RUN_ROOT_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Parser, Debug)]
#[command(name = "zkpatternfuzz")]
#[command(about = "Batch runner for YAML attack-pattern catalogs")]
struct Args {
    /// Path to JSON/YAML run config (target/env/iterations/timeouts); `run_overrides` wrapper is supported
    #[arg(long)]
    config_json: Option<String>,

    /// Path to fuzzer registry YAML
    #[arg(long)]
    registry: Option<String>,

    /// Config profile for default registry path selection
    #[arg(long, value_enum)]
    config_profile: Option<ConfigProfile>,

    /// List available collections/aliases/templates and exit
    #[arg(long, default_value_t = false)]
    list_catalog: bool,

    /// Comma-separated collection names to run
    /// If no selector flags are provided, all discovered pattern YAML files are executed.
    #[arg(long)]
    collection: Option<String>,

    /// Comma-separated alias names to run
    /// If no selector flags are provided, all discovered pattern YAML files are executed.
    #[arg(long)]
    alias: Option<String>,

    /// Comma-separated template filenames to run
    /// If no selector flags are provided, all discovered pattern YAML files are executed.
    #[arg(long)]
    template: Option<String>,

    /// Comma-separated pattern YAML paths (bypasses registry selectors)
    /// If omitted with no selector flags, the runner auto-discovers all pattern-compatible YAML files.
    #[arg(long)]
    pattern_yaml: Option<String>,

    /// Target circuit path used for all selected templates
    #[arg(long)]
    target_circuit: Option<String>,

    /// Main component used for all selected templates
    #[arg(long, default_value = "main")]
    main_component: String,

    /// Framework used for all selected templates
    #[arg(long, default_value = "circom")]
    framework: String,

    /// Family override passed to `zk-fuzzer scan`
    #[arg(long, default_value = "auto")]
    family: String,

    /// Build release binary if missing
    #[arg(long, default_value_t = true)]
    build: bool,

    /// Skip YAML validation pass
    #[arg(long, default_value_t = false)]
    skip_validate: bool,

    /// Dry run (print commands only)
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Maximum number of templates to execute in parallel (env: ZKF_ZKPATTERNFUZZ_DEFAULT_JOBS)
    #[arg(long, env = DEFAULT_BATCH_JOBS_ENV)]
    jobs: usize,

    /// Worker count per run (env: ZKF_ZKPATTERNFUZZ_DEFAULT_WORKERS)
    #[arg(long, env = DEFAULT_BATCH_WORKERS_ENV)]
    workers: usize,

    /// RNG seed per run
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Iterations per run (env: ZKF_ZKPATTERNFUZZ_DEFAULT_ITERATIONS)
    #[arg(long, env = DEFAULT_BATCH_ITERATIONS_ENV, default_value_t = 50_000)]
    iterations: u64,

    /// Timeout per run in seconds (env: ZKF_ZKPATTERNFUZZ_DEFAULT_TIMEOUT_SECS).
    /// Halo2 uses a higher framework default when this is left unset.
    #[arg(long, env = DEFAULT_BATCH_TIMEOUT_ENV, default_value_t = DEFAULT_BATCH_TIMEOUT_SECS)]
    timeout: u64,

    /// Emit per-template reason codes as TSV to stdout (for external harness ingestion)
    #[arg(long, default_value_t = false)]
    emit_reason_tsv: bool,

    /// Disable batch-level progress lines (enabled by default)
    #[arg(long, default_value_t = false)]
    no_batch_progress: bool,

    /// Prepare target artifacts before template execution (framework-specific)
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    prepare_target: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConfigProfile {
    Dev,
    Prod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Auto,
    Mono,
    Multi,
}

impl Family {
    fn as_str(self) -> &'static str {
        match self {
            Family::Auto => "auto",
            Family::Mono => "mono",
            Family::Multi => "multi",
        }
    }
}

fn default_registry_for_profile(profile: Option<ConfigProfile>) -> &'static str {
    match profile {
        Some(ConfigProfile::Dev) => DEV_REGISTRY_PATH,
        Some(ConfigProfile::Prod) => PROD_REGISTRY_PATH,
        None => DEFAULT_REGISTRY_PATH,
    }
}

#[derive(Debug, Deserialize, Default)]
struct RegistryFile {
    version: serde_yaml::Value,
    #[serde(default)]
    registries: BTreeMap<String, RegistryEntry>,
    #[serde(default)]
    collections: BTreeMap<String, CollectionEntry>,
    #[serde(default)]
    aliases: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct RegistryEntry {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    maintainer: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct CollectionEntry {
    registry: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    templates: Vec<String>,
}

#[derive(Debug, Clone)]
struct TemplateInfo {
    file_name: String,
    path: PathBuf,
    family: Family,
}

type TemplateIndex = BTreeMap<String, TemplateInfo>;
type CollectionIndex = BTreeMap<String, Vec<String>>;
type DedupeResult = (Vec<TemplateInfo>, Vec<(TemplateInfo, TemplateInfo)>);

#[derive(Debug, Deserialize, Clone, Default)]
struct BatchFileConfig {
    #[serde(default)]
    target_circuit: Option<String>,
    #[serde(default)]
    main_component: Option<String>,
    #[serde(default)]
    framework: Option<String>,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    collection: Option<String>,
    #[serde(default)]
    alias: Option<String>,
    #[serde(default)]
    template: Option<String>,
    #[serde(default)]
    pattern_yaml: Option<String>,
    #[serde(default)]
    jobs: Option<usize>,
    #[serde(default)]
    workers: Option<usize>,
    #[serde(default)]
    seed: Option<u64>,
    #[serde(default)]
    iterations: Option<u64>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    env: BTreeMap<String, serde_yaml::Value>,
    #[serde(default)]
    extra_args: Vec<String>,
    #[serde(default)]
    prepare_target: Option<bool>,
}

#[derive(Debug, Clone, Default)]
struct EffectiveFileConfig {
    env: BTreeMap<String, String>,
    extra_args: Vec<String>,
}

#[derive(Clone, Copy)]
struct ScanRunConfig<'a> {
    bin_path: &'a Path,
    target_circuit: &'a str,
    framework: &'a str,
    main_component: &'a str,
    env_overrides: &'a BTreeMap<String, String>,
    extra_args: &'a [String],
    workers: usize,
    seed: u64,
    iterations: u64,
    timeout: u64,
    scan_run_root: Option<&'a str>,
    results_root: &'a Path,
    run_signal_dir: &'a Path,
    build_cache_dir: &'a Path,
    dry_run: bool,
    artifacts_root: &'a Path,
    memory_guard: MemoryGuardConfig,
    stage_timeouts: StageTimeoutConfig,
}

#[derive(Debug, Clone, Copy)]
struct MemoryGuardConfig {
    enabled: bool,
    reserved_mb: u64,
    mb_per_template: u64,
    mb_per_worker: u64,
    launch_floor_mb: u64,
    wait_secs: u64,
    poll_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct StageTimeoutConfig {
    detection_timeout_secs: u64,
    proof_timeout_secs: u64,
    stuck_step_warn_secs: u64,
}

#[derive(Debug, Clone)]
struct TemplateOutcomeReason {
    template_file: String,
    template_path: String,
    suffix: String,
    status: Option<String>,
    stage: Option<String>,
    proof_status: Option<String>,
    reason_code: String,
    high_confidence_detected: bool,
    detected_pattern_count: usize,
}

struct ScanRunResult {
    success: bool,
    stdout: String,
    stderr: String,
}

struct TemplateProgressUpdate {
    dedupe_key: String,
    rendered_line: String,
    stage: String,
    step_fraction: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardTimeoutStage {
    Detecting,
    Proving,
}

struct BatchProgress {
    total: usize,
    started_at: Instant,
    completed: AtomicUsize,
    template_errors: AtomicUsize,
}

impl BatchProgress {
    fn new(total: usize) -> Self {
        Self {
            total,
            started_at: Instant::now(),
            completed: AtomicUsize::new(0),
            template_errors: AtomicUsize::new(0),
        }
    }

    fn record(&self, template_file: &str, success: bool) -> String {
        let completed = self.completed.fetch_add(1, Ordering::SeqCst) + 1;
        let template_errors = if success {
            self.template_errors.load(Ordering::SeqCst)
        } else {
            self.template_errors.fetch_add(1, Ordering::SeqCst) + 1
        };
        let succeeded = completed.saturating_sub(template_errors);
        let elapsed_secs = self.started_at.elapsed().as_secs_f64();

        format_batch_progress_line(
            completed,
            self.total,
            succeeded,
            template_errors,
            elapsed_secs,
            template_file,
            success,
        )
    }
}

fn format_batch_progress_line(
    completed: usize,
    total: usize,
    succeeded: usize,
    template_errors: usize,
    elapsed_secs: f64,
    template_file: &str,
    success: bool,
) -> String {
    let percent = if total == 0 {
        100.0
    } else {
        (completed as f64 * 100.0) / total as f64
    };
    let elapsed = elapsed_secs.max(0.001);
    let rate = completed as f64 / elapsed;
    let remaining = total.saturating_sub(completed);
    let eta_secs = if rate > 0.0 {
        remaining as f64 / rate
    } else {
        0.0
    };
    let result = if success { "ok" } else { "template_error" };

    format!(
        "[BATCH PROGRESS] {}/{} ({:.1}%) ok={} template_errors={} elapsed={:.1}s rate={:.2}/s eta={:.1}s last={} result={}",
        completed,
        total,
        percent,
        succeeded,
        template_errors,
        elapsed,
        rate,
        eta_secs,
        template_file,
        result
    )
}

#[cfg(unix)]
fn prepare_child_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Place child in its own process group so timeout kills can terminate descendants.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn prepare_child_process_group(_cmd: &mut Command) {}

#[cfg(unix)]
fn kill_child_tree(child: &mut Child) -> std::io::Result<()> {
    let pgid = child.id() as i32;
    let rc = unsafe { libc::killpg(pgid, libc::SIGKILL) };
    if rc == 0 {
        return Ok(());
    }
    child.kill()
}

#[cfg(not(unix))]
fn kill_child_tree(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

#[derive(Debug)]
struct PipeCapture {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_pipe_with_cap<R: Read>(mut reader: R) -> anyhow::Result<PipeCapture> {
    let mut bytes = Vec::new();
    let mut scratch = [0u8; 8192];
    let mut truncated = false;

    loop {
        let read = reader.read(&mut scratch)?;
        if read == 0 {
            break;
        }

        let remaining = MAX_PIPE_CAPTURE_BYTES.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = remaining.min(read);
            bytes.extend_from_slice(&scratch[..keep]);
            if keep < read {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    Ok(PipeCapture { bytes, truncated })
}

fn spawn_pipe_reader<R>(reader: R) -> JoinHandle<anyhow::Result<PipeCapture>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || read_pipe_with_cap(reader))
}

fn join_pipe_reader(
    handle: Option<JoinHandle<anyhow::Result<PipeCapture>>>,
) -> anyhow::Result<PipeCapture> {
    match handle {
        Some(handle) => {
            let result = handle
                .join()
                .map_err(|_| anyhow::anyhow!("failed to join command output reader thread"))?;
            result
        }
        None => Ok(PipeCapture {
            bytes: Vec::new(),
            truncated: false,
        }),
    }
}

fn finalize_pipe_capture(stdout: PipeCapture, mut stderr: PipeCapture) -> (Vec<u8>, Vec<u8>) {
    if stdout.truncated || stderr.truncated {
        stderr
            .bytes
            .extend_from_slice(PIPE_CAPTURE_TRUNCATED_NOTICE.as_bytes());
    }
    (stdout.bytes, stderr.bytes)
}

fn template_progress_path(run_cfg: ScanRunConfig<'_>, output_suffix: &str) -> PathBuf {
    if let Some(run_root) = run_cfg.scan_run_root {
        run_cfg
            .artifacts_root
            .join(run_root)
            .join(output_suffix)
            .join("progress.json")
    } else {
        run_cfg
            .results_root
            .join(output_suffix)
            .join("progress.json")
    }
}

fn read_template_progress_update(
    template_file: &str,
    progress_path: &Path,
) -> Option<TemplateProgressUpdate> {
    let raw = fs::read_to_string(progress_path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let progress = doc.get("progress")?;
    let step_fraction = progress
        .get("step_fraction")
        .and_then(|v| v.as_str())
        .unwrap_or("?/??");
    let stage = doc
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let details = doc.get("details");
    let attack_type = details
        .and_then(|d| d.get("attack_type"))
        .and_then(|v| v.as_str());
    let elapsed_seconds = details
        .and_then(|d| d.get("elapsed_seconds"))
        .and_then(|v| v.as_u64());
    let findings_total = details
        .and_then(|d| d.get("findings_total"))
        .and_then(|v| v.as_u64());

    let mut rendered = format!(
        "[TEMPLATE STEP] {} step={} stage={}",
        template_file, step_fraction, stage
    );
    if let Some(attack_type) = attack_type {
        rendered.push_str(&format!(" attack={}", attack_type));
    }
    if let Some(elapsed_seconds) = elapsed_seconds {
        rendered.push_str(&format!(" elapsed={}s", elapsed_seconds));
    }
    if stage == "completed" {
        if let Some(findings_total) = findings_total {
            rendered.push_str(&format!(" detected_patterns={}", findings_total));
        }
    }

    let dedupe_key = format!(
        "{}|{}|{}|{}|{}",
        step_fraction,
        stage,
        attack_type.unwrap_or_default(),
        elapsed_seconds.unwrap_or(0),
        findings_total.unwrap_or(0)
    );

    Some(TemplateProgressUpdate {
        dedupe_key,
        rendered_line: rendered,
        stage: stage.to_string(),
        step_fraction: step_fraction.to_string(),
    })
}

fn progress_stage_is_proof(stage: &str) -> bool {
    let normalized = stage.trim().to_ascii_lowercase();
    normalized == "reporting"
        || normalized == "completed"
        || normalized.contains("proof")
        || normalized.contains("report")
        || normalized.contains("evidence")
}

fn format_stuck_step_warning_line(
    template_file: &str,
    stage: &str,
    step_fraction: &str,
    stagnant_secs: u64,
    window_secs: u64,
) -> String {
    format!(
        "[TEMPLATE WARNING] {} warning=stuck_step stage={} step={} no_progress_for={}s window={}s",
        template_file, stage, step_fraction, stagnant_secs, window_secs
    )
}

fn run_command_with_stage_timeouts(
    cmd: &mut Command,
    template_file: &str,
    progress_path: &Path,
    stage_timeouts: StageTimeoutConfig,
    memory_guard: MemoryGuardConfig,
) -> anyhow::Result<(Output, Option<HardTimeoutStage>)> {
    let launch_guard = memory_headroom_launch_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    wait_for_memory_headroom(memory_guard).with_context(|| {
        format!(
            "Template '{}' launch blocked by memory guard",
            template_file
        )
    })?;

    prepare_child_process_group(cmd);
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(launch_guard);

    let stdout_reader = child.stdout.take().map(spawn_pipe_reader);
    let stderr_reader = child.stderr.take().map(spawn_pipe_reader);

    let started = Instant::now();
    let detection_timeout = Duration::from_secs(stage_timeouts.detection_timeout_secs.max(1));
    let proof_timeout = Duration::from_secs(stage_timeouts.proof_timeout_secs.max(1));
    let stuck_warn_window = Duration::from_secs(stage_timeouts.stuck_step_warn_secs.max(1));
    let mut proof_stage_started: Option<Instant> = None;
    let mut last_progress_dedupe_key: Option<String> = None;
    let mut last_progress_change_at = started;
    let mut next_stuck_warning_at = started + stuck_warn_window;
    let mut last_stage_label = "unknown".to_string();
    let mut last_step_fraction = "?/??".to_string();

    loop {
        if let Some(status) = child.try_wait()? {
            if let Some(update) = read_template_progress_update(template_file, progress_path) {
                let changed = match &last_progress_dedupe_key {
                    Some(prev) => prev != &update.dedupe_key,
                    None => true,
                };
                if changed {
                    println!("{}", update.rendered_line);
                }
            }
            let stdout_capture = join_pipe_reader(stdout_reader)?;
            let stderr_capture = join_pipe_reader(stderr_reader)?;
            let (stdout, stderr) = finalize_pipe_capture(stdout_capture, stderr_capture);
            return Ok((
                Output {
                    status,
                    stdout,
                    stderr,
                },
                None,
            ));
        }

        if let Some(update) = read_template_progress_update(template_file, progress_path) {
            let changed = match &last_progress_dedupe_key {
                Some(prev) => prev != &update.dedupe_key,
                None => true,
            };
            last_stage_label = update.stage.clone();
            last_step_fraction = update.step_fraction.clone();
            if changed {
                println!("{}", update.rendered_line);
                last_progress_dedupe_key = Some(update.dedupe_key.clone());
                last_progress_change_at = Instant::now();
                next_stuck_warning_at = last_progress_change_at + stuck_warn_window;
            }
            if proof_stage_started.is_none() && progress_stage_is_proof(&update.stage) {
                proof_stage_started = Some(Instant::now());
            }
        }

        let now = Instant::now();
        if now >= next_stuck_warning_at {
            let stagnant_secs = now.duration_since(last_progress_change_at).as_secs();
            eprintln!(
                "{}",
                format_stuck_step_warning_line(
                    template_file,
                    &last_stage_label,
                    &last_step_fraction,
                    stagnant_secs,
                    stage_timeouts.stuck_step_warn_secs,
                )
            );
            next_stuck_warning_at = now + stuck_warn_window;
        }
        let timeout_stage = if let Some(proof_started_at) = proof_stage_started {
            if now.duration_since(proof_started_at) >= proof_timeout {
                Some(HardTimeoutStage::Proving)
            } else {
                None
            }
        } else if now.duration_since(started) >= detection_timeout {
            Some(HardTimeoutStage::Detecting)
        } else {
            None
        };

        if let Some(stage) = timeout_stage {
            let _ = kill_child_tree(&mut child);
            let status = child.wait()?;
            let stdout_capture = join_pipe_reader(stdout_reader)?;
            let stderr_capture = join_pipe_reader(stderr_reader)?;
            let (stdout, mut stderr) = finalize_pipe_capture(stdout_capture, stderr_capture);
            let (stage_label, stage_budget) = match stage {
                HardTimeoutStage::Detecting => ("detection", stage_timeouts.detection_timeout_secs),
                HardTimeoutStage::Proving => ("proof", stage_timeouts.proof_timeout_secs),
            };
            stderr.extend_from_slice(
                format!(
                    "\nPer-template hard wall-clock timeout reached during {} stage (budget={}s)\n",
                    stage_label, stage_budget
                )
                .as_bytes(),
            );
            return Ok((
                Output {
                    status,
                    stdout,
                    stderr,
                },
                Some(stage),
            ));
        }

        thread::sleep(Duration::from_millis(200));
    }
}

fn report_has_high_confidence_finding(report_path: &Path) -> bool {
    report_has_high_confidence_finding_with_min_oracles(
        report_path,
        high_confidence_min_oracles_from_env(),
    )
}

fn report_detected_pattern_count(report_path: &Path) -> usize {
    let raw = match fs::read_to_string(report_path) {
        Ok(raw) => raw,
        Err(_) => return 0,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(_) => return 0,
    };
    parsed
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|entries| entries.len())
        .unwrap_or(0)
}

fn high_confidence_min_oracles_from_env() -> usize {
    std::env::var(HIGH_CONFIDENCE_MIN_ORACLES_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_HIGH_CONFIDENCE_MIN_ORACLES)
}

fn parse_correlation_confidence(description: &str) -> Option<String> {
    let marker = "correlation:";
    let description_lc = description.to_ascii_lowercase();
    let start = description_lc.find(marker)?;
    let tail = description_lc.get(start + marker.len()..)?.trim_start();
    let token = tail
        .split_whitespace()
        .next()?
        .trim_matches(|ch: char| ch == '(' || ch == ')' || ch == ',' || ch == ';' || ch == '.');
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn parse_correlation_oracle_count(description: &str) -> Option<usize> {
    let marker = "oracles=";
    let start = description.find(marker)?;
    let tail = description.get(start + marker.len()..)?;
    let digits: String = tail.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<usize>().ok()
}

fn report_has_high_confidence_finding_with_min_oracles(
    report_path: &Path,
    min_oracles: usize,
) -> bool {
    let raw = match fs::read_to_string(report_path) {
        Ok(raw) => raw,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    let Some(findings) = parsed.get("findings").and_then(|v| v.as_array()) else {
        return false;
    };
    findings.iter().any(|finding| {
        let description = finding
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(confidence) = parse_correlation_confidence(description) else {
            return false;
        };
        if confidence == "critical" {
            return true;
        }
        if confidence != "high" {
            return false;
        }
        match parse_correlation_oracle_count(description) {
            Some(oracles) => oracles >= min_oracles,
            None => true,
        }
    })
}

fn parse_family(value: &str) -> anyhow::Result<Family> {
    match value {
        "auto" => Ok(Family::Auto),
        "mono" => Ok(Family::Mono),
        "multi" => Ok(Family::Multi),
        other => anyhow::bail!(
            "Unsupported family '{}'. Expected one of: auto, mono, multi",
            other
        ),
    }
}

fn ensure_positive_cli_values(args: &Args) -> anyhow::Result<()> {
    if args.jobs == 0 {
        anyhow::bail!("--jobs must be >= 1");
    }
    if args.workers == 0 {
        anyhow::bail!("--workers must be >= 1");
    }
    if args.iterations == 0 {
        anyhow::bail!("--iterations must be >= 1");
    }
    if args.timeout == 0 {
        anyhow::bail!("--timeout must be >= 1");
    }
    Ok(())
}

fn env_bool_with_default(name: &str, default: bool) -> anyhow::Result<bool> {
    let Ok(raw) = std::env::var(name) else {
        return Ok(default);
    };
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!(
            "Invalid {}='{}'. Use one of: 1/0, true/false, yes/no, on/off",
            name,
            raw
        ),
    }
}

fn env_u64_with_default(name: &str, default: u64, min: u64) -> anyhow::Result<u64> {
    let Ok(raw) = std::env::var(name) else {
        return Ok(default.max(min));
    };
    let trimmed = raw.trim();
    let parsed = trimmed
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Invalid {}='{}'. Expected an unsigned integer", name, raw))?;
    if parsed < min {
        anyhow::bail!("Invalid {}={}: must be >= {}", name, parsed, min);
    }
    Ok(parsed)
}

fn load_memory_guard_config() -> anyhow::Result<MemoryGuardConfig> {
    Ok(MemoryGuardConfig {
        enabled: env_bool_with_default(MEMORY_GUARD_ENABLED_ENV, true)?,
        reserved_mb: env_u64_with_default(
            MEMORY_GUARD_RESERVED_MB_ENV,
            DEFAULT_MEMORY_GUARD_RESERVED_MB,
            0,
        )?,
        mb_per_template: env_u64_with_default(
            MEMORY_GUARD_MB_PER_TEMPLATE_ENV,
            DEFAULT_MEMORY_GUARD_MB_PER_TEMPLATE,
            1,
        )?,
        mb_per_worker: env_u64_with_default(
            MEMORY_GUARD_MB_PER_WORKER_ENV,
            DEFAULT_MEMORY_GUARD_MB_PER_WORKER,
            1,
        )?,
        launch_floor_mb: env_u64_with_default(
            MEMORY_GUARD_LAUNCH_FLOOR_MB_ENV,
            DEFAULT_MEMORY_GUARD_LAUNCH_FLOOR_MB,
            1,
        )?,
        wait_secs: env_u64_with_default(
            MEMORY_GUARD_WAIT_SECS_ENV,
            DEFAULT_MEMORY_GUARD_WAIT_SECS,
            1,
        )?,
        poll_ms: env_u64_with_default(MEMORY_GUARD_POLL_MS_ENV, DEFAULT_MEMORY_GUARD_POLL_MS, 50)?,
    })
}

fn load_stage_timeout_config(default_timeout_secs: u64) -> anyhow::Result<StageTimeoutConfig> {
    Ok(StageTimeoutConfig {
        detection_timeout_secs: env_u64_with_default(
            DETECTION_STAGE_TIMEOUT_ENV,
            default_timeout_secs,
            1,
        )?,
        proof_timeout_secs: env_u64_with_default(PROOF_STAGE_TIMEOUT_ENV, default_timeout_secs, 1)?,
        stuck_step_warn_secs: env_u64_with_default(
            STUCK_STEP_WARN_SECS_ENV,
            DEFAULT_STUCK_STEP_WARN_SECS,
            1,
        )?,
    })
}

fn parse_mem_available_kib(meminfo: &str) -> Option<u64> {
    let mut mem_available_kib: Option<u64> = None;
    let mut mem_total_kib: Option<u64> = None;

    for line in meminfo.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(raw_value) = parts.next() else {
            continue;
        };
        let Ok(value) = raw_value.parse::<u64>() else {
            continue;
        };
        match key {
            "MemAvailable:" => mem_available_kib = Some(value),
            "MemTotal:" => mem_total_kib = Some(value),
            _ => {}
        }
    }

    mem_available_kib.or(mem_total_kib)
}

fn host_available_memory_mb() -> Option<u64> {
    let raw = fs::read_to_string("/proc/meminfo").ok()?;
    let kib = parse_mem_available_kib(&raw)?;
    Some((kib / 1024).max(1))
}

fn estimated_batch_memory_mb(jobs: usize, workers: usize, guard: MemoryGuardConfig) -> u64 {
    let jobs_u64 = jobs as u64;
    let workers_u64 = workers as u64;
    jobs_u64.saturating_mul(
        guard
            .mb_per_template
            .saturating_add(workers_u64.saturating_mul(guard.mb_per_worker)),
    )
}

fn apply_memory_parallelism_guardrails_with_available(
    args: &mut Args,
    guard: MemoryGuardConfig,
    available_mb: Option<u64>,
) -> anyhow::Result<()> {
    if !guard.enabled {
        anyhow::bail!(
            "Unsafe proof-stage memory settings: {}=false disables launch guardrails. \
             Keep memory guard enabled for proof-stage runs.",
            MEMORY_GUARD_ENABLED_ENV
        );
    }
    if guard.reserved_mb == 0 {
        anyhow::bail!(
            "Unsafe proof-stage memory settings: {}=0 removes host safety reserve. \
             Set {} to a positive value.",
            MEMORY_GUARD_RESERVED_MB_ENV,
            MEMORY_GUARD_RESERVED_MB_ENV
        );
    }

    let Some(available_mb) = available_mb else {
        eprintln!(
            "Memory guard: unable to read /proc/meminfo; skipping automatic jobs/workers throttling"
        );
        return Ok(());
    };

    let budget_mb = available_mb.saturating_sub(guard.reserved_mb);
    if budget_mb == 0 {
        anyhow::bail!(
            "Memory guard blocked run: MemAvailable={}MB <= reserved={}MB. \
             Lower {} or free memory.",
            available_mb,
            guard.reserved_mb,
            MEMORY_GUARD_RESERVED_MB_ENV
        );
    }

    let requested_jobs = args.jobs.max(1);
    let requested_workers = args.workers.max(1);
    let requested_estimate = estimated_batch_memory_mb(requested_jobs, requested_workers, guard);

    let mut safe_jobs = requested_jobs;
    let mut safe_workers = requested_workers;
    while safe_jobs > 1 && estimated_batch_memory_mb(safe_jobs, safe_workers, guard) > budget_mb {
        safe_jobs -= 1;
    }
    while safe_workers > 1 && estimated_batch_memory_mb(safe_jobs, safe_workers, guard) > budget_mb
    {
        safe_workers -= 1;
    }

    let safe_estimate = estimated_batch_memory_mb(safe_jobs, safe_workers, guard);
    if safe_estimate > budget_mb {
        anyhow::bail!(
            "Memory guard blocked run: requested jobs={} workers={} (~{}MB) exceeds budget {}MB \
             and cannot be safely reduced below jobs=1 workers=1 under current guardrail settings.",
            requested_jobs,
            requested_workers,
            requested_estimate,
            budget_mb
        );
    }

    if safe_jobs != requested_jobs || safe_workers != requested_workers {
        eprintln!(
            "Memory guard throttled parallelism: jobs {} -> {}, workers {} -> {} \
             (MemAvailable={}MB, reserve={}MB, budget={}MB, estimated={}MB)",
            requested_jobs,
            safe_jobs,
            requested_workers,
            safe_workers,
            available_mb,
            guard.reserved_mb,
            budget_mb,
            safe_estimate
        );
        args.jobs = safe_jobs;
        args.workers = safe_workers;
    }

    Ok(())
}

fn apply_memory_parallelism_guardrails(
    args: &mut Args,
    guard: MemoryGuardConfig,
) -> anyhow::Result<()> {
    apply_memory_parallelism_guardrails_with_available(args, guard, host_available_memory_mb())
}

fn memory_headroom_launch_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn wait_for_memory_headroom(guard: MemoryGuardConfig) -> anyhow::Result<()> {
    if !guard.enabled {
        return Ok(());
    }

    let Some(initial_available_mb) = host_available_memory_mb() else {
        return Ok(());
    };
    if initial_available_mb >= guard.launch_floor_mb {
        return Ok(());
    }

    let deadline = Instant::now() + Duration::from_secs(guard.wait_secs);
    let mut last_seen_mb = initial_available_mb;
    let mut warned = false;

    loop {
        if let Some(available_mb) = host_available_memory_mb() {
            last_seen_mb = available_mb;
            if available_mb >= guard.launch_floor_mb {
                return Ok(());
            }
            if !warned {
                eprintln!(
                    "Memory guard waiting: MemAvailable={}MB below launch floor {}MB \
                     (wait up to {}s)",
                    available_mb, guard.launch_floor_mb, guard.wait_secs
                );
                warned = true;
            }
        }

        if Instant::now() >= deadline {
            anyhow::bail!(
                "Memory guard timeout: MemAvailable={}MB stayed below launch floor {}MB \
                 for {}s",
                last_seen_mb,
                guard.launch_floor_mb,
                guard.wait_secs
            );
        }

        std::thread::sleep(Duration::from_millis(guard.poll_ms));
    }
}

fn template_family_from_name(name: &str) -> anyhow::Result<Family> {
    if name.ends_with(".yaml") || name.ends_with(".yml") {
        return Ok(Family::Auto);
    }
    anyhow::bail!(
        "Invalid template filename '{}': expected .yaml or .yml extension",
        name
    )
}

fn validate_template_name(name: &str) -> anyhow::Result<()> {
    let _family = template_family_from_name(name)?;
    let prefix = name.trim_end_matches(".yaml").trim_end_matches(".yml");

    if prefix.is_empty() {
        anyhow::bail!(
            "Invalid template filename '{}': missing attack identifier before extension",
            name
        );
    }

    if !prefix
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        anyhow::bail!(
            "Invalid template filename '{}': use only letters, digits, and underscores before suffix",
            name
        );
    }

    if !prefix.contains('_') {
        anyhow::bail!(
            "Invalid template filename '{}': expected pattern '<attacktype>_<attack>.yaml'",
            name
        );
    }

    Ok(())
}

fn split_csv(input: Option<&str>) -> Vec<String> {
    let Some(input) = input else {
        return Vec::new();
    };

    input
        .split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect()
}

fn yaml_key(name: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(name.to_string())
}

fn env_value_to_string(value: &serde_yaml::Value) -> anyhow::Result<Option<String>> {
    let rendered = match value {
        serde_yaml::Value::Null => return Ok(None),
        serde_yaml::Value::Bool(v) => {
            if *v {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        serde_yaml::Value::Number(v) => v.to_string(),
        serde_yaml::Value::String(v) => v.clone(),
        other => anyhow::bail!(
            "Unsupported env override value type: {:?}. Use scalar string/number/bool.",
            other
        ),
    };
    Ok(Some(rendered))
}

fn load_batch_file_config(raw_path: &str) -> anyhow::Result<BatchFileConfig> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        anyhow::bail!("--config-json cannot be empty");
    }
    let path = PathBuf::from(trimmed);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config file '{}'", path.display()))?;
    let mut parsed: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse config file '{}'", path.display()))?;

    if let Some(map) = parsed.as_mapping_mut() {
        if let Some(inner) = map.get(yaml_key("run_overrides")) {
            parsed = inner.clone();
        } else if let Some(inner) = map.get(yaml_key("run")) {
            parsed = inner.clone();
        } else if let Some(inner) = map.get(yaml_key("config")) {
            parsed = inner.clone();
        }
    }

    if let Some(map) = parsed.as_mapping() {
        if map.contains_key(yaml_key("output_root")) {
            anyhow::bail!(
                "Invalid config '{}': output_root is no longer supported; set {} in your env config file",
                path.display(),
                SCAN_OUTPUT_ROOT_ENV
            );
        }
    }

    serde_yaml::from_value(parsed).with_context(|| {
        format!(
            "Failed to decode config file '{}'. Expected keys such as pattern_yaml/target_circuit/workers/iterations/timeout/env.",
            path.display()
        )
    })
}

fn apply_file_config(args: &mut Args, cfg: BatchFileConfig) -> anyhow::Result<EffectiveFileConfig> {
    if args.target_circuit.is_none() {
        args.target_circuit = cfg.target_circuit;
    }
    if args.collection.is_none() {
        args.collection = cfg.collection;
    }
    if args.alias.is_none() {
        args.alias = cfg.alias;
    }
    if args.template.is_none() {
        args.template = cfg.template;
    }
    if args.pattern_yaml.is_none() {
        args.pattern_yaml = cfg.pattern_yaml;
    }
    if let Some(value) = cfg.main_component {
        args.main_component = value;
    }
    if let Some(value) = cfg.framework {
        args.framework = value;
    }
    if let Some(value) = cfg.family {
        args.family = value;
    }
    if let Some(value) = cfg.jobs {
        if value == 0 {
            anyhow::bail!("Invalid config: jobs cannot be zero");
        }
        args.jobs = value;
    }
    if let Some(value) = cfg.workers {
        if value == 0 {
            anyhow::bail!("Invalid config: workers cannot be zero");
        }
        args.workers = value;
    }
    if let Some(value) = cfg.seed {
        args.seed = value;
    }
    if let Some(value) = cfg.iterations {
        args.iterations = value;
    }
    if let Some(value) = cfg.timeout {
        if value == 0 {
            anyhow::bail!("Invalid config: timeout cannot be zero");
        }
        args.timeout = value;
    }
    if let Some(value) = cfg.prepare_target {
        args.prepare_target = value;
    }

    let mut env = BTreeMap::new();
    for (key, value) in cfg.env {
        if key.trim().is_empty() {
            anyhow::bail!("Invalid config: env key cannot be empty");
        }
        if let Some(rendered) = env_value_to_string(&value)? {
            env.insert(key, rendered);
        }
    }

    Ok(EffectiveFileConfig {
        env,
        extra_args: cfg.extra_args,
    })
}

fn validate_pattern_only_yaml(path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read pattern YAML '{}': {}", path.display(), e))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("Failed to parse pattern YAML '{}': {}", path.display(), e))?;
    let root = doc.as_mapping().ok_or_else(|| {
        anyhow::anyhow!("Pattern YAML '{}' root must be a mapping", path.display())
    })?;

    let allowed: BTreeSet<&'static str> = BTreeSet::from([
        "includes",
        "profiles",
        "active_profile",
        "patterns",
        "selector_policy",
        "selector_synonyms",
        "synonym_bundles",
        "selector_normalization",
        "target_traits",
        "invariants",
        "schedule",
        "attacks",
        "inputs",
        "mutations",
        "oracles",
        "chains",
    ]);

    let mut unexpected = Vec::new();
    for key in root.keys() {
        let Some(key) = key.as_str() else {
            anyhow::bail!(
                "Pattern YAML '{}' contains a non-string top-level key",
                path.display()
            );
        };
        if !allowed.contains(key) {
            unexpected.push(key.to_string());
        }
    }

    if !unexpected.is_empty() {
        unexpected.sort();
        anyhow::bail!(
            "Pattern YAML '{}' must be pattern-only. Unsupported top-level keys: [{}]",
            path.display(),
            unexpected.join(", ")
        );
    }

    Ok(())
}

fn collection_base_path(
    registry_path: &Path,
    collection: &CollectionEntry,
    registries: &BTreeMap<String, RegistryEntry>,
) -> anyhow::Result<PathBuf> {
    let registry = registries
        .get(&collection.registry)
        .ok_or_else(|| anyhow::anyhow!("Unknown registry '{}'", collection.registry))?;

    let base = match &registry.path {
        Some(path) => {
            let from_cwd = PathBuf::from(path);
            if from_cwd.is_absolute() || from_cwd.exists() {
                from_cwd
            } else {
                // Recovery for catalogs that keep paths relative to the catalog file.
                registry_path.join(from_cwd)
            }
        }
        None => {
            let source = registry.url.as_deref().unwrap_or("<no-path-no-url>");
            anyhow::bail!(
                "Registry '{}' has no local `path` (source: '{}'). Remote registries are not executable by zkpatternfuzz.",
                collection.registry,
                source
            );
        }
    };

    let base = match &collection.path {
        Some(path) => base.join(path),
        None => base,
    };

    Ok(base)
}

fn build_template_index(
    registry_file: &RegistryFile,
    registry_path: &Path,
) -> anyhow::Result<(TemplateIndex, CollectionIndex)> {
    let mut templates: TemplateIndex = BTreeMap::new();
    let mut by_collection: CollectionIndex = BTreeMap::new();

    for (collection_name, collection) in &registry_file.collections {
        if collection.templates.is_empty() {
            continue;
        }

        let base = collection_base_path(registry_path, collection, &registry_file.registries)
            .with_context(|| {
                format!(
                    "Invalid collection '{}' (registry='{}')",
                    collection_name, collection.registry
                )
            })?;

        let mut names = Vec::with_capacity(collection.templates.len());
        for template in &collection.templates {
            validate_template_name(template)?;
            let family = template_family_from_name(template)?;
            let path = base.join(template);

            if let Some(prev) = templates.get(template) {
                if prev.path != path {
                    anyhow::bail!(
                        "Template '{}' resolves to multiple paths: '{}' and '{}'",
                        template,
                        prev.path.display(),
                        path.display()
                    );
                }
            } else {
                templates.insert(
                    template.clone(),
                    TemplateInfo {
                        file_name: template.clone(),
                        path,
                        family,
                    },
                );
            }

            names.push(template.clone());
        }
        by_collection.insert(collection_name.clone(), names);
    }

    Ok((templates, by_collection))
}

fn print_catalog(
    registry_file: &RegistryFile,
    template_index: &TemplateIndex,
    by_collection: &CollectionIndex,
) {
    let version = match &registry_file.version {
        serde_yaml::Value::Null => "unknown".to_string(),
        serde_yaml::Value::Bool(v) => v.to_string(),
        serde_yaml::Value::Number(v) => v.to_string(),
        serde_yaml::Value::String(v) => v.clone(),
        _ => "<non-scalar>".to_string(),
    };
    println!("Catalog version: {}", version);
    println!("Registries ({}):", registry_file.registries.len());
    for (name, registry) in &registry_file.registries {
        let location = registry
            .path
            .as_deref()
            .or(registry.url.as_deref())
            .unwrap_or("<unconfigured>");
        println!("  - {} -> {}", name, location);
        if let Some(desc) = &registry.description {
            println!("      {}", desc);
        }
        if let Some(maintainer) = &registry.maintainer {
            println!("      maintainer: {}", maintainer);
        }
    }

    println!("\nCollections ({}):", registry_file.collections.len());
    for (name, collection) in &registry_file.collections {
        let count = by_collection.get(name).map(|v| v.len()).unwrap_or(0);
        println!("  - {} ({} templates)", name, count);
        if let Some(desc) = &collection.description {
            println!("      {}", desc);
        }
    }

    println!("\nAliases ({}):", registry_file.aliases.len());
    for (name, values) in &registry_file.aliases {
        println!("  - {} -> {}", name, values.join(", "));
    }

    println!("\nTemplates ({}):", template_index.len());
    for (name, info) in template_index {
        println!(
            "  - {} [{}] {}",
            name,
            info.family.as_str(),
            info.path.display()
        );
    }
}

fn append_selector_value(
    requested_templates: &mut Vec<String>,
    by_collection: &CollectionIndex,
    template_index: &TemplateIndex,
    value: &str,
    source_label: &str,
) -> anyhow::Result<()> {
    if let Some(collection_templates) = by_collection.get(value) {
        requested_templates.extend(collection_templates.iter().cloned());
        return Ok(());
    }
    if template_index.contains_key(value) {
        requested_templates.push(value.to_string());
        return Ok(());
    }
    anyhow::bail!(
        "{} contains unknown item '{}'. It must reference a collection or template filename.",
        source_label,
        value
    );
}

fn resolve_selection(
    args: &Args,
    registry_file: &RegistryFile,
    template_index: &TemplateIndex,
    by_collection: &CollectionIndex,
) -> anyhow::Result<Vec<TemplateInfo>> {
    let selected_collections = split_csv(args.collection.as_deref());
    let selected_aliases = split_csv(args.alias.as_deref());
    let selected_templates = split_csv(args.template.as_deref());

    let mut requested_templates: Vec<String> = Vec::new();

    if selected_collections.is_empty()
        && selected_aliases.is_empty()
        && selected_templates.is_empty()
    {
        // Default mode: run all available YAML templates from the registry index.
        for template_name in template_index.keys() {
            requested_templates.push(template_name.clone());
        }
    }

    for collection in &selected_collections {
        append_selector_value(
            &mut requested_templates,
            by_collection,
            template_index,
            collection,
            "Collection selection",
        )?;
    }

    for alias in &selected_aliases {
        let Some(values) = registry_file.aliases.get(alias) else {
            anyhow::bail!("Unknown alias '{}'", alias);
        };
        for value in values {
            let source = format!("Alias '{}'", alias);
            append_selector_value(
                &mut requested_templates,
                by_collection,
                template_index,
                value,
                &source,
            )?;
        }
    }

    for template in &selected_templates {
        if !template_index.contains_key(template) {
            anyhow::bail!(
                "Unknown template '{}'. Use --list-catalog to inspect available template filenames.",
                template
            );
        }
        requested_templates.push(template.clone());
    }

    let mut dedup = BTreeSet::new();
    let mut ordered = Vec::new();
    for template in requested_templates {
        if dedup.insert(template.clone()) {
            let info = template_index.get(&template).ok_or_else(|| {
                anyhow::anyhow!("Template '{}' vanished during selection", template)
            })?;
            ordered.push(info.clone());
        }
    }

    if ordered.is_empty() {
        anyhow::bail!(
            "Selection resolved to zero templates. Use --list-catalog to inspect available entries."
        );
    }

    Ok(ordered)
}

fn run_scan(
    run_cfg: ScanRunConfig<'_>,
    template: &TemplateInfo,
    family: Family,
    validate_only: bool,
    output_suffix: &str,
) -> anyhow::Result<ScanRunResult> {
    let family_str = family.as_str();
    let mut cmd = Command::new(run_cfg.bin_path);
    cmd.env(SCAN_OUTPUT_ROOT_ENV, run_cfg.results_root)
        .env(RUN_SIGNAL_DIR_ENV, run_cfg.run_signal_dir)
        .env(BUILD_CACHE_DIR_ENV, run_cfg.build_cache_dir);
    for (key, value) in run_cfg.env_overrides {
        cmd.env(key, value);
    }
    if std::env::var_os(HALO2_EXTERNAL_TIMEOUT_ENV).is_none() {
        cmd.env(
            HALO2_EXTERNAL_TIMEOUT_ENV,
            halo2_effective_external_timeout_secs(run_cfg.framework, run_cfg.timeout).to_string(),
        );
    }
    if std::env::var_os(CAIRO_EXTERNAL_TIMEOUT_ENV).is_none() {
        cmd.env(CAIRO_EXTERNAL_TIMEOUT_ENV, run_cfg.timeout.to_string());
    }
    if std::env::var_os(SCARB_DOWNLOAD_TIMEOUT_ENV).is_none() {
        cmd.env(SCARB_DOWNLOAD_TIMEOUT_ENV, run_cfg.timeout.to_string());
    }
    if let Some(run_root) = run_cfg.scan_run_root {
        cmd.env(SCAN_RUN_ROOT_ENV, run_root);
    }
    if run_cfg.framework.eq_ignore_ascii_case("halo2") {
        let selected_bin = run_cfg.main_component.trim();
        if !selected_bin.is_empty() {
            cmd.env(HALO2_CARGO_RUN_BIN_ENV, selected_bin);
        }
    }
    if is_external_target(run_cfg.target_circuit) && run_cfg.framework.eq_ignore_ascii_case("halo2")
    {
        let auto_candidates = auto_halo2_toolchain_candidates();

        // External targets often live outside the writable workspace; keep Halo2 Cargo state
        // local and avoid broad toolchain cascades that trigger rustup network fetches.
        if std::env::var_os(HALO2_USE_HOST_CARGO_HOME_ENV).is_none() {
            cmd.env(HALO2_USE_HOST_CARGO_HOME_ENV, "0");
        }
        if std::env::var_os(HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV).is_none()
            && !auto_candidates.is_empty()
        {
            cmd.env(
                HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV,
                auto_candidates.join(","),
            );
        }
        if std::env::var_os(HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV).is_none() {
            let cascade_limit = auto_candidates.len().clamp(1, 8);
            cmd.env(HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV, cascade_limit.to_string());
        }
    }
    cmd.arg("scan")
        .arg(&template.path)
        .arg("--family")
        .arg(family_str)
        .arg("--target-circuit")
        .arg(run_cfg.target_circuit)
        .arg("--main-component")
        .arg(run_cfg.main_component)
        .arg("--framework")
        .arg(run_cfg.framework)
        .arg("--workers")
        .arg(run_cfg.workers.to_string())
        .arg("--seed")
        .arg(run_cfg.seed.to_string())
        .arg("--iterations")
        .arg(run_cfg.iterations.to_string())
        .arg("--timeout")
        .arg(run_cfg.timeout.to_string())
        .arg("--simple-progress");
    if !run_cfg.extra_args.is_empty() {
        cmd.args(run_cfg.extra_args);
    }

    // Validation dry-runs should not materialize results roots.
    if !validate_only {
        cmd.arg("--output-suffix").arg(output_suffix);
    }

    if validate_only {
        cmd.arg("--dry-run");
    }

    if run_cfg.dry_run {
        let suffix_arg = if !validate_only {
            format!(" --output-suffix {}", output_suffix)
        } else {
            String::new()
        };
        let extra_args = if run_cfg.extra_args.is_empty() {
            String::new()
        } else {
            format!(" {}", run_cfg.extra_args.join(" "))
        };
        println!(
            "[DRY RUN] {}={} {}={} {}={} {} scan {} --family {} --target-circuit {} --main-component {} --framework {} --workers {} --seed {} --iterations {} --timeout {} --simple-progress{}{}{}",
            SCAN_OUTPUT_ROOT_ENV,
            run_cfg.results_root.display(),
            RUN_SIGNAL_DIR_ENV,
            run_cfg.run_signal_dir.display(),
            BUILD_CACHE_DIR_ENV,
            run_cfg.build_cache_dir.display(),
            run_cfg.bin_path.display(),
            template.path.display(),
            family_str,
            run_cfg.target_circuit,
            run_cfg.main_component,
            run_cfg.framework,
            run_cfg.workers,
            run_cfg.seed,
            run_cfg.iterations,
            run_cfg.timeout,
            extra_args,
            suffix_arg,
            if validate_only { " --dry-run" } else { "" }
        );
        return Ok(ScanRunResult {
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        });
    }

    let progress_path = template_progress_path(run_cfg, output_suffix);
    let (output, timeout_stage_hit) = if !validate_only {
        run_command_with_stage_timeouts(
            &mut cmd,
            &template.file_name,
            &progress_path,
            run_cfg.stage_timeouts,
            run_cfg.memory_guard,
        )?
    } else {
        (cmd.output()?, None)
    };
    if let Some(stage) = timeout_stage_hit {
        let stage_budget_secs = match stage {
            HardTimeoutStage::Detecting => run_cfg.stage_timeouts.detection_timeout_secs,
            HardTimeoutStage::Proving => run_cfg.stage_timeouts.proof_timeout_secs,
        };
        if let Err(err) = write_stage_timeout_outcome(
            run_cfg.artifacts_root,
            run_cfg.scan_run_root,
            output_suffix,
            stage,
            stage_budget_secs,
        ) {
            eprintln!(
                "Failed to write hard-timeout run outcome for '{}' [{}]: {:#}",
                template.file_name, output_suffix, err
            );
        }
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        if !stdout.is_empty() {
            print!("{}", stdout);
        }
        if !stderr.is_empty() {
            eprint!("{}", stderr);
        }
    }

    Ok(ScanRunResult {
        success: output.status.success(),
        stdout,
        stderr,
    })
}

fn resolve_build_cache_dir(results_root: &Path) -> PathBuf {
    for env_name in [BUILD_CACHE_DIR_ENV, SHARED_BUILD_CACHE_DIR_ENV] {
        if let Ok(raw) = std::env::var(env_name) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
    }
    results_root.join("_build_cache")
}

fn ensure_writable_dir(path: &Path, label: &str) -> anyhow::Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("Failed to create {} '{}'", label, path.display()))?;

    let probe_name = format!(
        ".zkpatternfuzz_probe_{}_{}",
        std::process::id(),
        RUN_ROOT_NONCE.fetch_add(1, Ordering::Relaxed)
    );
    let probe_path = path.join(probe_name);
    fs::write(&probe_path, b"probe")
        .with_context(|| format!("{} is not writable at '{}'", label, path.display()))?;
    let _ = fs::remove_file(&probe_path);
    Ok(())
}

fn preflight_runtime_paths(results_root: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    ensure_writable_dir(results_root, "results root")?;
    let run_signal_dir = results_root.join("run_signals");
    ensure_writable_dir(&run_signal_dir, "run signal dir")?;
    let build_cache_dir = resolve_build_cache_dir(results_root);
    ensure_writable_dir(&build_cache_dir, "build cache dir")?;
    Ok((run_signal_dir, build_cache_dir))
}

fn halo2_effective_external_timeout_secs(framework: &str, requested_timeout: u64) -> u64 {
    if !framework.eq_ignore_ascii_case("halo2") {
        return requested_timeout;
    }

    let floor = std::env::var(HALO2_MIN_EXTERNAL_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(180);

    requested_timeout.max(floor)
}

fn effective_batch_timeout_secs(framework: &str, requested_timeout: u64) -> u64 {
    // Keep explicit user/config timeout values unchanged.
    if requested_timeout != DEFAULT_BATCH_TIMEOUT_SECS {
        return requested_timeout;
    }
    if !framework.eq_ignore_ascii_case("halo2") {
        return requested_timeout;
    }

    let halo2_default = std::env::var(HALO2_DEFAULT_BATCH_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_HALO2_BATCH_TIMEOUT_SECS);

    requested_timeout.max(halo2_default)
}

fn push_unique_nonempty(values: &mut Vec<String>, candidate: impl Into<String>) {
    let candidate = candidate.into();
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return;
    }
    if values.iter().any(|existing| existing == trimmed) {
        return;
    }
    values.push(trimmed.to_string());
}

fn parse_rustup_toolchain_names(raw: &str) -> Vec<String> {
    let mut parsed = Vec::new();
    for line in raw.lines() {
        let first = line.split_whitespace().next().unwrap_or_default().trim();
        if first.is_empty() || first.starts_with("info:") || first.starts_with("error:") {
            continue;
        }
        push_unique_nonempty(&mut parsed, first.trim_end_matches(','));
    }
    parsed
}

fn rustup_stdout(args: &[&str]) -> Option<String> {
    let output = Command::new("rustup").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn auto_halo2_toolchain_candidates() -> Vec<String> {
    let mut candidates = Vec::<String>::new();

    if let Some(active) = rustup_stdout(&["show", "active-toolchain"]) {
        if let Some(toolchain) = active.split_whitespace().next() {
            push_unique_nonempty(&mut candidates, toolchain);
        }
    }

    let installed = rustup_stdout(&["toolchain", "list"])
        .map(|raw| parse_rustup_toolchain_names(&raw))
        .unwrap_or_default();
    let installed_set = installed.iter().cloned().collect::<BTreeSet<String>>();

    for preferred in [
        "nightly-x86_64-unknown-linux-gnu",
        "nightly",
        "stable-x86_64-unknown-linux-gnu",
        "stable",
    ] {
        if installed_set.contains(preferred) {
            push_unique_nonempty(&mut candidates, preferred);
        }
    }

    for name in &installed {
        if name.starts_with("nightly-") {
            push_unique_nonempty(&mut candidates, name);
        }
    }
    for name in &installed {
        if name.starts_with("stable-") {
            push_unique_nonempty(&mut candidates, name);
        }
    }
    for name in &installed {
        push_unique_nonempty(&mut candidates, name);
    }

    const MAX_AUTO_TOOLCHAINS: usize = 6;
    if candidates.len() > MAX_AUTO_TOOLCHAINS {
        candidates.truncate(MAX_AUTO_TOOLCHAINS);
    }
    candidates
}

fn is_external_target(target_circuit: &str) -> bool {
    let target_path = Path::new(target_circuit);
    if !target_path.is_absolute() {
        return false;
    }

    let Ok(workspace_root) = std::env::current_dir() else {
        return false;
    };
    !target_path.starts_with(&workspace_root)
}

fn resolve_halo2_manifest_path(target_circuit: &str) -> anyhow::Result<PathBuf> {
    let candidate = PathBuf::from(target_circuit);
    if candidate.is_file() {
        let is_manifest = candidate
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == "Cargo.toml")
            .unwrap_or(false);
        if is_manifest {
            return Ok(candidate);
        }
        anyhow::bail!(
            "Halo2 target '{}' must be Cargo.toml or a directory containing Cargo.toml",
            target_circuit
        );
    }

    if candidate.is_dir() {
        let manifest = candidate.join("Cargo.toml");
        if manifest.is_file() {
            return Ok(manifest);
        }
        anyhow::bail!(
            "Halo2 target directory '{}' does not contain Cargo.toml",
            target_circuit
        );
    }

    anyhow::bail!(
        "Halo2 target '{}' does not exist or is not a file/directory",
        target_circuit
    );
}

fn prepare_target_for_framework(framework: &str, target_circuit: &str) -> anyhow::Result<bool> {
    if !framework.eq_ignore_ascii_case("halo2") {
        return Ok(false);
    }

    let manifest = resolve_halo2_manifest_path(target_circuit)?;
    let status = Command::new("cargo")
        .args(["build", "--release", "--manifest-path"])
        .arg(&manifest)
        .status()
        .with_context(|| {
            format!(
                "Failed to execute cargo build for Halo2 target '{}'",
                manifest.display()
            )
        })?;

    if !status.success() {
        anyhow::bail!(
            "Halo2 target prepare failed: cargo build --release --manifest-path '{}' exited with non-zero status",
            manifest.display()
        );
    }

    Ok(true)
}

fn effective_family(template_family: Family, family_override: Family) -> Family {
    match family_override {
        Family::Auto => template_family,
        Family::Mono => Family::Mono,
        Family::Multi => Family::Multi,
    }
}

fn validate_template_compatibility(
    template: &TemplateInfo,
    family_override: Family,
) -> anyhow::Result<Family> {
    if template.family != Family::Auto
        && family_override != Family::Auto
        && template.family != family_override
    {
        anyhow::bail!(
            "Template '{}' family '{}' is incompatible with override '{}'",
            template.file_name,
            template.family.as_str(),
            family_override.as_str()
        );
    }
    let effective = effective_family(template.family, family_override);
    Ok(effective)
}

fn resolved_release_bin_path(binary_name: &str) -> PathBuf {
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR") {
        PathBuf::from(target_dir).join("release").join(binary_name)
    } else {
        PathBuf::from("target").join("release").join(binary_name)
    }
}

fn run_template(
    run_cfg: ScanRunConfig<'_>,
    template: &TemplateInfo,
    family: Family,
    skip_validate: bool,
    output_suffix: &str,
) -> anyhow::Result<bool> {
    if !template.path.exists() {
        eprintln!(
            "Template '{}' failed: file not found '{}'",
            template.file_name,
            template.path.display()
        );
        return Ok(false);
    }

    if let Err(err) = validate_pattern_only_yaml(&template.path) {
        eprintln!(
            "Template '{}' failed: invalid pattern YAML '{}': {}",
            template.file_name,
            template.path.display(),
            err
        );
        return Ok(false);
    }

    if !skip_validate {
        let validate = run_scan(run_cfg, template, family, true, output_suffix)?;
        if !validate.success {
            if is_selector_mismatch_validation(&validate.stdout, &validate.stderr)
                && write_selector_mismatch_outcome(
                    run_cfg.artifacts_root,
                    run_cfg.scan_run_root,
                    output_suffix,
                )
                .is_ok()
            {
                eprintln!(
                    "Template '{}' selector mismatch recorded as synthetic preflight outcome",
                    template.file_name
                );
                return Ok(true);
            }
            eprintln!("Template '{}' failed validation", template.file_name);
            return Ok(false);
        }
    }

    println!("[TEMPLATE STAGE] {} stage=detecting", template.file_name);
    println!("[TEMPLATE STAGE] {} stage=proving", template.file_name);
    let scan_result = run_scan(run_cfg, template, family, false, output_suffix)?;
    if !scan_result.success {
        let reason_code = read_template_reason_code(run_cfg, output_suffix)
            .unwrap_or_else(|| "unknown".to_string());
        if reason_code == "critical_findings_detected" {
            let proof_status = read_template_proof_status(run_cfg, output_suffix)
                .unwrap_or_else(|| "unknown".to_string());
            println!(
                "[TEMPLATE STAGE] {} stage=proof_done proof_status={}",
                template.file_name, proof_status
            );
            println!(
                "[TEMPLATE STAGE] {} stage=completed_with_critical_findings",
                template.file_name
            );
            return Ok(true);
        }
        eprintln!(
            "Template '{}' failed (reason_code={})",
            template.file_name, reason_code
        );
        return Ok(false);
    }
    let proof_status =
        read_template_proof_status(run_cfg, output_suffix).unwrap_or_else(|| "unknown".to_string());
    println!(
        "[TEMPLATE STAGE] {} stage=proof_done proof_status={}",
        template.file_name, proof_status
    );

    Ok(true)
}

fn scan_output_suffix(template: &TemplateInfo, family: Family) -> String {
    let stem = template
        .file_name
        .strip_suffix(".yaml")
        .unwrap_or(template.file_name.as_str());
    let mut normalized = String::with_capacity(stem.len() + 8);
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            normalized.push(ch);
        } else {
            normalized.push('_');
        }
    }
    if normalized.is_empty() {
        normalized = "pattern".to_string();
    }
    format!("{}__{}", family.as_str(), normalized)
}

fn resolve_results_root() -> anyhow::Result<PathBuf> {
    let raw = std::env::var(SCAN_OUTPUT_ROOT_ENV).with_context(|| {
        format!(
            "{} is required (output path is env-only)",
            SCAN_OUTPUT_ROOT_ENV
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "{} is set but empty; provide a writable output root",
            SCAN_OUTPUT_ROOT_ENV
        );
    }
    Ok(PathBuf::from(trimmed))
}

fn reserve_batch_scan_run_root(artifacts_root: &Path) -> anyhow::Result<String> {
    std::fs::create_dir_all(artifacts_root).with_context(|| {
        format!(
            "Failed to create scan artifacts root '{}'",
            artifacts_root.display()
        )
    })?;

    // Process-safe reservation via atomic create_dir; candidate includes pid + monotonic nonce.
    for _ in 0..512 {
        let ts = Utc::now().format("%Y%m%d_%H%M%S_%3f").to_string();
        let nonce = RUN_ROOT_NONCE.fetch_add(1, Ordering::Relaxed);
        let candidate = format!("scan_run{}_p{}_n{}", ts, std::process::id(), nonce);
        let reservation = artifacts_root.join(&candidate);
        match std::fs::create_dir(&reservation) {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Failed to reserve batch scan run root '{}' under '{}': {}",
                    candidate,
                    artifacts_root.display(),
                    err
                ));
            }
        }
    }

    anyhow::bail!(
        "Failed to allocate unique batch scan run root after repeated collisions under '{}'",
        artifacts_root.display()
    )
}

fn list_scan_run_roots(artifacts_root: &Path) -> anyhow::Result<BTreeSet<String>> {
    if !artifacts_root.exists() {
        return Ok(BTreeSet::new());
    }

    let mut roots = BTreeSet::new();
    for entry in fs::read_dir(artifacts_root).with_context(|| {
        format!(
            "Failed to read artifacts root '{}'",
            artifacts_root.display()
        )
    })? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("scan_run") {
            continue;
        }
        if entry.file_type()?.is_dir() {
            roots.insert(name.to_string());
        }
    }

    Ok(roots)
}

fn collect_observed_suffixes_for_roots(
    artifacts_root: &Path,
    run_roots: &BTreeSet<String>,
) -> anyhow::Result<BTreeSet<String>> {
    let mut observed = BTreeSet::new();
    for run_root in run_roots {
        let run_root_path = artifacts_root.join(run_root);
        if !run_root_path.exists() {
            continue;
        }
        for entry in fs::read_dir(&run_root_path).with_context(|| {
            format!(
                "Failed to read run artifact root '{}'",
                run_root_path.display()
            )
        })? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            observed.insert(name.to_string());
        }
    }
    Ok(observed)
}

fn classify_run_reason_code(doc: &serde_json::Value) -> &'static str {
    let Some(obj) = doc.as_object() else {
        return "invalid_run_outcome_json";
    };
    let status = obj
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let stage = obj
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let error_lc = obj
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reason_lc = obj
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let panic_message_lc = obj
        .get("panic")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_dependency_resolution_failure = |message: &str| -> bool {
        message.contains("failed to load source for dependency")
            || message.contains("failed to get `")
            || message.contains("failed to update")
            || message.contains("unable to update")
            || message.contains("could not clone")
            || message.contains("failed to clone")
            || message.contains("failed to fetch into")
            || message.contains("couldn't find remote ref")
            || message.contains("network failure seems to have happened")
            || message.contains("spurious network error")
            || message.contains("index-pack failed")
            || message.contains("failed to download")
            || message.contains("checksum failed")
    };
    let is_input_contract_mismatch = |message: &str| -> bool {
        message.contains("not all inputs have been set")
            || message.contains("input map is missing")
            || message.contains("missing required circom signals")
    };
    let is_circom_compilation_failure = |message: &str| -> bool {
        message.contains("circom compilation failed")
            || message.contains("failed to run circom compiler")
            || (message.contains("out of bounds exception") && message.contains(".circom"))
    };
    let is_backend_toolchain_mismatch = |message: &str| -> bool {
        let cascade_exhausted = message.contains("toolchain cascade exhausted")
            || message.contains("scarb build failed for all configured candidates")
            || message.contains("no working scarb candidate found");
        let scarb_compile_mismatch = message.contains("scarb build failed")
            && message.contains("could not compile `")
            && (message.contains("error[e")
                || message.contains("identifier not found")
                || message.contains("type annotations needed")
                || message.contains("unsupported"));
        let rust_toolchain_mismatch = message.contains("requires rustc")
            || message.contains("the package requires")
            || message.contains("is not supported by this compiler")
            || message.contains("cargo-features");
        cascade_exhausted || scarb_compile_mismatch || rust_toolchain_mismatch
    };

    if status == "completed_with_critical_findings" {
        return "critical_findings_detected";
    }
    if status == "completed" {
        return "completed";
    }
    if status == "failed_engagement_contract" {
        return "engagement_contract_failed";
    }
    if status == "stale_interrupted" {
        return "stale_interrupted";
    }
    if status == "panic" {
        if panic_message_lc.contains("missing required 'command' in run document") {
            return "artifact_mirror_panic_missing_command";
        }
        return "panic";
    }
    if status == "running" {
        return "running";
    }
    if error_lc.contains("permission denied") {
        return "filesystem_permission_denied";
    }
    if stage == "preflight_backend"
        && (error_lc.contains("backend required but not available")
            || error_lc.contains("not found in path")
            || error_lc.contains("snarkjs not found")
            || error_lc.contains("circom not found")
            || error_lc.contains("install circom"))
    {
        return "backend_tooling_missing";
    }
    if stage == "preflight_backend" && is_dependency_resolution_failure(&error_lc) {
        return "backend_dependency_resolution_failed";
    }
    if stage == "preflight_backend" && is_backend_toolchain_mismatch(&error_lc) {
        return "backend_toolchain_mismatch";
    }
    if is_circom_compilation_failure(&error_lc) {
        return "circom_compilation_failed";
    }
    if error_lc.contains("key generation failed")
        || error_lc.contains("key setup failed")
        || error_lc.contains("proving key")
    {
        return "key_generation_failed";
    }
    if error_lc.contains("wall-clock timeout") || reason_lc.contains("wall-clock timeout") {
        return "wall_clock_timeout";
    }
    if stage == "acquire_output_lock" {
        return "output_dir_locked";
    }
    if is_input_contract_mismatch(&error_lc) {
        return "backend_input_contract_mismatch";
    }
    if stage == "preflight_backend" {
        return "backend_preflight_failed";
    }
    if stage == "preflight_selector" {
        return "selector_mismatch";
    }
    if stage == "preflight_invariants" {
        return "missing_invariants";
    }
    if stage == "preflight_readiness" {
        return "readiness_failed";
    }
    if stage == "parse_chains" && reason_lc.contains("requires chains") {
        return "missing_chains_definition";
    }
    if status == "failed" {
        return "runtime_error";
    }

    "unknown"
}

fn collect_template_outcome_reasons(
    artifacts_root: &Path,
    run_root: Option<&str>,
    selected_with_family: &[(TemplateInfo, Family)],
) -> Vec<TemplateOutcomeReason> {
    let Some(run_root) = run_root else {
        return Vec::new();
    };

    selected_with_family
        .iter()
        .map(|(template, family)| {
            let suffix = scan_output_suffix(template, *family);
            let run_outcome_path = artifacts_root
                .join(run_root)
                .join(&suffix)
                .join("run_outcome.json");

            if !run_outcome_path.exists() {
                return TemplateOutcomeReason {
                    template_file: template.file_name.clone(),
                    template_path: template.path.display().to_string(),
                    suffix,
                    status: None,
                    stage: None,
                    proof_status: None,
                    reason_code: "run_outcome_missing".to_string(),
                    high_confidence_detected: false,
                    detected_pattern_count: 0,
                };
            }

            let raw = match fs::read_to_string(&run_outcome_path) {
                Ok(raw) => raw,
                Err(_) => {
                    return TemplateOutcomeReason {
                        template_file: template.file_name.clone(),
                        template_path: template.path.display().to_string(),
                        suffix,
                        status: None,
                        stage: None,
                        proof_status: None,
                        reason_code: "run_outcome_unreadable".to_string(),
                        high_confidence_detected: false,
                        detected_pattern_count: 0,
                    };
                }
            };

            let parsed: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(parsed) => parsed,
                Err(_) => {
                    return TemplateOutcomeReason {
                        template_file: template.file_name.clone(),
                        template_path: template.path.display().to_string(),
                        suffix,
                        status: None,
                        stage: None,
                        proof_status: None,
                        reason_code: "run_outcome_invalid_json".to_string(),
                        high_confidence_detected: false,
                        detected_pattern_count: 0,
                    };
                }
            };

            let status = parsed
                .get("status")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let stage = parsed
                .get("stage")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let report_path = artifacts_root
                .join(run_root)
                .join(&suffix)
                .join("report.json");

            let mut reason = TemplateOutcomeReason {
                template_file: template.file_name.clone(),
                template_path: template.path.display().to_string(),
                suffix,
                status,
                stage,
                proof_status: proof_status_from_run_outcome_doc(&parsed),
                reason_code: parsed
                    .get("reason_code")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| classify_run_reason_code(&parsed).to_string()),
                high_confidence_detected: report_has_high_confidence_finding(&report_path),
                detected_pattern_count: report_detected_pattern_count(&report_path),
            };
            enforce_detected_pattern_proof_contract(&mut reason);
            reason
        })
        .collect()
}

fn proof_stage_started_for_status(proof_status: Option<&str>) -> bool {
    matches!(
        proof_status,
        Some("exploitable" | "not_exploitable_within_bounds" | "proof_failed")
    )
}

fn enforce_detected_pattern_proof_contract(reason: &mut TemplateOutcomeReason) {
    if reason.detected_pattern_count == 0
        || proof_stage_started_for_status(reason.proof_status.as_deref())
    {
        return;
    }
    reason.proof_status = Some("proof_failed".to_string());
    if matches!(
        reason.reason_code.as_str(),
        "completed" | "critical_findings_detected"
    ) {
        reason.reason_code = PROOF_STAGE_NOT_STARTED_REASON_CODE.to_string();
    }
}

fn print_reason_summary(reasons: &[TemplateOutcomeReason]) {
    if reasons.is_empty() {
        return;
    }

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for reason in reasons {
        *counts.entry(reason.reason_code.clone()).or_insert(0) += 1;
    }

    let summary_line = counts
        .iter()
        .map(|(code, count)| format!("{}={}", code, count))
        .collect::<Vec<_>>()
        .join(", ");

    println!("Reason code summary: {}", summary_line);

    for reason in reasons {
        if (reason.reason_code == "completed" || reason.reason_code == "critical_findings_detected")
            && reason.proof_status.as_deref() != Some("proof_failed")
        {
            continue;
        }
        println!(
            "  - {} [{}]: reason_code={} status={} stage={} proof_status={}",
            reason.template_file,
            reason.suffix,
            reason.reason_code,
            reason.status.as_deref().unwrap_or("unknown"),
            reason.stage.as_deref().unwrap_or("unknown"),
            reason.proof_status.as_deref().unwrap_or("unknown"),
        );
    }
}

fn print_reason_tsv(reasons: &[TemplateOutcomeReason]) {
    if reasons.is_empty() {
        return;
    }

    println!("REASON_TSV_START");
    println!(
        "template\tsuffix\treason_code\tstatus\tstage\tproof_status\thigh_confidence_detected\tdetected_pattern_count"
    );
    for reason in reasons {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            reason.template_file,
            reason.suffix,
            reason.reason_code,
            reason.status.as_deref().unwrap_or("unknown"),
            reason.stage.as_deref().unwrap_or("unknown"),
            reason.proof_status.as_deref().unwrap_or("unknown"),
            if reason.high_confidence_detected {
                "1"
            } else {
                "0"
            },
            reason.detected_pattern_count,
        );
    }
    println!("REASON_TSV_END");
}

fn proof_state_counts(reasons: &[TemplateOutcomeReason]) -> (usize, usize, usize, usize) {
    let exploitable = reasons
        .iter()
        .filter(|reason| reason.proof_status.as_deref() == Some("exploitable"))
        .count();
    let not_exploitable_within_bounds = reasons
        .iter()
        .filter(|reason| reason.proof_status.as_deref() == Some("not_exploitable_within_bounds"))
        .count();
    let proof_failed = reasons
        .iter()
        .filter(|reason| reason.proof_status.as_deref() == Some("proof_failed"))
        .count();
    let proof_skipped_by_policy = reasons
        .iter()
        .filter(|reason| reason.proof_status.as_deref() == Some("proof_skipped_by_policy"))
        .count();
    (
        exploitable,
        not_exploitable_within_bounds,
        proof_failed,
        proof_skipped_by_policy,
    )
}

#[derive(Debug, Serialize)]
struct PatternReportRow {
    pattern_file: String,
    pattern_path: String,
    output_suffix: String,
    reason_code: String,
    status: String,
    stage: String,
    proof_status: String,
    detected_pattern_count: usize,
    high_confidence_detected: bool,
    matched: bool,
}

#[derive(Debug, Serialize)]
struct BatchFindingsReport<'a> {
    report_schema: &'static str,
    generated_utc: String,
    verdict: &'static str,
    target_circuit: &'a str,
    framework: &'a str,
    main_component: &'a str,
    input: BatchReportInput<'a>,
    run: BatchReportRun,
    gates: BatchReportGates,
    artifacts: BatchReportArtifacts,
    totals: BatchReportTotals,
    patterns: Vec<PatternReportRow>,
}

#[derive(Debug, Serialize)]
struct BatchReportInput<'a> {
    config_json: Option<&'a str>,
    registry: Option<&'a str>,
    collection: Option<&'a str>,
    alias: Option<&'a str>,
    template: Option<&'a str>,
    pattern_yaml: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct BatchReportRun {
    jobs: usize,
    workers: usize,
    seed: u64,
    iterations: u64,
    timeout: u64,
    results_root: String,
}

#[derive(Debug, Serialize)]
struct BatchReportGates {
    gate1_expected_patterns: usize,
    gate2_completion: bool,
    gate3_artifact_reconciliation: bool,
    template_reason_errors: usize,
    dry_run: bool,
    campaign_success: bool,
}

#[derive(Debug, Serialize)]
struct BatchReportArtifacts {
    timestamped_result_bundle: String,
    timestamped_run_log: String,
    timestamped_error_log: String,
    batch_run_root: Option<String>,
}

#[derive(Debug, Serialize)]
struct BatchReportTotals {
    expected_patterns: usize,
    executed_patterns: usize,
    template_errors: usize,
    matched_patterns: usize,
    detected_patterns_total: usize,
    high_confidence_patterns: usize,
    exploitable_patterns: usize,
    not_exploitable_within_bounds_patterns: usize,
    proof_failed_patterns: usize,
    proof_skipped_by_policy_patterns: usize,
}

#[allow(clippy::too_many_arguments)]
fn write_report_json(
    args: &Args,
    path: &Path,
    target_circuit: &str,
    reasons: &[TemplateOutcomeReason],
    expected_count: usize,
    executed: usize,
    template_errors: usize,
    results_root: &Path,
    gate2_ok: bool,
    gate3_ok: bool,
    campaign_success: bool,
    timestamped_result_dir: &Path,
    timestamped_run_log: &Path,
    timestamped_error_log: &Path,
    batch_run_root: Option<&str>,
) -> anyhow::Result<()> {
    let matched_patterns = reasons
        .iter()
        .filter(|reason| reason.detected_pattern_count > 0)
        .count();
    let detected_patterns_total = reasons
        .iter()
        .map(|reason| reason.detected_pattern_count)
        .sum::<usize>();
    let high_confidence_patterns = reasons
        .iter()
        .filter(|reason| reason.high_confidence_detected)
        .count();
    let (
        exploitable_patterns,
        not_exploitable_within_bounds_patterns,
        proof_failed_patterns,
        proof_skipped_by_policy_patterns,
    ) = proof_state_counts(reasons);
    let reason_error_count = reasons
        .iter()
        .filter(|reason| is_error_reason(reason))
        .count();
    let verdict = if args.dry_run {
        "dry_run"
    } else if !gate2_ok || !gate3_ok || reason_error_count > 0 || template_errors > 0 {
        "run_failed"
    } else if matched_patterns > 0 {
        "matching_patterns_found"
    } else {
        "no_matching_patterns_found"
    };

    let patterns = reasons
        .iter()
        .map(|reason| PatternReportRow {
            pattern_file: reason.template_file.clone(),
            pattern_path: reason.template_path.clone(),
            output_suffix: reason.suffix.clone(),
            reason_code: reason.reason_code.clone(),
            status: reason
                .status
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            stage: reason
                .stage
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            proof_status: reason
                .proof_status
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            detected_pattern_count: reason.detected_pattern_count,
            high_confidence_detected: reason.high_confidence_detected,
            matched: reason.detected_pattern_count > 0,
        })
        .collect::<Vec<_>>();

    let report = BatchFindingsReport {
        report_schema: "zkfuzz.batch_detected_patterns.v2",
        generated_utc: Utc::now().to_rfc3339(),
        verdict,
        target_circuit,
        framework: &args.framework,
        main_component: &args.main_component,
        input: BatchReportInput {
            config_json: args.config_json.as_deref(),
            registry: args.registry.as_deref(),
            collection: args.collection.as_deref(),
            alias: args.alias.as_deref(),
            template: args.template.as_deref(),
            pattern_yaml: args.pattern_yaml.as_deref(),
        },
        run: BatchReportRun {
            jobs: args.jobs,
            workers: args.workers,
            seed: args.seed,
            iterations: args.iterations,
            timeout: args.timeout,
            results_root: results_root.display().to_string(),
        },
        gates: BatchReportGates {
            gate1_expected_patterns: expected_count,
            gate2_completion: gate2_ok,
            gate3_artifact_reconciliation: gate3_ok,
            template_reason_errors: reason_error_count,
            dry_run: args.dry_run,
            campaign_success,
        },
        artifacts: BatchReportArtifacts {
            timestamped_result_bundle: timestamped_result_dir.display().to_string(),
            timestamped_run_log: timestamped_run_log.display().to_string(),
            timestamped_error_log: timestamped_error_log.display().to_string(),
            batch_run_root: batch_run_root.map(|value| value.to_string()),
        },
        totals: BatchReportTotals {
            expected_patterns: expected_count,
            executed_patterns: executed,
            template_errors,
            matched_patterns,
            detected_patterns_total,
            high_confidence_patterns,
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
        },
        patterns,
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create detected-patterns report parent directory '{}'",
                parent.display()
            )
        })?;
    }
    let encoded = serde_json::to_string_pretty(&report)?;
    fs::write(path, encoded)
        .with_context(|| format!("Failed to write report JSON '{}'", path.display()))?;
    Ok(())
}

fn create_timestamped_result_dir(results_root: &Path) -> anyhow::Result<PathBuf> {
    let ts = Utc::now().format("%Y%m%d_%H%M%S_%3f").to_string();
    let dir = results_root.join("ResultJsonTimestamped").join(ts);
    fs::create_dir_all(&dir).with_context(|| {
        format!(
            "Failed to create timestamped result directory '{}'",
            dir.display()
        )
    })?;
    Ok(dir)
}

fn run_log_file_cache() -> &'static Mutex<HashMap<PathBuf, fs::File>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, fs::File>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn append_run_log(path: &Path, message: impl AsRef<str>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create run log directory '{}'", parent.display())
        })?;
    }
    let path_buf = path.to_path_buf();
    let mut cache = run_log_file_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let file = match cache.entry(path_buf.clone()) {
        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::hash_map::Entry::Vacant(entry) => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path_buf)
                .with_context(|| format!("Failed to open run log '{}'", path.display()))?;
            entry.insert(file)
        }
    };
    writeln!(file, "{}", message.as_ref())
        .with_context(|| format!("Failed to write run log '{}'", path.display()))?;
    file.flush()
        .with_context(|| format!("Failed to flush run log '{}'", path.display()))?;
    Ok(())
}

fn append_run_log_best_effort(path: &Path, message: impl AsRef<str>) {
    if let Err(err) = append_run_log(path, message) {
        eprintln!("run.log write failed ({}): {:#}", path.display(), err);
    }
}

fn step_started(step: usize, total_steps: usize, label: &str, run_log: &Path) -> Instant {
    println!("[STEP {}/{}] {}: started", step, total_steps, label);
    append_run_log_best_effort(
        run_log,
        format!("step={} status=started", label.replace(' ', "_")),
    );
    Instant::now()
}

fn step_succeeded(
    step: usize,
    total_steps: usize,
    label: &str,
    started_at: Instant,
    run_log: &Path,
) {
    let elapsed_secs = started_at.elapsed().as_secs_f64();
    println!(
        "[STEP {}/{}] {}: completed ({:.1}s)",
        step, total_steps, label, elapsed_secs
    );
    append_run_log_best_effort(
        run_log,
        format!(
            "step={} status=completed elapsed_secs={:.3}",
            label.replace(' ', "_"),
            elapsed_secs
        ),
    );
}

fn step_skipped(step: usize, total_steps: usize, label: &str, reason: &str, run_log: &Path) {
    println!(
        "[STEP {}/{}] {}: skipped ({})",
        step, total_steps, label, reason
    );
    append_run_log_best_effort(
        run_log,
        format!(
            "step={} status=skipped reason={}",
            label.replace(' ', "_"),
            reason
        ),
    );
}

fn step_failed(
    step: usize,
    total_steps: usize,
    label: &str,
    started_at: Instant,
    run_log: &Path,
    err: &anyhow::Error,
) {
    let elapsed_secs = started_at.elapsed().as_secs_f64();
    println!(
        "[STEP {}/{}] {}: FAILED ({:.1}s)",
        step, total_steps, label, elapsed_secs
    );
    append_run_log_best_effort(
        run_log,
        format!(
            "step={} status=failed elapsed_secs={:.3} error={}",
            label.replace(' ', "_"),
            elapsed_secs,
            err.to_string().replace('\n', " | ")
        ),
    );
}

fn is_error_reason(reason: &TemplateOutcomeReason) -> bool {
    if reason.proof_status.as_deref() == Some("proof_failed") {
        return true;
    }
    !matches!(
        reason.reason_code.as_str(),
        "completed" | "critical_findings_detected"
    )
}

fn write_error_log(
    path: &Path,
    reasons: &[TemplateOutcomeReason],
    template_errors: usize,
    gate2_ok: bool,
    gate3_ok: bool,
    dry_run: bool,
) -> anyhow::Result<()> {
    let mut lines = Vec::<String>::new();
    lines.push(format!("generated_utc={}", Utc::now().to_rfc3339()));
    lines.push(format!("dry_run={}", dry_run));
    lines.push(format!("gate2_ok={}", gate2_ok));
    lines.push(format!("gate3_ok={}", gate3_ok));
    lines.push(format!("template_errors={}", template_errors));

    let mut error_count = 0usize;
    for reason in reasons {
        if !is_error_reason(reason) {
            continue;
        }
        error_count += 1;
        lines.push(format!(
            "template={} suffix={} reason_code={} status={} stage={} proof_status={} detected_pattern_count={}",
            reason.template_file,
            reason.suffix,
            reason.reason_code,
            reason.status.as_deref().unwrap_or("unknown"),
            reason.stage.as_deref().unwrap_or("unknown"),
            reason.proof_status.as_deref().unwrap_or("unknown"),
            reason.detected_pattern_count,
        ));
    }

    if error_count == 0 {
        lines.push("no_errors_detected".to_string());
    } else {
        lines.push(format!("error_entries={}", error_count));
    }

    fs::write(path, lines.join("\n") + "\n")
        .with_context(|| format!("Failed to write error log '{}'", path.display()))?;
    Ok(())
}

fn is_selector_mismatch_validation(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{}\n{}", stdout, stderr).to_ascii_lowercase();
    combined.contains("selectors did not match target circuit")
}

fn write_selector_mismatch_outcome(
    artifacts_root: &Path,
    run_root: Option<&str>,
    output_suffix: &str,
) -> anyhow::Result<()> {
    let Some(run_root) = run_root else {
        anyhow::bail!("scan_run_root is unavailable for selector mismatch outcome");
    };

    let template_dir = artifacts_root.join(run_root).join(output_suffix);
    fs::create_dir_all(&template_dir).with_context(|| {
        format!(
            "Failed creating selector-mismatch artifact dir '{}'",
            template_dir.display()
        )
    })?;

    let run_outcome_path = template_dir.join("run_outcome.json");
    let payload = serde_json::json!({
        "status": "failed",
        "stage": "preflight_selector",
        "reason": "selector_mismatch",
        "error": "Pattern selectors did not match target circuit",
    });
    let serialized = serde_json::to_string_pretty(&payload)?;
    fs::write(&run_outcome_path, serialized).with_context(|| {
        format!(
            "Failed writing selector-mismatch run outcome '{}'",
            run_outcome_path.display()
        )
    })?;

    Ok(())
}

fn write_stage_timeout_outcome(
    artifacts_root: &Path,
    run_root: Option<&str>,
    output_suffix: &str,
    stage: HardTimeoutStage,
    stage_budget_secs: u64,
) -> anyhow::Result<()> {
    let Some(run_root) = run_root else {
        anyhow::bail!("scan_run_root is unavailable for hard-timeout outcome");
    };

    let template_dir = artifacts_root.join(run_root).join(output_suffix);
    fs::create_dir_all(&template_dir).with_context(|| {
        format!(
            "Failed creating hard-timeout artifact dir '{}'",
            template_dir.display()
        )
    })?;

    let stage_name = match stage {
        HardTimeoutStage::Detecting => "detecting",
        HardTimeoutStage::Proving => "proof",
    };
    let run_outcome_stage = match stage {
        HardTimeoutStage::Detecting => "detection_timeout",
        HardTimeoutStage::Proving => "proof_timeout",
    };

    let run_outcome_path = template_dir.join("run_outcome.json");
    let payload = serde_json::json!({
        "status": "failed",
        "stage": run_outcome_stage,
        "reason_code": "wall_clock_timeout",
        "reason": "wall_clock_timeout",
        "error": format!(
            "Per-template hard wall-clock timeout reached during {} stage (budget={}s)",
            stage_name,
            stage_budget_secs
        ),
        "discovery_qualification": {
            "proof_status": "proof_failed"
        },
    });
    let serialized = serde_json::to_string_pretty(&payload)?;
    fs::write(&run_outcome_path, serialized).with_context(|| {
        format!(
            "Failed writing hard-timeout run outcome '{}'",
            run_outcome_path.display()
        )
    })?;

    Ok(())
}

fn template_run_outcome_path(run_cfg: ScanRunConfig<'_>, output_suffix: &str) -> Option<PathBuf> {
    let run_root = run_cfg.scan_run_root?;
    Some(
        run_cfg
            .artifacts_root
            .join(run_root)
            .join(output_suffix)
            .join("run_outcome.json"),
    )
}

fn proof_status_from_run_outcome_doc(doc: &serde_json::Value) -> Option<String> {
    doc.get("discovery_qualification")
        .and_then(|v| v.get("proof_status"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn reason_code_from_run_outcome_doc(doc: &serde_json::Value) -> Option<String> {
    doc.get("reason_code")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn read_template_run_outcome_doc(
    run_cfg: ScanRunConfig<'_>,
    output_suffix: &str,
) -> Option<serde_json::Value> {
    let run_outcome_path = template_run_outcome_path(run_cfg, output_suffix)?;
    let raw = fs::read_to_string(run_outcome_path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn read_template_reason_code(run_cfg: ScanRunConfig<'_>, output_suffix: &str) -> Option<String> {
    let parsed = read_template_run_outcome_doc(run_cfg, output_suffix)?;
    reason_code_from_run_outcome_doc(&parsed)
        .or_else(|| Some(classify_run_reason_code(&parsed).to_string()))
}

fn read_template_proof_status(run_cfg: ScanRunConfig<'_>, output_suffix: &str) -> Option<String> {
    let parsed = read_template_run_outcome_doc(run_cfg, output_suffix)?;
    proof_status_from_run_outcome_doc(&parsed)
}

fn resolve_explicit_pattern_selection(
    raw_paths: &[String],
    family_override: Family,
) -> anyhow::Result<Vec<TemplateInfo>> {
    let mut dedup = BTreeSet::new();
    let mut selected = Vec::new();
    for raw in raw_paths {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = PathBuf::from(trimmed);
        let canonical = path.to_string_lossy().to_string();
        if !dedup.insert(canonical.clone()) {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or(trimmed)
            .to_string();
        validate_template_name(&file_name)?;
        let family = validate_template_compatibility(
            &TemplateInfo {
                file_name: file_name.clone(),
                path: path.clone(),
                family: template_family_from_name(&file_name)?,
            },
            family_override,
        )?;
        selected.push(TemplateInfo {
            file_name,
            path,
            family,
        });
    }

    if selected.is_empty() {
        anyhow::bail!("pattern_yaml resolved to zero usable pattern paths");
    }

    Ok(selected)
}

fn should_skip_pattern_discovery_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "target"
            | "artifacts"
            | "node_modules"
            | "vendor"
            | "ZkFuzz"
            | "reports"
            | "build"
    )
}

fn discover_all_pattern_templates(repo_root: &Path) -> anyhow::Result<Vec<TemplateInfo>> {
    let mut stack = vec![repo_root.to_path_buf()];
    let mut discovered = Vec::<TemplateInfo>::new();
    let mut dedup = BTreeSet::<String>::new();

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if should_skip_pattern_discovery_dir(name) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Some(ext) = path.extension().and_then(|v| v.to_str()) else {
                continue;
            };
            if ext != "yaml" && ext != "yml" {
                continue;
            }

            let canonical = path.display().to_string();
            if !dedup.insert(canonical) {
                continue;
            }

            let Some(file_name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if validate_template_name(file_name).is_err() {
                continue;
            }
            if validate_pattern_only_yaml(&path).is_err() {
                continue;
            }

            let family = template_family_from_name(file_name)?;
            discovered.push(TemplateInfo {
                file_name: file_name.to_string(),
                path,
                family,
            });
        }
    }

    discovered.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(discovered)
}

fn pattern_regex_signature(path: &Path) -> anyhow::Result<Option<Vec<String>>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", path.display()))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", path.display()))?;
    let Some(root) = doc.as_mapping() else {
        return Ok(None);
    };
    let patterns_key = yaml_key("patterns");
    let Some(patterns) = root.get(&patterns_key) else {
        return Ok(None);
    };
    let Some(items) = patterns.as_sequence() else {
        return Ok(None);
    };
    let mut selectors = Vec::<String>::new();
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        let pattern_key = yaml_key("pattern");
        let kind_key = yaml_key("kind");
        let Some(pattern) = map.get(&pattern_key).and_then(|v| v.as_str()) else {
            continue;
        };
        let kind = map
            .get(&kind_key)
            .and_then(|v| v.as_str())
            .unwrap_or("regex")
            .trim()
            .to_ascii_lowercase();
        selectors.push(format!("{}::{}", kind, pattern.trim()));
    }
    if selectors.is_empty() {
        return Ok(None);
    }
    selectors.sort();
    selectors.dedup();
    Ok(Some(selectors))
}

fn pattern_specificity_score(path: &Path) -> i64 {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return 0,
    };
    let doc: serde_yaml::Value = match serde_yaml::from_str(&raw) {
        Ok(doc) => doc,
        Err(_) => return 0,
    };
    let Some(root) = doc.as_mapping() else {
        return 0;
    };
    let mut score = 0i64;
    if root.contains_key(yaml_key("profiles")) {
        score += 4;
    }
    if root.contains_key(yaml_key("active_profile")) {
        score += 4;
    }
    if root.contains_key(yaml_key("selector_policy")) {
        score += 1;
    }
    if root.contains_key(yaml_key("selector_synonyms")) {
        score += 1;
    }
    if root.contains_key(yaml_key("selector_normalization")) {
        score += 1;
    }
    score + (raw.len() as i64 / 1024)
}

fn dedupe_patterns_by_signature(selected: Vec<TemplateInfo>) -> anyhow::Result<DedupeResult> {
    let mut kept = Vec::<TemplateInfo>::new();
    let mut dropped = Vec::<(TemplateInfo, TemplateInfo)>::new();
    let mut signature_to_index = BTreeMap::<String, usize>::new();

    for template in selected {
        let signature = pattern_regex_signature(&template.path)?;
        let Some(signature) = signature else {
            kept.push(template);
            continue;
        };
        let key = signature.join("\n");
        if let Some(existing_idx) = signature_to_index.get(&key).copied() {
            let existing = kept[existing_idx].clone();
            let existing_score = pattern_specificity_score(&existing.path);
            let incoming_score = pattern_specificity_score(&template.path);
            let incoming_better = incoming_score > existing_score
                || (incoming_score == existing_score && template.path < existing.path);
            if incoming_better {
                kept[existing_idx] = template.clone();
                dropped.push((existing, template.clone()));
            } else {
                dropped.push((template.clone(), existing));
            }
            continue;
        }
        signature_to_index.insert(key, kept.len());
        kept.push(template);
    }

    Ok((kept, dropped))
}

fn main() -> anyhow::Result<()> {
    let _check_env = CheckEnv::new(
        Path::new(".env"),
        &[
            SCAN_OUTPUT_ROOT_ENV,
            RUN_SIGNAL_DIR_ENV,
            BUILD_CACHE_DIR_ENV,
            DEFAULT_BATCH_JOBS_ENV,
            DEFAULT_BATCH_WORKERS_ENV,
            DEFAULT_BATCH_ITERATIONS_ENV,
            DEFAULT_BATCH_TIMEOUT_ENV,
            MEMORY_GUARD_ENABLED_ENV,
            MEMORY_GUARD_RESERVED_MB_ENV,
            MEMORY_GUARD_MB_PER_TEMPLATE_ENV,
            MEMORY_GUARD_MB_PER_WORKER_ENV,
            MEMORY_GUARD_LAUNCH_FLOOR_MB_ENV,
            MEMORY_GUARD_WAIT_SECS_ENV,
            MEMORY_GUARD_POLL_MS_ENV,
            DETECTION_STAGE_TIMEOUT_ENV,
            PROOF_STAGE_TIMEOUT_ENV,
            STUCK_STEP_WARN_SECS_ENV,
        ],
    )?;

    let mut args = Args::parse();
    let effective_file_cfg = if let Some(path) = args.config_json.clone() {
        let cfg = load_batch_file_config(&path)?;
        apply_file_config(&mut args, cfg)?
    } else {
        EffectiveFileConfig::default()
    };
    let requested_timeout = args.timeout;
    args.timeout = effective_batch_timeout_secs(&args.framework, args.timeout);
    if args.timeout != requested_timeout {
        eprintln!(
            "Halo2 timeout default applied: {}s -> {}s (override with --timeout or {})",
            requested_timeout, args.timeout, HALO2_DEFAULT_BATCH_TIMEOUT_ENV
        );
    }
    ensure_positive_cli_values(&args)?;
    let memory_guard = load_memory_guard_config()?;
    let stage_timeouts = load_stage_timeout_config(args.timeout)?;
    apply_memory_parallelism_guardrails(&mut args, memory_guard)?;
    let family_override = parse_family(&args.family)?;

    let explicit_patterns = split_csv(args.pattern_yaml.as_deref());
    let using_explicit_patterns = !explicit_patterns.is_empty();
    let has_registry_selectors =
        args.collection.is_some() || args.alias.is_some() || args.template.is_some();

    let selected = if using_explicit_patterns {
        if args.list_catalog {
            anyhow::bail!("--list-catalog cannot be combined with --pattern-yaml");
        }
        resolve_explicit_pattern_selection(&explicit_patterns, family_override)?
    } else if !has_registry_selectors {
        if args.list_catalog {
            anyhow::bail!("--list-catalog requires registry mode; omit --list-catalog for auto-discovery mode");
        }
        let repo_root = std::env::current_dir().context("Failed to resolve current directory")?;
        let discovered = discover_all_pattern_templates(&repo_root)?;
        if discovered.is_empty() {
            anyhow::bail!(
                "Auto-discovery found zero pattern-compatible YAML files under '{}'. Use --pattern-yaml or registry selectors.",
                repo_root.display()
            );
        }
        discovered
    } else {
        let registry_path_raw = args
            .registry
            .clone()
            .unwrap_or_else(|| default_registry_for_profile(args.config_profile).to_string());
        let registry_path = PathBuf::from(&registry_path_raw);
        let registry_dir = registry_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        let raw = std::fs::read_to_string(&registry_path).with_context(|| {
            format!("Failed to read registry YAML '{}'", registry_path.display())
        })?;
        let registry_file: RegistryFile = serde_yaml::from_str(&raw).with_context(|| {
            format!(
                "Failed to parse registry YAML '{}'",
                registry_path.display()
            )
        })?;
        let (template_index, by_collection) = build_template_index(&registry_file, &registry_dir)?;

        if args.list_catalog {
            print_catalog(&registry_file, &template_index, &by_collection);
            return Ok(());
        }

        args.registry = Some(registry_path_raw);
        resolve_selection(&args, &registry_file, &template_index, &by_collection)?
    };

    let target_circuit_raw = args.target_circuit.as_deref().ok_or_else(|| {
        anyhow::anyhow!("Missing required --target-circuit (unless --list-catalog is used)")
    })?;
    let target_circuit = expand_env_placeholders(target_circuit_raw).with_context(|| {
        format!(
            "Failed to resolve environment placeholders in target_circuit '{}'",
            target_circuit_raw
        )
    })?;
    if has_unresolved_env_placeholder(&target_circuit) {
        anyhow::bail!(
            "Unresolved env placeholder in target_circuit '{}'. Set required environment variables.",
            target_circuit_raw
        );
    }

    let target_circuit_path = PathBuf::from(&target_circuit);
    if !target_circuit_path.exists() {
        anyhow::bail!(
            "target_circuit not found '{}' (resolved from '{}')",
            target_circuit,
            target_circuit_raw
        );
    }

    let (selected, signature_dupes) = dedupe_patterns_by_signature(selected)?;
    if !signature_dupes.is_empty() {
        eprintln!(
            "Skipped {} full-overlap duplicate patterns (same normalized selector set):",
            signature_dupes.len()
        );
        for (dup, kept) in signature_dupes.iter().take(20) {
            eprintln!("  - {} -> kept {}", dup.path.display(), kept.path.display());
        }
    }

    let mut selected_with_family: Vec<(TemplateInfo, Family)> = Vec::with_capacity(selected.len());
    for template in selected {
        let chosen_family = validate_template_compatibility(&template, family_override)?;
        selected_with_family.push((template, chosen_family));
    }
    let expected_suffixes: BTreeSet<String> = selected_with_family
        .iter()
        .map(|(template, family)| scan_output_suffix(template, *family))
        .collect();
    let expected_count = expected_suffixes.len();
    let batch_started_at = Instant::now();

    println!("Gate 1/3 (expected templates): {}", expected_count);
    let results_root = resolve_results_root().map_err(|err| {
        anyhow::anyhow!(
            "Output path configuration failed: {:#}\nHint: set {} to a writable directory (example: export {}=/home/teycir/zkfuzz)",
            err,
            SCAN_OUTPUT_ROOT_ENV,
            SCAN_OUTPUT_ROOT_ENV
        )
    })?;
    let timestamped_result_dir = create_timestamped_result_dir(&results_root).with_context(
        || {
            format!(
                "Unable to create result directory under '{}'. Check that the path exists and is writable.",
                results_root.display()
            )
        },
    )?;
    let timestamped_report_path = timestamped_result_dir.join("detected_patterns.json");
    let timestamped_error_log = timestamped_result_dir.join("errors.log");
    let timestamped_run_log = timestamped_result_dir.join("run.log");
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "start_utc={} step=gate1_expected_templates expected_patterns={}",
            Utc::now().to_rfc3339(),
            expected_count
        ),
    );
    let template_paths: Vec<PathBuf> = selected_with_family
        .iter()
        .map(|(template, _)| template.path.clone())
        .collect();
    let total_steps = 5usize;

    let preflight_step_started =
        step_started(1, total_steps, "template preflight", &timestamped_run_log);
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=template_preflight status=started templates={}",
            template_paths.len()
        ),
    );
    if let Err(err) = preflight_template_paths(&template_paths, validate_pattern_only_yaml) {
        step_failed(
            1,
            total_steps,
            "template preflight",
            preflight_step_started,
            &timestamped_run_log,
            &err,
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!("step=template_preflight status=failed error={}", err),
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "end_utc={} campaign_success=false dry_run={} termination_cause=template_preflight",
                Utc::now().to_rfc3339(),
                args.dry_run
            ),
        );
        if let Err(log_err) =
            write_error_log(&timestamped_error_log, &[], 1, false, false, args.dry_run)
        {
            eprintln!(
                "Failed to write early error log '{}': {:#}",
                timestamped_error_log.display(),
                log_err
            );
        }
        return Err(err);
    }
    append_run_log_best_effort(
        &timestamped_run_log,
        "step=template_preflight status=completed",
    );
    step_succeeded(
        1,
        total_steps,
        "template preflight",
        preflight_step_started,
        &timestamped_run_log,
    );

    let readiness_step_started =
        step_started(2, total_steps, "local readiness", &timestamped_run_log);
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=local_readiness status=started framework={} target_circuit={} results_root={}",
            args.framework,
            target_circuit,
            results_root.display()
        ),
    );
    if let Err(err) = ensure_local_runtime_requirements(
        &args.framework,
        &target_circuit,
        &target_circuit_path,
        &args.main_component,
    ) {
        step_failed(
            2,
            total_steps,
            "local readiness",
            readiness_step_started,
            &timestamped_run_log,
            &err,
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!("step=local_readiness status=failed error={}", err),
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "end_utc={} campaign_success=false dry_run={} termination_cause=local_readiness",
                Utc::now().to_rfc3339(),
                args.dry_run
            ),
        );
        if let Err(log_err) =
            write_error_log(&timestamped_error_log, &[], 1, false, false, args.dry_run)
        {
            eprintln!(
                "Failed to write early error log '{}': {:#}",
                timestamped_error_log.display(),
                log_err
            );
        }
        return Err(err);
    }
    let (run_signal_dir, build_cache_dir) = match preflight_runtime_paths(&results_root) {
        Ok(paths) => paths,
        Err(err) => {
            step_failed(
                2,
                total_steps,
                "local readiness",
                readiness_step_started,
                &timestamped_run_log,
                &err,
            );
            append_run_log_best_effort(
                &timestamped_run_log,
                format!("step=local_readiness status=failed error={}", err),
            );
            append_run_log_best_effort(
                &timestamped_run_log,
                format!(
                    "end_utc={} campaign_success=false dry_run={} termination_cause=runtime_paths",
                    Utc::now().to_rfc3339(),
                    args.dry_run
                ),
            );
            if let Err(log_err) =
                write_error_log(&timestamped_error_log, &[], 1, false, false, args.dry_run)
            {
                eprintln!(
                    "Failed to write early error log '{}': {:#}",
                    timestamped_error_log.display(),
                    log_err
                );
            }
            return Err(anyhow::anyhow!(
                "Output path readiness check failed for '{}': {:#}\nHint: ensure this directory and its subdirectories are writable.",
                results_root.display(),
                err
            ));
        }
    };
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=local_readiness status=completed run_signal_dir={} build_cache_dir={}",
            run_signal_dir.display(),
            build_cache_dir.display()
        ),
    );
    append_run_log_best_effort(
        &timestamped_run_log,
        "step=local_readiness checks=framework_tools,target_shape,runtime_paths",
    );
    step_succeeded(
        2,
        total_steps,
        "local readiness",
        readiness_step_started,
        &timestamped_run_log,
    );

    let bin_path = resolved_release_bin_path("zk-fuzzer");
    let build_step_started = step_started(3, total_steps, "build zk-fuzzer", &timestamped_run_log);
    if args.build {
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "step=build_zk_fuzzer status=started bin={}",
                bin_path.display()
            ),
        );
        let status = match Command::new("cargo")
            .args(["build", "--release", "--bin", "zk-fuzzer"])
            .status()
        {
            Ok(status) => status,
            Err(err) => {
                let err = anyhow::anyhow!("Failed to execute cargo build for zk-fuzzer: {}", err);
                step_failed(
                    3,
                    total_steps,
                    "build zk-fuzzer",
                    build_step_started,
                    &timestamped_run_log,
                    &err,
                );
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!(
                        "step=build_zk_fuzzer status=failed error=cargo_command_failed detail={}",
                        err
                    ),
                );
                append_run_log_best_effort(
                        &timestamped_run_log,
                        format!(
                        "end_utc={} campaign_success=false dry_run={} termination_cause=build_zk_fuzzer_command",
                        Utc::now().to_rfc3339(),
                        args.dry_run
                    ),
                    );
                if let Err(log_err) =
                    write_error_log(&timestamped_error_log, &[], 1, false, false, args.dry_run)
                {
                    eprintln!(
                        "Failed to write early error log '{}': {:#}",
                        timestamped_error_log.display(),
                        log_err
                    );
                }
                return Err(err);
            }
        };
        if !status.success() {
            let err = anyhow::anyhow!("cargo build --release --bin zk-fuzzer failed");
            step_failed(
                3,
                total_steps,
                "build zk-fuzzer",
                build_step_started,
                &timestamped_run_log,
                &err,
            );
            append_run_log_best_effort(&timestamped_run_log, "step=build_zk_fuzzer status=failed");
            append_run_log_best_effort(
                &timestamped_run_log,
                format!(
                    "end_utc={} campaign_success=false dry_run={} termination_cause=build_zk_fuzzer",
                    Utc::now().to_rfc3339(),
                    args.dry_run
                ),
            );
            if let Err(err) =
                write_error_log(&timestamped_error_log, &[], 1, false, false, args.dry_run)
            {
                eprintln!(
                    "Failed to write early error log '{}': {:#}",
                    timestamped_error_log.display(),
                    err
                );
            }
            return Err(err);
        }
        append_run_log_best_effort(
            &timestamped_run_log,
            "step=build_zk_fuzzer status=completed",
        );
        step_succeeded(
            3,
            total_steps,
            "build zk-fuzzer",
            build_step_started,
            &timestamped_run_log,
        );
    } else if !bin_path.exists() {
        let err = anyhow::anyhow!(
            "zk-fuzzer binary not found at '{}' and --build=false",
            bin_path.display()
        );
        step_failed(
            3,
            total_steps,
            "build zk-fuzzer",
            build_step_started,
            &timestamped_run_log,
            &err,
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "step=build_zk_fuzzer status=missing_binary path={}",
                bin_path.display()
            ),
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "end_utc={} campaign_success=false dry_run={} termination_cause=missing_binary",
                Utc::now().to_rfc3339(),
                args.dry_run
            ),
        );
        if let Err(err) =
            write_error_log(&timestamped_error_log, &[], 1, false, false, args.dry_run)
        {
            eprintln!(
                "Failed to write early error log '{}': {:#}",
                timestamped_error_log.display(),
                err
            );
        }
        return Err(err);
    } else {
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "step=build_zk_fuzzer status=skipped_existing_binary path={}",
                bin_path.display()
            ),
        );
        step_skipped(
            3,
            total_steps,
            "build zk-fuzzer",
            "existing binary (--build=false)",
            &timestamped_run_log,
        );
    }

    let prepare_step_started = step_started(4, total_steps, "target prepare", &timestamped_run_log);
    if args.dry_run {
        append_run_log_best_effort(
            &timestamped_run_log,
            "step=prepare_target status=skipped reason=dry_run",
        );
        step_skipped(
            4,
            total_steps,
            "target prepare",
            "dry run",
            &timestamped_run_log,
        );
    } else if args.prepare_target {
        match prepare_target_for_framework(&args.framework, &target_circuit) {
            Ok(prepared) if prepared => {
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!(
                        "step=prepare_target status=completed framework={} target_circuit={}",
                        args.framework, target_circuit
                    ),
                );
                step_succeeded(
                    4,
                    total_steps,
                    "target prepare",
                    prepare_step_started,
                    &timestamped_run_log,
                );
            }
            Ok(_) => {
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!(
                        "step=prepare_target status=skipped framework={}",
                        args.framework
                    ),
                );
                step_skipped(
                    4,
                    total_steps,
                    "target prepare",
                    "framework has no explicit prepare phase",
                    &timestamped_run_log,
                );
            }
            Err(err) => {
                step_failed(
                    4,
                    total_steps,
                    "target prepare",
                    prepare_step_started,
                    &timestamped_run_log,
                    &err,
                );
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!("step=prepare_target status=failed error={}", err),
                );
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!(
                        "end_utc={} campaign_success=false dry_run={} termination_cause=prepare_target",
                        Utc::now().to_rfc3339(),
                        args.dry_run
                    ),
                );
                if let Err(log_err) =
                    write_error_log(&timestamped_error_log, &[], 1, false, false, args.dry_run)
                {
                    eprintln!(
                        "Failed to write early error log '{}': {:#}",
                        timestamped_error_log.display(),
                        log_err
                    );
                }
                return Err(err);
            }
        }
    } else {
        append_run_log_best_effort(
            &timestamped_run_log,
            "step=prepare_target status=skipped reason=disabled_by_flag",
        );
        step_skipped(
            4,
            total_steps,
            "target prepare",
            "disabled by --prepare-target=false",
            &timestamped_run_log,
        );
    }

    let artifacts_root = results_root.join(".scan_run_artifacts");

    let run_cfg_base = ScanRunConfig {
        bin_path: &bin_path,
        target_circuit: &target_circuit,
        framework: &args.framework,
        main_component: &args.main_component,
        env_overrides: &effective_file_cfg.env,
        extra_args: &effective_file_cfg.extra_args,
        workers: args.workers,
        seed: args.seed,
        iterations: args.iterations,
        timeout: args.timeout,
        scan_run_root: None,
        results_root: &results_root,
        run_signal_dir: &run_signal_dir,
        build_cache_dir: &build_cache_dir,
        dry_run: args.dry_run,
        artifacts_root: &artifacts_root,
        memory_guard,
        stage_timeouts,
    };

    let execute_step_started =
        step_started(5, total_steps, "execute templates", &timestamped_run_log);
    let baseline_roots = if args.dry_run {
        BTreeSet::new()
    } else {
        match list_scan_run_roots(&artifacts_root) {
            Ok(roots) => roots,
            Err(err) => {
                step_failed(
                    5,
                    total_steps,
                    "execute templates",
                    execute_step_started,
                    &timestamped_run_log,
                    &err,
                );
                return Err(err);
            }
        }
    };
    // One batch command -> one collision-safe scan_run root.
    let batch_run_root = if args.dry_run {
        None
    } else {
        match reserve_batch_scan_run_root(&artifacts_root) {
            Ok(run_root) => Some(run_root),
            Err(err) => {
                step_failed(
                    5,
                    total_steps,
                    "execute templates",
                    execute_step_started,
                    &timestamped_run_log,
                    &err,
                );
                return Err(err);
            }
        }
    };
    let run_cfg = ScanRunConfig {
        scan_run_root: batch_run_root.as_deref(),
        ..run_cfg_base
    };

    use rayon::prelude::*;

    let jobs = args.jobs.max(1);
    println!(
        "Running {} templates in parallel (jobs={})",
        selected_with_family.len(),
        jobs
    );
    println!(
        "Batch progress indicator: {}",
        if args.no_batch_progress {
            "disabled"
        } else {
            "enabled"
        }
    );
    println!(
        "Execution mode: detect patterns, then immediately resolve proof status from evidence artifacts."
    );
    println!(
        "Per-template hard timeouts: detection={}s proof={}s stuck_step_warn={}s",
        stage_timeouts.detection_timeout_secs,
        stage_timeouts.proof_timeout_secs,
        stage_timeouts.stuck_step_warn_secs
    );
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=execute_templates status=started templates={} jobs={} dry_run={} detection_timeout_secs={} proof_timeout_secs={} stuck_step_warn_secs={}",
            selected_with_family.len(),
            jobs,
            args.dry_run,
            stage_timeouts.detection_timeout_secs,
            stage_timeouts.proof_timeout_secs,
            stage_timeouts.stuck_step_warn_secs
        ),
    );
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .map_err(|err| anyhow::anyhow!("Failed to build rayon thread pool: {}", err));
    let pool = match pool {
        Ok(pool) => pool,
        Err(err) => {
            step_failed(
                5,
                total_steps,
                "execute templates",
                execute_step_started,
                &timestamped_run_log,
                &err,
            );
            return Err(err);
        }
    };
    let progress = if args.no_batch_progress {
        None
    } else {
        Some(Arc::new(BatchProgress::new(selected_with_family.len())))
    };

    let outcomes = pool.install(|| {
        selected_with_family
            .par_iter()
            .map(|(template, family)| {
                let suffix = scan_output_suffix(template, *family);
                println!(
                    "[TEMPLATE START] {} family={} output_suffix={}",
                    template.file_name,
                    family.as_str(),
                    suffix
                );
                let ok = match run_template(
                    run_cfg,
                    template,
                    *family,
                    args.skip_validate,
                    suffix.as_str(),
                ) {
                    Ok(ok) => ok,
                    Err(err) => {
                        eprintln!("Template '{}' failed: {}", template.file_name, err);
                        false
                    }
                };
                println!(
                    "[TEMPLATE END] {} result={}",
                    template.file_name,
                    if ok { "ok" } else { "template_error" }
                );
                if let Some(progress) = progress.as_ref() {
                    println!("{}", progress.record(&template.file_name, ok));
                }
                ok
            })
            .collect::<Vec<_>>()
    });

    let executed = outcomes.len();
    let template_errors = outcomes.iter().filter(|ok| !**ok).count();
    let duration_secs = batch_started_at.elapsed().as_secs_f64().max(0.001);
    let avg_rate = executed as f64 / duration_secs;

    println!(
        "Batch complete. Templates executed: {}, template_errors: {}, duration: {:.1}s, avg_rate: {:.2}/s",
        executed, template_errors, duration_secs, avg_rate
    );
    let gate2_ok = executed == expected_count && template_errors == 0;
    println!(
        "Gate 2/3 (completion line): {}",
        if gate2_ok {
            format!("PASS (executed={}, template_errors=0)", executed)
        } else {
            format!(
                "FAIL (expected={}, executed={}, template_errors={})",
                expected_count, executed, template_errors
            )
        }
    );

    let gate3_ok = if args.dry_run {
        println!("Gate 3/3 (artifact reconciliation): SKIP (dry run)");
        true
    } else {
        let after_roots = list_scan_run_roots(&artifacts_root)?;
        let new_roots: BTreeSet<String> =
            after_roots.difference(&baseline_roots).cloned().collect();
        let observed_suffixes = collect_observed_suffixes_for_roots(&artifacts_root, &new_roots)?;
        let missing: Vec<String> = expected_suffixes
            .difference(&observed_suffixes)
            .cloned()
            .collect();
        if missing.is_empty() {
            println!(
                "Gate 3/3 (artifact reconciliation): PASS (new run roots={}, observed={})",
                new_roots.len(),
                observed_suffixes.len()
            );
            true
        } else {
            eprintln!(
                "Gate 3/3 (artifact reconciliation): FAIL (missing={})",
                missing.len()
            );
            eprintln!("Missing suffixes: {}", missing.join(", "));
            false
        }
    };

    let mut reasons = Vec::new();
    if !args.dry_run {
        reasons = collect_template_outcome_reasons(
            &artifacts_root,
            batch_run_root.as_deref(),
            &selected_with_family,
        );
        print_reason_summary(&reasons);
        if args.emit_reason_tsv {
            print_reason_tsv(&reasons);
        }
        let (
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
        ) = proof_state_counts(&reasons);
        println!(
            "Proof totals: proven_exploitable={}, proven_not_exploitable_within_bounds={}, proof_failed={}, proof_skipped_by_policy={}",
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns
        );
    }
    let detected_patterns_total = reasons
        .iter()
        .map(|reason| reason.detected_pattern_count)
        .sum::<usize>();
    if !args.dry_run {
        let (
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
        ) = proof_state_counts(&reasons);
        println!(
            "Final totals: detected_patterns={} proven_exploitable={} proven_not_exploitable_within_bounds={} proof_failed={} proof_skipped_by_policy={} template_errors={}",
            detected_patterns_total,
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
            template_errors
        );
    }

    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=execute_templates status=completed executed={} template_errors={} duration_secs={:.3} avg_rate={:.3}",
            executed, template_errors, duration_secs, avg_rate
        ),
    );
    if !args.dry_run {
        let (
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
        ) = proof_state_counts(&reasons);
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "proof_totals proven_exploitable={} proven_not_exploitable_within_bounds={} proof_failed={} proof_skipped_by_policy={}",
                exploitable_patterns,
                not_exploitable_within_bounds_patterns,
                proof_failed_patterns,
                proof_skipped_by_policy_patterns
            ),
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "final_totals detected_patterns={} template_errors={}",
                detected_patterns_total, template_errors
            ),
        );
    }
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=gate2 status={}",
            if gate2_ok { "pass" } else { "fail" }
        ),
    );
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=gate3 status={}",
            if gate3_ok { "pass" } else { "fail" }
        ),
    );
    for reason in reasons.iter().filter(|reason| is_error_reason(reason)) {
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "error template={} suffix={} reason_code={} status={} stage={} proof_status={} detected_pattern_count={}",
                reason.template_file,
                reason.suffix,
                reason.reason_code,
                reason.status.as_deref().unwrap_or("unknown"),
                reason.stage.as_deref().unwrap_or("unknown"),
                reason.proof_status.as_deref().unwrap_or("unknown"),
                reason.detected_pattern_count
            ),
        );
    }

    write_error_log(
        &timestamped_error_log,
        &reasons,
        template_errors,
        gate2_ok,
        gate3_ok,
        args.dry_run,
    )?;

    let has_reason_errors = reasons.iter().any(is_error_reason);
    let campaign_success = !args.dry_run && gate2_ok && gate3_ok && !has_reason_errors;
    if !args.dry_run {
        write_report_json(
            &args,
            &timestamped_report_path,
            &target_circuit,
            &reasons,
            expected_count,
            executed,
            template_errors,
            &results_root,
            gate2_ok,
            gate3_ok,
            campaign_success,
            &timestamped_result_dir,
            &timestamped_run_log,
            &timestamped_error_log,
            batch_run_root.as_deref(),
        )?;
        println!(
            "Wrote detected-patterns report JSON: {}",
            timestamped_report_path.display()
        );
    } else {
        println!("Skipped detected-patterns JSON for dry run.");
    }
    println!(
        "Wrote timestamped result bundle: {}",
        timestamped_result_dir.display()
    );
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "end_utc={} campaign_success={} dry_run={} gate2_ok={} gate3_ok={} template_errors={}",
            Utc::now().to_rfc3339(),
            campaign_success,
            args.dry_run,
            gate2_ok,
            gate3_ok,
            template_errors
        ),
    );

    if gate2_ok && gate3_ok {
        step_succeeded(
            5,
            total_steps,
            "execute templates",
            execute_step_started,
            &timestamped_run_log,
        );
    } else {
        let err = anyhow::anyhow!(
            "execution gates failed (gate2_ok={}, gate3_ok={}, template_errors={})",
            gate2_ok,
            gate3_ok,
            template_errors
        );
        step_failed(
            5,
            total_steps,
            "execute templates",
            execute_step_started,
            &timestamped_run_log,
            &err,
        );
    }

    if !gate2_ok || !gate3_ok {
        std::process::exit(1);
    }

    Ok(())
}
