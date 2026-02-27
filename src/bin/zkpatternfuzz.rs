use anyhow::Context;
use chrono::Utc;
use clap::{ArgAction, Parser, ValueEnum};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[path = "zkpatternfuzz/checkenv.rs"]
mod checkenv;
#[path = "zkpatternfuzz/run_log.rs"]
mod run_log;
#[path = "zkpatternfuzz/zkpatternfuzz_config.rs"]
mod zkpatternfuzz_config;
#[path = "zkpatternfuzz/zkpatternfuzz_discovery.rs"]
mod zkpatternfuzz_discovery;
#[path = "zkpatternfuzz/zkpatternfuzz_env.rs"]
mod zkpatternfuzz_env;
#[path = "zkpatternfuzz/zkpatternfuzz_execution.rs"]
mod zkpatternfuzz_execution;
#[path = "zkpatternfuzz/zkpatternfuzz_readiness.rs"]
mod zkpatternfuzz_readiness;
#[path = "zkpatternfuzz/zkpatternfuzz_reporting.rs"]
mod zkpatternfuzz_reporting;

use checkenv::{is_set as env_is_set, var as env_var, CheckEnv};
#[cfg(test)]
use run_log::{append_run_log, run_log_file_cache};
use run_log::{
    append_run_log_best_effort, step_failed, step_skipped, step_started, step_succeeded,
};
use zkpatternfuzz_config::{
    apply_file_config, effective_batch_timeout_secs, halo2_effective_external_timeout_secs,
    high_confidence_min_oracles_from_env, load_batch_file_config, load_memory_guard_config,
    load_stage_timeout_config, resolve_build_cache_dir, resolve_results_root,
};
use zkpatternfuzz_discovery::{
    build_template_index, dedupe_patterns_by_signature, discover_all_pattern_templates,
    print_catalog, resolve_explicit_pattern_selection, resolve_selection, split_csv,
    validate_pattern_only_yaml,
};
use zkpatternfuzz_env::{expand_env_placeholders, has_unresolved_env_placeholder};
#[cfg(test)]
use zkpatternfuzz_execution::{
    finalize_pipe_capture, join_pipe_reader, run_scan, spawn_pipe_reader,
    write_stage_timeout_outcome, PipeCapture,
};
use zkpatternfuzz_execution::{
    proof_status_from_run_outcome_doc, run_template, scan_output_suffix,
};
use zkpatternfuzz_readiness::{ensure_local_runtime_requirements, preflight_template_paths};
use zkpatternfuzz_reporting::{
    create_timestamped_result_dir, is_error_reason, print_reason_tsv, proof_state_counts,
    write_error_log, write_report_json,
};

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
