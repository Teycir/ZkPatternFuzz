use clap::{ArgAction, Parser, ValueEnum};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;

pub(super) const SCAN_RUN_ROOT_ENV: &str = "ZKF_SCAN_RUN_ROOT";
pub(super) const SCAN_OUTPUT_ROOT_ENV: &str = "ZKF_SCAN_OUTPUT_ROOT";
pub(super) const RUN_SIGNAL_DIR_ENV: &str = "ZKF_RUN_SIGNAL_DIR";
pub(super) const BUILD_CACHE_DIR_ENV: &str = "ZKF_BUILD_CACHE_DIR";
pub(super) const SHARED_BUILD_CACHE_DIR_ENV: &str = "ZKF_SHARED_BUILD_CACHE_DIR";
pub(super) const HALO2_EXTERNAL_TIMEOUT_ENV: &str = "ZK_FUZZER_HALO2_EXTERNAL_TIMEOUT_SECS";
pub(super) const HALO2_MIN_EXTERNAL_TIMEOUT_ENV: &str = "ZK_FUZZER_HALO2_MIN_EXTERNAL_TIMEOUT_SECS";
pub(super) const HALO2_CARGO_RUN_BIN_ENV: &str = "ZK_FUZZER_HALO2_CARGO_RUN_BIN";
pub(super) const HALO2_USE_HOST_CARGO_HOME_ENV: &str = "ZK_FUZZER_HALO2_USE_HOST_CARGO_HOME";
pub(super) const HALO2_CARGO_TOOLCHAIN_CANDIDATES_ENV: &str =
    "ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES";
pub(super) const HALO2_TOOLCHAIN_CASCADE_LIMIT_ENV: &str =
    "ZK_FUZZER_HALO2_TOOLCHAIN_CASCADE_LIMIT";
pub(super) const HALO2_DEFAULT_BATCH_TIMEOUT_ENV: &str = "ZKF_HALO2_DEFAULT_TIMEOUT_SECS";
pub(super) const CAIRO_EXTERNAL_TIMEOUT_ENV: &str = "ZK_FUZZER_CAIRO_EXTERNAL_TIMEOUT_SECS";
pub(super) const SCARB_DOWNLOAD_TIMEOUT_ENV: &str = "ZK_FUZZER_SCARB_DOWNLOAD_TIMEOUT_SECS";
pub(super) const HIGH_CONFIDENCE_MIN_ORACLES_ENV: &str = "ZKF_HIGH_CONFIDENCE_MIN_ORACLES";
pub(super) const DEFAULT_BATCH_JOBS_ENV: &str = "ZKF_ZKPATTERNFUZZ_DEFAULT_JOBS";
pub(super) const DEFAULT_BATCH_WORKERS_ENV: &str = "ZKF_ZKPATTERNFUZZ_DEFAULT_WORKERS";
pub(super) const DEFAULT_BATCH_ITERATIONS_ENV: &str = "ZKF_ZKPATTERNFUZZ_DEFAULT_ITERATIONS";
pub(super) const DEFAULT_BATCH_TIMEOUT_ENV: &str = "ZKF_ZKPATTERNFUZZ_DEFAULT_TIMEOUT_SECS";
pub(super) const MEMORY_GUARD_ENABLED_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_GUARD_ENABLED";
pub(super) const MEMORY_GUARD_RESERVED_MB_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_RESERVED_MB";
pub(super) const MEMORY_GUARD_MB_PER_TEMPLATE_ENV: &str =
    "ZKF_ZKPATTERNFUZZ_MEMORY_MB_PER_TEMPLATE";
pub(super) const MEMORY_GUARD_MB_PER_WORKER_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_MB_PER_WORKER";
pub(super) const MEMORY_GUARD_LAUNCH_FLOOR_MB_ENV: &str =
    "ZKF_ZKPATTERNFUZZ_MEMORY_LAUNCH_FLOOR_MB";
pub(super) const MEMORY_GUARD_WAIT_SECS_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_WAIT_SECS";
pub(super) const MEMORY_GUARD_POLL_MS_ENV: &str = "ZKF_ZKPATTERNFUZZ_MEMORY_POLL_MS";
pub(super) const DETECTION_STAGE_TIMEOUT_ENV: &str =
    "ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS";
pub(super) const PROOF_STAGE_TIMEOUT_ENV: &str = "ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS";
pub(super) const STUCK_STEP_WARN_SECS_ENV: &str = "ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS";
pub(super) const DEFAULT_HIGH_CONFIDENCE_MIN_ORACLES: usize = 2;
pub(super) const DEFAULT_BATCH_TIMEOUT_SECS: u64 = 1_800;
pub(super) const DEFAULT_HALO2_BATCH_TIMEOUT_SECS: u64 = 3_600;
pub(super) const DEFAULT_STUCK_STEP_WARN_SECS: u64 = 60;
pub(super) const DEFAULT_MEMORY_GUARD_RESERVED_MB: u64 = 4_096;
pub(super) const DEFAULT_MEMORY_GUARD_MB_PER_TEMPLATE: u64 = 768;
pub(super) const DEFAULT_MEMORY_GUARD_MB_PER_WORKER: u64 = 1_536;
pub(super) const DEFAULT_MEMORY_GUARD_LAUNCH_FLOOR_MB: u64 = 2_048;
pub(super) const DEFAULT_MEMORY_GUARD_WAIT_SECS: u64 = 180;
pub(super) const DEFAULT_MEMORY_GUARD_POLL_MS: u64 = 1_000;
pub(super) const DEFAULT_REGISTRY_PATH: &str = "targets/fuzzer_registry.yaml";
pub(super) const DEV_REGISTRY_PATH: &str = "targets/fuzzer_registry.dev.yaml";
pub(super) const PROD_REGISTRY_PATH: &str = "targets/fuzzer_registry.prod.yaml";
pub(super) const PROOF_STAGE_NOT_STARTED_REASON_CODE: &str = "proof_stage_not_started";
pub(super) const MAX_PIPE_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const PIPE_CAPTURE_TRUNCATED_NOTICE: &str =
    "\n[zkpatternfuzz] command output truncated to 8 MiB per stream\n";
pub(super) static RUN_ROOT_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Parser, Debug)]
#[command(name = "zkpatternfuzz")]
#[command(about = "Batch runner for YAML attack-pattern catalogs")]
pub(super) struct Args {
    /// Path to JSON/YAML run config (target/env/iterations/timeouts); `run_overrides` wrapper is supported
    #[arg(long)]
    pub(super) config_json: Option<String>,

    /// Path to fuzzer registry YAML
    #[arg(long)]
    pub(super) registry: Option<String>,

    /// Config profile for default registry path selection
    #[arg(long, value_enum)]
    pub(super) config_profile: Option<ConfigProfile>,

    /// List available collections/aliases/templates and exit
    #[arg(long, default_value_t = false)]
    pub(super) list_catalog: bool,

    /// Comma-separated collection names to run
    /// If no selector flags are provided, all discovered pattern YAML files are executed.
    #[arg(long)]
    pub(super) collection: Option<String>,

    /// Comma-separated alias names to run
    /// If no selector flags are provided, all discovered pattern YAML files are executed.
    #[arg(long)]
    pub(super) alias: Option<String>,

    /// Comma-separated template filenames to run
    /// If no selector flags are provided, all discovered pattern YAML files are executed.
    #[arg(long)]
    pub(super) template: Option<String>,

    /// Comma-separated pattern YAML paths (bypasses registry selectors)
    /// If omitted with no selector flags, the runner auto-discovers all pattern-compatible YAML files.
    #[arg(long)]
    pub(super) pattern_yaml: Option<String>,

    /// Target circuit path used for all selected templates
    #[arg(long)]
    pub(super) target_circuit: Option<String>,

    /// Main component used for all selected templates
    #[arg(long, default_value = "main")]
    pub(super) main_component: String,

    /// Framework used for all selected templates
    #[arg(long, default_value = "circom")]
    pub(super) framework: String,

    /// Family override passed to `zk-fuzzer scan`
    #[arg(long, default_value = "auto")]
    pub(super) family: String,

    /// Build release binary if missing
    #[arg(long, default_value_t = true)]
    pub(super) build: bool,

    /// Skip YAML validation pass
    #[arg(long, default_value_t = false)]
    pub(super) skip_validate: bool,

    /// Dry run (print commands only)
    #[arg(long, default_value_t = false)]
    pub(super) dry_run: bool,

    /// Maximum number of templates to execute in parallel (env: ZKF_ZKPATTERNFUZZ_DEFAULT_JOBS)
    #[arg(long, env = DEFAULT_BATCH_JOBS_ENV)]
    pub(super) jobs: usize,

    /// Worker count per run (env: ZKF_ZKPATTERNFUZZ_DEFAULT_WORKERS)
    #[arg(long, env = DEFAULT_BATCH_WORKERS_ENV)]
    pub(super) workers: usize,

    /// RNG seed per run
    #[arg(long, default_value_t = 42)]
    pub(super) seed: u64,

    /// Iterations per run (env: ZKF_ZKPATTERNFUZZ_DEFAULT_ITERATIONS)
    #[arg(long, env = DEFAULT_BATCH_ITERATIONS_ENV, default_value_t = 50_000)]
    pub(super) iterations: u64,

    /// Timeout per run in seconds (env: ZKF_ZKPATTERNFUZZ_DEFAULT_TIMEOUT_SECS).
    /// Halo2 uses a higher framework default when this is left unset.
    #[arg(long, env = DEFAULT_BATCH_TIMEOUT_ENV, default_value_t = DEFAULT_BATCH_TIMEOUT_SECS)]
    pub(super) timeout: u64,

    /// Emit per-template reason codes as TSV to stdout (for external harness ingestion)
    #[arg(long, default_value_t = false)]
    pub(super) emit_reason_tsv: bool,

    /// Disable batch-level progress lines (enabled by default)
    #[arg(long, default_value_t = false)]
    pub(super) no_batch_progress: bool,

    /// Prepare target artifacts before template execution (framework-specific)
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub(super) prepare_target: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum ConfigProfile {
    Dev,
    Prod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    Auto,
    Mono,
    Multi,
}

impl Family {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Family::Auto => "auto",
            Family::Mono => "mono",
            Family::Multi => "multi",
        }
    }
}

pub(super) fn default_registry_for_profile(profile: Option<ConfigProfile>) -> &'static str {
    match profile {
        Some(ConfigProfile::Dev) => DEV_REGISTRY_PATH,
        Some(ConfigProfile::Prod) => PROD_REGISTRY_PATH,
        None => DEFAULT_REGISTRY_PATH,
    }
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RegistryFile {
    pub(super) version: serde_yaml::Value,
    #[serde(default)]
    pub(super) registries: BTreeMap<String, RegistryEntry>,
    #[serde(default)]
    pub(super) collections: BTreeMap<String, CollectionEntry>,
    #[serde(default)]
    pub(super) aliases: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RegistryEntry {
    #[serde(default)]
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) url: Option<String>,
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) maintainer: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct CollectionEntry {
    pub(super) registry: String,
    #[serde(default)]
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) templates: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct TemplateInfo {
    pub(super) file_name: String,
    pub(super) path: PathBuf,
    pub(super) family: Family,
}

pub(super) type TemplateIndex = BTreeMap<String, TemplateInfo>;
pub(super) type CollectionIndex = BTreeMap<String, Vec<String>>;
pub(super) type DedupeResult = (Vec<TemplateInfo>, Vec<(TemplateInfo, TemplateInfo)>);

#[derive(Debug, Deserialize, Clone, Default)]
pub(super) struct BatchFileConfig {
    #[serde(default)]
    pub(super) target_circuit: Option<String>,
    #[serde(default)]
    pub(super) main_component: Option<String>,
    #[serde(default)]
    pub(super) framework: Option<String>,
    #[serde(default)]
    pub(super) family: Option<String>,
    #[serde(default)]
    pub(super) collection: Option<String>,
    #[serde(default)]
    pub(super) alias: Option<String>,
    #[serde(default)]
    pub(super) template: Option<String>,
    #[serde(default)]
    pub(super) pattern_yaml: Option<String>,
    #[serde(default)]
    pub(super) jobs: Option<usize>,
    #[serde(default)]
    pub(super) workers: Option<usize>,
    #[serde(default)]
    pub(super) seed: Option<u64>,
    #[serde(default)]
    pub(super) iterations: Option<u64>,
    #[serde(default)]
    pub(super) timeout: Option<u64>,
    #[serde(default)]
    pub(super) env: BTreeMap<String, serde_yaml::Value>,
    #[serde(default)]
    pub(super) extra_args: Vec<String>,
    #[serde(default)]
    pub(super) prepare_target: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct EffectiveFileConfig {
    pub(super) env: BTreeMap<String, String>,
    pub(super) extra_args: Vec<String>,
}

#[derive(Clone, Copy)]
pub(super) struct ScanRunConfig<'a> {
    pub(super) bin_path: &'a Path,
    pub(super) target_circuit: &'a str,
    pub(super) framework: &'a str,
    pub(super) main_component: &'a str,
    pub(super) env_overrides: &'a BTreeMap<String, String>,
    pub(super) extra_args: &'a [String],
    pub(super) workers: usize,
    pub(super) seed: u64,
    pub(super) iterations: u64,
    pub(super) timeout: u64,
    pub(super) scan_run_root: Option<&'a str>,
    pub(super) results_root: &'a Path,
    pub(super) run_signal_dir: &'a Path,
    pub(super) build_cache_dir: &'a Path,
    pub(super) dry_run: bool,
    pub(super) artifacts_root: &'a Path,
    pub(super) memory_guard: MemoryGuardConfig,
    pub(super) stage_timeouts: StageTimeoutConfig,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct MemoryGuardConfig {
    pub(super) enabled: bool,
    pub(super) reserved_mb: u64,
    pub(super) mb_per_template: u64,
    pub(super) mb_per_worker: u64,
    pub(super) launch_floor_mb: u64,
    pub(super) wait_secs: u64,
    pub(super) poll_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct StageTimeoutConfig {
    pub(super) detection_timeout_secs: u64,
    pub(super) proof_timeout_secs: u64,
    pub(super) stuck_step_warn_secs: u64,
}

#[derive(Debug, Clone)]
pub(super) struct TemplateOutcomeReason {
    pub(super) template_file: String,
    pub(super) template_path: String,
    pub(super) suffix: String,
    pub(super) status: Option<String>,
    pub(super) stage: Option<String>,
    pub(super) proof_status: Option<String>,
    pub(super) reason_code: String,
    pub(super) high_confidence_detected: bool,
    pub(super) detected_pattern_count: usize,
}

pub(super) struct ScanRunResult {
    pub(super) success: bool,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HardTimeoutStage {
    Detecting,
    Proving,
}
