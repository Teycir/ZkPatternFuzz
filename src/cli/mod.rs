use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "zk-fuzzer")]
#[command(version = "0.1.0")]
#[command(about = "Zero-Knowledge Proof Security Testing Framework")]
#[command(
    long_about = "A comprehensive fuzzing framework for detecting vulnerabilities in ZK circuits.\n\nSupports Circom, Noir, Halo2, and Cairo backends with coverage-guided fuzzing,\nmultiple attack vectors, and detailed vulnerability reporting."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to YAML campaign configuration
    #[arg(short, long, global = true)]
    pub config: Option<String>,

    /// Number of parallel workers
    #[arg(short, long, default_value = "4", global = true)]
    pub workers: usize,

    /// Seed for reproducibility
    #[arg(short, long, global = true)]
    pub seed: Option<u64>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Quiet mode - minimal output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Dry run - validate config without executing
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Use simple progress (no fancy terminal UI)
    #[arg(long, global = true)]
    pub simple_progress: bool,

    /// Require strict backend availability checks.
    #[arg(long, global = true)]
    pub real_only: bool,

    /// Configuration profile (quick, standard, deep, perf)
    /// Quick: 10K iterations, fast exploration
    /// Standard: 100K iterations, balanced fuzzing (default for evidence)
    /// Deep: 1M iterations, thorough analysis
    #[arg(long, global = true)]
    pub profile: Option<String>,

    /// Kill other zk-fuzzer instances on startup (use with caution)
    #[arg(long, global = true)]
    pub kill_existing: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Unified scan command: auto-dispatch mono/multi pattern YAML
    Scan {
        /// Path to pattern YAML (pattern-only schema)
        pattern: String,

        /// Pattern family hint (auto/mono/multi)
        #[arg(long, default_value = "auto")]
        family: ScanFamily,

        /// Target circuit path used to materialize runtime campaign metadata
        #[arg(long)]
        target_circuit: String,

        /// Main component name for target circuit
        #[arg(long, default_value = "main")]
        main_component: String,

        /// Framework for target circuit (circom, noir, halo2, cairo)
        #[arg(long, default_value = "circom")]
        framework: String,

        /// Number of iterations
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Timeout in seconds (mono: optional, multi: defaults to 600 if omitted)
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Resume from existing corpus
        #[arg(long)]
        resume: bool,

        /// Custom corpus directory (mono only)
        #[arg(long)]
        corpus_dir: Option<String>,

        /// Optional output suffix for scan isolation (used by batch parallel runs)
        #[arg(long)]
        output_suffix: Option<String>,
    },
    /// Legacy run mode (backward-compatible alias for campaign execution)
    Run {
        /// Path to campaign YAML file
        campaign: String,

        /// Number of iterations
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Timeout in seconds
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Resume from existing corpus
        #[arg(long)]
        resume: bool,

        /// Custom corpus directory
        #[arg(long)]
        corpus_dir: Option<String>,
    },
    /// Legacy evidence mode (strict evidence campaign execution)
    Evidence {
        /// Path to campaign YAML file
        campaign: String,

        /// Number of iterations
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Timeout in seconds
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Resume from existing corpus
        #[arg(long)]
        resume: bool,

        /// Custom corpus directory
        #[arg(long)]
        corpus_dir: Option<String>,
    },
    /// Legacy chains mode (backward-compatible chain execution command)
    Chains {
        /// Path to campaign YAML file
        campaign: String,

        /// Number of iterations
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Chain-mode timeout in seconds
        #[arg(short, long, default_value = "600")]
        timeout: u64,

        /// Resume from existing chain corpus
        #[arg(long)]
        resume: bool,
    },
    /// Run backend/key-setup preflight for a campaign and exit
    Preflight {
        /// Path to campaign YAML file
        campaign: String,
        /// Require Circom key setup to pass during preflight
        #[arg(long, default_value_t = false)]
        setup_keys: bool,
    },
    /// Validate a campaign configuration
    Validate {
        /// Path to campaign YAML file
        campaign: String,
    },
    /// Local toolchain bootstrap utilities
    Bins {
        #[command(subcommand)]
        command: BinsCommands,
    },
    /// Minimize a corpus
    Minimize {
        /// Path to corpus directory
        corpus_dir: String,
        /// Output directory for minimized corpus
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Generate a sample campaign configuration
    Init {
        /// Output file path
        #[arg(short, long, default_value = "campaign.yaml")]
        output: String,
        /// Target framework (circom, noir, halo2)
        #[arg(short, long, default_value = "circom")]
        framework: String,
    },
    #[command(hide = true)]
    ExecWorker,
}

#[derive(Subcommand)]
pub enum BinsCommands {
    /// Install/update local circom/snarkjs/ptau assets under bins/
    Bootstrap {
        /// Local bins directory root
        #[arg(long, default_value = "bins")]
        bins_dir: String,
        /// Circom release version (tag or semver, e.g. v2.2.3 or 2.2.3)
        #[arg(long, default_value = "v2.2.3")]
        circom_version: String,
        /// snarkjs npm version
        #[arg(long, default_value = "0.7.5")]
        snarkjs_version: String,
        /// Output filename under <bins_dir>/ptau/
        #[arg(long, default_value = "pot12_final.ptau")]
        ptau_file: String,
        /// Optional ptau download URL (when omitted, uses local fixture)
        #[arg(long)]
        ptau_url: Option<String>,
        /// Expected SHA-256 for ptau file (required when --ptau-url is used)
        #[arg(long)]
        ptau_sha256: Option<String>,
        /// Skip circom bootstrap
        #[arg(long, default_value_t = false)]
        skip_circom: bool,
        /// Skip snarkjs bootstrap
        #[arg(long, default_value_t = false)]
        skip_snarkjs: bool,
        /// Skip ptau bootstrap
        #[arg(long, default_value_t = false)]
        skip_ptau: bool,
        /// Force re-download/reinstall even when local artifacts already exist
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Hash)]
pub enum ScanFamily {
    Auto,
    Mono,
    Multi,
}

#[derive(Debug, Clone)]
pub struct CampaignRunOptions {
    pub command_label: &'static str,
    pub workers: usize,
    pub seed: Option<u64>,
    pub verbose: bool,
    pub dry_run: bool,
    pub simple_progress: bool,
    pub real_only: bool,
    pub iterations: u64,
    pub timeout: Option<u64>,
    pub require_invariants: bool,
    pub resume: bool,
    pub corpus_dir: Option<String>,
    pub profile: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChainRunOptions {
    pub workers: usize,
    pub seed: Option<u64>,
    pub verbose: bool,
    pub dry_run: bool,
    pub simple_progress: bool,
    pub iterations: u64,
    pub timeout: u64,
    pub resume: bool,
}
