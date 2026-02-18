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

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub pattern: String,
    pub family: ScanFamily,
    pub target_circuit: String,
    pub main_component: String,
    pub framework: String,
    pub output_suffix: Option<String>,
    pub mono_options: CampaignRunOptions,
    pub chain_options: ChainRunOptions,
}

#[derive(Debug, Clone)]
pub struct BinsBootstrapRequest {
    pub bins_dir: String,
    pub circom_version: String,
    pub snarkjs_version: String,
    pub ptau_file: String,
    pub ptau_url: Option<String>,
    pub ptau_sha256: Option<String>,
    pub skip_circom: bool,
    pub skip_snarkjs: bool,
    pub skip_ptau: bool,
    pub force: bool,
}

#[derive(Debug, Clone)]
pub enum CommandRequest {
    Scan(ScanRequest),
    RunCampaign {
        campaign: String,
        options: CampaignRunOptions,
    },
    RunChainCampaign {
        campaign: String,
        options: ChainRunOptions,
    },
    Preflight {
        campaign: String,
        setup_keys: bool,
    },
    Validate {
        campaign: String,
    },
    BinsBootstrap(BinsBootstrapRequest),
    Minimize {
        corpus_dir: String,
        output: Option<String>,
    },
    Init {
        output: String,
        framework: String,
    },
    ExecWorker,
    MissingCommand,
}

impl Cli {
    pub fn into_request(self) -> CommandRequest {
        match self.command {
            Some(Commands::Scan {
                pattern,
                family,
                target_circuit,
                main_component,
                framework,
                iterations,
                timeout,
                resume,
                corpus_dir,
                output_suffix,
            }) => CommandRequest::Scan(ScanRequest {
                pattern,
                family,
                target_circuit,
                main_component,
                framework,
                output_suffix,
                mono_options: CampaignRunOptions {
                    command_label: "scan",
                    workers: self.workers,
                    seed: self.seed,
                    verbose: self.verbose,
                    dry_run: self.dry_run,
                    simple_progress: self.simple_progress,
                    real_only: true,
                    iterations,
                    timeout,
                    require_invariants: true,
                    resume,
                    corpus_dir: corpus_dir.clone(),
                    profile: self.profile.clone(),
                },
                chain_options: ChainRunOptions {
                    workers: self.workers,
                    seed: self.seed,
                    verbose: self.verbose,
                    dry_run: self.dry_run,
                    simple_progress: self.simple_progress,
                    iterations,
                    timeout: timeout.unwrap_or(600),
                    resume,
                },
            }),
            Some(Commands::Run {
                campaign,
                iterations,
                timeout,
                resume,
                corpus_dir,
            }) => CommandRequest::RunCampaign {
                campaign,
                options: CampaignRunOptions {
                    command_label: "run",
                    workers: self.workers,
                    seed: self.seed,
                    verbose: self.verbose,
                    dry_run: self.dry_run,
                    simple_progress: self.simple_progress,
                    real_only: true,
                    iterations,
                    timeout,
                    require_invariants: false,
                    resume,
                    corpus_dir,
                    profile: self.profile.clone(),
                },
            },
            Some(Commands::Evidence {
                campaign,
                iterations,
                timeout,
                resume,
                corpus_dir,
            }) => CommandRequest::RunCampaign {
                campaign,
                options: CampaignRunOptions {
                    command_label: "evidence",
                    workers: self.workers,
                    seed: self.seed,
                    verbose: self.verbose,
                    dry_run: self.dry_run,
                    simple_progress: self.simple_progress,
                    real_only: true,
                    iterations,
                    timeout,
                    require_invariants: true,
                    resume,
                    corpus_dir,
                    profile: self.profile.clone(),
                },
            },
            Some(Commands::Chains {
                campaign,
                iterations,
                timeout,
                resume,
            }) => CommandRequest::RunChainCampaign {
                campaign,
                options: ChainRunOptions {
                    workers: self.workers,
                    seed: self.seed,
                    verbose: self.verbose,
                    dry_run: self.dry_run,
                    simple_progress: self.simple_progress,
                    iterations,
                    timeout,
                    resume,
                },
            },
            Some(Commands::Preflight {
                campaign,
                setup_keys,
            }) => CommandRequest::Preflight {
                campaign,
                setup_keys,
            },
            Some(Commands::Validate { campaign }) => CommandRequest::Validate { campaign },
            Some(Commands::Bins {
                command:
                    BinsCommands::Bootstrap {
                        bins_dir,
                        circom_version,
                        snarkjs_version,
                        ptau_file,
                        ptau_url,
                        ptau_sha256,
                        skip_circom,
                        skip_snarkjs,
                        skip_ptau,
                        force,
                    },
            }) => CommandRequest::BinsBootstrap(BinsBootstrapRequest {
                bins_dir,
                circom_version,
                snarkjs_version,
                ptau_file,
                ptau_url,
                ptau_sha256,
                skip_circom,
                skip_snarkjs,
                skip_ptau,
                force,
            }),
            Some(Commands::Minimize { corpus_dir, output }) => {
                CommandRequest::Minimize { corpus_dir, output }
            }
            Some(Commands::Init { output, framework }) => CommandRequest::Init { output, framework },
            Some(Commands::ExecWorker) => CommandRequest::ExecWorker,
            None => {
                if let Some(config_path) = self.config {
                    CommandRequest::RunCampaign {
                        campaign: config_path,
                        options: CampaignRunOptions {
                            command_label: "run",
                            workers: self.workers,
                            seed: self.seed,
                            verbose: self.verbose,
                            dry_run: self.dry_run,
                            simple_progress: self.simple_progress,
                            real_only: true,
                            iterations: 100_000,
                            timeout: None,
                            require_invariants: false,
                            resume: false,
                            corpus_dir: None,
                            profile: self.profile.clone(),
                        },
                    }
                } else {
                    CommandRequest::MissingCommand
                }
            }
        }
    }
}

pub fn campaign_run_options_doc(options: &CampaignRunOptions) -> serde_json::Value {
    serde_json::json!({
        "command": options.command_label,
        "workers": options.workers,
        "seed": options.seed,
        "iterations": options.iterations,
        "timeout_seconds": options.timeout,
        "resume": options.resume,
        "corpus_dir": options.corpus_dir,
        "profile": options.profile,
        "simple_progress": options.simple_progress,
        "dry_run": options.dry_run,
    })
}

pub fn chain_run_options_doc(options: &ChainRunOptions) -> serde_json::Value {
    serde_json::json!({
        "workers": options.workers,
        "seed": options.seed,
        "iterations": options.iterations,
        "timeout_seconds": options.timeout,
        "resume": options.resume,
        "simple_progress": options.simple_progress,
        "dry_run": options.dry_run,
    })
}
