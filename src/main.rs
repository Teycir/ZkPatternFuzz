use clap::{Parser, Subcommand};
use chrono::{DateTime, Duration as ChronoDuration, Local};
use zk_fuzzer::config::{FuzzConfig, ProfileName, apply_profile};
use zk_fuzzer::fuzzer::ZkFuzzer;

#[derive(Parser)]
#[command(name = "zk-fuzzer")]
#[command(version = "0.1.0")]
#[command(about = "Zero-Knowledge Proof Security Testing Framework")]
#[command(long_about = "A comprehensive fuzzing framework for detecting vulnerabilities in ZK circuits.\n\nSupports Circom, Noir, Halo2, and Cairo backends with coverage-guided fuzzing,\nmultiple attack vectors, and detailed vulnerability reporting.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to YAML campaign configuration
    #[arg(short, long, global = true)]
    config: Option<String>,

    /// Number of parallel workers
    #[arg(short, long, default_value = "4", global = true)]
    workers: usize,

    /// Seed for reproducibility
    #[arg(short, long, global = true)]
    seed: Option<u64>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Quiet mode - minimal output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Dry run - validate config without executing
    #[arg(long, global = true)]
    dry_run: bool,

    /// Use simple progress (no fancy terminal UI)
    #[arg(long, global = true)]
    simple_progress: bool,

    /// Require strict backend availability checks.
    #[arg(long, global = true)]
    real_only: bool,

    /// Configuration profile (quick, standard, deep, perf)
    /// Quick: 10K iterations, fast exploration
    /// Standard: 100K iterations, balanced fuzzing (default for evidence)
    /// Deep: 1M iterations, thorough analysis
    #[arg(long, global = true)]
    profile: Option<String>,

    /// Kill other zk-fuzzer instances on startup (use with caution)
    #[arg(long, global = true)]
    kill_existing: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a fuzzing campaign
    Run {
        /// Path to campaign YAML file
        campaign: String,
        
        /// Number of continuous fuzzing iterations (Phase 0)
        #[arg(short, long, default_value = "100000")]
        iterations: u64,
        
        /// Timeout in seconds for continuous fuzzing phase
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Resume from existing corpus (loads from reports/<campaign>/corpus/)
        #[arg(long)]
        resume: bool,

        /// Custom corpus directory for resume (default: reports/<campaign>/corpus/)
        #[arg(long)]
        corpus_dir: Option<String>,
    },
    /// Run an evidence-focused campaign (requires invariants)
    Evidence {
        /// Path to campaign YAML file
        campaign: String,

        /// Number of continuous fuzzing iterations (Phase 0)
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Timeout in seconds for continuous fuzzing phase
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Resume from existing corpus (loads from reports/<campaign>/corpus/)
        #[arg(long)]
        resume: bool,

        /// Custom corpus directory for resume (default: reports/<campaign>/corpus/)
        #[arg(long)]
        corpus_dir: Option<String>,
    },
    /// Run multi-step chain fuzzing (Mode 3: Deepest)
    Chains {
        /// Path to campaign YAML file with chain definitions
        campaign: String,

        /// Number of chain fuzzing iterations
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Timeout in seconds for chain fuzzing
        #[arg(short, long, default_value = "600")]
        timeout: u64,

        /// Resume from existing chain corpus
        #[arg(long)]
        resume: bool,
    },
    /// Validate a campaign configuration
    Validate {
        /// Path to campaign YAML file
        campaign: String,
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

#[derive(Debug, Clone)]
struct CampaignRunOptions {
    workers: usize,
    seed: Option<u64>,
    verbose: bool,
    dry_run: bool,
    simple_progress: bool,
    real_only: bool,
    iterations: u64,
    timeout: Option<u64>,
    require_invariants: bool,
    resume: bool,
    corpus_dir: Option<String>,
    profile: Option<String>,
}

#[derive(Debug, Clone)]
struct ChainRunOptions {
    workers: usize,
    seed: Option<u64>,
    verbose: bool,
    dry_run: bool,
    simple_progress: bool,
    iterations: u64,
    timeout: u64,
    resume: bool,
}

/// Kill existing zk-fuzzer instances with graceful shutdown
async fn kill_existing_instances() {
    let current_pid = std::process::id();
    
    let pgrep_output = std::process::Command::new("pgrep")
        .args(["-f", "zk-fuzzer"])
        .output();
    
    if let Ok(output) = pgrep_output {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        // Try graceful shutdown first (SIGTERM)
                        let _ = std::process::Command::new("kill")
                            .args(["-15", &pid.to_string()])
                            .output();
                    }
                }
            }
            
            // Wait for graceful shutdown
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // Force kill any remaining processes (SIGKILL)
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        let _ = std::process::Command::new("kill")
                            .args(["-9", &pid.to_string()])
                            .output();
                    }
                }
            }
            
            eprintln!("Terminated existing zk-fuzzer instances (excluding PID {})", current_pid);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Only kill existing instances if explicitly requested
    if cli.kill_existing {
        kill_existing_instances().await;
    }

    // Run the command and ensure cleanup
    let result = run_cli_command(cli).await;

    result
}

async fn run_cli_command(cli: Cli) -> anyhow::Result<()> {
    // Initialize logging
    let log_level = if cli.quiet {
        tracing::Level::WARN
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_ansi(false)
        .init();

    match cli.command {
        Some(Commands::Run { campaign, iterations, timeout, resume, corpus_dir }) => {
            run_campaign(
                &campaign,
                CampaignRunOptions {
                    workers: cli.workers,
                    seed: cli.seed,
                    verbose: cli.verbose,
                    dry_run: cli.dry_run,
                    simple_progress: cli.simple_progress,
                    real_only: cli.real_only,
                    iterations,
                    timeout,
                    require_invariants: false,
                    resume,
                    corpus_dir,
                    profile: cli.profile.clone(),
                },
            )
            .await
        }
        Some(Commands::Evidence { campaign, iterations, timeout, resume, corpus_dir }) => {
            run_campaign(
                &campaign,
                CampaignRunOptions {
                    workers: cli.workers,
                    seed: cli.seed,
                    verbose: cli.verbose,
                    dry_run: cli.dry_run,
                    simple_progress: cli.simple_progress,
                    real_only: true, // Evidence mode always requires real backend
                    iterations,
                    timeout,
                    require_invariants: true,
                    resume,
                    corpus_dir,
                    profile: cli.profile.clone(),
                },
            )
            .await
        }
        Some(Commands::Chains { campaign, iterations, timeout, resume }) => {
            run_chain_campaign(
                &campaign,
                ChainRunOptions {
                    workers: cli.workers,
                    seed: cli.seed,
                    verbose: cli.verbose,
                    dry_run: cli.dry_run,
                    simple_progress: cli.simple_progress,
                    iterations,
                    timeout,
                    resume,
                },
            )
            .await
        }
        Some(Commands::Validate { campaign }) => {
            validate_campaign(&campaign)
        }
        Some(Commands::Minimize { corpus_dir, output }) => {
            minimize_corpus(&corpus_dir, output.as_deref())
        }
        Some(Commands::Init { output, framework }) => {
            generate_sample_config(&output, &framework)
        }
        Some(Commands::ExecWorker) => {
            zk_fuzzer::executor::run_exec_worker()
        }
        None => {
            // Default behavior: run with config if provided
            if let Some(config_path) = cli.config {
                // Use default values for iterations and timeout
                run_campaign(
                    &config_path,
                    CampaignRunOptions {
                        workers: cli.workers,
                        seed: cli.seed,
                        verbose: cli.verbose,
                        dry_run: cli.dry_run,
                        simple_progress: cli.simple_progress,
                        real_only: cli.real_only,
                        iterations: 1000,
                        timeout: None,
                        require_invariants: false,
                        resume: false, // resume
                        corpus_dir: None,
                        profile: cli.profile.clone(),
                    },
                )
                .await
            } else {
                eprintln!("Error: No campaign configuration provided.");
                eprintln!("Usage: zk-fuzzer --config <path> or zk-fuzzer run <path>");
                eprintln!("Run 'zk-fuzzer --help' for more information.");
                std::process::exit(1);
            }
        }
    }
}

async fn run_campaign(config_path: &str, options: CampaignRunOptions) -> anyhow::Result<()> {
    tracing::info!("Loading campaign from: {}", config_path);
    let mut config = FuzzConfig::from_yaml(config_path)?;

    // Apply profile if specified
    if let Some(profile_name) = options.profile.as_deref() {
        let parsed_profile: ProfileName = profile_name.parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;
        apply_profile(&mut config, parsed_profile);
    }

    if options.real_only {
        tracing::info!("--real-only set (real backend mode is already enforced)");
    }
    config.campaign.parameters.additional.insert(
        "strict_backend".to_string(),
        serde_yaml::Value::Bool(true),
    );

    if options.require_invariants {
        let invariants = config.get_invariants();
        if invariants.is_empty() {
            anyhow::bail!(
                "Evidence mode requires v2 invariants in the YAML (invariants: ...)."
            );
        }
        config.campaign.parameters.additional.insert(
            "evidence_mode".to_string(),
            serde_yaml::Value::Bool(true),
        );
        config.campaign.parameters.additional.insert(
            "engagement_strict".to_string(),
            serde_yaml::Value::Bool(true),
        );
        config.campaign.parameters.additional.insert(
            "strict_backend".to_string(),
            serde_yaml::Value::Bool(true),
        );
    }
    
    // Inject CLI fuzzing parameters into config
    config.campaign.parameters.additional.insert(
        "fuzzing_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.iterations)),
    );
    if let Some(t) = options.timeout {
        config.campaign.parameters.additional.insert(
            "fuzzing_timeout_seconds".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(t)),
        );
    }

    // Pre-flight readiness check for strict evidence engagements.
    if options.require_invariants {
        println!();
        let readiness = zk_fuzzer::config::check_0day_readiness(&config);
        print!("{}", readiness.format());
        if !readiness.ready_for_evidence {
            anyhow::bail!("Campaign has critical issues; refusing to start strict evidence run");
        }
    }

    // Prevent multi-process collisions on the same output dir (reports/corpus/report.json, etc.).
    // Skip in --dry-run since no files are written.
    let _output_lock = if options.dry_run {
        None
    } else {
        let output_dir = config.reporting.output_dir.clone();
        Some(match zk_fuzzer::util::file_lock::lock_dir_exclusive(
            &output_dir,
            ".zkfuzz.lock",
            zk_fuzzer::util::file_lock::LockMode::NonBlocking,
        ) {
            Ok(lock) => lock,
            Err(err) => {
                anyhow::bail!(
                    "Output directory is already in use (locked): {}. \
                     Choose a different `reporting.output_dir` (or wait for the other run to finish). \
                     Error: {:#}",
                    output_dir.display(),
                    err
                );
            }
        })
    };

    // Print banner
    print_banner(&config);
    let run_start = Local::now();
    print_run_window(run_start, options.timeout);

    // Handle resume mode
    if options.resume {
        let corpus_path = if let Some(ref dir) = options.corpus_dir {
            std::path::PathBuf::from(dir)
        } else {
            config.reporting.output_dir.join("corpus")
        };
        
        if corpus_path.exists() {
            tracing::info!("Resume mode: loading corpus from {:?}", corpus_path);
            config.campaign.parameters.additional.insert(
                "resume_corpus_dir".to_string(),
                serde_yaml::Value::String(corpus_path.display().to_string()),
            );
            println!("📂 Resuming from corpus: {}", corpus_path.display());
        } else {
            tracing::warn!("Resume requested but corpus directory not found: {:?}", corpus_path);
            println!("⚠️  Corpus directory not found, starting fresh: {}", corpus_path.display());
        }
    }

    if options.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Configuration is valid");
        println!("  Campaign: {}", config.campaign.name);
        println!("  Target: {:?}", config.campaign.target.framework);
        println!("  Attacks: {}", config.attacks.len());
        println!("  Inputs: {}", config.inputs.len());
        if options.resume {
            println!("  Resume: enabled");
        }
        if let Some(ref p) = options.profile {
            println!("  Profile: {}", p);
        }
        return Ok(());
    }

    // Run with new engine if not using simple progress
    let report = if options.simple_progress {
        let mut fuzzer = ZkFuzzer::new(config, options.seed);
        fuzzer.run_with_workers(options.workers).await?
    } else {
        ZkFuzzer::run_with_progress(config, options.seed, options.workers, options.verbose).await?
    };

    // Output results
    report.print_summary();
    report.save_to_files()?;

    if report.has_critical_findings() {
        std::process::exit(1);
    }

    Ok(())
}

fn validate_campaign(config_path: &str) -> anyhow::Result<()> {
    tracing::info!("Validating campaign: {}", config_path);

    match FuzzConfig::from_yaml(config_path) {
        Ok(config) => {
            println!("✓ Configuration is valid");
            println!();
            println!("Campaign Details:");
            println!("  Name: {}", config.campaign.name);
            println!("  Version: {}", config.campaign.version);
            println!("  Framework: {:?}", config.campaign.target.framework);
            println!("  Circuit: {:?}", config.campaign.target.circuit_path);
            println!("  Main Component: {}", config.campaign.target.main_component);
            println!();
            println!("Attacks ({}):", config.attacks.len());
            for attack in &config.attacks {
                println!("  - {:?}: {}", attack.attack_type, attack.description);
            }
            println!();
            println!("Inputs ({}):", config.inputs.len());
            for input in &config.inputs {
                println!("  - {}: {} ({:?})", input.name, input.input_type, input.fuzz_strategy);
            }
            
            // Phase 4C: 0-day readiness check
            println!();
            let readiness = zk_fuzzer::config::check_0day_readiness(&config);
            print!("{}", readiness.format());
            
            if !readiness.ready_for_evidence {
                eprintln!("\n⚠️  Campaign has critical issues - not ready for evidence mode");
                std::process::exit(1);
            }
            
            Ok(())
        }
        Err(e) => {
            eprintln!("✗ Configuration is invalid");
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn minimize_corpus(corpus_dir: &str, output: Option<&str>) -> anyhow::Result<()> {
    use zk_fuzzer::corpus::{minimizer, storage};
    use std::path::Path;

    tracing::info!("Loading corpus from: {}", corpus_dir);

    let entries = storage::load_corpus_from_dir(Path::new(corpus_dir))?;
    tracing::info!("Loaded {} entries", entries.len());

    let minimized = minimizer::minimize_corpus(&entries);
    let stats = minimizer::MinimizationStats::compute(entries.len(), minimized.len());

    println!("Corpus minimization:");
    println!("  Original size: {}", stats.original_size);
    println!("  Minimized size: {}", stats.minimized_size);
    println!("  Reduction: {:.1}%", stats.reduction_percentage);

    if let Some(output_dir) = output {
        let output_path = Path::new(output_dir);
        std::fs::create_dir_all(output_path)?;

        for (i, entry) in minimized.iter().enumerate() {
            storage::save_test_case(entry, output_path, i)?;
        }

        println!("Saved minimized corpus to: {}", output_dir);
    }

    Ok(())
}

fn generate_sample_config(output: &str, framework: &str) -> anyhow::Result<()> {
    let (circuit_path, main_component) = match framework {
        "circom" => ("./circuits/example.circom", "Main"),
        "noir" => ("./circuits/example", "main"),
        "halo2" => ("./circuits/example.rs", "ExampleCircuit"),
        "cairo" => ("./circuits/example.cairo", "main"),
        _ => ("./circuits/example.circom", "Main"),
    };
    
    let sample = format!(r#"# ZK-Fuzzer Campaign Configuration
# Generated sample for {} framework

campaign:
  name: "Sample {} Audit"
  version: "1.0"
  target:
    framework: "{}"
    circuit_path: "{}"
    main_component: "{}"

  parameters:
    field: "bn254"
    max_constraints: 100000
    timeout_seconds: 300
    # NOTE: campaign.parameters is a flattened key/value map.
    # Do NOT nest under `additional:` (legacy templates used that shape).
    strict_backend: true
    mark_fallback: true

attacks:
  - type: underconstrained
    description: "Find inputs that satisfy constraints but produce wrong outputs"
    config:
      witness_pairs: 1000
      # Optional: fix public inputs for consistent checks
      # public_input_names: ["input1"]
      # fixed_public_inputs: ["0x01"]

  - type: soundness
    description: "Attempt to create valid proofs for false statements"
    config:
      forge_attempts: 1000
      mutation_rate: 0.1

  - type: arithmetic_overflow
    description: "Test field arithmetic edge cases"
    config:
      test_values:
        - "0"
        - "1"
        - "p-1"
        - "p"

  - type: collision
    description: "Detect hash collisions or output collisions"
    config:
      samples: 10000

inputs:
  - name: "input1"
    type: "field"
    fuzz_strategy: random
    constraints:
      - "nonzero"

  - name: "input2"
    type: "field"
    fuzz_strategy: interesting_values
    interesting:
      - "0x0"
      - "0x1"
      - "0xdead"

reporting:
  output_dir: "./reports"
  formats:
    - json
    - markdown
  include_poc: true
  crash_reproduction: true
"#, framework, framework, framework, circuit_path, main_component);

    std::fs::write(output, sample)?;
    println!("Generated sample configuration: {}", output);
    println!("Edit this file and run: zk-fuzzer run {}", output);

    Ok(())
}

fn print_banner(config: &FuzzConfig) {
    use colored::*;

    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║              ZK-FUZZER v0.1.0                             ║".bright_cyan());
    println!("{}", "║       Zero-Knowledge Proof Security Tester                ║".bright_cyan());
    println!("{}", "╠═══════════════════════════════════════════════════════════╣".bright_cyan());
    println!("{}  Campaign: {:<45} {}", "║".bright_cyan(), truncate_str(&config.campaign.name, 45).white(), "║".bright_cyan());
    println!("{}  Target:   {:<45} {}", "║".bright_cyan(), format!("{:?}", config.campaign.target.framework).yellow(), "║".bright_cyan());
    println!("{}  Attacks:  {:<45} {}", "║".bright_cyan(), format!("{} configured", config.attacks.len()).green(), "║".bright_cyan());
    println!("{}  Inputs:   {:<45} {}", "║".bright_cyan(), format!("{} defined", config.inputs.len()).green(), "║".bright_cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

fn print_run_window(start: DateTime<Local>, timeout_seconds: Option<u64>) {
    println!("RUN WINDOW");
    println!(
        "  Start: {}",
        start.format("%Y-%m-%d %H:%M:%S %Z")
    );

    match timeout_seconds.and_then(|s| i64::try_from(s).ok()) {
        Some(seconds) => {
            let expected_end = start + ChronoDuration::seconds(seconds);
            println!(
                "  Expected latest end: {} (timeout {}s)",
                expected_end.format("%Y-%m-%d %H:%M:%S %Z"),
                seconds
            );
            tracing::info!(
                "RUN_WINDOW start={} expected_latest_end={} timeout_seconds={}",
                start.to_rfc3339(),
                expected_end.to_rfc3339(),
                seconds
            );
        }
        None => {
            println!("  Expected latest end: unbounded (no --timeout)");
            tracing::info!(
                "RUN_WINDOW start={} expected_latest_end=unbounded",
                start.to_rfc3339()
            );
        }
    }
    println!();
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Run a chain-focused fuzzing campaign (Mode 3: Deepest)
async fn run_chain_campaign(config_path: &str, options: ChainRunOptions) -> anyhow::Result<()> {
    use colored::*;
    use zk_fuzzer::chain_fuzzer::{ChainCorpus, ChainFinding, DepthMetrics};
    use zk_fuzzer::config::parse_chains;
    use zk_fuzzer::fuzzer::FuzzingEngine;
    use zk_fuzzer::reporting::FuzzReport;

    tracing::info!("Loading chain campaign from: {}", config_path);
    let mut config = FuzzConfig::from_yaml(config_path)?;

    // Prevent multi-process collisions on the same output dir (chain_corpus.json, reports, etc.).
    // Skip in --dry-run since no files are written.
    let _output_lock = if options.dry_run {
        None
    } else {
        let output_dir = config.reporting.output_dir.clone();
        Some(match zk_fuzzer::util::file_lock::lock_dir_exclusive(
            &output_dir,
            ".zkfuzz.lock",
            zk_fuzzer::util::file_lock::LockMode::NonBlocking,
        ) {
            Ok(lock) => lock,
            Err(err) => {
                anyhow::bail!(
                    "Output directory is already in use (locked): {}. \
                     Choose a different `reporting.output_dir` (or wait for the other run to finish). \
                     Error: {:#}",
                    output_dir.display(),
                    err
                );
            }
        })
    };

    // Get chains from config
    let chains = parse_chains(&config);
    if chains.is_empty() {
        anyhow::bail!(
            "Chain mode requires chains: definitions in the YAML. \
             See campaigns/templates/deepest_multistep.yaml for examples."
        );
    }

    // Force evidence mode settings for chain fuzzing
    config.campaign.parameters.additional.insert(
        "evidence_mode".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "strict_backend".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "chain_budget_seconds".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.timeout)),
    );
    config.campaign.parameters.additional.insert(
        "chain_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.iterations)),
    );

    // Pre-flight readiness check (chains need assertions; strict mode blocks silent runs).
    println!();
    let readiness = zk_fuzzer::config::check_0day_readiness(&config);
    print!("{}", readiness.format());
    if !readiness.ready_for_evidence {
        anyhow::bail!("Campaign has critical issues; refusing to start strict chain run");
    }

    // Print chain-specific banner
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".bright_magenta());
    println!("{}", "║         ZK-FUZZER v0.1.0 — MODE 3: CHAIN FUZZING          ║".bright_magenta());
    println!("{}", "║               Multi-Step Deep Bug Discovery               ║".bright_magenta());
    println!("{}", "╠═══════════════════════════════════════════════════════════╣".bright_magenta());
    println!("{}  Campaign: {:<45} {}", "║".bright_magenta(), truncate_str(&config.campaign.name, 45).white(), "║".bright_magenta());
    println!("{}  Chains:   {:<45} {}", "║".bright_magenta(), format!("{} defined", chains.len()).cyan(), "║".bright_magenta());
    println!("{}  Budget:   {:<45} {}", "║".bright_magenta(), format!("{}s total", options.timeout).yellow(), "║".bright_magenta());
    println!("{}  Resume:   {:<45} {}", "║".bright_magenta(), if options.resume { "yes".green() } else { "no".white() }, "║".bright_magenta());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".bright_magenta());
    println!();
    let run_start = Local::now();
    print_run_window(run_start, Some(options.timeout));

    // List chains
    println!("{}", "CHAINS TO FUZZ:".bright_yellow().bold());
    for chain in &chains {
        println!(
            "  {} {} ({} steps, {} assertions)",
            "→".bright_cyan(),
            chain.name.white(),
            chain.steps.len(),
            chain.assertions.len()
        );
    }
    println!();

    if options.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Chain configuration is valid");
        return Ok(());
    }

    let output_dir = std::path::PathBuf::from(&config.reporting.output_dir);
    let corpus_path = output_dir.join("chain_corpus.json");
    let baseline_corpus = ChainCorpus::load(&corpus_path).unwrap_or_else(|_| ChainCorpus::with_storage(&corpus_path));
    let baseline_total_entries = baseline_corpus.len();
    let baseline_unique_coverage_bits: usize = {
        use std::collections::HashSet;
        baseline_corpus.entries().iter().map(|e| e.coverage_bits).collect::<HashSet<_>>().len()
    };

    // Create engine directly
    let mut engine = FuzzingEngine::new(config.clone(), options.seed, options.workers)?;
    
    // Run chain fuzzing
    let progress = if options.simple_progress {
        None
    } else {
        // Create a progress reporter for chain mode
        let total = (options.iterations as usize * chains.len()) as u64;
        Some(zk_fuzzer::progress::ProgressReporter::new(
            &format!("{} (chains)", config.campaign.name),
            total,
            options.verbose,
        ))
    };

    let chain_findings: Vec<ChainFinding> = engine.run_chains(&chains, progress.as_ref()).await;

    // Load chain corpus for quality/coverage metrics (persistent across runs).
    let final_corpus = ChainCorpus::load(&corpus_path).unwrap_or_else(|_| ChainCorpus::with_storage(&corpus_path));
    let final_total_entries = final_corpus.len();
    let final_unique_coverage_bits: usize = {
        use std::collections::HashSet;
        final_corpus.entries().iter().map(|e| e.coverage_bits).collect::<HashSet<_>>().len()
    };
    let final_max_depth = final_corpus
        .entries()
        .iter()
        .map(|e| e.depth_reached)
        .max()
        .unwrap_or(0);

    // Engagement contract for Mode 3: refuse to report a "clean" run when exploration is too narrow.
    let engagement_strict = config
        .campaign
        .parameters
        .additional
        .get_bool("engagement_strict")
        .unwrap_or(true);
    let min_unique_coverage_bits = config
        .campaign
        .parameters
        .additional
        .get_usize("engagement_min_chain_unique_coverage_bits")
        .unwrap_or(2);
    let min_completed_per_chain = config
        .campaign
        .parameters
        .additional
        .get_usize("engagement_min_chain_completed_per_chain")
        .unwrap_or(1);

    let mut quality_failures: Vec<String> = Vec::new();
    for chain in &chains {
        let entries: Vec<_> = final_corpus
            .entries()
            .iter()
            .filter(|e| e.spec_name == chain.name)
            .collect();
        let completed = entries.len();
        let unique_cov: usize = {
            use std::collections::HashSet;
            entries.iter().map(|e| e.coverage_bits).collect::<HashSet<_>>().len()
        };
        if completed < min_completed_per_chain {
            quality_failures.push(format!(
                "chain '{}' completed_traces={} < min_completed_per_chain={}",
                chain.name, completed, min_completed_per_chain
            ));
        }
        if unique_cov < min_unique_coverage_bits {
            quality_failures.push(format!(
                "chain '{}' unique_coverage_bits={} < min_unique_coverage_bits={}",
                chain.name, unique_cov, min_unique_coverage_bits
            ));
        }
    }
    let run_valid = quality_failures.is_empty();

    // Compute metrics
    let metrics = DepthMetrics::new(chain_findings.clone());
    let summary = metrics.summary();

    // Print results
    println!();
    println!("{}", "═".repeat(60).bright_magenta());
    println!("{}", "  CHAIN FUZZING RESULTS".bright_white().bold());
    println!("{}", "═".repeat(60).bright_magenta());

    println!("\n{}", "DEPTH METRICS".bright_yellow().bold());
    println!("  Total Chain Findings:  {}", summary.total_findings);
    println!("  Mean L_min (D):        {:.2}", summary.d_mean);
    println!("  P(L_min >= 2):         {:.1}%", summary.p_deep * 100.0);
    println!();
    println!("{}", "CORPUS / EXPLORATION METRICS".bright_yellow().bold());
    println!("  Corpus entries:            {} (Δ {})", final_total_entries, final_total_entries.saturating_sub(baseline_total_entries));
    println!("  Unique coverage bits:      {} (Δ {})", final_unique_coverage_bits, final_unique_coverage_bits.saturating_sub(baseline_unique_coverage_bits));
    println!("  Max depth reached:         {}", final_max_depth);

    if !summary.depth_distribution.is_empty() {
        println!("\n{}", "DEPTH DISTRIBUTION".bright_yellow().bold());
        let mut depths: Vec<_> = summary.depth_distribution.iter().collect();
        depths.sort_by_key(|(k, _)| *k);
        for (depth, count) in depths {
            let bar = "█".repeat((*count).min(30));
            println!("  L_min={}: {} ({})", depth, bar.bright_cyan(), count);
        }
    }

    if !chain_findings.is_empty() {
        println!("\n{}", "CHAIN FINDINGS".bright_yellow().bold());
        for (i, finding) in chain_findings.iter().enumerate() {
            let severity_str = match finding.finding.severity.to_uppercase().as_str() {
                "CRITICAL" => format!("[{}]", finding.finding.severity).bright_red().bold(),
                "HIGH" => format!("[{}]", finding.finding.severity).red(),
                "MEDIUM" => format!("[{}]", finding.finding.severity).yellow(),
                "LOW" => format!("[{}]", finding.finding.severity).bright_yellow(),
                _ => format!("[{}]", finding.finding.severity).white(),
            };

            println!(
                "\n  {}. {} Chain: {} (L_min: {})",
                i + 1,
                severity_str,
                finding.spec_name.cyan(),
                finding.l_min.to_string().bright_green()
            );
            println!("     {}", finding.finding.description);
            
            if let Some(ref assertion) = finding.violated_assertion {
                println!("     Violated: {}", assertion.bright_red());
            }

            // Print reproduction command
            println!("     {}", "Reproduction:".bright_yellow());
            println!("       cargo run --release -- chains {} --seed {}", 
                config_path, options.seed.unwrap_or(42));
        }
    } else {
        if run_valid {
            println!("\n{}", "  ✓ No chain vulnerabilities found!".bright_green().bold());
        } else {
            println!(
                "\n{}",
                "  ✗ Run invalid: exploration too narrow to treat as 'clean'".bright_red().bold()
            );
            for failure in &quality_failures {
                println!("     - {}", failure);
            }
        }
    }

    println!("\n{}", "═".repeat(60).bright_magenta());

    // Save reports
    std::fs::create_dir_all(&output_dir)?;

    // Save chain findings as JSON
    let chain_report_path = output_dir.join("chain_report.json");
    let chain_report = serde_json::json!({
        "campaign_name": config.campaign.name,
        "mode": "chain_fuzzing",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "engagement": {
            "strict": engagement_strict,
            "valid_run": run_valid,
            "failures": quality_failures,
            "thresholds": {
                "min_unique_coverage_bits": min_unique_coverage_bits,
                "min_completed_per_chain": min_completed_per_chain,
            },
        },
        "metrics": {
            "total_findings": summary.total_findings,
            "d_mean": summary.d_mean,
            "p_deep": summary.p_deep,
            "depth_distribution": summary.depth_distribution,
        },
        "corpus_metrics": {
            "corpus_entries": final_total_entries,
            "unique_coverage_bits": final_unique_coverage_bits,
            "max_depth": final_max_depth,
            "baseline": {
                "corpus_entries": baseline_total_entries,
                "unique_coverage_bits": baseline_unique_coverage_bits,
            }
        },
        "chain_findings": chain_findings,
    });
    std::fs::write(&chain_report_path, serde_json::to_string_pretty(&chain_report)?)?;
    tracing::info!("Saved chain report to {:?}", chain_report_path);

    // Save chain findings as markdown
    let chain_md_path = output_dir.join("chain_report.md");
    let mut md = String::new();
    md.push_str(&format!("# Chain Fuzzing Report: {}\n\n", config.campaign.name));
    md.push_str("**Mode:** Multi-Step Chain Fuzzing (Mode 3)\n");
    md.push_str(&format!("**Generated:** {}\n\n", chrono::Utc::now().to_rfc3339()));

    md.push_str("## Engagement Validation\n\n");
    md.push_str(&format!("**Strict:** {}\n", engagement_strict));
    md.push_str(&format!("**Valid Run:** {}\n", if run_valid { "yes" } else { "no" }));
    md.push_str(&format!(
        "**Thresholds:** min_unique_coverage_bits={}, min_completed_per_chain={}\n\n",
        min_unique_coverage_bits, min_completed_per_chain
    ));

    md.push_str("### Corpus / Exploration Metrics\n\n");
    md.push_str(&format!(
        "- Corpus entries: {} (delta {})\n",
        final_total_entries,
        final_total_entries.saturating_sub(baseline_total_entries)
    ));
    md.push_str(&format!(
        "- Unique coverage bits: {} (delta {})\n",
        final_unique_coverage_bits,
        final_unique_coverage_bits.saturating_sub(baseline_unique_coverage_bits)
    ));
    md.push_str(&format!("- Max depth: {}\n\n", final_max_depth));

    if !quality_failures.is_empty() {
        md.push_str("### Failures\n\n");
        for failure in &quality_failures {
            md.push_str(&format!("- {}\n", failure));
        }
        md.push('\n');
    }

    md.push_str("## Depth Metrics\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| Total Findings | {} |\n", summary.total_findings));
    md.push_str(&format!("| Mean L_min (D) | {:.2} |\n", summary.d_mean));
    md.push_str(&format!("| P(L_min >= 2) | {:.1}% |\n\n", summary.p_deep * 100.0));

    if !chain_findings.is_empty() {
        md.push_str("## Chain Findings\n\n");
        for (i, finding) in chain_findings.iter().enumerate() {
            md.push_str(&format!("### {}. [{}] Chain: {}\n\n", i + 1, finding.finding.severity.to_uppercase(), finding.spec_name));
            md.push_str(&format!("**L_min:** {}\n\n", finding.l_min));
            md.push_str(&format!("{}\n\n", finding.finding.description));
            
            if let Some(ref assertion) = finding.violated_assertion {
                md.push_str(&format!("**Violated Assertion:** `{}`\n\n", assertion));
            }

            // Add trace summary
            md.push_str("**Trace:**\n\n");
            for (step_idx, step) in finding.trace.steps.iter().enumerate() {
                let status = if step.success { "✓" } else { "✗" };
                md.push_str(&format!("- Step {}: {} `{}` - {}\n", 
                    step_idx, status, step.circuit_ref,
                    if step.success { "success" } else { step.error.as_deref().unwrap_or("failed") }
                ));
            }
            md.push('\n');

            // Add reproduction
            md.push_str("**Reproduction:**\n\n");
            md.push_str(&format!("```bash\ncargo run --release -- chains {} --seed {}\n```\n\n", 
                config_path, options.seed.unwrap_or(42)));
        }
    }

    std::fs::write(&chain_md_path, md)?;
    tracing::info!("Saved chain markdown report to {:?}", chain_md_path);

    // Convert chain findings to regular findings for standard report
    let standard_findings: Vec<_> = chain_findings.iter()
        .map(|cf| cf.to_finding())
        .collect();

    // Create standard report with chain findings merged in
    let mut report = FuzzReport::new(
        config.campaign.name.clone(),
        standard_findings,
        zk_core::CoverageMap::default(),
        config.reporting.clone(),
    );
    report.statistics.total_executions = options.iterations * chains.len() as u64;
    report.save_to_files()?;

    // Exit with error code if critical findings
    if chain_findings.iter().any(|f| f.finding.severity.to_lowercase() == "critical") {
        std::process::exit(1);
    }

    if engagement_strict && !run_valid {
        anyhow::bail!("Strict chain run failed engagement contract; see chain_report.json for details");
    }

    Ok(())
}
