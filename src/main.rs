use clap::{Parser, Subcommand};

mod analysis;
mod attacks;
mod config;
mod corpus;
mod differential;
mod errors;
mod executor;
mod fuzzer;
mod multi_circuit;
mod progress;
mod reporting;
mod targets;

use crate::config::FuzzConfig;
use crate::fuzzer::ZkFuzzer;

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

    /// Use simple progress (no interactive bars)
    #[arg(long, global = true)]
    simple_progress: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a fuzzing campaign
    Run {
        /// Path to campaign YAML file
        campaign: String,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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
        .init();

    match cli.command {
        Some(Commands::Run { campaign }) => {
            run_campaign(&campaign, cli.workers, cli.seed, cli.verbose, cli.dry_run, cli.simple_progress).await
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
        None => {
            // Default behavior: run with config if provided
            if let Some(config_path) = cli.config {
                run_campaign(&config_path, cli.workers, cli.seed, cli.verbose, cli.dry_run, cli.simple_progress).await
            } else {
                eprintln!("Error: No campaign configuration provided.");
                eprintln!("Usage: zk-fuzzer --config <path> or zk-fuzzer run <path>");
                eprintln!("Run 'zk-fuzzer --help' for more information.");
                std::process::exit(1);
            }
        }
    }
}

async fn run_campaign(
    config_path: &str,
    workers: usize,
    seed: Option<u64>,
    verbose: bool,
    dry_run: bool,
    simple_progress: bool,
) -> anyhow::Result<()> {
    tracing::info!("Loading campaign from: {}", config_path);
    let config = FuzzConfig::from_yaml(config_path)?;

    // Print banner
    print_banner(&config);

    if dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Configuration is valid");
        println!("  Campaign: {}", config.campaign.name);
        println!("  Target: {:?}", config.campaign.target.framework);
        println!("  Attacks: {}", config.attacks.len());
        println!("  Inputs: {}", config.inputs.len());
        return Ok(());
    }

    // Run with new engine if not using simple progress
    let report = if simple_progress {
        let mut fuzzer = ZkFuzzer::new(config, seed);
        fuzzer.run().await?
    } else {
        ZkFuzzer::run_with_progress(config, seed, workers, verbose).await?
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
    use crate::corpus::{minimizer, storage};
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
    let sample = format!(r#"# ZK-Fuzzer Campaign Configuration
# Generated sample for {} framework

campaign:
  name: "Sample {} Audit"
  version: "1.0"
  target:
    framework: "{}"
    circuit_path: "./circuits/example.circom"
    main_component: "Main"

  parameters:
    field: "bn254"
    max_constraints: 100000
    timeout_seconds: 300

attacks:
  - type: underconstrained
    description: "Find inputs that satisfy constraints but produce wrong outputs"
    config:
      witness_pairs: 1000
      compare_outputs: true

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
"#, framework, framework, framework);

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

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
