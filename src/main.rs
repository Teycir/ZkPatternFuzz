use clap::Parser;
use tracing_subscriber;

mod attacks;
mod config;
mod fuzzer;
mod reporting;
mod targets;

use crate::config::FuzzConfig;
use crate::fuzzer::ZkFuzzer;

#[derive(Parser)]
#[command(name = "zk-fuzzer")]
#[command(about = "Zero-Knowledge Proof Security Testing Framework")]
struct Cli {
    /// Path to YAML campaign configuration
    #[arg(short, long)]
    config: String,

    /// Number of parallel workers
    #[arg(short, long, default_value = "4")]
    workers: usize,

    /// Seed for reproducibility
    #[arg(short, long)]
    seed: Option<u64>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Dry run - validate config without executing
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(if cli.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .init();

    // Load configuration
    tracing::info!("Loading campaign from: {}", cli.config);
    let config = FuzzConfig::from_yaml(&cli.config)?;

    // Print banner
    print_banner(&config);

    if cli.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Configuration is valid");
        println!("  Campaign: {}", config.campaign.name);
        println!("  Target: {:?}", config.campaign.target.framework);
        println!("  Attacks: {}", config.attacks.len());
        println!("  Inputs: {}", config.inputs.len());
        return Ok(());
    }

    // Create and run fuzzer
    let mut fuzzer = ZkFuzzer::new(config, cli.seed);
    let report = fuzzer.run().await?;

    // Output results
    report.print_summary();
    report.save_to_files()?;

    if report.has_critical_findings() {
        std::process::exit(1);
    }

    Ok(())
}

fn print_banner(config: &FuzzConfig) {
    println!(
        r#"
    ╔═══════════════════════════════════════════════════════════╗
    ║              ZK-FUZZER v0.1.0                             ║
    ║       Zero-Knowledge Proof Security Tester                ║
    ╠═══════════════════════════════════════════════════════════╣
    ║ Campaign: {:<45} ║
    ║ Target:   {:<45} ║
    ║ Attacks:  {:<45} ║
    ╚═══════════════════════════════════════════════════════════╝
    "#,
        truncate_str(&config.campaign.name, 45),
        format!("{:?}", config.campaign.target.framework),
        config.attacks.len()
    );
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
