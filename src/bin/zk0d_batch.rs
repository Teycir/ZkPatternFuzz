use clap::Parser;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use zk_fuzzer::config::FuzzConfig;

#[derive(Parser, Debug)]
#[command(name = "zk0d_batch")]
#[command(about = "Batch runner for zk0d campaigns")]
struct Args {
    /// Path to targets YAML
    #[arg(long, default_value = "targets/zk0d_targets.yaml")]
    targets: String,

    /// Build release binary if missing
    #[arg(long, default_value_t = true)]
    build: bool,

    /// Skip YAML validation
    #[arg(long, default_value_t = false)]
    skip_validate: bool,

    /// Dry run (print commands only)
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct TargetsFile {
    #[allow(dead_code)]
    version: u32,
    #[serde(default)]
    defaults: Defaults,
    targets: Vec<Target>,
}

#[derive(Debug, Deserialize, Default)]
struct Defaults {
    workers: Option<usize>,
    seed: Option<u64>,
    iterations: Option<u64>,
    timeout: Option<u64>,
    mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Target {
    name: String,
    campaign: String,
    #[serde(default = "default_true")]
    enabled: bool,
    output_dir: Option<String>,
    workers: Option<usize>,
    seed: Option<u64>,
    iterations: Option<u64>,
    timeout: Option<u64>,
    mode: Option<String>,
}

fn default_true() -> bool {
    true
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let data = std::fs::read_to_string(&args.targets)?;
    let targets_file: TargetsFile = serde_yaml::from_str(&data)?;

    if targets_file.targets.is_empty() {
        anyhow::bail!("No targets found in {}", args.targets);
    }

    let bin_path = PathBuf::from("target/release/zk-fuzzer");
    if args.build && !bin_path.exists() {
        let status = Command::new("cargo")
            .args(["build", "--release", "--bin", "zk-fuzzer"])
            .status()?;
        if !status.success() {
            anyhow::bail!("cargo build --release --bin zk-fuzzer failed");
        }
    }

    let mut failures = 0usize;
    let mut executed = 0usize;

    for target in targets_file.targets.iter().filter(|t| t.enabled) {
        executed += 1;
        let mode = target
            .mode
            .clone()
            .or_else(|| targets_file.defaults.mode.clone())
            .unwrap_or_else(|| "evidence".to_string());

        let workers = target.workers.or(targets_file.defaults.workers).unwrap_or(8);
        let seed = target.seed.or(targets_file.defaults.seed).unwrap_or(42);
        let iterations = target
            .iterations
            .or(targets_file.defaults.iterations)
            .unwrap_or(50000);
        let timeout = target
            .timeout
            .or(targets_file.defaults.timeout)
            .unwrap_or(1800);

        let output_dir = target.output_dir.clone().unwrap_or_else(|| {
            format!("reports/zk0d/{}", target.name)
        });

        if !args.skip_validate {
            validate_campaign(&target.campaign, &output_dir)?;
        }

        let campaign_path = write_campaign_override(&target.campaign, &output_dir)?;

        let cmd = format!(
            "./target/release/zk-fuzzer {} {} --workers {} --seed {} --iterations {} --timeout {} --simple-progress",
            mode,
            campaign_path.display(),
            workers,
            seed,
            iterations,
            timeout
        );

        if args.dry_run {
            println!("[DRY RUN] {}", cmd);
            continue;
        }

        let status = Command::new(&bin_path)
            .arg(mode)
            .arg(campaign_path)
            .args([
                "--workers",
                &workers.to_string(),
                "--seed",
                &seed.to_string(),
                "--iterations",
                &iterations.to_string(),
                "--timeout",
                &timeout.to_string(),
                "--simple-progress",
            ])
            .status()?;

        if !status.success() {
            failures += 1;
            eprintln!("Target '{}' failed", target.name);
        }
    }

    println!(
        "Batch complete. Targets executed: {}, failures: {}",
        executed, failures
    );

    if failures > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn validate_campaign(campaign: &str, output_dir: &str) -> anyhow::Result<()> {
    let config = FuzzConfig::from_yaml(campaign)?;
    let invariants = config.get_invariants();
    if invariants.is_empty() {
        anyhow::bail!(
            "Campaign '{}' missing invariants (required for evidence mode)",
            campaign
        );
    }

    // Ensure output_dir is not empty
    if output_dir.trim().is_empty() {
        anyhow::bail!("Output dir is empty for campaign {}", campaign);
    }

    Ok(())
}

fn write_campaign_override(campaign: &str, output_dir: &str) -> anyhow::Result<PathBuf> {
    let raw = std::fs::read_to_string(campaign)?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw)?;

    let output_dir = PathBuf::from(output_dir);
    std::fs::create_dir_all(&output_dir)?;

    if let Some(map) = doc.as_mapping_mut() {
        let reporting_key = serde_yaml::Value::String("reporting".to_string());
        let output_key = serde_yaml::Value::String("output_dir".to_string());

        if let Some(reporting) = map.get_mut(&reporting_key) {
            if let Some(reporting_map) = reporting.as_mapping_mut() {
                reporting_map.insert(output_key, serde_yaml::Value::String(output_dir.to_string_lossy().to_string()));
            }
        } else {
            let mut reporting_map = serde_yaml::Mapping::new();
            reporting_map.insert(
                output_key,
                serde_yaml::Value::String(output_dir.to_string_lossy().to_string()),
            );
            map.insert(reporting_key, serde_yaml::Value::Mapping(reporting_map));
        }
    } else {
        anyhow::bail!("Campaign YAML is not a mapping");
    }

    let path = Path::new(&output_dir).join("campaign.yaml");
    let yaml = serde_yaml::to_string(&doc)?;
    std::fs::write(&path, yaml)?;
    Ok(path)
}
