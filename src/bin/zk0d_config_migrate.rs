use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_yaml::Value;
use std::path::{Path, PathBuf};
use zk_fuzzer::config::{migrate_config_value, MigrationReport};

#[derive(Debug, Parser)]
#[command(
    name = "zk0d_config_migrate",
    about = "Migrate legacy ZkPatternFuzz YAML config shapes and emit compatibility report"
)]
struct Args {
    /// Input YAML configuration path.
    input: PathBuf,

    /// Output YAML path. Defaults to <input>.migrated.yaml when not using --in-place.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Rewrite the input file directly.
    #[arg(long, default_value_t = false)]
    in_place: bool,

    /// Optional JSON output path for the migration report.
    #[arg(long)]
    report: Option<PathBuf>,

    /// Check-only mode. Returns non-zero if migration changes are required.
    #[arg(long, default_value_t = false)]
    check: bool,
}

fn default_output_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("config");
    let file_name = format!("{}.migrated.yaml", stem);
    match input.parent() {
        Some(parent) => parent.join(file_name),
        None => PathBuf::from(file_name),
    }
}

fn print_report(report: &MigrationReport) {
    println!("Changed: {}", report.changed);
    println!("Rewritten keys: {}", report.rewritten_keys.len());
    for change in &report.rewritten_keys {
        println!("- rewrite {} -> {}", change.path, change.detail);
    }
    println!(
        "Deprecated constructs: {}",
        report.deprecated_constructs.len()
    );
    for change in &report.deprecated_constructs {
        println!("- deprecated {} -> {}", change.path, change.detail);
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.in_place && args.out.is_some() {
        bail!("--in-place cannot be combined with --out");
    }

    let raw = std::fs::read_to_string(&args.input)
        .with_context(|| format!("Failed reading '{}'", args.input.display()))?;
    let parsed: Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed parsing YAML '{}'", args.input.display()))?;

    let (migrated, report) = migrate_config_value(parsed);
    print_report(&report);

    if let Some(report_path) = &args.report {
        let data = serde_json::to_vec_pretty(&report)
            .context("Failed serializing migration report as JSON")?;
        std::fs::write(report_path, data)
            .with_context(|| format!("Failed writing report '{}'", report_path.display()))?;
        println!("Report written: {}", report_path.display());
    }

    if args.check {
        if report.changed {
            bail!("Migration required: config still uses legacy constructs");
        }
        println!("No migration changes required.");
        return Ok(());
    }

    let output_path = if args.in_place {
        args.input.clone()
    } else {
        args.out
            .clone()
            .unwrap_or_else(|| default_output_path(&args.input))
    };

    let yaml = serde_yaml::to_string(&migrated).context("Failed serializing migrated YAML")?;
    std::fs::write(&output_path, yaml)
        .with_context(|| format!("Failed writing migrated YAML '{}'", output_path.display()))?;
    println!("Migrated YAML written: {}", output_path.display());

    Ok(())
}
