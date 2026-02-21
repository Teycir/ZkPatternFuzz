use anyhow::Context;
use clap::Parser;
use rayon::prelude::*;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "zk0d_matrix")]
#[command(about = "Run zk0d target matrix via zk0d_batch with guarded parallelism")]
struct Args {
    /// Path to target matrix YAML
    #[arg(long, default_value = "targets/zk0d_matrix.yaml")]
    matrix: String,

    /// Path to fuzzer registry YAML passed to zk0d_batch
    #[arg(long, default_value = "targets/fuzzer_registry.yaml")]
    registry: String,

    /// Alias to run for each target (default when selector omitted)
    #[arg(long)]
    alias: Option<String>,

    /// Collection to run for each target
    #[arg(long)]
    collection: Option<String>,

    /// Template list to run for each target
    #[arg(long)]
    template: Option<String>,

    /// Parallel target jobs (matrix-level parallelism)
    #[arg(long, default_value_t = 2)]
    jobs: usize,

    /// Template-parallelism passed to each zk0d_batch process
    #[arg(long, default_value_t = 1)]
    batch_jobs: usize,

    /// Worker count per scan process
    #[arg(long, default_value_t = 2)]
    workers: usize,

    /// RNG seed per target run
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Iterations per target run
    #[arg(long, default_value_t = 50_000)]
    iterations: u64,

    /// Timeout seconds per target run
    #[arg(long, default_value_t = 1_800)]
    timeout: u64,

    /// Build release zk0d_batch binary if missing
    #[arg(long, default_value_t = true)]
    build: bool,

    /// Skip YAML validation in zk0d_batch
    #[arg(long, default_value_t = false)]
    skip_validate: bool,

    /// Dry-run: print commands only
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Optional TSV output path for matrix summary
    #[arg(long)]
    summary_tsv: Option<String>,

    /// Allow oversubscribed jobs*batch_jobs*workers beyond CPU-based guardrail
    #[arg(long, default_value_t = false)]
    allow_oversubscription: bool,
}

#[derive(Debug, Deserialize)]
struct MatrixFile {
    targets: Vec<MatrixTarget>,
}

#[derive(Debug, Deserialize, Clone)]
struct MatrixTarget {
    name: String,
    target_circuit: String,
    #[serde(default = "default_main_component")]
    main_component: String,
    #[serde(default = "default_framework")]
    framework: String,
    #[serde(default)]
    alias: Option<String>,
    #[serde(default)]
    collection: Option<String>,
    #[serde(default)]
    template: Option<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Debug, Clone)]
struct ReasonRow {
    reason_code: String,
}

#[derive(Debug, Clone)]
struct TargetRunSummary {
    name: String,
    exit_code: i32,
    reason_counts: BTreeMap<String, usize>,
}

fn default_main_component() -> String {
    "main".to_string()
}

fn default_framework() -> String {
    "circom".to_string()
}

fn default_enabled() -> bool {
    true
}

fn parse_reason_tsv_rows(stdout: &str) -> Vec<ReasonRow> {
    let mut in_block = false;
    let mut rows = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed == "REASON_TSV_START" {
            in_block = true;
            continue;
        }
        if trimmed == "REASON_TSV_END" {
            break;
        }
        if !in_block || trimmed.is_empty() || trimmed.starts_with("template\t") {
            continue;
        }
        let mut cols = trimmed.split('\t');
        let _template = cols.next();
        let _suffix = cols.next();
        let reason_code = cols.next().unwrap_or("unknown").trim();
        rows.push(ReasonRow {
            reason_code: reason_code.to_string(),
        });
    }
    rows
}

fn selector_for_target(
    args: &Args,
    target: &MatrixTarget,
) -> anyhow::Result<(&'static str, String)> {
    let alias = target.alias.clone().or_else(|| args.alias.clone());
    let collection = target
        .collection
        .clone()
        .or_else(|| args.collection.clone());
    let template = target.template.clone().or_else(|| args.template.clone());

    let mut selected: Vec<(&'static str, String)> = Vec::new();
    if let Some(value) = alias {
        selected.push(("alias", value));
    }
    if let Some(value) = collection {
        selected.push(("collection", value));
    }
    if let Some(value) = template {
        selected.push(("template", value));
    }

    if selected.is_empty() {
        return Ok(("alias", "always".to_string()));
    }
    if selected.len() > 1 {
        anyhow::bail!(
            "Target '{}' has conflicting selector config (alias/collection/template); choose exactly one",
            target.name
        );
    }
    Ok(selected.remove(0))
}

fn run_target(
    args: &Args,
    batch_bin: &Path,
    target: &MatrixTarget,
) -> anyhow::Result<TargetRunSummary> {
    let (selector_key, selector_value) = selector_for_target(args, target)?;

    let mut cmd = Command::new(batch_bin);
    cmd.arg("--registry")
        .arg(&args.registry)
        .arg(format!("--{}", selector_key))
        .arg(selector_value)
        .arg("--target-circuit")
        .arg(&target.target_circuit)
        .arg("--main-component")
        .arg(&target.main_component)
        .arg("--framework")
        .arg(&target.framework)
        .arg("--jobs")
        .arg(args.batch_jobs.to_string())
        .arg("--workers")
        .arg(args.workers.to_string())
        .arg("--seed")
        .arg(args.seed.to_string())
        .arg("--iterations")
        .arg(args.iterations.to_string())
        .arg("--timeout")
        .arg(args.timeout.to_string())
        .arg("--emit-reason-tsv");

    if args.skip_validate {
        cmd.arg("--skip-validate");
    }
    if args.dry_run {
        cmd.arg("--dry-run");
    }
    if args.build {
        cmd.arg("--build");
    }

    let output = cmd
        .output()
        .with_context(|| format!("Failed to run zk0d_batch for target '{}'", target.name))?;
    let exit_code = output.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        eprintln!("[{}] stderr:\n{}", target.name, stderr);
    }

    let reason_rows = parse_reason_tsv_rows(&stdout);
    let mut reason_counts = BTreeMap::new();
    for row in reason_rows {
        *reason_counts.entry(row.reason_code).or_insert(0) += 1;
    }
    if reason_counts.is_empty() {
        reason_counts.insert("none".to_string(), 1);
    }

    Ok(TargetRunSummary {
        name: target.name.clone(),
        exit_code,
        reason_counts,
    })
}

fn write_summary_tsv(path: &Path, summaries: &[TargetRunSummary]) -> anyhow::Result<()> {
    let mut out = String::new();
    out.push_str("target\texit_code\treason_code\treason_count\n");
    for summary in summaries {
        for (reason, count) in &summary.reason_counts {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                summary.name, summary.exit_code, reason, count
            ));
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create summary directory '{}'", parent.display())
        })?;
    }
    fs::write(path, out)
        .with_context(|| format!("Failed to write summary TSV '{}'", path.display()))?;
    Ok(())
}

fn build_batch_binary(args: &Args, batch_bin: &Path) -> anyhow::Result<()> {
    if !args.build {
        if batch_bin.exists() {
            return Ok(());
        }
        anyhow::bail!(
            "zk0d_batch binary not found at '{}' and --build=false",
            batch_bin.display()
        );
    }
    let status = Command::new("cargo")
        .args(["build", "--release", "--bin", "zk0d_batch"])
        .status()
        .context("Failed to build zk0d_batch binary")?;
    if !status.success() {
        anyhow::bail!("cargo build --release --bin zk0d_batch failed");
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let max_recommended = num_cpus::get().max(1) * 2;
    let requested_capacity = args.jobs.max(1) * args.batch_jobs.max(1) * args.workers.max(1);
    if requested_capacity > max_recommended && !args.allow_oversubscription {
        anyhow::bail!(
            "Requested jobs*batch_jobs*workers={} exceeds recommended limit {}. \
             Reduce parallelism or pass --allow-oversubscription.",
            requested_capacity,
            max_recommended
        );
    }

    let matrix_raw = fs::read_to_string(&args.matrix)
        .with_context(|| format!("Failed to read '{}'", args.matrix))?;
    let matrix: MatrixFile = serde_yaml::from_str(&matrix_raw)
        .with_context(|| format!("Failed to parse matrix YAML '{}'", args.matrix))?;
    let enabled_targets: Vec<MatrixTarget> =
        matrix.targets.into_iter().filter(|t| t.enabled).collect();
    if enabled_targets.is_empty() {
        anyhow::bail!("No enabled targets in matrix '{}'", args.matrix);
    }

    let batch_bin = PathBuf::from("target/release/zk0d_batch");
    build_batch_binary(&args, &batch_bin)?;

    println!(
        "Running {} targets (jobs={}, batch_jobs={}, workers={})",
        enabled_targets.len(),
        args.jobs.max(1),
        args.batch_jobs.max(1),
        args.workers.max(1)
    );

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.jobs.max(1))
        .build()
        .context("Failed to create matrix thread pool")?;

    let mut summaries = pool.install(|| {
        enabled_targets
            .par_iter()
            .map(|target| run_target(&args, &batch_bin, target))
            .collect::<Vec<_>>()
    });

    let mut flattened = Vec::new();
    let mut failures = 0usize;
    for summary in summaries.drain(..) {
        match summary {
            Ok(result) => {
                let reason_summary = result
                    .reason_counts
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{}\texit={}\treasons:{}",
                    result.name, result.exit_code, reason_summary
                );
                if result.exit_code != 0 {
                    failures += 1;
                }
                flattened.push(result);
            }
            Err(err) => {
                failures += 1;
                eprintln!("target run failed: {:#}", err);
            }
        }
    }

    if let Some(path) = args.summary_tsv.as_deref() {
        write_summary_tsv(Path::new(path), &flattened)?;
    }

    if failures > 0 {
        anyhow::bail!("Matrix run finished with {} failed target runs", failures);
    }
    Ok(())
}
