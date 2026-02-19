use anyhow::Context;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_BENCHMARK_SUITES_PATH: &str = "targets/benchmark_suites.yaml";
const DEFAULT_BENCHMARK_REGISTRY_PATH: &str = "targets/benchmark_registry.yaml";
const DEV_BENCHMARK_SUITES_PATH: &str = "targets/benchmark_suites.dev.yaml";
const DEV_BENCHMARK_REGISTRY_PATH: &str = "targets/benchmark_registry.dev.yaml";
const PROD_BENCHMARK_SUITES_PATH: &str = "targets/benchmark_suites.prod.yaml";
const PROD_BENCHMARK_REGISTRY_PATH: &str = "targets/benchmark_registry.prod.yaml";

#[derive(Parser, Debug)]
#[command(name = "zk0d_benchmark")]
#[command(about = "Repeated-trial benchmark runner for vulnerable/safe target suites")]
struct Args {
    /// Path to benchmark suites YAML
    #[arg(long)]
    suites: Option<String>,

    /// Path to fuzzer registry YAML passed to zk0d_batch
    #[arg(long)]
    registry: Option<String>,

    /// Config profile for default benchmark suites/registry selection
    #[arg(long, value_enum)]
    config_profile: Option<ConfigProfile>,

    /// Optional comma-separated suite names to run
    #[arg(long)]
    suite: Option<String>,

    /// Number of repeated trials per target
    #[arg(long, default_value_t = 3)]
    trials: usize,

    /// Base seed for deterministic repeated trials
    #[arg(long, default_value_t = 42)]
    base_seed: u64,

    /// Parallel target-trial jobs
    #[arg(long, default_value_t = 2)]
    jobs: usize,

    /// Template parallelism inside each zk0d_batch process
    #[arg(long, default_value_t = 1)]
    batch_jobs: usize,

    /// Worker count per scan
    #[arg(long, default_value_t = 2)]
    workers: usize,

    /// Iterations per scan run
    #[arg(long, default_value_t = 50_000)]
    iterations: u64,

    /// Timeout per scan run (seconds)
    #[arg(long, default_value_t = 1_800)]
    timeout: u64,

    /// Build release zk0d_batch binary
    #[arg(long, default_value_t = true)]
    build: bool,

    /// Skip validation pass in zk0d_batch
    #[arg(long, default_value_t = false)]
    skip_validate: bool,

    /// Dry-run (print commands but do not execute)
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Base output directory for benchmark artifacts
    #[arg(long, default_value = "artifacts/benchmark_runs")]
    output_dir: String,

    /// Allow oversubscribed jobs*batch_jobs*workers beyond CPU guardrail
    #[arg(long, default_value_t = false)]
    allow_oversubscription: bool,

    /// Optional benchmark override for evidence confidence threshold (e.g. low/medium/high)
    #[arg(long)]
    benchmark_min_evidence_confidence: Option<String>,

    /// Optional benchmark override for oracle validation minimum agreement ratio
    #[arg(long)]
    benchmark_oracle_min_agreement_ratio: Option<f64>,

    /// Optional benchmark override for oracle validation cross-attack weight
    #[arg(long)]
    benchmark_oracle_cross_attack_weight: Option<f64>,

    /// Optional benchmark override for strict high-confidence minimum oracle count
    #[arg(long)]
    benchmark_high_confidence_min_oracles: Option<usize>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConfigProfile {
    Dev,
    Prod,
}

#[derive(Debug, Deserialize)]
struct BenchmarkSuitesFile {
    suites: BTreeMap<String, BenchmarkSuite>,
}

#[derive(Debug, Deserialize)]
struct BenchmarkSuite {
    positive: bool,
    #[serde(default)]
    description: Option<String>,
    targets: Vec<BenchmarkTarget>,
}

#[derive(Debug, Deserialize, Clone)]
struct BenchmarkTarget {
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
struct WorkItem {
    suite_name: String,
    suite_description: Option<String>,
    positive: bool,
    target: BenchmarkTarget,
    trial_idx: usize,
    seed: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ConfidenceInterval {
    lower: f64,
    upper: f64,
}

#[derive(Debug, Clone, Serialize)]
struct TrialOutcome {
    suite_name: String,
    suite_description: Option<String>,
    positive: bool,
    target_name: String,
    trial_idx: usize,
    seed: u64,
    exit_code: i32,
    completed: bool,
    scan_findings_total: u64,
    detected: bool,
    high_confidence_detected: bool,
    attack_stage_reached: bool,
    reason_counts: BTreeMap<String, usize>,
    error_message: Option<String>,
}

#[derive(Debug, Serialize)]
struct SuiteSummary {
    suite_name: String,
    description: Option<String>,
    positive: bool,
    runs_total: usize,
    detections: usize,
    detection_rate: f64,
    detection_rate_ci95: ConfidenceInterval,
    high_confidence_detections: usize,
    high_confidence_detection_rate: f64,
    high_confidence_detection_rate_ci95: ConfidenceInterval,
    completion_rate: f64,
    completion_rate_ci95: ConfidenceInterval,
    attack_stage_reach_rate: f64,
    attack_stage_reach_rate_ci95: ConfidenceInterval,
    mean_scan_findings: f64,
    reason_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct BenchmarkSummary {
    generated_utc: String,
    config: BenchmarkConfigSnapshot,
    suites: Vec<SuiteSummary>,
    total_runs: usize,
    total_detected: usize,
    overall_completion_rate: f64,
    overall_attack_stage_reach_rate: f64,
    vulnerable_recall: f64,
    vulnerable_recall_ci95: ConfidenceInterval,
    vulnerable_high_confidence_recall: f64,
    vulnerable_high_confidence_recall_ci95: ConfidenceInterval,
    precision: f64,
    precision_ci95: ConfidenceInterval,
    safe_false_positive_rate: f64,
    safe_false_positive_rate_ci95: ConfidenceInterval,
    safe_high_confidence_false_positive_rate: f64,
    safe_high_confidence_false_positive_rate_ci95: ConfidenceInterval,
}

#[derive(Debug, Clone)]
struct ReasonRow {
    reason_code: String,
    high_confidence_detected: bool,
}

#[derive(Debug, Serialize)]
struct BenchmarkConfigSnapshot {
    suites_path: String,
    selected_suites: Vec<String>,
    trials: usize,
    base_seed: u64,
    jobs: usize,
    batch_jobs: usize,
    workers: usize,
    iterations: u64,
    timeout: u64,
    dry_run: bool,
    benchmark_min_evidence_confidence: Option<String>,
    benchmark_oracle_min_agreement_ratio: Option<f64>,
    benchmark_oracle_cross_attack_weight: Option<f64>,
    benchmark_high_confidence_min_oracles: Option<usize>,
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

fn split_csv(input: Option<&str>) -> Vec<String> {
    let Some(input) = input else {
        return Vec::new();
    };
    input
        .split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect()
}

fn default_paths_for_profile(profile: Option<ConfigProfile>) -> (&'static str, &'static str) {
    match profile {
        Some(ConfigProfile::Dev) => (DEV_BENCHMARK_SUITES_PATH, DEV_BENCHMARK_REGISTRY_PATH),
        Some(ConfigProfile::Prod) => (PROD_BENCHMARK_SUITES_PATH, PROD_BENCHMARK_REGISTRY_PATH),
        None => (
            DEFAULT_BENCHMARK_SUITES_PATH,
            DEFAULT_BENCHMARK_REGISTRY_PATH,
        ),
    }
}

fn expand_env_placeholders(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut out = String::new();

    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        if i + 1 < chars.len() && chars[i + 1] == '{' {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != '}' {
                j += 1;
            }
            if j >= chars.len() {
                out.push(chars[i]);
                i += 1;
                continue;
            }

            let inner: String = chars[i + 2..j].iter().collect();
            let placeholder = format!("${{{}}}", inner);
            if let Some((var, _default_ignored)) = inner.split_once(":-") {
                match env::var(var) {
                    Ok(value) => out.push_str(&value),
                    Err(env::VarError::NotPresent) => out.push_str(&placeholder),
                    Err(_) => out.push_str(&placeholder),
                }
            } else {
                match env::var(&inner) {
                    Ok(value) => out.push_str(&value),
                    Err(env::VarError::NotPresent) => out.push_str(&placeholder),
                    Err(_) => out.push_str(&placeholder),
                }
            }
            i = j + 1;
            continue;
        }

        let mut j = i + 1;
        if j < chars.len() && (chars[j].is_ascii_alphabetic() || chars[j] == '_') {
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            let var: String = chars[i + 1..j].iter().collect();
            let placeholder = format!("${}", var);
            match env::var(&var) {
                Ok(value) => out.push_str(&value),
                Err(env::VarError::NotPresent) => out.push_str(&placeholder),
                Err(_) => out.push_str(&placeholder),
            }
            i = j;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

fn has_unresolved_env_placeholder(input: &str) -> bool {
    input.contains("${") || input.contains('$')
}

fn parse_reason_tsv(stdout: &str) -> Vec<ReasonRow> {
    let mut in_block = false;
    let mut out = Vec::new();
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
        let reason = cols.next().unwrap_or("unknown").trim();
        let _status = cols.next();
        let _stage = cols.next();
        let high_confidence_detected = cols
            .next()
            .map(|raw| {
                let normalized = raw.trim().to_ascii_lowercase();
                normalized == "1" || normalized == "true" || normalized == "yes"
            })
            .unwrap_or(false);
        out.push(ReasonRow {
            reason_code: reason.to_string(),
            high_confidence_detected,
        });
    }
    out
}

fn parse_scan_findings_total(stdout: &str) -> u64 {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("scan findings: "))
        .filter_map(|raw| raw.trim().parse::<u64>().ok())
        .sum()
}

fn reached_attack_stage(reason_counts: &BTreeMap<String, usize>) -> bool {
    reached_completion(reason_counts)
}

fn reached_completion(reason_counts: &BTreeMap<String, usize>) -> bool {
    reason_counts.contains_key("completed")
        || reason_counts.contains_key("critical_findings_detected")
}

fn selector_for_target(target: &BenchmarkTarget) -> anyhow::Result<(&'static str, String)> {
    let mut selected: Vec<(&'static str, String)> = Vec::new();
    if let Some(value) = target.alias.clone() {
        selected.push(("alias", value));
    }
    if let Some(value) = target.collection.clone() {
        selected.push(("collection", value));
    }
    if let Some(value) = target.template.clone() {
        selected.push(("template", value));
    }
    if selected.is_empty() {
        return Ok(("alias", "always".to_string()));
    }
    if selected.len() > 1 {
        anyhow::bail!(
            "Target '{}' has conflicting selector config (alias/collection/template)",
            target.name
        );
    }
    Ok(selected.remove(0))
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

fn build_scan_binary(args: &Args, scan_bin: &Path) -> anyhow::Result<()> {
    if !args.build {
        if scan_bin.exists() {
            return Ok(());
        }
        anyhow::bail!(
            "zk-fuzzer binary not found at '{}' and --build=false",
            scan_bin.display()
        );
    }
    let status = Command::new("cargo")
        .args(["build", "--release", "--bin", "zk-fuzzer"])
        .status()
        .context("Failed to build zk-fuzzer binary")?;
    if !status.success() {
        anyhow::bail!("cargo build --release --bin zk-fuzzer failed");
    }
    Ok(())
}

fn run_trial(
    args: &Args,
    batch_bin: &Path,
    registry_path: &str,
    item: &WorkItem,
) -> anyhow::Result<TrialOutcome> {
    let (selector_key, selector_value) = selector_for_target(&item.target)?;
    let mut cmd = Command::new(batch_bin);
    // Keep benchmark child runs sandbox/writable even when $HOME points to a restricted path.
    // We pin HOME and run-signal dir under the benchmark output directory.
    let benchmark_home = PathBuf::from(&args.output_dir).join("benchmark_home");
    fs::create_dir_all(&benchmark_home).with_context(|| {
        format!(
            "Failed to create benchmark home root '{}'",
            benchmark_home.display()
        )
    })?;
    let run_signal_dir = benchmark_home.join("ZkFuzz");
    fs::create_dir_all(&run_signal_dir).with_context(|| {
        format!(
            "Failed to create benchmark run-signal root '{}'",
            run_signal_dir.display()
        )
    })?;
    cmd.env("HOME", &benchmark_home)
        .env("ZKF_RUN_SIGNAL_DIR", &run_signal_dir)
        .env("ZKF_DISABLE_EVIDENCE_BUNDLES", "1");
    if let Some(value) = args.benchmark_min_evidence_confidence.as_deref() {
        cmd.env("ZKF_MIN_EVIDENCE_CONFIDENCE", value);
    }
    if let Some(value) = args.benchmark_oracle_min_agreement_ratio {
        cmd.env(
            "ZKF_ORACLE_VALIDATION_MIN_AGREEMENT_RATIO",
            format!("{:.3}", value),
        );
    }
    if let Some(value) = args.benchmark_oracle_cross_attack_weight {
        cmd.env(
            "ZKF_ORACLE_VALIDATION_CROSS_ATTACK_WEIGHT",
            format!("{:.3}", value),
        );
    }
    if let Some(value) = args.benchmark_high_confidence_min_oracles {
        cmd.env("ZKF_HIGH_CONFIDENCE_MIN_ORACLES", value.to_string());
    }
    cmd.arg("--registry")
        .arg(registry_path)
        .arg(format!("--{}", selector_key))
        .arg(selector_value)
        .arg("--target-circuit")
        .arg(&item.target.target_circuit)
        .arg("--main-component")
        .arg(&item.target.main_component)
        .arg("--framework")
        .arg(&item.target.framework)
        .arg("--jobs")
        .arg(args.batch_jobs.to_string())
        .arg("--workers")
        .arg(args.workers.to_string())
        .arg("--seed")
        .arg(item.seed.to_string())
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
    let output = cmd.output().with_context(|| {
        format!(
            "Failed to run target '{}' trial {}",
            item.target.name, item.trial_idx
        )
    })?;
    let exit_code = output.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        eprintln!(
            "[{}::trial{}] stderr:\n{}",
            item.target.name, item.trial_idx, stderr
        );
    }

    let reason_rows = parse_reason_tsv(&stdout);
    let mut reason_counts = BTreeMap::new();
    for row in &reason_rows {
        *reason_counts.entry(row.reason_code.clone()).or_insert(0) += 1;
    }
    if reason_counts.is_empty() {
        reason_counts.insert("none".to_string(), 1);
    }
    let high_confidence_detected = reason_rows.iter().any(|row| row.high_confidence_detected);

    let scan_findings_total = parse_scan_findings_total(&stdout);
    let completed = if reason_rows.is_empty() {
        exit_code == 0
    } else {
        reached_completion(&reason_counts)
    };
    let detected =
        scan_findings_total > 0 || reason_counts.contains_key("critical_findings_detected");
    let attack_stage_reached = reached_attack_stage(&reason_counts);

    Ok(TrialOutcome {
        suite_name: item.suite_name.clone(),
        suite_description: item.suite_description.clone(),
        positive: item.positive,
        target_name: item.target.name.clone(),
        trial_idx: item.trial_idx,
        seed: item.seed,
        exit_code,
        completed,
        scan_findings_total,
        detected,
        high_confidence_detected,
        attack_stage_reached,
        reason_counts,
        error_message: None,
    })
}

fn trial_error_outcome(item: &WorkItem, err: &anyhow::Error) -> TrialOutcome {
    let mut reason_counts = BTreeMap::new();
    reason_counts.insert("trial_runner_error".to_string(), 1);
    TrialOutcome {
        suite_name: item.suite_name.clone(),
        suite_description: item.suite_description.clone(),
        positive: item.positive,
        target_name: item.target.name.clone(),
        trial_idx: item.trial_idx,
        seed: item.seed,
        exit_code: 1,
        completed: false,
        scan_findings_total: 0,
        detected: false,
        high_confidence_detected: false,
        attack_stage_reached: false,
        reason_counts,
        error_message: Some(format!("{:#}", err)),
    }
}

fn wilson_interval(successes: usize, trials: usize) -> ConfidenceInterval {
    if trials == 0 {
        return ConfidenceInterval {
            lower: 0.0,
            upper: 0.0,
        };
    }
    let z = 1.959_963_984_540_054_f64;
    let n = trials as f64;
    let p = successes as f64 / n;
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denom;
    let half = (z / denom) * ((p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt());

    ConfidenceInterval {
        lower: (center - half).clamp(0.0, 1.0),
        upper: (center + half).clamp(0.0, 1.0),
    }
}

fn actionable_safe_false_positives(safe_runs: &[&TrialOutcome]) -> usize {
    // Low-confidence safe detections are triage signals, not actionable gate failures.
    safe_runs
        .iter()
        .filter(|o| o.high_confidence_detected)
        .count()
}

fn compute_suite_summaries(outcomes: &[TrialOutcome]) -> Vec<SuiteSummary> {
    let mut grouped: BTreeMap<String, Vec<&TrialOutcome>> = BTreeMap::new();
    for outcome in outcomes {
        grouped
            .entry(outcome.suite_name.clone())
            .or_default()
            .push(outcome);
    }

    let mut suites = Vec::new();
    for (suite_name, items) in grouped {
        let runs_total = items.len();
        let detections = items.iter().filter(|o| o.detected).count();
        let high_confidence_detections = items
            .iter()
            .filter(|o| o.high_confidence_detected)
            .count();
        let completions = items.iter().filter(|o| o.completed).count();
        let attack_stage_reached = items.iter().filter(|o| o.attack_stage_reached).count();
        let mean_scan_findings = if runs_total == 0 {
            0.0
        } else {
            items
                .iter()
                .map(|o| o.scan_findings_total as f64)
                .sum::<f64>()
                / runs_total as f64
        };
        let mut reason_counts = BTreeMap::new();
        for outcome in &items {
            for (reason, count) in &outcome.reason_counts {
                *reason_counts.entry(reason.clone()).or_insert(0) += count;
            }
        }
        let positive = items.first().map(|o| o.positive).unwrap_or(false);
        let description = items.first().and_then(|o| o.suite_description.clone());
        suites.push(SuiteSummary {
            suite_name,
            description,
            positive,
            runs_total,
            detections,
            detection_rate: if runs_total == 0 {
                0.0
            } else {
                detections as f64 / runs_total as f64
            },
            detection_rate_ci95: wilson_interval(detections, runs_total),
            high_confidence_detections,
            high_confidence_detection_rate: if runs_total == 0 {
                0.0
            } else {
                high_confidence_detections as f64 / runs_total as f64
            },
            high_confidence_detection_rate_ci95: wilson_interval(
                high_confidence_detections,
                runs_total,
            ),
            completion_rate: if runs_total == 0 {
                0.0
            } else {
                completions as f64 / runs_total as f64
            },
            completion_rate_ci95: wilson_interval(completions, runs_total),
            attack_stage_reach_rate: if runs_total == 0 {
                0.0
            } else {
                attack_stage_reached as f64 / runs_total as f64
            },
            attack_stage_reach_rate_ci95: wilson_interval(attack_stage_reached, runs_total),
            mean_scan_findings,
            reason_counts,
        });
    }
    suites
}

fn write_markdown(
    path: &Path,
    summary: &BenchmarkSummary,
    outcomes: &[TrialOutcome],
) -> anyhow::Result<()> {
    let mut md = String::new();
    md.push_str("# zk0d Benchmark Summary\n\n");
    md.push_str(&format!("Generated: `{}`\n\n", summary.generated_utc));
    md.push_str("## Global Metrics\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|---|---|\n");
    md.push_str(&format!("| Total runs | {} |\n", summary.total_runs));
    md.push_str(&format!(
        "| Overall completion rate | {:.1}% |\n",
        summary.overall_completion_rate * 100.0
    ));
    md.push_str(&format!(
        "| Attack-stage reach rate | {:.1}% |\n",
        summary.overall_attack_stage_reach_rate * 100.0
    ));
    md.push_str(&format!(
        "| Vulnerable recall | {:.1}% |\n",
        summary.vulnerable_recall * 100.0
    ));
    md.push_str(&format!(
        "| Vulnerable recall (high-confidence) | {:.1}% |\n",
        summary.vulnerable_high_confidence_recall * 100.0
    ));
    md.push_str(&format!(
        "| Vulnerable recall (95% CI) | {:.1}% - {:.1}% |\n",
        summary.vulnerable_recall_ci95.lower * 100.0,
        summary.vulnerable_recall_ci95.upper * 100.0
    ));
    md.push_str(&format!(
        "| Vulnerable recall (high-confidence, 95% CI) | {:.1}% - {:.1}% |\n",
        summary.vulnerable_high_confidence_recall_ci95.lower * 100.0,
        summary.vulnerable_high_confidence_recall_ci95.upper * 100.0
    ));
    md.push_str(&format!(
        "| Precision | {:.1}% |\n",
        summary.precision * 100.0
    ));
    md.push_str(&format!(
        "| Precision (95% CI) | {:.1}% - {:.1}% |\n",
        summary.precision_ci95.lower * 100.0,
        summary.precision_ci95.upper * 100.0
    ));
    md.push_str(&format!(
        "| Safe actionable false-positive rate | {:.1}% |\n",
        summary.safe_false_positive_rate * 100.0
    ));
    md.push_str(&format!(
        "| Safe high-confidence false-positive rate | {:.1}% |\n",
        summary.safe_high_confidence_false_positive_rate * 100.0
    ));
    md.push_str(&format!(
        "| Safe actionable false-positive rate (95% CI) | {:.1}% - {:.1}% |\n",
        summary.safe_false_positive_rate_ci95.lower * 100.0,
        summary.safe_false_positive_rate_ci95.upper * 100.0
    ));
    md.push_str(&format!(
        "| Safe high-confidence false-positive rate (95% CI) | {:.1}% - {:.1}% |\n\n",
        summary.safe_high_confidence_false_positive_rate_ci95.lower * 100.0,
        summary.safe_high_confidence_false_positive_rate_ci95.upper * 100.0
    ));

    md.push_str("## Suite Metrics\n\n");
    md.push_str(
        "| Suite | Positive | Runs | Detection Rate (95% CI) | High-Conf Detection Rate (95% CI) | Completion Rate (95% CI) | Attack-Stage Reach (95% CI) | Mean Findings |\n",
    );
    md.push_str("|---|---|---:|---:|---:|---:|---:|---:|\n");
    for suite in &summary.suites {
        md.push_str(&format!(
            "| {} | {} | {} | {:.1}% ({:.1}-{:.1}) | {:.1}% ({:.1}-{:.1}) | {:.1}% ({:.1}-{:.1}) | {:.1}% ({:.1}-{:.1}) | {:.2} |\n",
            suite.suite_name,
            suite.positive,
            suite.runs_total,
            suite.detection_rate * 100.0,
            suite.detection_rate_ci95.lower * 100.0,
            suite.detection_rate_ci95.upper * 100.0,
            suite.high_confidence_detection_rate * 100.0,
            suite.high_confidence_detection_rate_ci95.lower * 100.0,
            suite.high_confidence_detection_rate_ci95.upper * 100.0,
            suite.completion_rate * 100.0,
            suite.completion_rate_ci95.lower * 100.0,
            suite.completion_rate_ci95.upper * 100.0,
            suite.attack_stage_reach_rate * 100.0,
            suite.attack_stage_reach_rate_ci95.lower * 100.0,
            suite.attack_stage_reach_rate_ci95.upper * 100.0,
            suite.mean_scan_findings
        ));
    }
    md.push('\n');

    md.push_str("## Trial Outcomes\n\n");
    md.push_str("| Suite | Target | Trial | Seed | Exit | Completed | Findings | Detected | High-Conf Detected | Attack Stage | Error |\n");
    md.push_str("|---|---|---:|---:|---:|---|---:|---|---|---|---|\n");
    for o in outcomes {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            o.suite_name,
            o.target_name,
            o.trial_idx,
            o.seed,
            o.exit_code,
            o.completed,
            o.scan_findings_total,
            o.detected,
            o.high_confidence_detected,
            o.attack_stage_reached,
            if o.error_message.is_some() {
                "yes"
            } else {
                "no"
            }
        ));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, md).with_context(|| format!("Failed to write '{}'", path.display()))?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let (default_suites, default_registry) = default_paths_for_profile(args.config_profile);
    let suites_arg = args
        .suites
        .clone()
        .unwrap_or_else(|| default_suites.to_string());
    let registry_arg = args
        .registry
        .clone()
        .unwrap_or_else(|| default_registry.to_string());

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

    let suites_path = expand_env_placeholders(&suites_arg);
    if has_unresolved_env_placeholder(&suites_path) {
        anyhow::bail!(
            "Unresolved env placeholder in --suites '{}'. Set required environment variables.",
            suites_arg
        );
    }
    let suites_raw = fs::read_to_string(&suites_path)
        .with_context(|| format!("Failed to read '{}'", suites_path))?;
    let suites_file: BenchmarkSuitesFile = serde_yaml::from_str(&suites_raw)
        .with_context(|| format!("Failed to parse suites YAML '{}'", suites_path))?;

    let registry_path = expand_env_placeholders(&registry_arg);
    if has_unresolved_env_placeholder(&registry_path) {
        anyhow::bail!(
            "Unresolved env placeholder in --registry '{}'. Set required environment variables.",
            registry_arg
        );
    }

    let requested_suites = split_csv(args.suite.as_deref());
    let selected_suite_names: Vec<String> = if requested_suites.is_empty() {
        suites_file.suites.keys().cloned().collect()
    } else {
        requested_suites
    };
    if selected_suite_names.is_empty() {
        anyhow::bail!("No suites selected");
    }

    let mut work_items = Vec::new();
    for suite_name in &selected_suite_names {
        let suite = suites_file
            .suites
            .get(suite_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown suite '{}'", suite_name))?;
        for target in &suite.targets {
            if !target.enabled {
                continue;
            }
            let target_circuit = expand_env_placeholders(&target.target_circuit);
            if has_unresolved_env_placeholder(&target_circuit) {
                anyhow::bail!(
                    "Unresolved env placeholder in target '{}' circuit path '{}'",
                    target.name,
                    target.target_circuit
                );
            }
            let circuit_path = PathBuf::from(&target_circuit);
            if !circuit_path.exists() {
                anyhow::bail!(
                    "Target '{}' circuit not found at '{}'",
                    target.name,
                    circuit_path.display()
                );
            }
            for trial_idx in 0..args.trials.max(1) {
                let seed = args
                    .base_seed
                    .wrapping_add((trial_idx as u64) * 1000)
                    .wrapping_add(work_items.len() as u64);
                work_items.push(WorkItem {
                    suite_name: suite_name.clone(),
                    suite_description: suite.description.clone(),
                    positive: suite.positive,
                    target: BenchmarkTarget {
                        target_circuit: target_circuit.clone(),
                        ..target.clone()
                    },
                    trial_idx: trial_idx + 1,
                    seed,
                });
            }
        }
    }

    if work_items.is_empty() {
        anyhow::bail!("No enabled targets for selected suites");
    }

    let batch_bin = PathBuf::from("target/release/zk0d_batch");
    build_batch_binary(&args, &batch_bin)?;
    let scan_bin = PathBuf::from("target/release/zk-fuzzer");
    build_scan_binary(&args, &scan_bin)?;

    println!(
        "Running {} trial jobs across {} suite(s) (jobs={}, batch_jobs={}, workers={})",
        work_items.len(),
        selected_suite_names.len(),
        args.jobs.max(1),
        args.batch_jobs.max(1),
        args.workers.max(1)
    );

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.jobs.max(1))
        .build()
        .context("Failed to create benchmark thread pool")?;

    let results = pool.install(|| {
        work_items
            .par_iter()
            .map(
                |item| match run_trial(&args, &batch_bin, &registry_path, item) {
                    Ok(outcome) => outcome,
                    Err(err) => trial_error_outcome(item, &err),
                },
            )
            .collect::<Vec<_>>()
    });

    let mut outcomes = Vec::new();
    for outcome in results {
        if let Some(err) = &outcome.error_message {
            eprintln!(
                "{}::{}::trial{} failed: {}",
                outcome.suite_name, outcome.target_name, outcome.trial_idx, err
            );
        } else {
            println!(
                "{}::{}::trial{} exit={} completed={} findings={} detected={} high_conf_detected={}",
                outcome.suite_name,
                outcome.target_name,
                outcome.trial_idx,
                outcome.exit_code,
                outcome.completed,
                outcome.scan_findings_total,
                outcome.detected,
                outcome.high_confidence_detected
            );
        }
        outcomes.push(outcome);
    }

    let suite_summaries = compute_suite_summaries(&outcomes);
    let total_runs = outcomes.len();
    let completed = outcomes.iter().filter(|o| o.completed).count();
    let attack_stage_reached = outcomes.iter().filter(|o| o.attack_stage_reached).count();
    let total_detected = outcomes.iter().filter(|o| o.detected).count();

    let vulnerable_runs: Vec<&TrialOutcome> = outcomes.iter().filter(|o| o.positive).collect();
    let safe_runs: Vec<&TrialOutcome> = outcomes.iter().filter(|o| !o.positive).collect();
    let vulnerable_recall = if vulnerable_runs.is_empty() {
        0.0
    } else {
        vulnerable_runs.iter().filter(|o| o.detected).count() as f64 / vulnerable_runs.len() as f64
    };
    let vulnerable_high_confidence_recall = if vulnerable_runs.is_empty() {
        0.0
    } else {
        vulnerable_runs
            .iter()
            .filter(|o| o.high_confidence_detected)
            .count() as f64
            / vulnerable_runs.len() as f64
    };
    let safe_actionable_fp_count = actionable_safe_false_positives(&safe_runs);
    let safe_false_positive_rate = if safe_runs.is_empty() {
        0.0
    } else {
        safe_actionable_fp_count as f64 / safe_runs.len() as f64
    };
    let safe_high_confidence_false_positive_rate = if safe_runs.is_empty() {
        0.0
    } else {
        safe_runs
            .iter()
            .filter(|o| o.high_confidence_detected)
            .count() as f64
            / safe_runs.len() as f64
    };
    let true_positives = vulnerable_runs.iter().filter(|o| o.detected).count();
    let false_positives = safe_actionable_fp_count;
    let precision_denom = true_positives + false_positives;
    let precision = if precision_denom == 0 {
        0.0
    } else {
        true_positives as f64 / precision_denom as f64
    };

    let summary = BenchmarkSummary {
        generated_utc: Utc::now().to_rfc3339(),
        config: BenchmarkConfigSnapshot {
            suites_path: suites_path.clone(),
            selected_suites: selected_suite_names.clone(),
            trials: args.trials,
            base_seed: args.base_seed,
            jobs: args.jobs,
            batch_jobs: args.batch_jobs,
            workers: args.workers,
            iterations: args.iterations,
            timeout: args.timeout,
            dry_run: args.dry_run,
            benchmark_min_evidence_confidence: args.benchmark_min_evidence_confidence.clone(),
            benchmark_oracle_min_agreement_ratio: args.benchmark_oracle_min_agreement_ratio,
            benchmark_oracle_cross_attack_weight: args.benchmark_oracle_cross_attack_weight,
            benchmark_high_confidence_min_oracles: args.benchmark_high_confidence_min_oracles,
        },
        suites: suite_summaries,
        total_runs,
        total_detected,
        overall_completion_rate: completed as f64 / total_runs as f64,
        overall_attack_stage_reach_rate: attack_stage_reached as f64 / total_runs as f64,
        vulnerable_recall,
        vulnerable_recall_ci95: wilson_interval(
            vulnerable_runs.iter().filter(|o| o.detected).count(),
            vulnerable_runs.len(),
        ),
        vulnerable_high_confidence_recall,
        vulnerable_high_confidence_recall_ci95: wilson_interval(
            vulnerable_runs
                .iter()
                .filter(|o| o.high_confidence_detected)
                .count(),
            vulnerable_runs.len(),
        ),
        precision,
        precision_ci95: wilson_interval(true_positives, precision_denom),
        safe_false_positive_rate,
        safe_false_positive_rate_ci95: wilson_interval(
            safe_actionable_fp_count,
            safe_runs.len(),
        ),
        safe_high_confidence_false_positive_rate,
        safe_high_confidence_false_positive_rate_ci95: wilson_interval(
            safe_runs
                .iter()
                .filter(|o| o.high_confidence_detected)
                .count(),
            safe_runs.len(),
        ),
    };

    let run_id = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let out_dir = PathBuf::from(&args.output_dir).join(format!("benchmark_{}", run_id));
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("Failed to create '{}'", out_dir.display()))?;
    let summary_json_path = out_dir.join("summary.json");
    fs::write(&summary_json_path, serde_json::to_string_pretty(&summary)?)
        .with_context(|| format!("Failed to write '{}'", summary_json_path.display()))?;

    let outcomes_json_path = out_dir.join("outcomes.json");
    fs::write(
        &outcomes_json_path,
        serde_json::to_string_pretty(&outcomes)?,
    )
    .with_context(|| format!("Failed to write '{}'", outcomes_json_path.display()))?;

    let summary_md_path = out_dir.join("summary.md");
    write_markdown(&summary_md_path, &summary, &outcomes)?;

    println!("Saved benchmark summary: {}", summary_json_path.display());
    println!(
        "Metrics: completion_rate={:.1}% attack_stage={:.1}% recall={:.1}% recall_high_conf={:.1}% precision={:.1}% safe_fpr={:.1}% safe_high_conf_fpr={:.1}%",
        summary.overall_completion_rate * 100.0,
        summary.overall_attack_stage_reach_rate * 100.0,
        summary.vulnerable_recall * 100.0,
        summary.vulnerable_high_confidence_recall * 100.0,
        summary.precision * 100.0,
        summary.safe_false_positive_rate * 100.0,
        summary.safe_high_confidence_false_positive_rate * 100.0
    );

    Ok(())
}

#[cfg(test)]
#[path = "zk0d_benchmark/zk0d_benchmark_tests.rs"]
mod tests;
