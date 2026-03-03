use anyhow::Context;
use clap::{Parser, Subcommand};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "zkf_checks")]
#[command(
    about = "Integrated Rust repository checks (panic surface, hygiene, prod/test separation)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check production panic-surface calls against an allowlist
    PanicSurface {
        #[arg(long, default_value = ".")]
        repo_root: String,
        #[arg(long, default_value = "config/panic_surface_allowlist.txt")]
        allowlist: String,
        #[arg(long, default_value = "src,crates")]
        search_roots: String,
        #[arg(long, default_value_t = false)]
        write_allowlist: bool,
        #[arg(long, default_value_t = false)]
        fail_on_stale: bool,
    },
    /// Check repository root for blocked placeholder files
    RepoHygiene {
        #[arg(long, default_value = ".")]
        repo_root: String,
        #[arg(long)]
        blocklist: Option<String>,
        #[arg(long)]
        json_out: Option<String>,
    },
    /// Check production Rust tree for prod/test separation violations
    ProdTestSeparation {
        #[arg(long, default_value = ".")]
        repo_root: String,
        #[arg(long, default_value = "src,crates")]
        search_roots: String,
        #[arg(long, default_value = "config/prod_test_separation_baseline.json")]
        baseline: String,
        #[arg(long, default_value_t = false)]
        write_baseline: bool,
        #[arg(long, default_value_t = false)]
        strict: bool,
        #[arg(long)]
        json_out: Option<String>,
    },
    /// Regression gate for benchmark summaries
    BenchmarkRegressionGate {
        #[arg(long, default_value = "artifacts/benchmark_runs")]
        benchmark_root: String,
        #[arg(long)]
        summary: Option<String>,
        #[arg(long)]
        min_completion_rate: Option<f64>,
        #[arg(long)]
        min_vulnerable_recall: Option<f64>,
        #[arg(long)]
        min_precision: Option<f64>,
        #[arg(long)]
        max_safe_fpr: Option<f64>,
        #[arg(long)]
        max_safe_high_conf_fpr: Option<f64>,
    },
    /// Generate benchmark trend artifacts (JSON + Markdown)
    BenchmarkTrendReport {
        #[arg(long, default_value = "artifacts/benchmark_runs")]
        benchmark_root: String,
        #[arg(long, default_value = "artifacts/benchmark_trends")]
        output_dir: String,
        #[arg(long, default_value = "artifacts/benchmark_trends/history.jsonl")]
        history_file: String,
    },
    /// Generate benchmark failure-class dashboard artifacts
    BenchmarkFailureDashboard {
        #[arg(long, default_value = "artifacts/benchmark_runs")]
        benchmark_root: String,
        #[arg(long, default_value = "artifacts/benchmark_trends")]
        output_dir: String,
        #[arg(long, action = clap::ArgAction::Append)]
        threshold: Vec<String>,
    },
}

fn parse_roots(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn absolute_from_root(repo_root: &Path, input: &str) -> PathBuf {
    let path = PathBuf::from(input);
    if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    }
}

fn resolve_repo_root(raw: &str) -> PathBuf {
    let candidate = PathBuf::from(raw);
    if let Ok(canonical) = candidate.canonicalize() {
        return canonical;
    }
    if candidate.is_absolute() {
        return candidate;
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(candidate)
}

fn cmd_panic_surface(
    repo_root: &Path,
    allowlist: &Path,
    search_roots: &[String],
    write_allowlist: bool,
    fail_on_stale: bool,
) -> anyhow::Result<i32> {
    let matches = zk_fuzzer::checks::panic_surface::collect_panic_matches(repo_root, search_roots)?;
    let current_keys: BTreeSet<String> = matches.iter().map(|m| m.key()).collect();

    if write_allowlist {
        zk_fuzzer::checks::panic_surface::write_allowlist(allowlist, &current_keys)?;
        println!(
            "panic-surface allowlist written: {} (entries={})",
            allowlist.display(),
            current_keys.len()
        );
        return Ok(0);
    }

    let allowed = zk_fuzzer::checks::panic_surface::load_allowlist(allowlist)?;
    let report = zk_fuzzer::checks::panic_surface::build_report(&current_keys, &allowed);

    println!(
        "panic-surface check: matches={} allowlist={} unknown={} stale={}",
        report.matches, report.allowlist, report.unknown, report.stale
    );

    if !report.unknown_entries.is_empty() {
        println!("\nNew panic-surface entries not in allowlist:");
        for entry in &report.unknown_entries {
            println!("  {}", entry);
        }
        println!("\nUpdate allowlist intentionally via:");
        println!("  cargo run --bin zkf_checks -- panic-surface --write-allowlist");
        return Ok(1);
    }

    if fail_on_stale && !report.stale_entries.is_empty() {
        println!("\nStale allowlist entries (no longer present):");
        for entry in &report.stale_entries {
            println!("  {}", entry);
        }
        return Ok(1);
    }

    Ok(0)
}

fn cmd_repo_hygiene(
    repo_root: &Path,
    blocklist: Option<&Path>,
    json_out: Option<&Path>,
) -> anyhow::Result<i32> {
    let mut extra_blocked = BTreeSet::new();
    if let Some(path) = blocklist {
        extra_blocked = zk_fuzzer::checks::repo_hygiene::parse_blocklist_file(path)?;
    }

    let report = zk_fuzzer::checks::repo_hygiene::build_report(
        repo_root,
        zk_fuzzer::checks::repo_hygiene::DEFAULT_BLOCKED_ROOT_FILES,
        &extra_blocked,
    );

    if let Some(out_path) = json_out {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(out_path, format!("{json}\n"))?;
    }

    if !report.matches.is_empty() {
        println!("Repo hygiene check failed: blocked root files detected.");
        for name in &report.matches {
            println!("  - {}", name);
        }
        return Ok(1);
    }
    println!("Repo hygiene check passed: no blocked root placeholder files found.");
    Ok(0)
}

fn cmd_prod_test_separation(
    repo_root: &Path,
    search_roots: &[String],
    baseline: &Path,
    write_baseline: bool,
    strict: bool,
    json_out: Option<&Path>,
) -> anyhow::Result<i32> {
    let violations =
        zk_fuzzer::checks::prod_test_separation::collect_violations(repo_root, search_roots)?;

    if write_baseline {
        zk_fuzzer::checks::prod_test_separation::write_baseline(baseline, &violations)?;
        let unique = zk_fuzzer::checks::prod_test_separation::unique_signatures(&violations);
        println!(
            "Wrote prod/test separation baseline: {} ({} signatures, {} total violations)",
            baseline.display(),
            unique.len(),
            violations.len()
        );
        return Ok(0);
    }

    let baseline_counts = if strict {
        Default::default()
    } else {
        zk_fuzzer::checks::prod_test_separation::load_baseline(baseline)?
    };
    let new_violations = if strict {
        violations.clone()
    } else {
        zk_fuzzer::checks::prod_test_separation::filter_new_violations(
            &violations,
            &baseline_counts,
        )
    };

    let report = zk_fuzzer::checks::prod_test_separation::ProdTestSeparationReport {
        repo_root: repo_root.display().to_string(),
        search_roots: search_roots.to_vec(),
        baseline_path: baseline.display().to_string(),
        strict,
        violation_count: violations.len(),
        legacy_violation_count: violations.len().saturating_sub(new_violations.len()),
        new_violation_count: new_violations.len(),
        baseline_signature_count: baseline_counts.len(),
        violations: violations.clone(),
        new_violations: new_violations.clone(),
        pass: new_violations.is_empty(),
    };

    if let Some(out_path) = json_out {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(out_path, format!("{json}\n"))?;
    }

    if violations.is_empty() {
        println!("Production/test separation check passed: no violations found.");
        return Ok(0);
    }

    if strict {
        println!("Production/test separation check failed (strict mode):");
        for violation in &violations {
            println!(
                "  - {}:{}: {}: {}",
                violation.path,
                violation.line,
                violation.kind,
                violation.code.trim()
            );
        }
        return Ok(1);
    }

    if !baseline.exists() {
        println!(
            "Production/test separation check failed: baseline not found and violations exist."
        );
        println!(
            "Generate baseline with: cargo run --bin zkf_checks -- prod-test-separation --write-baseline"
        );
        return Ok(1);
    }

    if new_violations.is_empty() {
        println!(
            "Production/test separation check passed: no new violations (legacy baseline signatures matched: {}).",
            baseline_counts.len()
        );
        return Ok(0);
    }

    println!("Production/test separation check failed: new violations detected.");
    for violation in &new_violations {
        println!(
            "  - {}:{}: {}: {}",
            violation.path,
            violation.line,
            violation.kind,
            violation.code.trim()
        );
    }
    Ok(1)
}

fn cmd_benchmark_regression_gate(
    benchmark_root: &Path,
    summary_override: Option<&Path>,
    threshold_overrides: zk_fuzzer::checks::benchmark_regression_gate::RegressionThresholdOverrides,
) -> anyhow::Result<i32> {
    if !benchmark_root.is_dir() {
        println!(
            "::error::Benchmark output directory not found: {}",
            benchmark_root.display()
        );
        return Ok(1);
    }

    let summary_path = if let Some(path) = summary_override {
        if !path.is_file() {
            println!(
                "::error::Benchmark summary override not found: {}",
                path.display()
            );
            return Ok(1);
        }
        path.to_path_buf()
    } else {
        match zk_fuzzer::checks::benchmark_regression_gate::latest_summary_path(benchmark_root) {
            Ok(path) => path,
            Err(_) => {
                println!(
                    "::error::No benchmark summary.json found under {}",
                    benchmark_root.display()
                );
                return Ok(1);
            }
        }
    };

    let thresholds =
        zk_fuzzer::checks::benchmark_regression_gate::resolve_thresholds(threshold_overrides)?;
    println!("Using benchmark summary: {}", summary_path.display());
    println!(
        "Thresholds: completion>={} recall>={} precision>={} safe_fpr<={} safe_high_conf_fpr<={}",
        thresholds.min_completion_rate,
        thresholds.min_vulnerable_recall,
        thresholds.min_precision,
        thresholds.max_safe_fpr,
        thresholds.max_safe_high_conf_fpr
    );

    let summary = zk_fuzzer::checks::benchmark_regression_gate::load_summary(&summary_path)?;
    let evaluation =
        zk_fuzzer::checks::benchmark_regression_gate::evaluate_summary(&summary, &thresholds);

    println!(
        "Metrics: total_runs={} total_detected={} completion={:.4} recall={:.4} precision={:.4} safe_fpr={:.4} safe_high_conf_fpr={:.4}",
        evaluation.metrics.total_runs,
        evaluation.metrics.total_detected,
        evaluation.metrics.completion,
        evaluation.metrics.vulnerable_recall,
        evaluation.metrics.precision,
        evaluation.metrics.safe_fpr,
        evaluation.metrics.safe_high_conf_fpr
    );

    if !evaluation.failures.is_empty() {
        println!("::error::Benchmark regression gate failed:");
        for failure in evaluation.failures {
            println!("  - {failure}");
        }
        return Ok(1);
    }

    println!("Benchmark regression gate passed.");
    Ok(0)
}

fn cmd_benchmark_trend_report(
    benchmark_root: &Path,
    output_dir: &Path,
    history_file: &Path,
) -> anyhow::Result<i32> {
    let summary_path = zk_fuzzer::checks::benchmark_trend::latest_summary_path(benchmark_root)?;
    let summary = zk_fuzzer::checks::benchmark_trend::load_json(&summary_path)?;
    let entry = zk_fuzzer::checks::benchmark_trend::extract_entry(&summary, &summary_path);
    let previous = zk_fuzzer::checks::benchmark_trend::last_history_entry(history_file)?;

    zk_fuzzer::checks::benchmark_trend::ensure_output_dir(output_dir)?;
    if let Some(parent) = history_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed creating '{}'", parent.display()))?;
    }

    let payload = zk_fuzzer::checks::benchmark_trend::TrendPayload {
        entry: entry.clone(),
        previous: previous.clone(),
    };
    let json_path = output_dir.join("latest_trend.json");
    let md_path = output_dir.join("latest_trend.md");
    zk_fuzzer::checks::benchmark_trend::write_payload_json(&json_path, &payload)?;
    zk_fuzzer::checks::benchmark_trend::write_markdown(&md_path, &entry, previous.as_ref())?;
    zk_fuzzer::checks::benchmark_trend::append_history(history_file, &entry)?;

    println!("Trend entry written: {}", json_path.display());
    println!("Trend report written: {}", md_path.display());
    Ok(0)
}

fn cmd_benchmark_failure_dashboard(
    benchmark_root: &Path,
    output_dir: &Path,
    threshold_overrides: &[String],
) -> anyhow::Result<i32> {
    let thresholds =
        zk_fuzzer::checks::benchmark_failure_dashboard::resolve_thresholds(threshold_overrides)?;
    let latest_dir =
        zk_fuzzer::checks::benchmark_failure_dashboard::latest_benchmark_dir(benchmark_root)?;
    let summary_path = latest_dir.join("summary.json");
    let outcomes_path = latest_dir.join("outcomes.json");

    if !summary_path.is_file() {
        anyhow::bail!("Missing summary.json at {}", summary_path.display());
    }
    if !outcomes_path.is_file() {
        anyhow::bail!("Missing outcomes.json at {}", outcomes_path.display());
    }

    let summary = zk_fuzzer::checks::benchmark_failure_dashboard::load_json(&summary_path)?;
    let outcomes_raw = zk_fuzzer::checks::benchmark_failure_dashboard::load_json(&outcomes_path)?;
    let outcomes = outcomes_raw
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Expected list in {}", outcomes_path.display()))?;
    let payload = zk_fuzzer::checks::benchmark_failure_dashboard::dashboard(
        &summary,
        outcomes,
        &summary_path,
        &outcomes_path,
        &thresholds,
    )?;

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed creating '{}'", output_dir.display()))?;
    let json_path = output_dir.join("latest_failure_dashboard.json");
    let md_path = output_dir.join("latest_failure_dashboard.md");
    std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&payload)
            .with_context(|| "Failed serializing failure dashboard payload")?,
    )
    .with_context(|| format!("Failed writing '{}'", json_path.display()))?;
    zk_fuzzer::checks::benchmark_failure_dashboard::write_markdown(&md_path, &payload)?;

    println!("Failure dashboard written: {}", json_path.display());
    println!("Failure dashboard report written: {}", md_path.display());
    Ok(0)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::PanicSurface {
            repo_root,
            allowlist,
            search_roots,
            write_allowlist,
            fail_on_stale,
        } => {
            let root = resolve_repo_root(&repo_root);
            let allowlist_path = absolute_from_root(&root, &allowlist);
            let roots = parse_roots(&search_roots);
            cmd_panic_surface(
                &root,
                &allowlist_path,
                &roots,
                write_allowlist,
                fail_on_stale,
            )?
        }
        Commands::RepoHygiene {
            repo_root,
            blocklist,
            json_out,
        } => {
            let root = resolve_repo_root(&repo_root);
            let blocklist_path = blocklist
                .as_deref()
                .map(|value| absolute_from_root(&root, value));
            let json_out_path = json_out
                .as_deref()
                .map(|value| absolute_from_root(&root, value));
            cmd_repo_hygiene(&root, blocklist_path.as_deref(), json_out_path.as_deref())?
        }
        Commands::ProdTestSeparation {
            repo_root,
            search_roots,
            baseline,
            write_baseline,
            strict,
            json_out,
        } => {
            let root = resolve_repo_root(&repo_root);
            let roots = parse_roots(&search_roots);
            let baseline_path = absolute_from_root(&root, &baseline);
            let json_out_path = json_out
                .as_deref()
                .map(|value| absolute_from_root(&root, value));
            cmd_prod_test_separation(
                &root,
                &roots,
                &baseline_path,
                write_baseline,
                strict,
                json_out_path.as_deref(),
            )?
        }
        Commands::BenchmarkRegressionGate {
            benchmark_root,
            summary,
            min_completion_rate,
            min_vulnerable_recall,
            min_precision,
            max_safe_fpr,
            max_safe_high_conf_fpr,
        } => {
            let benchmark_root_path = PathBuf::from(benchmark_root);
            let summary_path = summary.as_deref().map(PathBuf::from);
            let threshold_overrides =
                zk_fuzzer::checks::benchmark_regression_gate::RegressionThresholdOverrides {
                    min_completion_rate,
                    min_vulnerable_recall,
                    min_precision,
                    max_safe_fpr,
                    max_safe_high_conf_fpr,
                };
            cmd_benchmark_regression_gate(
                &benchmark_root_path,
                summary_path.as_deref(),
                threshold_overrides,
            )?
        }
        Commands::BenchmarkTrendReport {
            benchmark_root,
            output_dir,
            history_file,
        } => {
            let benchmark_root_path = PathBuf::from(benchmark_root);
            let output_dir_path = PathBuf::from(output_dir);
            let history_path = PathBuf::from(history_file);
            cmd_benchmark_trend_report(&benchmark_root_path, &output_dir_path, &history_path)?
        }
        Commands::BenchmarkFailureDashboard {
            benchmark_root,
            output_dir,
            threshold,
        } => {
            let benchmark_root_path = PathBuf::from(benchmark_root);
            let output_dir_path = PathBuf::from(output_dir);
            cmd_benchmark_failure_dashboard(&benchmark_root_path, &output_dir_path, &threshold)?
        }
    };

    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
