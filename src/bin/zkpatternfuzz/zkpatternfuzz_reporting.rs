use anyhow::Context;
use chrono::Utc;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

use super::{Args, TemplateOutcomeReason};

pub(super) fn print_reason_tsv(reasons: &[TemplateOutcomeReason]) {
    if reasons.is_empty() {
        return;
    }

    println!("REASON_TSV_START");
    println!(
        "template\tsuffix\treason_code\tstatus\tstage\tproof_status\thigh_confidence_detected\tdetected_pattern_count"
    );
    for reason in reasons {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            reason.template_file,
            reason.suffix,
            reason.reason_code,
            reason.status.as_deref().unwrap_or("unknown"),
            reason.stage.as_deref().unwrap_or("unknown"),
            reason.proof_status.as_deref().unwrap_or("unknown"),
            if reason.high_confidence_detected {
                "1"
            } else {
                "0"
            },
            reason.detected_pattern_count,
        );
    }
    println!("REASON_TSV_END");
}

pub(super) fn proof_state_counts(
    reasons: &[TemplateOutcomeReason],
) -> (usize, usize, usize, usize) {
    let exploitable = reasons
        .iter()
        .filter(|reason| reason.proof_status.as_deref() == Some("exploitable"))
        .count();
    let not_exploitable_within_bounds = reasons
        .iter()
        .filter(|reason| reason.proof_status.as_deref() == Some("not_exploitable_within_bounds"))
        .count();
    let proof_failed = reasons
        .iter()
        .filter(|reason| reason.proof_status.as_deref() == Some("proof_failed"))
        .count();
    let proof_skipped_by_policy = reasons
        .iter()
        .filter(|reason| reason.proof_status.as_deref() == Some("proof_skipped_by_policy"))
        .count();
    (
        exploitable,
        not_exploitable_within_bounds,
        proof_failed,
        proof_skipped_by_policy,
    )
}

#[derive(Debug, Serialize)]
struct PatternReportRow {
    pattern_file: String,
    pattern_path: String,
    output_suffix: String,
    reason_code: String,
    status: String,
    stage: String,
    proof_status: String,
    detected_pattern_count: usize,
    high_confidence_detected: bool,
    selector_matched: bool,
    matched: bool,
}

#[derive(Debug, Serialize)]
struct BatchFindingsReport<'a> {
    report_schema: &'static str,
    generated_utc: String,
    verdict: &'static str,
    target_circuit: &'a str,
    framework: &'a str,
    main_component: &'a str,
    input: BatchReportInput<'a>,
    run: BatchReportRun,
    gates: BatchReportGates,
    artifacts: BatchReportArtifacts,
    totals: BatchReportTotals,
    patterns: Vec<PatternReportRow>,
}

#[derive(Debug, Serialize)]
struct BatchReportInput<'a> {
    config_json: Option<&'a str>,
    registry: Option<&'a str>,
    collection: Option<&'a str>,
    alias: Option<&'a str>,
    template: Option<&'a str>,
    pattern_yaml: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct BatchReportRun {
    jobs: usize,
    workers: usize,
    seed: u64,
    iterations: u64,
    timeout: u64,
    results_root: String,
}

#[derive(Debug, Serialize)]
struct BatchReportGates {
    gate1_expected_patterns: usize,
    gate2_completion: bool,
    gate3_artifact_reconciliation: bool,
    template_reason_errors: usize,
    dry_run: bool,
    campaign_success: bool,
}

#[derive(Debug, Serialize)]
struct BatchReportArtifacts {
    timestamped_result_bundle: String,
    timestamped_run_log: String,
    timestamped_error_log: String,
    batch_run_root: Option<String>,
}

#[derive(Debug, Serialize)]
struct BatchReportTotals {
    expected_patterns: usize,
    executed_patterns: usize,
    template_errors: usize,
    selector_matched_patterns: usize,
    matched_patterns: usize,
    detected_patterns_total: usize,
    high_confidence_patterns: usize,
    exploitable_patterns: usize,
    not_exploitable_within_bounds_patterns: usize,
    proof_failed_patterns: usize,
    proof_skipped_by_policy_patterns: usize,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_report_json(
    args: &Args,
    path: &Path,
    target_circuit: &str,
    reasons: &[TemplateOutcomeReason],
    expected_count: usize,
    executed: usize,
    template_errors: usize,
    results_root: &Path,
    gate2_ok: bool,
    gate3_ok: bool,
    campaign_success: bool,
    timestamped_result_dir: &Path,
    timestamped_run_log: &Path,
    timestamped_error_log: &Path,
    batch_run_root: Option<&str>,
) -> anyhow::Result<()> {
    let matched_patterns = reasons
        .iter()
        .filter(|reason| reason.detected_pattern_count > 0)
        .count();
    let selector_matched_patterns = reasons
        .iter()
        .filter(|reason| reason.reason_code != "selector_mismatch")
        .count();
    let detected_patterns_total = reasons
        .iter()
        .map(|reason| reason.detected_pattern_count)
        .sum::<usize>();
    let high_confidence_patterns = reasons
        .iter()
        .filter(|reason| reason.high_confidence_detected)
        .count();
    let (
        exploitable_patterns,
        not_exploitable_within_bounds_patterns,
        proof_failed_patterns,
        proof_skipped_by_policy_patterns,
    ) = proof_state_counts(reasons);
    let reason_error_count = reasons
        .iter()
        .filter(|reason| is_error_reason(reason))
        .count();
    let verdict = if args.dry_run {
        "dry_run"
    } else if !gate2_ok || !gate3_ok || reason_error_count > 0 || template_errors > 0 {
        "run_failed"
    } else if matched_patterns > 0 {
        "matching_patterns_found"
    } else {
        "no_matching_patterns_found"
    };

    let patterns = reasons
        .iter()
        .map(|reason| PatternReportRow {
            pattern_file: reason.template_file.clone(),
            pattern_path: reason.template_path.clone(),
            output_suffix: reason.suffix.clone(),
            reason_code: reason.reason_code.clone(),
            status: reason
                .status
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            stage: reason
                .stage
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            proof_status: reason
                .proof_status
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            detected_pattern_count: reason.detected_pattern_count,
            high_confidence_detected: reason.high_confidence_detected,
            selector_matched: reason.reason_code != "selector_mismatch",
            matched: reason.detected_pattern_count > 0,
        })
        .collect::<Vec<_>>();

    let report = BatchFindingsReport {
        report_schema: "zkfuzz.batch_detected_patterns.v2",
        generated_utc: Utc::now().to_rfc3339(),
        verdict,
        target_circuit,
        framework: &args.framework,
        main_component: &args.main_component,
        input: BatchReportInput {
            config_json: args.config_json.as_deref(),
            registry: args.registry.as_deref(),
            collection: args.collection.as_deref(),
            alias: args.alias.as_deref(),
            template: args.template.as_deref(),
            pattern_yaml: args.pattern_yaml.as_deref(),
        },
        run: BatchReportRun {
            jobs: args.jobs,
            workers: args.workers,
            seed: args.seed,
            iterations: args.iterations,
            timeout: args.timeout,
            results_root: results_root.display().to_string(),
        },
        gates: BatchReportGates {
            gate1_expected_patterns: expected_count,
            gate2_completion: gate2_ok,
            gate3_artifact_reconciliation: gate3_ok,
            template_reason_errors: reason_error_count,
            dry_run: args.dry_run,
            campaign_success,
        },
        artifacts: BatchReportArtifacts {
            timestamped_result_bundle: timestamped_result_dir.display().to_string(),
            timestamped_run_log: timestamped_run_log.display().to_string(),
            timestamped_error_log: timestamped_error_log.display().to_string(),
            batch_run_root: batch_run_root.map(|value| value.to_string()),
        },
        totals: BatchReportTotals {
            expected_patterns: expected_count,
            executed_patterns: executed,
            template_errors,
            selector_matched_patterns,
            matched_patterns,
            detected_patterns_total,
            high_confidence_patterns,
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
        },
        patterns,
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create detected-patterns report parent directory '{}'",
                parent.display()
            )
        })?;
    }
    let encoded = serde_json::to_string_pretty(&report)?;
    fs::write(path, encoded)
        .with_context(|| format!("Failed to write report JSON '{}'", path.display()))?;
    Ok(())
}

pub(super) fn create_timestamped_result_dir(results_root: &Path) -> anyhow::Result<PathBuf> {
    let ts = Utc::now().format("%Y%m%d_%H%M%S_%3f").to_string();
    let dir = results_root.join("ResultJsonTimestamped").join(ts);
    fs::create_dir_all(&dir).with_context(|| {
        format!(
            "Failed to create timestamped result directory '{}'",
            dir.display()
        )
    })?;
    Ok(dir)
}

pub(super) fn is_error_reason(reason: &TemplateOutcomeReason) -> bool {
    if reason.proof_status.as_deref() == Some("proof_failed") {
        return true;
    }
    !matches!(
        reason.reason_code.as_str(),
        "completed" | "critical_findings_detected"
    )
}

pub(super) fn write_error_log(
    path: &Path,
    reasons: &[TemplateOutcomeReason],
    template_errors: usize,
    gate2_ok: bool,
    gate3_ok: bool,
    dry_run: bool,
) -> anyhow::Result<()> {
    let mut lines = Vec::<String>::new();
    lines.push(format!("generated_utc={}", Utc::now().to_rfc3339()));
    lines.push(format!("dry_run={}", dry_run));
    lines.push(format!("gate2_ok={}", gate2_ok));
    lines.push(format!("gate3_ok={}", gate3_ok));
    lines.push(format!("template_errors={}", template_errors));

    let mut error_count = 0usize;
    for reason in reasons {
        if !is_error_reason(reason) {
            continue;
        }
        error_count += 1;
        lines.push(format!(
            "template={} suffix={} reason_code={} status={} stage={} proof_status={} detected_pattern_count={}",
            reason.template_file,
            reason.suffix,
            reason.reason_code,
            reason.status.as_deref().unwrap_or("unknown"),
            reason.stage.as_deref().unwrap_or("unknown"),
            reason.proof_status.as_deref().unwrap_or("unknown"),
            reason.detected_pattern_count,
        ));
    }

    if error_count == 0 {
        lines.push("no_errors_detected".to_string());
    } else {
        lines.push(format!("error_entries={}", error_count));
    }

    fs::write(path, lines.join("\n") + "\n")
        .with_context(|| format!("Failed to write error log '{}'", path.display()))?;
    Ok(())
}
