use std::path::Path;

use chrono::{DateTime, Utc};
use std::path::PathBuf;
use zk_fuzzer::config::ReportingConfig;
use zk_fuzzer::chain_fuzzer::metrics::DepthMetricsSummary;
use zk_fuzzer::chain_fuzzer::ChainFinding;
use zk_fuzzer::reporting::FuzzReport;

use crate::engagement_artifacts::write_run_artifacts;
use crate::run_lifecycle::write_failed_mode_run_artifact_with_error;
use crate::run_outcome_docs::completed_run_doc_with_window;

pub(crate) struct ChainReportContext<'a> {
    pub campaign_name: &'a str,
    pub engagement_strict: bool,
    pub run_valid: bool,
    pub quality_failures: &'a [String],
    pub min_unique_coverage_bits: usize,
    pub min_completed_per_chain: usize,
    pub summary: &'a DepthMetricsSummary,
    pub final_total_entries: usize,
    pub final_unique_coverage_bits: usize,
    pub final_max_depth: usize,
    pub baseline_total_entries: usize,
    pub baseline_unique_coverage_bits: usize,
    pub chain_findings: &'a [ChainFinding],
}

pub(crate) struct ChainReportContextInput<'a> {
    pub campaign_name: &'a str,
    pub engagement_strict: bool,
    pub run_valid: bool,
    pub quality_failures: &'a [String],
    pub min_unique_coverage_bits: usize,
    pub min_completed_per_chain: usize,
    pub summary: &'a DepthMetricsSummary,
    pub final_total_entries: usize,
    pub final_unique_coverage_bits: usize,
    pub final_max_depth: usize,
    pub baseline_total_entries: usize,
    pub baseline_unique_coverage_bits: usize,
    pub chain_findings: &'a [ChainFinding],
}

pub(crate) fn build_chain_report_context<'a>(
    input: ChainReportContextInput<'a>,
) -> ChainReportContext<'a> {
    ChainReportContext {
        campaign_name: input.campaign_name,
        engagement_strict: input.engagement_strict,
        run_valid: input.run_valid,
        quality_failures: input.quality_failures,
        min_unique_coverage_bits: input.min_unique_coverage_bits,
        min_completed_per_chain: input.min_completed_per_chain,
        summary: input.summary,
        final_total_entries: input.final_total_entries,
        final_unique_coverage_bits: input.final_unique_coverage_bits,
        final_max_depth: input.final_max_depth,
        baseline_total_entries: input.baseline_total_entries,
        baseline_unique_coverage_bits: input.baseline_unique_coverage_bits,
        chain_findings: input.chain_findings,
    }
}

pub(crate) fn build_chain_report_json(ctx: &ChainReportContext<'_>) -> serde_json::Value {
    serde_json::json!({
        "campaign_name": ctx.campaign_name,
        "mode": "chain_fuzzing",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "engagement": {
            "strict": ctx.engagement_strict,
            "valid_run": ctx.run_valid,
            "failures": ctx.quality_failures,
            "thresholds": {
                "min_unique_coverage_bits": ctx.min_unique_coverage_bits,
                "min_completed_per_chain": ctx.min_completed_per_chain,
            },
        },
        "metrics": {
            "total_findings": ctx.summary.total_findings,
            "d_mean": ctx.summary.d_mean,
            "p_deep": ctx.summary.p_deep,
            "depth_distribution": ctx.summary.depth_distribution,
        },
        "corpus_metrics": {
            "corpus_entries": ctx.final_total_entries,
            "unique_coverage_bits": ctx.final_unique_coverage_bits,
            "max_depth": ctx.final_max_depth,
            "baseline": {
                "corpus_entries": ctx.baseline_total_entries,
                "unique_coverage_bits": ctx.baseline_unique_coverage_bits,
            }
        },
        "chain_findings": ctx.chain_findings,
    })
}

pub(crate) fn write_chain_report_json(
    path: &Path,
    report: &serde_json::Value,
) -> anyhow::Result<()> {
    use std::io::{BufWriter, Write};
    let f = std::fs::File::create(path)?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, report)?;
    w.flush()?;
    Ok(())
}

pub(crate) fn build_chain_report_markdown(
    ctx: &ChainReportContext<'_>,
    config_path: &str,
    seed: Option<u64>,
) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "# Chain Fuzzing Report: {}\n\n",
        ctx.campaign_name
    ));
    md.push_str("**Mode:** Multi-Step Chain Fuzzing (Mode 3)\n");
    md.push_str(&format!(
        "**Generated:** {}\n\n",
        chrono::Utc::now().to_rfc3339()
    ));

    md.push_str("## Engagement Validation\n\n");
    md.push_str(&format!("**Strict:** {}\n", ctx.engagement_strict));
    md.push_str(&format!(
        "**Valid Run:** {}\n",
        if ctx.run_valid { "yes" } else { "no" }
    ));
    md.push_str(&format!(
        "**Thresholds:** min_unique_coverage_bits={}, min_completed_per_chain={}\n\n",
        ctx.min_unique_coverage_bits, ctx.min_completed_per_chain
    ));

    md.push_str("### Corpus / Exploration Metrics\n\n");
    md.push_str(&format!(
        "- Corpus entries: {} (delta {})\n",
        ctx.final_total_entries,
        ctx.final_total_entries
            .saturating_sub(ctx.baseline_total_entries)
    ));
    md.push_str(&format!(
        "- Unique coverage bits: {} (delta {})\n",
        ctx.final_unique_coverage_bits,
        ctx.final_unique_coverage_bits
            .saturating_sub(ctx.baseline_unique_coverage_bits)
    ));
    md.push_str(&format!("- Max depth: {}\n\n", ctx.final_max_depth));

    if !ctx.quality_failures.is_empty() {
        md.push_str("### Failures\n\n");
        for failure in ctx.quality_failures {
            md.push_str(&format!("- {}\n", failure));
        }
        md.push('\n');
    }

    md.push_str("## Depth Metrics\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Total Findings | {} |\n",
        ctx.summary.total_findings
    ));
    md.push_str(&format!("| Mean L_min (D) | {:.2} |\n", ctx.summary.d_mean));
    md.push_str(&format!(
        "| P(L_min >= 2) | {:.1}% |\n\n",
        ctx.summary.p_deep * 100.0
    ));

    if !ctx.chain_findings.is_empty() {
        md.push_str("## Chain Findings\n\n");
        for (i, finding) in ctx.chain_findings.iter().enumerate() {
            md.push_str(&format!(
                "### {}. [{}] Chain: {}\n\n",
                i + 1,
                finding.finding.severity.to_uppercase(),
                finding.spec_name
            ));
            md.push_str(&format!("**L_min:** {}\n\n", finding.l_min));
            md.push_str(&format!("{}\n\n", finding.finding.description));

            if let Some(ref assertion) = finding.violated_assertion {
                md.push_str(&format!("**Violated Assertion:** `{}`\n\n", assertion));
            }

            md.push_str("**Trace:**\n\n");
            for (step_idx, step) in finding.trace.steps.iter().enumerate() {
                let status = if step.success { "✓" } else { "✗" };
                md.push_str(&format!(
                    "- Step {}: {} `{}` - {}\n",
                    step_idx,
                    status,
                    step.circuit_ref,
                    if step.success {
                        "success"
                    } else {
                        step.error.as_deref().unwrap_or("failed")
                    }
                ));
            }
            md.push('\n');

            md.push_str("**Reproduction:**\n\n");
            md.push_str(&format!(
                "```bash\ncargo run --release -- chains {} --seed {}\n```\n\n",
                config_path,
                seed.unwrap_or(42)
            ));
        }
    }

    md
}

pub(crate) fn write_chain_report_markdown(path: &Path, markdown: &str) -> anyhow::Result<()> {
    std::fs::write(path, markdown)?;
    Ok(())
}

pub(crate) fn save_chain_reports_bundle(
    output_dir: &Path,
    config_path: &str,
    seed: Option<u64>,
    report_ctx: &ChainReportContext<'_>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(output_dir)?;

    let chain_report_path = output_dir.join("chain_report.json");
    let chain_report = build_chain_report_json(report_ctx);
    write_chain_report_json(&chain_report_path, &chain_report)?;
    tracing::info!("Saved chain report to {:?}", chain_report_path);

    let chain_md_path = output_dir.join("chain_report.md");
    let chain_md = build_chain_report_markdown(report_ctx, config_path, seed);
    write_chain_report_markdown(&chain_md_path, &chain_md)?;
    tracing::info!("Saved chain markdown report to {:?}", chain_md_path);

    Ok(())
}

pub(crate) fn chain_completion_status(
    engagement_strict: bool,
    run_valid: bool,
    chain_findings: &[ChainFinding],
) -> (&'static str, bool) {
    let critical = chain_findings
        .iter()
        .any(|f| f.finding.severity.to_lowercase() == "critical");
    let status = if critical {
        "completed_with_critical_findings"
    } else if engagement_strict && !run_valid {
        "failed_engagement_contract"
    } else {
        "completed"
    };
    (status, critical)
}

pub(crate) struct ChainCompletionDocContext<'a> {
    pub command: &'a str,
    pub run_id: &'a str,
    pub stage: &'a str,
    pub config_path: &'a str,
    pub campaign_name: &'a str,
    pub output_dir: &'a Path,
    pub started_utc: DateTime<Utc>,
    pub timeout_seconds: Option<u64>,
    pub status: &'a str,
    pub summary: &'a DepthMetricsSummary,
    pub critical: bool,
    pub final_total_entries: usize,
    pub final_unique_coverage_bits: usize,
    pub final_max_depth: usize,
    pub engagement_strict: bool,
    pub run_valid: bool,
    pub quality_failures: &'a [String],
    pub min_unique_coverage_bits: usize,
    pub min_completed_per_chain: usize,
}

pub(crate) fn build_chain_completion_doc(ctx: &ChainCompletionDocContext<'_>) -> serde_json::Value {
    let mut doc = completed_run_doc_with_window(
        ctx.command,
        ctx.run_id,
        ctx.status,
        ctx.stage,
        ctx.config_path,
        ctx.campaign_name,
        ctx.output_dir,
        ctx.started_utc,
        ctx.timeout_seconds,
    );
    doc["metrics"] = serde_json::json!({
        "chain_findings_total": ctx.summary.total_findings,
        "critical_findings": ctx.critical,
        "corpus_entries": ctx.final_total_entries,
        "unique_coverage_bits": ctx.final_unique_coverage_bits,
        "max_depth": ctx.final_max_depth,
        "d_mean": ctx.summary.d_mean,
        "p_deep": ctx.summary.p_deep,
    });
    doc["engagement"] = serde_json::json!({
        "strict": ctx.engagement_strict,
        "valid_run": ctx.run_valid,
        "failures": ctx.quality_failures,
        "thresholds": {
            "min_unique_coverage_bits": ctx.min_unique_coverage_bits,
            "min_completed_per_chain": ctx.min_completed_per_chain,
        }
    });
    doc
}

pub(crate) fn save_standard_chain_report(
    campaign_name: &str,
    chain_findings: &[ChainFinding],
    reporting: ReportingConfig,
    run_execution_count: u64,
) -> anyhow::Result<()> {
    let standard_findings: Vec<_> = chain_findings.iter().map(|cf| cf.to_finding()).collect();
    let mut report = FuzzReport::new(
        campaign_name.to_string(),
        standard_findings,
        zk_core::CoverageMap::default(),
        reporting,
    );
    report.statistics.total_executions = run_execution_count;
    report.save_to_files()
}

pub(crate) struct ChainSaveContext<'a> {
    pub output_dir: &'a Path,
    pub command: &'a str,
    pub run_id: &'a str,
    pub config_path: &'a str,
    pub campaign_name: &'a str,
    pub started_utc: DateTime<Utc>,
    pub timeout_seconds: Option<u64>,
}

pub(crate) fn save_chain_reports_and_standard_or_emit_failure(
    save_ctx: &ChainSaveContext<'_>,
    report_ctx: &ChainReportContext<'_>,
    seed: Option<u64>,
    reporting: ReportingConfig,
    run_execution_count: u64,
) -> anyhow::Result<()> {
    if let Err(err) = save_chain_reports_bundle(save_ctx.output_dir, save_ctx.config_path, seed, report_ctx) {
        write_failed_mode_run_artifact_with_error(
            save_ctx.output_dir,
            save_ctx.command,
            save_ctx.run_id,
            "save_chain_reports",
            save_ctx.config_path,
            save_ctx.campaign_name,
            save_ctx.started_utc,
            save_ctx.timeout_seconds,
            format!("{:#}", err),
        );
        return Err(err);
    }

    if let Err(err) = save_standard_chain_report(
        report_ctx.campaign_name,
        report_ctx.chain_findings,
        reporting,
        run_execution_count,
    ) {
        write_failed_mode_run_artifact_with_error(
            save_ctx.output_dir,
            save_ctx.command,
            save_ctx.run_id,
            "save_standard_report",
            save_ctx.config_path,
            save_ctx.campaign_name,
            save_ctx.started_utc,
            save_ctx.timeout_seconds,
            format!("{:#}", err),
        );
        return Err(err);
    }

    Ok(())
}

pub(crate) struct ChainFinalizeContext<'a> {
    pub completion_ctx: ChainCompletionDocContext<'a>,
    pub output_dir: &'a PathBuf,
    pub run_id: &'a str,
    pub engagement_strict: bool,
    pub run_valid: bool,
    pub critical: bool,
}

pub(crate) fn finalize_chain_run(ctx: ChainFinalizeContext<'_>) -> anyhow::Result<()> {
    let doc = build_chain_completion_doc(&ctx.completion_ctx);
    write_run_artifacts(ctx.output_dir, ctx.run_id, &doc);

    if ctx.critical {
        anyhow::bail!("Chain run produced CRITICAL findings (see chain_report.json/report.json)");
    }
    if ctx.engagement_strict && !ctx.run_valid {
        anyhow::bail!(
            "Strict chain run failed engagement contract; see chain_report.json for details"
        );
    }
    Ok(())
}
