use std::path::Path;

use zk_fuzzer::chain_fuzzer::metrics::DepthMetricsSummary;
use zk_fuzzer::chain_fuzzer::ChainFinding;

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
