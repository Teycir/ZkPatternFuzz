use std::path::Path;

use zk_fuzzer::chain_fuzzer::metrics::DepthMetricsSummary;
use zk_fuzzer::chain_fuzzer::DepthMetrics;
use zk_fuzzer::chain_fuzzer::{ChainCorpusMeta, ChainFinding, ChainSpec};

use crate::chain_completed_and_unique_cov_from_path;

pub(crate) struct ChainEngagementSettings {
    pub strict: bool,
    pub min_unique_coverage_bits: usize,
    pub min_completed_per_chain: usize,
}

pub(crate) struct ChainQualityAssessment {
    pub engagement: ChainEngagementSettings,
    pub quality_failures: Vec<String>,
    pub run_valid: bool,
    pub summary: DepthMetricsSummary,
}

pub(crate) fn load_chain_engagement_settings(
    config: &zk_fuzzer::config::FuzzConfig,
) -> ChainEngagementSettings {
    ChainEngagementSettings {
        strict: config
            .campaign
            .parameters
            .additional
            .get_bool("engagement_strict")
            .unwrap_or(true),
        min_unique_coverage_bits: config
            .campaign
            .parameters
            .additional
            .get_usize("engagement_min_chain_unique_coverage_bits")
            .unwrap_or(2),
        min_completed_per_chain: config
            .campaign
            .parameters
            .additional
            .get_usize("engagement_min_chain_completed_per_chain")
            .unwrap_or(1),
    }
}

pub(crate) fn assess_chain_quality(
    config: &zk_fuzzer::config::FuzzConfig,
    chains: &[ChainSpec],
    final_meta: Option<&ChainCorpusMeta>,
    corpus_path: &Path,
    chain_findings: &[ChainFinding],
) -> anyhow::Result<ChainQualityAssessment> {
    let engagement = load_chain_engagement_settings(config);
    let quality_failures = collect_chain_quality_failures(
        chains,
        final_meta,
        corpus_path,
        engagement.min_completed_per_chain,
        engagement.min_unique_coverage_bits,
    )?;
    let run_valid = quality_failures.is_empty();
    let metrics = DepthMetrics::new(chain_findings.to_vec());
    let summary = metrics.summary();
    Ok(ChainQualityAssessment {
        engagement,
        quality_failures,
        run_valid,
        summary,
    })
}

pub(crate) fn collect_chain_quality_failures(
    chains: &[ChainSpec],
    final_meta: Option<&ChainCorpusMeta>,
    corpus_path: &Path,
    min_completed_per_chain: usize,
    min_unique_coverage_bits: usize,
) -> anyhow::Result<Vec<String>> {
    let mut quality_failures = Vec::new();

    for chain in chains {
        let (completed, unique_cov): (usize, usize) = if let Some(meta) = final_meta {
            match meta.per_chain.get(&chain.name) {
                Some(m) => (m.completed_traces, m.unique_coverage_bits),
                None => {
                    tracing::warn!(
                        "Chain corpus metadata missing per-chain entry for '{}'",
                        chain.name
                    );
                    (0, 0)
                }
            }
        } else {
            chain_completed_and_unique_cov_from_path(corpus_path, &chain.name)?
        };

        if completed < min_completed_per_chain {
            quality_failures.push(format!(
                "chain '{}' completed_traces={} < min_completed_per_chain={}",
                chain.name, completed, min_completed_per_chain
            ));
        }
        if unique_cov < min_unique_coverage_bits {
            quality_failures.push(format!(
                "chain '{}' unique_coverage_bits={} < min_unique_coverage_bits={}",
                chain.name, unique_cov, min_unique_coverage_bits
            ));
        }
    }

    Ok(quality_failures)
}
