use std::path::Path;

use zk_fuzzer::chain_fuzzer::{ChainCorpusMeta, ChainSpec};

use crate::chain_completed_and_unique_cov_from_path;

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
