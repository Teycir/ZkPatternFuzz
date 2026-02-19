use std::collections::HashSet;
use std::path::Path;

use zk_fuzzer::chain_fuzzer::{ChainCorpus, ChainCorpusMeta};

pub(crate) fn read_chain_meta(path: &Path) -> Option<ChainCorpusMeta> {
    match std::fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<ChainCorpusMeta>(&raw) {
            Ok(meta) => Some(meta),
            Err(err) => {
                tracing::warn!(
                    "Invalid chain corpus metadata '{}': {}",
                    path.display(),
                    err
                );
                None
            }
        },
        Err(err) => {
            tracing::warn!(
                "Failed to read chain corpus metadata '{}': {}",
                path.display(),
                err
            );
            None
        }
    }
}

pub(crate) fn load_chain_corpus(path: &Path) -> anyhow::Result<ChainCorpus> {
    if path.exists() {
        ChainCorpus::load(path).map_err(|err| {
            anyhow::anyhow!(
                "Failed to load chain corpus from '{}': {}",
                path.display(),
                err
            )
        })
    } else {
        Ok(ChainCorpus::with_storage(path))
    }
}

pub(crate) fn read_chain_execution_count(path: &Path) -> anyhow::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let corpus = load_chain_corpus(path)?;
    Ok(corpus
        .entries()
        .iter()
        .map(|entry| entry.execution_count as u64)
        .sum())
}

pub(crate) fn chain_unique_coverage_bits(corpus: &ChainCorpus) -> usize {
    corpus
        .entries()
        .iter()
        .map(|e| e.coverage_bits)
        .collect::<HashSet<_>>()
        .len()
}

pub(crate) fn chain_completed_and_unique_cov_from_path(
    path: &Path,
    chain_name: &str,
) -> anyhow::Result<(usize, usize)> {
    let corpus = load_chain_corpus(path)?;
    let entries: Vec<_> = corpus
        .entries()
        .iter()
        .filter(|e| e.spec_name == chain_name)
        .collect();
    let completed = entries.len();
    let unique_cov = entries
        .iter()
        .map(|e| e.coverage_bits)
        .collect::<HashSet<_>>()
        .len();
    Ok((completed, unique_cov))
}
