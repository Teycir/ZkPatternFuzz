use std::collections::HashSet;
use std::path::Path;

use zk_fuzzer::chain_fuzzer::{ChainCorpus, ChainCorpusMeta};

pub(crate) struct ChainBaselineMetrics {
    pub execution_count: u64,
    pub total_entries: usize,
    pub unique_coverage_bits: usize,
}

pub(crate) struct ChainFinalMetrics {
    pub meta: Option<ChainCorpusMeta>,
    pub execution_count: u64,
    pub total_entries: usize,
    pub unique_coverage_bits: usize,
    pub max_depth: usize,
}

pub(crate) struct ChainRunCorpusMetrics {
    pub baseline: ChainBaselineMetrics,
    pub final_metrics: ChainFinalMetrics,
    pub run_execution_count: u64,
}

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

pub(crate) fn load_chain_baseline_metrics(
    corpus_path: &Path,
    corpus_meta_path: &Path,
    resume: bool,
) -> anyhow::Result<ChainBaselineMetrics> {
    let execution_count = if resume {
        read_chain_execution_count(corpus_path)?
    } else {
        0
    };
    let baseline_meta = if resume && corpus_meta_path.exists() {
        read_chain_meta(corpus_meta_path)
    } else {
        None
    };
    let (total_entries, unique_coverage_bits): (usize, usize) = if !resume {
        (0, 0)
    } else if let Some(meta) = &baseline_meta {
        (meta.total_entries, meta.unique_coverage_bits)
    } else {
        let baseline_corpus = load_chain_corpus(corpus_path)?;
        let baseline_total_entries = baseline_corpus.len();
        let baseline_unique_coverage_bits = chain_unique_coverage_bits(&baseline_corpus);
        (baseline_total_entries, baseline_unique_coverage_bits)
    };

    Ok(ChainBaselineMetrics {
        execution_count,
        total_entries,
        unique_coverage_bits,
    })
}

pub(crate) fn load_chain_final_metrics(
    corpus_path: &Path,
    corpus_meta_path: &Path,
) -> anyhow::Result<ChainFinalMetrics> {
    let meta = if corpus_meta_path.exists() {
        read_chain_meta(corpus_meta_path)
    } else {
        None
    };

    let (total_entries, unique_coverage_bits, max_depth): (usize, usize, usize) =
        if let Some(meta) = &meta {
            (
                meta.total_entries,
                meta.unique_coverage_bits,
                meta.max_depth,
            )
        } else {
            let final_corpus = load_chain_corpus(corpus_path)?;
            let final_total_entries = final_corpus.len();
            let final_unique_coverage_bits = chain_unique_coverage_bits(&final_corpus);
            let final_max_depth = final_corpus.entries().iter().map(|e| e.depth_reached).max();
            let final_max_depth: usize = final_max_depth.unwrap_or_default();
            (
                final_total_entries,
                final_unique_coverage_bits,
                final_max_depth,
            )
        };

    let execution_count = read_chain_execution_count(corpus_path)?;

    Ok(ChainFinalMetrics {
        meta,
        execution_count,
        total_entries,
        unique_coverage_bits,
        max_depth,
    })
}

pub(crate) fn load_chain_run_corpus_metrics(
    corpus_path: &Path,
    corpus_meta_path: &Path,
    resume: bool,
) -> anyhow::Result<ChainRunCorpusMetrics> {
    let baseline = load_chain_baseline_metrics(corpus_path, corpus_meta_path, resume)?;
    let final_metrics = load_chain_final_metrics(corpus_path, corpus_meta_path)?;
    let run_execution_count = final_metrics
        .execution_count
        .saturating_sub(baseline.execution_count);
    Ok(ChainRunCorpusMetrics {
        baseline,
        final_metrics,
        run_execution_count,
    })
}
