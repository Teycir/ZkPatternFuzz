//! Corpus minimization
//!
//! Reduces corpus size while maintaining coverage.

use super::CorpusEntry;
use std::collections::HashSet;

/// Minimize a corpus to the smallest set that maintains coverage
pub fn minimize_corpus(entries: &[CorpusEntry]) -> Vec<CorpusEntry> {
    if entries.is_empty() {
        return Vec::new();
    }

    // Greedy set cover algorithm
    let mut coverage_needed: HashSet<u64> = entries.iter().map(|e| e.coverage_hash).collect();
    let mut minimized = Vec::new();
    let mut remaining: Vec<_> = entries.to_vec();

    while !coverage_needed.is_empty() && !remaining.is_empty() {
        // Find entry that covers the most uncovered hashes
        // In this simple case, each entry has one coverage hash
        // More sophisticated: track individual constraint coverage

        if let Some(idx) = remaining
            .iter()
            .enumerate()
            .filter(|(_, e)| coverage_needed.contains(&e.coverage_hash))
            .max_by_key(|(_, e)| {
                // Prefer entries with new coverage and higher energy
                let new_cov_bonus = if e.discovered_new_coverage { 100 } else { 0 };
                new_cov_bonus + e.energy
            })
            .map(|(i, _)| i)
        {
            let entry = remaining.remove(idx);
            coverage_needed.remove(&entry.coverage_hash);
            minimized.push(entry);
        } else {
            break;
        }
    }

    minimized
}

/// Remove duplicate test cases (same inputs)
pub fn deduplicate_corpus(entries: &[CorpusEntry]) -> Vec<CorpusEntry> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for entry in entries {
        // Create a hash of inputs for deduplication
        let input_hash = compute_input_hash(&entry.test_case.inputs);
        if seen.insert(input_hash) {
            result.push(entry.clone());
        }
    }

    result
}

fn compute_input_hash(inputs: &[zk_core::FieldElement]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    for input in inputs {
        input.0.hash(&mut hasher);
    }
    hasher.finish()
}

/// Statistics about corpus minimization
#[derive(Debug)]
pub struct MinimizationStats {
    pub original_size: usize,
    pub minimized_size: usize,
    pub reduction_percentage: f64,
}

impl MinimizationStats {
    pub fn compute(original: usize, minimized: usize) -> Self {
        let reduction = if original > 0 {
            ((original - minimized) as f64 / original as f64) * 100.0
        } else {
            0.0
        };

        Self {
            original_size: original,
            minimized_size: minimized,
            reduction_percentage: reduction,
        }
    }
}

#[cfg(test)]
#[path = "minimizer_tests.rs"]
mod tests;
