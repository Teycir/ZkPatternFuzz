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
        if !seen.contains(&input_hash) {
            seen.insert(input_hash);
            result.push(entry.clone());
        }
    }

    result
}

fn compute_input_hash(inputs: &[crate::fuzzer::FieldElement]) -> u64 {
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
mod tests {
    use super::*;
    use crate::fuzzer::{FieldElement, TestCase, TestMetadata};

    fn create_entry(coverage_hash: u64, new_coverage: bool) -> CorpusEntry {
        let mut entry = CorpusEntry::new(
            TestCase {
                inputs: vec![FieldElement::from_u64(coverage_hash)],
                expected_output: None,
                metadata: TestMetadata::default(),
            },
            coverage_hash,
        );
        if new_coverage {
            entry = entry.with_new_coverage();
        }
        entry
    }

    #[test]
    fn test_minimize_corpus() {
        let entries = vec![
            create_entry(1, true),
            create_entry(2, false),
            create_entry(1, false), // Duplicate coverage
            create_entry(3, true),
        ];

        let minimized = minimize_corpus(&entries);

        // Should keep 3 unique coverage hashes
        assert_eq!(minimized.len(), 3);

        // Should prefer entries with new coverage
        let new_cov_count = minimized
            .iter()
            .filter(|e| e.discovered_new_coverage)
            .count();
        assert_eq!(new_cov_count, 2);
    }

    #[test]
    fn test_deduplicate_corpus() {
        let entries = vec![
            create_entry(1, true),
            create_entry(1, false), // Same input (same coverage_hash used for input)
            create_entry(2, true),
        ];

        let deduped = deduplicate_corpus(&entries);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_minimization_stats() {
        let stats = MinimizationStats::compute(100, 30);
        assert_eq!(stats.original_size, 100);
        assert_eq!(stats.minimized_size, 30);
        assert!((stats.reduction_percentage - 70.0).abs() < 0.1);
    }
}
