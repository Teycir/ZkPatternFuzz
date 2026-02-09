//! Mode 3: Chain Corpus - Persistence for multi-step chains
//!
//! Chain fuzzing is expensive. This module provides persistence for
//! chain corpus entries to avoid losing coverage state between runs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zk_core::FieldElement;

/// Corpus for chain fuzzing with persistence support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCorpus {
    /// Corpus entries
    entries: Vec<ChainCorpusEntry>,
    /// Storage path for persistence
    #[serde(skip)]
    storage_path: Option<PathBuf>,
}

/// A single entry in the chain corpus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCorpusEntry {
    /// Name of the chain spec this entry is for
    pub spec_name: String,
    /// Inputs that were used (keyed by circuit_ref)
    pub inputs: HashMap<String, Vec<String>>, // Hex-encoded field elements
    /// Coverage bits discovered by this entry
    pub coverage_bits: u64,
    /// Maximum depth reached in execution
    pub depth_reached: usize,
    /// Near-miss score (0.0 to 1.0) - higher means closer to violation
    pub near_miss_score: f64,
    /// Whether this entry triggered a violation
    pub triggered_violation: bool,
    /// Execution count for this entry
    #[serde(default)]
    pub execution_count: usize,
}

impl ChainCorpusEntry {
    /// Create a new corpus entry
    pub fn new(
        spec_name: impl Into<String>,
        inputs: HashMap<String, Vec<FieldElement>>,
        coverage_bits: u64,
        depth_reached: usize,
    ) -> Self {
        // Convert FieldElements to hex strings for serialization
        let inputs_hex: HashMap<String, Vec<String>> = inputs.into_iter()
            .map(|(k, v)| (k, v.iter().map(|fe| fe.to_hex()).collect()))
            .collect();

        Self {
            spec_name: spec_name.into(),
            inputs: inputs_hex,
            coverage_bits,
            depth_reached,
            near_miss_score: 0.0,
            triggered_violation: false,
            execution_count: 1,
        }
    }

    /// Set the near-miss score
    pub fn with_near_miss(mut self, score: f64) -> Self {
        self.near_miss_score = score;
        self
    }

    /// Mark as having triggered a violation
    pub fn with_violation(mut self) -> Self {
        self.triggered_violation = true;
        self
    }

    /// Get inputs as FieldElements
    pub fn get_inputs(&self) -> HashMap<String, Vec<FieldElement>> {
        self.inputs.iter()
            .map(|(k, v)| {
                let fes: Vec<FieldElement> = v.iter()
                    .filter_map(|hex| FieldElement::from_hex(hex).ok())
                    .collect();
                (k.clone(), fes)
            })
            .collect()
    }

    /// Check if this entry is interesting (worth keeping)
    pub fn is_interesting(&self) -> bool {
        self.triggered_violation
            || self.near_miss_score > 0.5
            || self.coverage_bits > 0
    }

    /// Compute a priority score for this entry (for mutation selection)
    pub fn priority_score(&self) -> f64 {
        let mut score = 0.0;

        // Higher near-miss = higher priority
        score += self.near_miss_score * 3.0;

        // Novel coverage = higher priority
        if self.coverage_bits > 0 {
            score += (self.coverage_bits as f64).log2() * 0.5;
        }

        // Deeper chains = slightly higher priority
        score += (self.depth_reached as f64) * 0.2;

        // Violations are important but less priority for re-mutation
        if self.triggered_violation {
            score += 1.0;
        }

        // Penalize frequently executed entries
        score -= (self.execution_count as f64).log2() * 0.1;

        score.max(0.0)
    }
}

impl ChainCorpus {
    /// Create a new empty corpus
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            storage_path: None,
        }
    }

    /// Create a corpus with a storage path
    pub fn with_storage(path: impl Into<PathBuf>) -> Self {
        Self {
            entries: Vec::new(),
            storage_path: Some(path.into()),
        }
    }

    /// Set the storage path
    pub fn set_storage_path(&mut self, path: impl Into<PathBuf>) {
        self.storage_path = Some(path.into());
    }

    /// Add an entry to the corpus
    pub fn add(&mut self, entry: ChainCorpusEntry) {
        // Check for duplicates based on inputs hash
        let inputs_hash = Self::hash_inputs(&entry.inputs);
        
        // Update if exists with same inputs, otherwise add
        if let Some(existing) = self.entries.iter_mut()
            .find(|e| Self::hash_inputs(&e.inputs) == inputs_hash)
        {
            existing.execution_count += 1;
            // Update coverage if better
            if entry.coverage_bits > existing.coverage_bits {
                existing.coverage_bits = entry.coverage_bits;
            }
            // Update near-miss if better
            if entry.near_miss_score > existing.near_miss_score {
                existing.near_miss_score = entry.near_miss_score;
            }
            // Mark violation if found
            if entry.triggered_violation {
                existing.triggered_violation = true;
            }
        } else {
            self.entries.push(entry);
        }
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries
    pub fn entries(&self) -> &[ChainCorpusEntry] {
        &self.entries
    }

    /// Get entries for a specific chain
    pub fn entries_for_chain(&self, spec_name: &str) -> Vec<&ChainCorpusEntry> {
        self.entries.iter()
            .filter(|e| e.spec_name == spec_name)
            .collect()
    }

    /// Get interesting entries (for mutation seeds)
    pub fn interesting_entries(&self) -> Vec<&ChainCorpusEntry> {
        self.entries.iter()
            .filter(|e| e.is_interesting())
            .collect()
    }

    /// Get top N entries by priority score
    pub fn top_entries(&self, n: usize) -> Vec<&ChainCorpusEntry> {
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by(|a, b| {
            b.priority_score().partial_cmp(&a.priority_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        entries.into_iter().take(n).collect()
    }

    /// Save the corpus to disk
    pub fn save(&self) -> anyhow::Result<()> {
        let path = match &self.storage_path {
            Some(p) => p,
            None => return Err(anyhow::anyhow!("No storage path set")),
        };

        // Create directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&self.entries)?;
        std::fs::write(path, json)?;

        tracing::info!("Saved chain corpus with {} entries to {:?}", self.entries.len(), path);
        Ok(())
    }

    /// Load a corpus from disk
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::with_storage(path));
        }

        let json = std::fs::read_to_string(path)?;
        let entries: Vec<ChainCorpusEntry> = serde_json::from_str(&json)?;

        tracing::info!("Loaded chain corpus with {} entries from {:?}", entries.len(), path);

        Ok(Self {
            entries,
            storage_path: Some(path.to_path_buf()),
        })
    }

    /// Merge another corpus into this one
    pub fn merge(&mut self, other: &ChainCorpus) {
        for entry in &other.entries {
            self.add(entry.clone());
        }
    }

    /// Remove entries that don't meet minimum criteria
    pub fn prune(&mut self, min_coverage: u64, min_near_miss: f64) {
        self.entries.retain(|e| {
            e.triggered_violation
                || e.coverage_bits >= min_coverage
                || e.near_miss_score >= min_near_miss
        });
    }

    /// Compact the corpus by removing duplicates and low-value entries
    pub fn compact(&mut self, max_entries: usize) {
        if self.entries.len() <= max_entries {
            return;
        }

        // Sort by priority and keep top entries
        self.entries.sort_by(|a, b| {
            b.priority_score().partial_cmp(&a.priority_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        self.entries.truncate(max_entries);
    }

    /// Hash inputs for deduplication
    fn hash_inputs(inputs: &HashMap<String, Vec<String>>) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        
        let mut keys: Vec<_> = inputs.keys().collect();
        keys.sort();
        
        for key in keys {
            key.hash(&mut hasher);
            if let Some(values) = inputs.get(key) {
                for v in values {
                    v.hash(&mut hasher);
                }
            }
        }

        hasher.finish()
    }

    /// Get corpus statistics
    pub fn stats(&self) -> CorpusStats {
        let total_entries = self.entries.len();
        let interesting_entries = self.entries.iter().filter(|e| e.is_interesting()).count();
        let violation_entries = self.entries.iter().filter(|e| e.triggered_violation).count();
        let total_coverage: u64 = self.entries.iter().map(|e| e.coverage_bits).sum();
        let avg_near_miss = if total_entries > 0 {
            self.entries.iter().map(|e| e.near_miss_score).sum::<f64>() / total_entries as f64
        } else {
            0.0
        };
        let max_depth = self.entries.iter().map(|e| e.depth_reached).max().unwrap_or(0);

        CorpusStats {
            total_entries,
            interesting_entries,
            violation_entries,
            total_coverage,
            avg_near_miss,
            max_depth,
        }
    }
}

impl Default for ChainCorpus {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the corpus
#[derive(Debug, Clone)]
pub struct CorpusStats {
    pub total_entries: usize,
    pub interesting_entries: usize,
    pub violation_entries: usize,
    pub total_coverage: u64,
    pub avg_near_miss: f64,
    pub max_depth: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_entry(name: &str, coverage: u64, near_miss: f64) -> ChainCorpusEntry {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        // Create unique inputs based on name to avoid deduplication
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        let unique_value = hasher.finish();
        
        let mut inputs = HashMap::new();
        inputs.insert("circuit_a".to_string(), vec![FieldElement::from_u64(unique_value)]);
        
        ChainCorpusEntry::new(name, inputs, coverage, 2)
            .with_near_miss(near_miss)
    }

    #[test]
    fn test_add_and_get() {
        let mut corpus = ChainCorpus::new();
        
        corpus.add(create_test_entry("chain_a", 10, 0.5));
        corpus.add(create_test_entry("chain_b", 20, 0.8));

        assert_eq!(corpus.len(), 2);
        assert_eq!(corpus.entries_for_chain("chain_a").len(), 1);
    }

    #[test]
    fn test_interesting_entries() {
        let mut corpus = ChainCorpus::new();
        
        corpus.add(create_test_entry("chain_a", 10, 0.9)); // Interesting (high near-miss)
        corpus.add(create_test_entry("chain_b", 0, 0.1));  // Not interesting

        let interesting = corpus.interesting_entries();
        assert_eq!(interesting.len(), 1);
        assert_eq!(interesting[0].spec_name, "chain_a");
    }

    #[test]
    fn test_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("chain_corpus.json");

        let mut corpus = ChainCorpus::with_storage(&path);
        corpus.add(create_test_entry("chain_a", 10, 0.5));
        corpus.add(create_test_entry("chain_b", 20, 0.8));
        corpus.save().unwrap();

        let loaded = ChainCorpus::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_merge() {
        let mut corpus1 = ChainCorpus::new();
        corpus1.add(create_test_entry("chain_a", 10, 0.5));

        let mut corpus2 = ChainCorpus::new();
        corpus2.add(create_test_entry("chain_b", 20, 0.8));

        corpus1.merge(&corpus2);
        assert_eq!(corpus1.len(), 2);
    }

    #[test]
    fn test_compact() {
        let mut corpus = ChainCorpus::new();
        
        for i in 0..10 {
            corpus.add(create_test_entry(&format!("chain_{}", i), i as u64, i as f64 * 0.1));
        }

        corpus.compact(5);
        assert_eq!(corpus.len(), 5);
    }

    #[test]
    fn test_priority_score() {
        let entry_high = create_test_entry("chain_a", 100, 0.9);
        let entry_low = create_test_entry("chain_b", 0, 0.1);

        assert!(entry_high.priority_score() > entry_low.priority_score());
    }
}
