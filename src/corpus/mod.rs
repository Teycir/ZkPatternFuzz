//! Corpus management for test cases
//!
//! Handles storage, persistence, and minimization of test cases.

pub mod storage;
pub mod minimizer;

pub use storage::*;
pub use minimizer::*;

use crate::fuzzer::{FieldElement, TestCase, TestMetadata};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Corpus entry with additional metadata
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub test_case: TestCase,
    pub coverage_hash: u64,
    pub discovered_new_coverage: bool,
    pub execution_count: u64,
    pub last_mutation_time: std::time::Instant,
    pub energy: usize,
    pub parent_id: Option<usize>,
}

impl CorpusEntry {
    pub fn new(test_case: TestCase, coverage_hash: u64) -> Self {
        Self {
            test_case,
            coverage_hash,
            discovered_new_coverage: false,
            execution_count: 1,
            last_mutation_time: std::time::Instant::now(),
            energy: 10, // Default energy
            parent_id: None,
        }
    }

    pub fn with_new_coverage(mut self) -> Self {
        self.discovered_new_coverage = true;
        self.energy = 60; // Higher energy for new coverage
        self
    }

    pub fn with_parent(mut self, parent_id: usize) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Decrease energy after mutation
    pub fn consume_energy(&mut self) {
        if self.energy > 0 {
            self.energy -= 1;
        }
    }

    /// Check if entry still has energy for mutation
    pub fn has_energy(&self) -> bool {
        self.energy > 0
    }
}

/// Thread-safe corpus for concurrent access
#[derive(Debug)]
pub struct Corpus {
    /// All test cases in the corpus
    entries: RwLock<Vec<CorpusEntry>>,
    /// Map from coverage hash to entry index for deduplication
    coverage_index: RwLock<HashMap<u64, usize>>,
    /// Maximum corpus size
    max_size: usize,
    /// Path for persistence
    persistence_path: Option<std::path::PathBuf>,
}

impl Corpus {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            coverage_index: RwLock::new(HashMap::new()),
            max_size,
            persistence_path: None,
        }
    }

    pub fn with_persistence(mut self, path: std::path::PathBuf) -> Self {
        self.persistence_path = Some(path);
        self
    }

    /// Add a test case to the corpus
    /// Returns true if the case was added (new coverage), false if duplicate
    pub fn add(&self, entry: CorpusEntry) -> bool {
        let coverage_hash = entry.coverage_hash;

        // Check for duplicate coverage
        {
            let index = self.coverage_index.read().unwrap();
            if index.contains_key(&coverage_hash) {
                return false;
            }
        }

        // Add to corpus
        {
            let mut entries = self.entries.write().unwrap();
            let mut index = self.coverage_index.write().unwrap();

            // Check size limit
            if entries.len() >= self.max_size {
                // Remove lowest energy entry
                if let Some(min_idx) = entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.energy)
                    .map(|(i, _)| i)
                {
                    let removed = entries.remove(min_idx);
                    index.remove(&removed.coverage_hash);

                    // Rebuild index to ensure consistency
                    // This is safer than trying to update indices incrementally
                    // which can lead to corruption if the removed entry's hash
                    // collides or if there are edge cases
                    index.clear();
                    for (i, entry) in entries.iter().enumerate() {
                        index.insert(entry.coverage_hash, i);
                    }
                }
            }

            let new_idx = entries.len();
            index.insert(coverage_hash, new_idx);
            entries.push(entry);
        }

        true
    }

    /// Get a random entry from the corpus
    pub fn get_random(&self, rng: &mut impl rand::Rng) -> Option<CorpusEntry> {
        let entries = self.entries.read().unwrap();
        if entries.is_empty() {
            return None;
        }

        // Energy-weighted selection
        // Note: total_energy can never be 0 because we use max(1) for each entry
        // This ensures we always have valid energy for weighted selection
        let total_energy: usize = entries.iter().map(|e| e.energy.max(1)).sum();

        let mut target = rng.gen_range(0..total_energy);
        for entry in entries.iter() {
            let energy = entry.energy.max(1);
            if target < energy {
                return Some(entry.clone());
            }
            target -= energy;
        }

        entries.last().cloned()
    }

    /// Get corpus size
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Check if corpus is empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }

    /// Get all entries (for persistence)
    pub fn all_entries(&self) -> Vec<CorpusEntry> {
        self.entries.read().unwrap().clone()
    }

    /// Get entries that discovered new coverage
    pub fn interesting_entries(&self) -> Vec<CorpusEntry> {
        self.entries
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.discovered_new_coverage)
            .cloned()
            .collect()
    }

    /// Decay energy of all entries (called periodically)
    pub fn decay_energy(&self, factor: f64) {
        let mut entries = self.entries.write().unwrap();
        for entry in entries.iter_mut() {
            entry.energy = ((entry.energy as f64) * factor) as usize;
        }
    }

    /// Save corpus to disk
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(ref path) = self.persistence_path {
            let entries = self.entries.read().unwrap();
            let data = serde_json::to_string_pretty(&SerializableCorpus::from_entries(&entries))?;
            std::fs::create_dir_all(path)?;
            std::fs::write(path.join("corpus.json"), data)?;
            tracing::info!("Saved {} corpus entries to {:?}", entries.len(), path);
        }
        Ok(())
    }

    /// Load corpus from disk
    pub fn load(&self) -> anyhow::Result<()> {
        if let Some(ref path) = self.persistence_path {
            let corpus_file = path.join("corpus.json");
            if corpus_file.exists() {
                let data = std::fs::read_to_string(&corpus_file)?;
                let serializable: SerializableCorpus = serde_json::from_str(&data)?;
                
                let mut entries = self.entries.write().unwrap();
                let mut index = self.coverage_index.write().unwrap();
                
                for (i, entry) in serializable.to_entries().into_iter().enumerate() {
                    index.insert(entry.coverage_hash, i);
                    entries.push(entry);
                }
                
                tracing::info!("Loaded {} corpus entries from {:?}", entries.len(), path);
            }
        }
        Ok(())
    }
}

/// Serializable corpus format for persistence
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SerializableCorpus {
    version: String,
    entries: Vec<SerializableEntry>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SerializableEntry {
    inputs: Vec<String>, // Hex-encoded field elements
    coverage_hash: u64,
    discovered_new_coverage: bool,
}

impl SerializableCorpus {
    fn from_entries(entries: &[CorpusEntry]) -> Self {
        Self {
            version: "1.0".to_string(),
            entries: entries
                .iter()
                .map(|e| SerializableEntry {
                    inputs: e.test_case.inputs.iter().map(|fe| fe.to_hex()).collect(),
                    coverage_hash: e.coverage_hash,
                    discovered_new_coverage: e.discovered_new_coverage,
                })
                .collect(),
        }
    }

    fn to_entries(&self) -> Vec<CorpusEntry> {
        self.entries
            .iter()
            .filter_map(|e| {
                let inputs: Result<Vec<FieldElement>, _> = e
                    .inputs
                    .iter()
                    .map(|hex| FieldElement::from_hex(hex))
                    .collect();

                inputs.ok().map(|inputs| {
                    let test_case = TestCase {
                        inputs,
                        expected_output: None,
                        metadata: TestMetadata::default(),
                    };
                    let mut entry = CorpusEntry::new(test_case, e.coverage_hash);
                    if e.discovered_new_coverage {
                        entry = entry.with_new_coverage();
                    }
                    entry
                })
            })
            .collect()
    }
}

/// Shared corpus type for concurrent access
pub type SharedCorpus = Arc<Corpus>;

/// Create a new shared corpus
pub fn create_corpus(max_size: usize) -> SharedCorpus {
    Arc::new(Corpus::new(max_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_corpus_add() {
        let corpus = Corpus::new(100);
        
        let entry1 = CorpusEntry::new(
            TestCase {
                inputs: vec![FieldElement::zero()],
                expected_output: None,
                metadata: TestMetadata::default(),
            },
            12345,
        );

        assert!(corpus.add(entry1.clone()));
        assert_eq!(corpus.len(), 1);

        // Duplicate should not be added
        assert!(!corpus.add(entry1));
        assert_eq!(corpus.len(), 1);

        // Different coverage hash should be added
        let entry2 = CorpusEntry::new(
            TestCase {
                inputs: vec![FieldElement::one()],
                expected_output: None,
                metadata: TestMetadata::default(),
            },
            67890,
        );
        assert!(corpus.add(entry2));
        assert_eq!(corpus.len(), 2);
    }

    #[test]
    fn test_corpus_max_size() {
        let corpus = Corpus::new(2);

        for i in 0..5u64 {
            let entry = CorpusEntry::new(
                TestCase {
                    inputs: vec![FieldElement::from_u64(i)],
                    expected_output: None,
                    metadata: TestMetadata::default(),
                },
                i,
            );
            corpus.add(entry);
        }

        assert!(corpus.len() <= 2);
    }
}
