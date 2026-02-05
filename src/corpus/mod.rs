//! Corpus management for test cases
//!
//! Handles storage, persistence, and minimization of test cases.

pub mod deduplication;
pub mod minimizer;
pub mod storage;

pub use deduplication::{
    SemanticDeduplicator, SemanticFingerprint, DeduplicationConfig, 
    DeduplicationStats, FindingCluster, calculate_confidence, InputPattern,
};

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
    ///
    /// # Thread Safety
    /// This method holds write locks for the entire operation to prevent
    /// TOCTOU race conditions where multiple threads could add the same
    /// coverage hash between check and insert.
    pub fn add(&self, entry: CorpusEntry) -> bool {
        let coverage_hash = entry.coverage_hash;

        // Acquire write locks upfront to prevent TOCTOU race condition
        // Previously, we checked with a read lock, released it, then acquired
        // a write lock - allowing another thread to insert the same hash
        let mut entries = self.entries.write().unwrap();
        let mut index = self.coverage_index.write().unwrap();

        // Check for duplicate coverage AFTER acquiring write locks
        if index.contains_key(&coverage_hash) {
            return false;
        }

        // Check size limit and evict if necessary
        if entries.len() >= self.max_size {
            // Find and remove the lowest energy entry
            // Using swap_remove for O(1) removal, then only update the swapped entry's index
            if let Some(min_idx) = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.energy)
                .map(|(i, _)| i)
            {
                let removed = entries.swap_remove(min_idx);
                index.remove(&removed.coverage_hash);

                // Only update the index for the entry that was swapped into min_idx position
                // (if any entry was swapped, i.e., min_idx wasn't the last element)
                if min_idx < entries.len() {
                    let swapped_hash = entries[min_idx].coverage_hash;
                    index.insert(swapped_hash, min_idx);
                }
            }
        }

        let new_idx = entries.len();
        index.insert(coverage_hash, new_idx);
        entries.push(entry);

        true
    }

    /// Get a random entry from the corpus using energy-weighted selection
    ///
    /// Entries with higher energy are more likely to be selected.
    /// Each entry has a minimum effective energy of 1 to ensure selection
    /// is always possible even after aggressive energy decay.
    ///
    /// # Panics
    /// This function will panic if the invariant `total_energy > 0` is violated,
    /// which should never happen given the `.max(1)` guarantee.
    pub fn get_random(&self, rng: &mut impl rand::Rng) -> Option<CorpusEntry> {
        let entries = self.entries.read().unwrap();
        if entries.is_empty() {
            return None;
        }

        // Energy-weighted selection with minimum energy guarantee
        // Each entry contributes at least 1 to total_energy, preventing division by zero
        // even after aggressive decay_energy() calls that might set all energies to 0
        let total_energy: usize = entries.iter().map(|e| e.energy.max(1)).sum();

        // Invariant: total_energy >= entries.len() >= 1
        debug_assert!(
            total_energy > 0,
            "Total energy must be > 0 when corpus is non-empty (got {} entries)",
            entries.len()
        );

        let mut target = rng.gen_range(0..total_energy);
        for entry in entries.iter() {
            let energy = entry.energy.max(1);
            if target < energy {
                return Some(entry.clone());
            }
            target -= energy;
        }

        // Fallback (should be unreachable due to energy sum matching selection)
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
    use std::sync::Arc;
    use std::thread;

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

    #[test]
    fn test_corpus_concurrent_add_no_duplicates() {
        // Test that concurrent adds of the same coverage hash don't result in duplicates
        let corpus = Arc::new(Corpus::new(1000));
        let num_threads = 10;
        let entries_per_thread = 100;

        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let corpus = Arc::clone(&corpus);
                thread::spawn(move || {
                    for i in 0..entries_per_thread {
                        // Use same coverage hash across threads to test deduplication
                        let hash = i as u64;
                        let entry = CorpusEntry::new(
                            TestCase {
                                inputs: vec![FieldElement::from_u64((thread_id * 1000 + i) as u64)],
                                expected_output: None,
                                metadata: TestMetadata::default(),
                            },
                            hash,
                        );
                        corpus.add(entry);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have exactly entries_per_thread unique hashes
        // (not num_threads * entries_per_thread duplicates)
        assert_eq!(corpus.len(), entries_per_thread);
    }

    #[test]
    fn test_get_random_with_zero_energy() {
        let corpus = Corpus::new(100);

        // Add entries with zero energy
        for i in 0..5u64 {
            let mut entry = CorpusEntry::new(
                TestCase {
                    inputs: vec![FieldElement::from_u64(i)],
                    expected_output: None,
                    metadata: TestMetadata::default(),
                },
                i,
            );
            entry.energy = 0; // Force zero energy
            corpus.add(entry);
        }

        // Should still be able to select (due to .max(1) guarantee)
        let mut rng = rand::thread_rng();
        let selected = corpus.get_random(&mut rng);
        assert!(selected.is_some());
    }
}
