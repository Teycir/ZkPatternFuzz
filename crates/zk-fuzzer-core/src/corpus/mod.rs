//! Corpus management for test cases
//!
//! Handles storage, persistence, and minimization of test cases.
//!
//! # Modules
//!
//! - [`minimizer`] - Basic corpus minimization (greedy set cover)
//! - [`delta_debug`] - Delta debugging for test case minimization
//! - [`deduplication`] - Semantic deduplication of findings
//! - [`storage`] - Corpus persistence

pub mod deduplication;
pub mod delta_debug;
pub mod minimizer;
pub mod storage;

pub use deduplication::{
    calculate_confidence, DeduplicationConfig, DeduplicationStats, FindingCluster, InputPattern,
    SemanticDeduplicator, SemanticFingerprint,
};
pub use delta_debug::{
    binary_minimize, minimize_test_case, DeltaDebugConfig, DeltaDebugStats, DeltaDebugger,
    OracleResult,
};

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use zk_core::{FieldElement, TestCase, TestMetadata};

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
        let mut entries = self.entries.write();
        let mut index = self.coverage_index.write();

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
        let entries = self.entries.read();
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

        // Defensive path (should be unreachable due to energy sum matching selection).
        entries.last().cloned()
    }

    /// Get corpus size
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Check if corpus is empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Get all entries (for persistence)
    pub fn all_entries(&self) -> Vec<CorpusEntry> {
        self.entries.read().clone()
    }

    /// Get entries that discovered new coverage
    pub fn interesting_entries(&self) -> Vec<CorpusEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.discovered_new_coverage)
            .cloned()
            .collect()
    }

    /// Decay energy of all entries (called periodically)
    pub fn decay_energy(&self, factor: f64) {
        let mut entries = self.entries.write();
        for entry in entries.iter_mut() {
            entry.energy = ((entry.energy as f64) * factor).round() as usize;
        }
    }

    /// Save corpus to disk
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(ref path) = self.persistence_path {
            let entries = self.entries.read();
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
                let mut loaded_entries = serializable.to_entries();
                let original_loaded_count = loaded_entries.len();

                if loaded_entries.len() > self.max_size {
                    tracing::warn!(
                        "Loaded corpus has {} entries, truncating to max_size={}",
                        loaded_entries.len(),
                        self.max_size
                    );
                    loaded_entries.truncate(self.max_size);
                }

                let mut entries = self.entries.write();
                let mut index = self.coverage_index.write();

                entries.clear();
                index.clear();

                for entry in loaded_entries {
                    if index.contains_key(&entry.coverage_hash) {
                        continue;
                    }
                    if entries.len() >= self.max_size {
                        break;
                    }
                    let i = entries.len();
                    index.insert(entry.coverage_hash, i);
                    entries.push(entry);
                }

                tracing::info!(
                    "Loaded {} corpus entries from {:?} (source entries: {})",
                    entries.len(),
                    path,
                    original_loaded_count
                );
            }
        }
        Ok(())
    }

    /// Phase 0 Fix: Minimize corpus to smallest set that maintains coverage
    ///
    /// Uses greedy set cover algorithm to remove redundant test cases.
    /// Returns statistics about the minimization.
    pub fn minimize(&self) -> minimizer::MinimizationStats {
        let mut entries = self.entries.write();
        let original_size = entries.len();

        if original_size == 0 {
            return minimizer::MinimizationStats::compute(0, 0);
        }

        // First deduplicate, then minimize
        let deduped = minimizer::deduplicate_corpus(&entries);
        let minimized = minimizer::minimize_corpus(&deduped);

        let minimized_size = minimized.len();

        // Rebuild the corpus with minimized entries
        let mut index = self.coverage_index.write();
        entries.clear();
        index.clear();

        for (i, entry) in minimized.into_iter().enumerate() {
            index.insert(entry.coverage_hash, i);
            entries.push(entry);
        }

        let stats = minimizer::MinimizationStats::compute(original_size, minimized_size);
        tracing::info!(
            "Corpus minimized: {} → {} entries ({:.1}% reduction)",
            stats.original_size,
            stats.minimized_size,
            stats.reduction_percentage
        );

        stats
    }

    /// Phase 0 Fix: Get max size configuration
    pub fn max_size(&self) -> usize {
        self.max_size
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
                    .map(|hex| FieldElement::from_hex_checked(hex))
                    .collect();

                match inputs {
                    Ok(inputs) => Some({
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
                    }),
                    Err(err) => {
                        tracing::warn!("Failed to parse persisted corpus entry inputs: {}", err);
                        None
                    }
                }
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
#[path = "mod_tests.rs"]
mod tests;
