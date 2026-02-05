//! Corpus Synchronization for Distributed Fuzzing
//!
//! Handles synchronization of test case corpus across multiple nodes.

use super::{NodeId, SerializableCorpusEntry};
use crate::corpus::{CorpusEntry, SharedCorpus};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Strategy for corpus synchronization
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyncStrategy {
    /// Full sync - send entire corpus periodically
    Full,
    /// Incremental - only send new entries since last sync
    Incremental,
    /// Interesting only - only sync entries that found new coverage
    InterestingOnly,
    /// Energy-based - sync based on entry energy levels
    EnergyBased { min_energy: usize },
    /// Random sampling - sync a random sample
    RandomSample { sample_rate: f64 },
}

/// Configuration for corpus synchronization
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Synchronization strategy
    pub strategy: SyncStrategy,
    /// Sync interval
    pub interval: Duration,
    /// Maximum entries per sync
    pub max_entries_per_sync: usize,
    /// Enable deduplication
    pub deduplicate: bool,
    /// Minimum age before syncing (to avoid syncing very new entries)
    pub min_age: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            strategy: SyncStrategy::Incremental,
            interval: Duration::from_secs(30),
            max_entries_per_sync: 1000,
            deduplicate: true,
            min_age: Duration::from_secs(5),
        }
    }
}

/// Manages corpus synchronization across nodes
pub struct CorpusSyncManager {
    /// Local corpus reference
    corpus: SharedCorpus,
    /// Configuration
    config: SyncConfig,
    /// Entries synced from remote nodes
    remote_entries: Arc<RwLock<HashMap<NodeId, Vec<CorpusEntry>>>>,
    /// Coverage hashes we've already seen
    seen_hashes: Arc<RwLock<HashSet<u64>>>,
    /// Last sync time per node
    last_sync: Arc<RwLock<HashMap<NodeId, Instant>>>,
    /// Entries pending to be shared
    pending_share: Arc<RwLock<Vec<SerializableCorpusEntry>>>,
    /// Last local sync timestamp
    last_local_sync: RwLock<Instant>,
    /// Statistics
    stats: Arc<RwLock<SyncStats>>,
}

impl CorpusSyncManager {
    pub fn new(corpus: SharedCorpus) -> Self {
        Self {
            corpus,
            config: SyncConfig::default(),
            remote_entries: Arc::new(RwLock::new(HashMap::new())),
            seen_hashes: Arc::new(RwLock::new(HashSet::new())),
            last_sync: Arc::new(RwLock::new(HashMap::new())),
            pending_share: Arc::new(RwLock::new(Vec::new())),
            last_local_sync: RwLock::new(Instant::now()),
            stats: Arc::new(RwLock::new(SyncStats::default())),
        }
    }

    pub fn with_config(mut self, config: SyncConfig) -> Self {
        self.config = config;
        self
    }

    /// Get entries to share with other nodes
    pub fn get_entries_to_share(&self) -> Vec<SerializableCorpusEntry> {
        let last_sync = *self.last_local_sync.read().unwrap();
        let now = Instant::now();

        if now.duration_since(last_sync) < self.config.interval {
            // Not time to sync yet
            return Vec::new();
        }

        *self.last_local_sync.write().unwrap() = now;

        let entries = self.corpus.all_entries();
        let seen = self.seen_hashes.read().unwrap();

        let to_share: Vec<SerializableCorpusEntry> = match self.config.strategy {
            SyncStrategy::Full => entries.iter().map(SerializableCorpusEntry::from).collect(),
            SyncStrategy::Incremental => entries
                .iter()
                .filter(|e| !seen.contains(&e.coverage_hash))
                .map(SerializableCorpusEntry::from)
                .collect(),
            SyncStrategy::InterestingOnly => entries
                .iter()
                .filter(|e| e.discovered_new_coverage && !seen.contains(&e.coverage_hash))
                .map(SerializableCorpusEntry::from)
                .collect(),
            SyncStrategy::EnergyBased { min_energy } => entries
                .iter()
                .filter(|e| e.energy >= min_energy && !seen.contains(&e.coverage_hash))
                .map(SerializableCorpusEntry::from)
                .collect(),
            SyncStrategy::RandomSample { sample_rate } => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                entries
                    .iter()
                    .filter(|e| !seen.contains(&e.coverage_hash) && rng.gen::<f64>() < sample_rate)
                    .map(SerializableCorpusEntry::from)
                    .collect()
            }
        };

        // Limit entries per sync
        let limited: Vec<_> = to_share
            .into_iter()
            .take(self.config.max_entries_per_sync)
            .collect();

        // Mark these as seen
        drop(seen);
        let mut seen = self.seen_hashes.write().unwrap();
        for entry in &limited {
            seen.insert(entry.coverage_hash);
        }

        // Update stats
        self.stats.write().unwrap().entries_shared += limited.len();

        limited
    }

    /// Receive entries from another node
    pub fn receive_entries(&self, node_id: &str, entries: Vec<SerializableCorpusEntry>) {
        let mut stats = self.stats.write().unwrap();
        stats.entries_received += entries.len();

        let mut added = 0;
        let mut duplicates = 0;

        for serializable in entries {
            // Check for duplicates
            {
                let seen = self.seen_hashes.read().unwrap();
                if seen.contains(&serializable.coverage_hash) {
                    duplicates += 1;
                    continue;
                }
            }

            // Convert and add to corpus
            if let Some(entry) = serializable.to_corpus_entry() {
                // Mark as seen
                self.seen_hashes
                    .write()
                    .unwrap()
                    .insert(entry.coverage_hash);

                // Add to corpus (will check for duplicates again internally)
                if self.corpus.add(entry.clone()) {
                    added += 1;

                    // Track remote entries
                    self.remote_entries
                        .write()
                        .unwrap()
                        .entry(node_id.to_string())
                        .or_default()
                        .push(entry);
                }
            }
        }

        stats.new_entries_from_sync += added;
        stats.duplicate_entries += duplicates;

        // Update last sync time for this node
        self.last_sync
            .write()
            .unwrap()
            .insert(node_id.to_string(), Instant::now());

        tracing::debug!(
            "Received {} entries from {}: {} new, {} duplicates",
            added + duplicates,
            node_id,
            added,
            duplicates
        );
    }

    /// Merge coverage bitmaps from remote nodes
    pub fn merge_coverage(&self, _node_id: &str, _bitmap: &[u8]) {
        // TODO: Implement coverage bitmap merging
        // This would update the global coverage tracker
    }

    /// Get entries received from a specific node
    pub fn get_remote_entries(&self, node_id: &str) -> Vec<CorpusEntry> {
        self.remote_entries
            .read()
            .unwrap()
            .get(node_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get synchronization statistics
    pub fn stats(&self) -> SyncStats {
        self.stats.read().unwrap().clone()
    }

    /// Reset synchronization state
    pub fn reset(&self) {
        self.remote_entries.write().unwrap().clear();
        self.seen_hashes.write().unwrap().clear();
        self.last_sync.write().unwrap().clear();
        self.pending_share.write().unwrap().clear();
        *self.stats.write().unwrap() = SyncStats::default();
    }

    /// Check if should sync with a node
    pub fn should_sync_with(&self, node_id: &str) -> bool {
        let last_sync = self.last_sync.read().unwrap();
        match last_sync.get(node_id) {
            Some(last) => last.elapsed() >= self.config.interval,
            None => true,
        }
    }

    /// Get number of unique entries across all nodes
    pub fn global_corpus_size(&self) -> usize {
        self.seen_hashes.read().unwrap().len()
    }
}

/// Statistics for corpus synchronization
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    /// Total entries shared with other nodes
    pub entries_shared: usize,
    /// Total entries received from other nodes
    pub entries_received: usize,
    /// New entries added from sync
    pub new_entries_from_sync: usize,
    /// Duplicate entries filtered
    pub duplicate_entries: usize,
    /// Number of sync operations
    pub sync_count: usize,
}

/// Global corpus manager for coordinator
pub struct GlobalCorpusManager {
    /// Per-node corpus
    node_corpora: HashMap<NodeId, Vec<CorpusEntry>>,
    /// Merged global corpus
    global_corpus: Vec<CorpusEntry>,
    /// Coverage hash to entry mapping for deduplication
    coverage_index: HashMap<u64, usize>,
    /// Statistics
    stats: GlobalCorpusStats,
}

impl GlobalCorpusManager {
    pub fn new() -> Self {
        Self {
            node_corpora: HashMap::new(),
            global_corpus: Vec::new(),
            coverage_index: HashMap::new(),
            stats: GlobalCorpusStats::default(),
        }
    }

    /// Add entries from a node
    pub fn add_from_node(&mut self, node_id: &str, entries: Vec<CorpusEntry>) {
        for entry in entries {
            if !self.coverage_index.contains_key(&entry.coverage_hash) {
                let idx = self.global_corpus.len();
                self.coverage_index.insert(entry.coverage_hash, idx);
                self.global_corpus.push(entry.clone());
                self.stats.unique_entries += 1;
            }

            self.node_corpora
                .entry(node_id.to_string())
                .or_default()
                .push(entry);
        }

        self.stats.total_entries = self.node_corpora.values().map(|v| v.len()).sum();
    }

    /// Get the global merged corpus
    pub fn global_corpus(&self) -> &[CorpusEntry] {
        &self.global_corpus
    }

    /// Get entries for redistribution to a node
    pub fn get_entries_for_node(&self, node_id: &str, max_entries: usize) -> Vec<CorpusEntry> {
        // Get entries this node hasn't seen
        let node_hashes: HashSet<u64> = self
            .node_corpora
            .get(node_id)
            .map(|entries| entries.iter().map(|e| e.coverage_hash).collect())
            .unwrap_or_default();

        self.global_corpus
            .iter()
            .filter(|e| !node_hashes.contains(&e.coverage_hash))
            .take(max_entries)
            .cloned()
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> &GlobalCorpusStats {
        &self.stats
    }
}

impl Default for GlobalCorpusManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for global corpus
#[derive(Debug, Clone, Default)]
pub struct GlobalCorpusStats {
    /// Total entries across all nodes (may include duplicates)
    pub total_entries: usize,
    /// Unique entries (deduplicated)
    pub unique_entries: usize,
    /// Number of nodes contributing
    pub contributing_nodes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::create_corpus;

    #[test]
    fn test_sync_manager_creation() {
        let corpus = create_corpus(1000);
        let manager = CorpusSyncManager::new(corpus);
        assert_eq!(manager.global_corpus_size(), 0);
    }

    #[test]
    fn test_receive_entries() {
        let corpus = create_corpus(1000);
        let manager = CorpusSyncManager::new(corpus);

        let entries = vec![
            SerializableCorpusEntry {
                inputs: vec!["0x01".to_string()],
                coverage_hash: 1,
                discovered_new_coverage: true,
                energy: 50,
            },
            SerializableCorpusEntry {
                inputs: vec!["0x02".to_string()],
                coverage_hash: 2,
                discovered_new_coverage: false,
                energy: 10,
            },
        ];

        manager.receive_entries("node-1", entries);
        assert_eq!(manager.global_corpus_size(), 2);
    }

    #[test]
    fn test_global_corpus_manager() {
        let mut manager = GlobalCorpusManager::new();

        let entry = CorpusEntry::new(
            crate::fuzzer::TestCase {
                inputs: vec![crate::fuzzer::FieldElement::zero()],
                expected_output: None,
                metadata: Default::default(),
            },
            12345,
        );

        manager.add_from_node("node-1", vec![entry.clone()]);
        manager.add_from_node("node-2", vec![entry]); // Duplicate

        assert_eq!(manager.stats().unique_entries, 1);
    }
}
