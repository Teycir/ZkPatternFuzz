//! Oracle State Management (Phase 5: Milestone 5.7)
//!
//! Provides bounded memory management for stateful oracles to prevent
//! memory exhaustion during long fuzzing campaigns.
//!
//! # Features
//!
//! - Bloom filters for fast first-pass collision detection
//! - LRU eviction for bounded oracle state
//! - DashMap for concurrent access
//! - Per-worker state management
//! - Memory usage tracking
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Oracle State Manager                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌─────────────────┐    ┌─────────────────┐                     │
//! │  │  Bloom Filter   │───►│   Full Check    │                     │
//! │  │  (Fast Pass)    │    │   (LRU Cache)   │                     │
//! │  └─────────────────┘    └─────────────────┘                     │
//! │           │                      │                               │
//! │           ▼                      ▼                               │
//! │  ┌─────────────────────────────────────────┐                    │
//! │  │           State Storage                  │                    │
//! │  │  • DashMap for concurrent access        │                    │
//! │  │  • LRU eviction policy                  │                    │
//! │  │  • Memory limit enforcement             │                    │
//! │  └─────────────────────────────────────────┘                    │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;

use zk_core::{FieldElement, TestCase};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for oracle state management
#[derive(Debug, Clone)]
pub struct OracleStateConfig {
    /// Maximum number of entries in the state map
    pub max_entries: usize,
    /// Bloom filter size (bits)
    pub bloom_filter_bits: usize,
    /// Number of hash functions for bloom filter
    pub bloom_hash_count: usize,
    /// Enable LRU eviction
    pub enable_lru: bool,
    /// Memory limit in bytes (0 = unlimited)
    pub memory_limit_bytes: usize,
    /// Eviction batch size (how many entries to remove at once)
    pub eviction_batch_size: usize,
}

impl Default for OracleStateConfig {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,        // 1M entries
            bloom_filter_bits: 10_000_000, // ~10MB bloom filter
            bloom_hash_count: 7,           // Optimal for 1% FP rate
            enable_lru: true,
            memory_limit_bytes: 1024 * 1024 * 1024, // 1GB
            eviction_batch_size: 10_000,
        }
    }
}

// ============================================================================
// Bloom Filter
// ============================================================================

/// Simple bloom filter for fast first-pass collision detection
pub struct BloomFilter {
    /// Bit storage
    bits: Vec<AtomicU64>,
    /// Number of bits
    num_bits: usize,
    /// Number of hash functions
    num_hashes: usize,
    /// Number of items added
    items_added: AtomicU64,
}

impl BloomFilter {
    /// Create a new bloom filter
    pub fn new(num_bits: usize, num_hashes: usize) -> Self {
        let num_words = num_bits.div_ceil(64);
        let bits = (0..num_words).map(|_| AtomicU64::new(0)).collect();

        Self {
            bits,
            num_bits,
            num_hashes,
            items_added: AtomicU64::new(0),
        }
    }

    /// Add an item to the filter
    pub fn add(&self, data: &[u8]) {
        for i in 0..self.num_hashes {
            let bit = self.hash(data, i);
            self.set_bit(bit);
        }
        self.items_added.fetch_add(1, Ordering::Relaxed);
    }

    /// Check if an item might be in the filter
    ///
    /// Returns:
    /// - `true`: Item might be present (could be false positive)
    /// - `false`: Item is definitely not present
    pub fn might_contain(&self, data: &[u8]) -> bool {
        for i in 0..self.num_hashes {
            let bit = self.hash(data, i);
            if !self.get_bit(bit) {
                return false;
            }
        }
        true
    }

    fn hash(&self, data: &[u8], seed: usize) -> usize {
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        seed.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_bits
    }

    fn set_bit(&self, bit: usize) {
        let word_idx = bit / 64;
        let bit_idx = bit % 64;
        self.bits[word_idx].fetch_or(1u64 << bit_idx, Ordering::Relaxed);
    }

    fn get_bit(&self, bit: usize) -> bool {
        let word_idx = bit / 64;
        let bit_idx = bit % 64;
        (self.bits[word_idx].load(Ordering::Relaxed) & (1u64 << bit_idx)) != 0
    }

    /// Get number of items added
    pub fn items_added(&self) -> u64 {
        self.items_added.load(Ordering::Relaxed)
    }

    /// Estimate false positive rate
    pub fn estimated_fp_rate(&self) -> f64 {
        let n = self.items_added() as f64;
        let m = self.num_bits as f64;
        let k = self.num_hashes as f64;

        // FP rate ≈ (1 - e^(-kn/m))^k
        let e_term = (-k * n / m).exp();
        (1.0 - e_term).powf(k)
    }

    /// Clear the filter
    pub fn clear(&self) {
        for word in &self.bits {
            word.store(0, Ordering::Relaxed);
        }
        self.items_added.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// LRU Entry
// ============================================================================

/// Entry in the LRU cache
#[derive(Debug, Clone)]
pub struct LruEntry<T> {
    /// The actual value
    pub value: T,
    /// Last access timestamp
    pub last_access: u64,
    /// Access count
    pub access_count: u64,
}

impl<T> LruEntry<T> {
    pub fn new(value: T, timestamp: u64) -> Self {
        Self {
            value,
            last_access: timestamp,
            access_count: 1,
        }
    }
}

// ============================================================================
// Bounded State Map
// ============================================================================

/// Bounded state map with LRU eviction
pub struct BoundedStateMap<K, V> {
    /// Internal storage
    storage: RwLock<HashMap<K, LruEntry<V>>>,
    /// Bloom filter for fast lookups
    bloom: BloomFilter,
    /// Configuration
    config: OracleStateConfig,
    /// Current logical timestamp
    timestamp: AtomicU64,
    /// Current entry count
    entry_count: AtomicUsize,
    /// Total memory used (estimated)
    memory_used: AtomicUsize,
    /// Statistics
    stats: StateMapStats,
}

/// Statistics for state map operations
#[derive(Debug, Default)]
pub struct StateMapStats {
    pub lookups: AtomicU64,
    pub bloom_hits: AtomicU64,
    pub bloom_misses: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub insertions: AtomicU64,
    pub evictions: AtomicU64,
}

impl StateMapStats {
    /// Get bloom filter effectiveness (false positives caught)
    pub fn bloom_effectiveness(&self) -> f64 {
        let hits = self.bloom_hits.load(Ordering::Relaxed);
        let misses = self.bloom_misses.load(Ordering::Relaxed);
        if hits + misses == 0 {
            return 1.0;
        }
        misses as f64 / (hits + misses) as f64
    }

    /// Get cache hit rate
    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        if hits + misses == 0 {
            return 0.0;
        }
        hits as f64 / (hits + misses) as f64
    }
}

impl<K, V> BoundedStateMap<K, V>
where
    K: Eq + Hash + Clone + AsRef<[u8]>,
    V: Clone,
{
    /// Create a new bounded state map
    pub fn new(config: OracleStateConfig) -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
            bloom: BloomFilter::new(config.bloom_filter_bits, config.bloom_hash_count),
            timestamp: AtomicU64::new(0),
            entry_count: AtomicUsize::new(0),
            memory_used: AtomicUsize::new(0),
            stats: StateMapStats::default(),
            config,
        }
    }

    /// Check if key might exist (fast path via bloom filter)
    pub fn might_contain(&self, key: &K) -> bool {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);
        let result = self.bloom.might_contain(key.as_ref());
        if result {
            self.stats.bloom_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.bloom_misses.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Get value for key
    pub fn get(&self, key: &K) -> Option<V> {
        // Fast path: bloom filter says definitely not present
        if !self.might_contain(key) {
            return None;
        }

        // Slow path: check actual storage
        let storage = match self.storage.read() {
            Ok(storage) => storage,
            Err(err) => {
                tracing::warn!("Oracle state storage lock poisoned in get(): {}", err);
                return None;
            }
        };
        if let Some(entry) = storage.get(key) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            // Note: We can't update last_access here without write lock
            // This is an approximation - true LRU would need write access
            Some(entry.value.clone())
        } else {
            self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert a key-value pair
    pub fn insert(&self, key: K, value: V, estimated_size: usize) -> bool {
        // Check if we need to evict
        if self.config.enable_lru
            && self.entry_count.load(Ordering::Relaxed) >= self.config.max_entries
        {
            self.evict_oldest();
        }

        // Check memory limit
        if self.config.memory_limit_bytes > 0
            && self.memory_used.load(Ordering::Relaxed) + estimated_size
                > self.config.memory_limit_bytes
        {
            self.evict_oldest();
        }

        // Add to bloom filter
        self.bloom.add(key.as_ref());

        // Add to storage
        let timestamp = self.timestamp.fetch_add(1, Ordering::Relaxed);
        let entry = LruEntry::new(value, timestamp);

        let mut storage = match self.storage.write() {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!("oracle state storage lock poisoned; recovering: {}", err);
                err.into_inner()
            }
        };

        let is_new = !storage.contains_key(&key);
        storage.insert(key, entry);

        if is_new {
            self.entry_count.fetch_add(1, Ordering::Relaxed);
            self.memory_used
                .fetch_add(estimated_size, Ordering::Relaxed);
        }

        self.stats.insertions.fetch_add(1, Ordering::Relaxed);
        is_new
    }

    /// Evict oldest entries
    fn evict_oldest(&self) {
        let mut storage = match self.storage.write() {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(
                    "oracle state storage lock poisoned during eviction; recovering: {}",
                    err
                );
                err.into_inner()
            }
        };

        if storage.len() < self.config.eviction_batch_size {
            return;
        }

        // Find oldest entries by timestamp
        let mut entries: Vec<_> = storage
            .iter()
            .map(|(k, v)| (k.clone(), v.last_access))
            .collect();

        entries.sort_by_key(|(_, ts)| *ts);

        // Remove oldest batch
        let to_remove: Vec<_> = entries
            .into_iter()
            .take(self.config.eviction_batch_size)
            .map(|(k, _)| k)
            .collect();

        for key in to_remove {
            storage.remove(&key);
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get current entry count
    pub fn len(&self) -> usize {
        self.entry_count.load(Ordering::Relaxed)
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get memory usage estimate
    pub fn memory_used(&self) -> usize {
        self.memory_used.load(Ordering::Relaxed)
    }

    /// Get statistics
    pub fn stats(&self) -> &StateMapStats {
        &self.stats
    }

    /// Clear all entries
    pub fn clear(&self) {
        if let Ok(mut storage) = self.storage.write() {
            storage.clear();
        }
        self.bloom.clear();
        self.entry_count.store(0, Ordering::Relaxed);
        self.memory_used.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// Oracle State Manager
// ============================================================================

/// Manages state for UnderconstrainedOracle with bounded memory
pub struct OracleStateManager {
    /// Output history (hash -> test case)
    output_history: BoundedStateMap<Vec<u8>, TestCase>,
    /// Collision count
    collision_count: AtomicU64,
}

impl OracleStateManager {
    /// Create a new oracle state manager
    pub fn new(config: OracleStateConfig) -> Self {
        Self {
            output_history: BoundedStateMap::new(config),
            collision_count: AtomicU64::new(0),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(OracleStateConfig::default())
    }

    /// Record an output and check for collision
    ///
    /// Returns Some(colliding_test_case) if a collision is detected
    pub fn record_output(&self, output_hash: Vec<u8>, test_case: TestCase) -> Option<TestCase> {
        // Fast path: check bloom filter
        if !self.output_history.might_contain(&output_hash) {
            // Definitely new - just insert
            let size = estimate_test_case_size(&test_case);
            self.output_history.insert(output_hash, test_case, size);
            return None;
        }

        // Slow path: might be collision
        if let Some(existing) = self.output_history.get(&output_hash) {
            // Collision detected!
            self.collision_count.fetch_add(1, Ordering::Relaxed);
            return Some(existing);
        }

        // False positive from bloom filter - insert
        let size = estimate_test_case_size(&test_case);
        self.output_history.insert(output_hash, test_case, size);
        None
    }

    /// Get collision count
    pub fn collision_count(&self) -> u64 {
        self.collision_count.load(Ordering::Relaxed)
    }

    /// Get statistics
    pub fn stats(&self) -> OracleStateStats {
        OracleStateStats {
            entries: self.output_history.len(),
            memory_used: self.output_history.memory_used(),
            collisions: self.collision_count(),
            bloom_fp_rate: self.output_history.bloom.estimated_fp_rate(),
            cache_hit_rate: self.output_history.stats().cache_hit_rate(),
            bloom_effectiveness: self.output_history.stats().bloom_effectiveness(),
            evictions: self
                .output_history
                .stats()
                .evictions
                .load(Ordering::Relaxed),
        }
    }

    /// Reset state
    pub fn reset(&self) {
        self.output_history.clear();
        self.collision_count.store(0, Ordering::Relaxed);
    }
}

/// Statistics for oracle state management
#[derive(Debug, Clone)]
pub struct OracleStateStats {
    /// Number of entries in state map
    pub entries: usize,
    /// Memory used in bytes
    pub memory_used: usize,
    /// Number of collisions detected
    pub collisions: u64,
    /// Estimated bloom filter false positive rate
    pub bloom_fp_rate: f64,
    /// Cache hit rate
    pub cache_hit_rate: f64,
    /// Bloom filter effectiveness
    pub bloom_effectiveness: f64,
    /// Number of evictions performed
    pub evictions: u64,
}

/// Estimate memory size of a test case
fn estimate_test_case_size(test_case: &TestCase) -> usize {
    // Base size + inputs + expected output
    let base = std::mem::size_of::<TestCase>();
    let inputs = test_case.inputs.len() * std::mem::size_of::<FieldElement>();
    let expected = test_case
        .expected_output
        .as_ref()
        .map(|v| v.len() * std::mem::size_of::<FieldElement>());
    let expected = expected.unwrap_or_default();
    base + inputs + expected
}

// ============================================================================
// Per-Worker Oracle State
// ============================================================================

/// Per-worker oracle state for lock-free operation
pub struct PerWorkerOracleState {
    /// Worker ID
    worker_id: usize,
    /// Local output history
    local_history: HashMap<Vec<u8>, TestCase>,
    /// Maximum local entries before merge
    max_local_entries: usize,
    /// Entries added since last merge
    entries_since_merge: usize,
}

impl PerWorkerOracleState {
    /// Create new per-worker state
    pub fn new(worker_id: usize, max_local_entries: usize) -> Self {
        Self {
            worker_id,
            local_history: HashMap::new(),
            max_local_entries,
            entries_since_merge: 0,
        }
    }

    /// Record output locally
    pub fn record_local(&mut self, output_hash: Vec<u8>, test_case: TestCase) -> bool {
        self.entries_since_merge += 1;
        match self.local_history.entry(output_hash) {
            std::collections::hash_map::Entry::Occupied(_) => true, // Collision
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(test_case);
                false
            }
        }
    }

    /// Check if merge is needed
    pub fn needs_merge(&self) -> bool {
        self.entries_since_merge >= self.max_local_entries
    }

    /// Take entries for merging
    pub fn take_for_merge(&mut self) -> HashMap<Vec<u8>, TestCase> {
        self.entries_since_merge = 0;
        std::mem::take(&mut self.local_history)
    }

    /// Get worker ID
    pub fn worker_id(&self) -> usize {
        self.worker_id
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "oracle_state_tests.rs"]
mod tests;
