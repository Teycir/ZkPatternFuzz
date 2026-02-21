//! Constraint Caching for Fuzzing Performance
//!
//! This module provides thread-safe constraint evaluation caching to
//! avoid redundant computation during fuzzing. Key features:
//! - LRU eviction with configurable size limits
//! - TTL-based expiration
//! - Thread-safe concurrent access
//! - Statistics tracking
//!
//! # Performance Impact
//! Expected 2-3x speedup on constraint-heavy circuits by avoiding
//! redundant evaluations of the same constraint configurations.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Instant;
use zk_core::FieldElement;

/// Result of a constraint evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintEvalResult {
    /// Constraint satisfied
    Satisfied,
    /// Constraint violated
    Violated,
    /// Evaluation failed (e.g., division by zero)
    Error(String),
}

/// Cache entry with timestamp
#[derive(Debug, Clone)]
struct CacheEntry {
    result: ConstraintEvalResult,
    timestamp: Instant,
    access_count: u64,
}

/// Errors that can occur when inserting a batch into the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintCacheInsertError {
    /// Batch exceeds total cache capacity and cannot be inserted safely.
    BatchExceedsCapacity { batch_size: usize, max_size: usize },
}

/// Thread-safe constraint evaluation cache
#[derive(Debug)]
pub struct ConstraintEvalCache {
    /// Main cache: (constraint_id, input_hash) -> result
    cache: RwLock<HashMap<(usize, u64), CacheEntry>>,
    /// Maximum cache size
    max_size: usize,
    /// TTL in seconds (0 = no expiry)
    ttl_seconds: u64,
    /// Statistics
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl ConstraintEvalCache {
    /// Create a new cache with default settings
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_size: 100_000,
            ttl_seconds: 0, // No expiry by default
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Create with custom max size
    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    /// Create with TTL
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }

    /// Get cached result for constraint evaluation
    pub fn get(
        &self,
        constraint_id: usize,
        inputs: &[FieldElement],
    ) -> Option<ConstraintEvalResult> {
        let input_hash = Self::hash_inputs(inputs);
        let key = (constraint_id, input_hash);

        let mut cache = self.cache.write();
        if let Some(entry) = cache.get_mut(&key) {
            if self.ttl_seconds > 0 && entry.timestamp.elapsed().as_secs() > self.ttl_seconds {
                self.misses.fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }

            entry.access_count = entry.access_count.saturating_add(1);
            self.hits.fetch_add(1, AtomicOrdering::Relaxed);
            Some(entry.result.clone())
        } else {
            self.misses.fetch_add(1, AtomicOrdering::Relaxed);
            None
        }
    }

    /// Insert result into cache
    pub fn insert(
        &self,
        constraint_id: usize,
        inputs: &[FieldElement],
        result: ConstraintEvalResult,
    ) {
        let input_hash = Self::hash_inputs(inputs);
        let key = (constraint_id, input_hash);

        let mut cache = self.cache.write();

        // Evict if necessary
        if cache.len() >= self.max_size {
            self.evict_lru(&mut cache);
        }

        cache.insert(
            key,
            CacheEntry {
                result,
                timestamp: Instant::now(),
                access_count: 0,
            },
        );
    }

    /// Batch get multiple constraints
    pub fn get_batch(
        &self,
        queries: &[(usize, Vec<FieldElement>)],
    ) -> Vec<Option<ConstraintEvalResult>> {
        let mut cache = self.cache.write();

        queries
            .iter()
            .map(|(constraint_id, inputs)| {
                let input_hash = Self::hash_inputs(inputs);
                let key = (*constraint_id, input_hash);

                match cache.get_mut(&key) {
                    Some(entry) => {
                        if self.ttl_seconds > 0
                            && entry.timestamp.elapsed().as_secs() > self.ttl_seconds
                        {
                            self.misses.fetch_add(1, AtomicOrdering::Relaxed);
                            None
                        } else {
                            entry.access_count = entry.access_count.saturating_add(1);
                            self.hits.fetch_add(1, AtomicOrdering::Relaxed);
                            Some(entry.result.clone())
                        }
                    }
                    None => {
                        self.misses.fetch_add(1, AtomicOrdering::Relaxed);
                        None
                    }
                }
            })
            .collect()
    }

    /// Batch insert multiple results
    pub fn insert_batch(
        &self,
        entries: Vec<(usize, Vec<FieldElement>, ConstraintEvalResult)>,
    ) -> Result<(), ConstraintCacheInsertError> {
        let mut cache = self.cache.write();

        // Pre-evict if necessary
        let needed_space = entries.len();
        if needed_space > self.max_size {
            return Err(ConstraintCacheInsertError::BatchExceedsCapacity {
                batch_size: needed_space,
                max_size: self.max_size,
            });
        }

        while cache.len() + needed_space > self.max_size {
            if self.evict_lru(&mut cache) == 0 {
                return Err(ConstraintCacheInsertError::BatchExceedsCapacity {
                    batch_size: needed_space,
                    max_size: self.max_size,
                });
            }
        }

        for (constraint_id, inputs, result) in entries {
            let input_hash = Self::hash_inputs(&inputs);
            let key = (constraint_id, input_hash);

            cache.insert(
                key,
                CacheEntry {
                    result,
                    timestamp: Instant::now(),
                    access_count: 0,
                },
            );
        }

        Ok(())
    }

    /// Evict low-priority entries.
    ///
    /// We evict lowest access-count entries first and break ties by oldest timestamp.
    fn evict_lru(&self, cache: &mut HashMap<(usize, u64), CacheEntry>) -> usize {
        if cache.is_empty() {
            return 0;
        }

        // Evict at least one entry to guarantee forward progress.
        let evict_count = (self.max_size / 10).max(1).min(cache.len());

        let mut entries: Vec<_> = cache
            .iter()
            .map(|(k, v)| (*k, v.timestamp, v.access_count))
            .collect();

        entries.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.1.cmp(&b.1)));

        let mut evicted = 0usize;
        for (key, _, _) in entries.into_iter().take(evict_count) {
            cache.remove(&key);
            self.evictions.fetch_add(1, AtomicOrdering::Relaxed);
            evicted += 1;
        }

        evicted
    }

    /// Hash input values for cache key
    fn hash_inputs(inputs: &[FieldElement]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        for input in inputs {
            input.to_bytes().hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(AtomicOrdering::Relaxed);
        let misses = self.misses.load(AtomicOrdering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            hits,
            misses,
            hit_rate,
            evictions: self.evictions.load(AtomicOrdering::Relaxed),
            current_size: self.cache.read().len(),
            max_size: self.max_size,
        }
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.cache.write().clear();
        self.hits.store(0, AtomicOrdering::Relaxed);
        self.misses.store(0, AtomicOrdering::Relaxed);
        self.evictions.store(0, AtomicOrdering::Relaxed);
    }

    /// Invalidate entries for a specific constraint
    pub fn invalidate_constraint(&self, constraint_id: usize) {
        let mut cache = self.cache.write();
        cache.retain(|(id, _), _| *id != constraint_id);
    }
}

impl Default for ConstraintEvalCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub evictions: u64,
    pub current_size: usize,
    pub max_size: usize,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache: {}/{} entries, {:.1}% hit rate ({} hits, {} misses, {} evictions)",
            self.current_size,
            self.max_size,
            self.hit_rate * 100.0,
            self.hits,
            self.misses,
            self.evictions
        )
    }
}

/// Wrapper for thread-safe shared cache
pub type SharedConstraintCache = Arc<ConstraintEvalCache>;

/// Create a new shared cache
pub fn create_shared_cache() -> SharedConstraintCache {
    Arc::new(ConstraintEvalCache::new())
}

/// Create a shared cache with custom settings
pub fn create_shared_cache_with_size(max_size: usize) -> SharedConstraintCache {
    Arc::new(ConstraintEvalCache::new().with_max_size(max_size))
}
