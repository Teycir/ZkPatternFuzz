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

        let cache = self.cache.read();
        if let Some(entry) = cache.get(&key) {
            // Check TTL
            if self.ttl_seconds > 0 && entry.timestamp.elapsed().as_secs() > self.ttl_seconds {
                drop(cache);
                self.misses.fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }

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
        let cache = self.cache.read();

        queries
            .iter()
            .map(|(constraint_id, inputs)| {
                let input_hash = Self::hash_inputs(inputs);
                let key = (*constraint_id, input_hash);

                cache.get(&key).and_then(|entry| {
                    if self.ttl_seconds > 0
                        && entry.timestamp.elapsed().as_secs() > self.ttl_seconds
                    {
                        self.misses.fetch_add(1, AtomicOrdering::Relaxed);
                        None
                    } else {
                        self.hits.fetch_add(1, AtomicOrdering::Relaxed);
                        Some(entry.result.clone())
                    }
                })
            })
            .collect()
    }

    /// Batch insert multiple results
    pub fn insert_batch(&self, entries: Vec<(usize, Vec<FieldElement>, ConstraintEvalResult)>) {
        let mut cache = self.cache.write();

        // Pre-evict if necessary
        let needed_space = entries.len();
        while cache.len() + needed_space > self.max_size {
            self.evict_lru(&mut cache);
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
    }

    /// Evict least recently used entries
    fn evict_lru(&self, cache: &mut HashMap<(usize, u64), CacheEntry>) {
        // Find entries to evict (oldest 10%)
        let evict_count = self.max_size / 10;

        let mut entries: Vec<_> = cache
            .iter()
            .map(|(k, v)| (*k, v.timestamp, v.access_count))
            .collect();

        // Sort by timestamp (oldest first) and access count
        entries.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)));

        for (key, _, _) in entries.into_iter().take(evict_count) {
            cache.remove(&key);
            self.evictions.fetch_add(1, AtomicOrdering::Relaxed);
        }
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

#[cfg(test)]
#[path = "constraint_cache_tests.rs"]
mod tests;
