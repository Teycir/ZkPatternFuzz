//! Lock-Free Corpus Data Structures
//!
//! This module provides lock-free data structures for high-performance
//! concurrent corpus management. Key features:
//! - Lock-free queue for test case submission
//! - Atomic coverage bitmap
//! - Concurrent corpus access without blocking
//!
//! # Performance Impact
//! Expected 2-3x reduction in contention overhead compared to RwLock-based
//! corpus management.

use crossbeam::queue::SegQueue;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use zk_core::TestCase;

/// Lock-free test case queue
#[derive(Debug)]
pub struct LockFreeTestQueue {
    /// Internal queue
    queue: SegQueue<TestCase>,
    /// Approximate size (for load balancing)
    size: AtomicUsize,
    /// Total cases ever added
    total_added: AtomicU64,
    /// Total cases ever removed
    total_removed: AtomicU64,
}

impl LockFreeTestQueue {
    /// Create a new empty queue
    pub fn new() -> Self {
        Self {
            queue: SegQueue::new(),
            size: AtomicUsize::new(0),
            total_added: AtomicU64::new(0),
            total_removed: AtomicU64::new(0),
        }
    }

    /// Push a test case to the queue
    pub fn push(&self, test_case: TestCase) {
        self.queue.push(test_case);
        self.size.fetch_add(1, Ordering::Relaxed);
        self.total_added.fetch_add(1, Ordering::Relaxed);
    }

    /// Try to pop a test case from the queue
    pub fn pop(&self) -> Option<TestCase> {
        self.queue.pop().inspect(|_| {
            self.size.fetch_sub(1, Ordering::Relaxed);
            self.total_removed.fetch_add(1, Ordering::Relaxed);
        })
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get approximate size (may be stale)
    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    /// Get total cases ever added
    pub fn total_added(&self) -> u64 {
        self.total_added.load(Ordering::Relaxed)
    }

    /// Get total cases ever removed
    pub fn total_removed(&self) -> u64 {
        self.total_removed.load(Ordering::Relaxed)
    }

    /// Pop multiple items (up to count)
    pub fn pop_batch(&self, count: usize) -> Vec<TestCase> {
        let mut batch = Vec::with_capacity(count);
        for _ in 0..count {
            match self.pop() {
                Some(tc) => batch.push(tc),
                None => break,
            }
        }
        batch
    }

    /// Push multiple items
    pub fn push_batch(&self, test_cases: Vec<TestCase>) {
        for tc in test_cases {
            self.push(tc);
        }
    }
}

impl Default for LockFreeTestQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Atomic coverage bitmap for concurrent coverage tracking
#[derive(Debug)]
pub struct AtomicCoverageBitmap {
    /// Bitmap stored as array of atomic u64s
    bitmap: Vec<AtomicU64>,
    /// Number of bits
    num_bits: usize,
    /// Number of bits set
    bits_set: AtomicUsize,
}

impl AtomicCoverageBitmap {
    /// Create a new bitmap with given number of bits
    pub fn new(num_bits: usize) -> Self {
        let num_words = num_bits.div_ceil(64);
        let bitmap = (0..num_words).map(|_| AtomicU64::new(0)).collect();

        Self {
            bitmap,
            num_bits,
            bits_set: AtomicUsize::new(0),
        }
    }

    /// Set a bit and return true if it was newly set
    pub fn set(&self, bit: usize) -> bool {
        if bit >= self.num_bits {
            return false;
        }

        let word_idx = bit / 64;
        let bit_idx = bit % 64;
        let mask = 1u64 << bit_idx;

        let old = self.bitmap[word_idx].fetch_or(mask, Ordering::Relaxed);
        let was_unset = (old & mask) == 0;

        if was_unset {
            self.bits_set.fetch_add(1, Ordering::Relaxed);
        }

        was_unset
    }

    /// Clear a bit
    pub fn clear(&self, bit: usize) {
        if bit >= self.num_bits {
            return;
        }

        let word_idx = bit / 64;
        let bit_idx = bit % 64;
        let mask = !(1u64 << bit_idx);

        let old = self.bitmap[word_idx].fetch_and(mask, Ordering::Relaxed);
        let was_set = (old & (1u64 << bit_idx)) != 0;

        if was_set {
            self.bits_set.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Check if a bit is set
    pub fn is_set(&self, bit: usize) -> bool {
        if bit >= self.num_bits {
            return false;
        }

        let word_idx = bit / 64;
        let bit_idx = bit % 64;
        let mask = 1u64 << bit_idx;

        (self.bitmap[word_idx].load(Ordering::Relaxed) & mask) != 0
    }

    /// Get number of bits set
    pub fn count_set(&self) -> usize {
        self.bits_set.load(Ordering::Relaxed)
    }

    /// Get coverage percentage
    pub fn coverage_percentage(&self) -> f64 {
        if self.num_bits == 0 {
            return 0.0;
        }
        self.count_set() as f64 / self.num_bits as f64 * 100.0
    }

    /// Merge another bitmap (OR operation)
    pub fn merge(&self, other: &AtomicCoverageBitmap) -> usize {
        let mut new_bits = 0;

        for (i, word) in self.bitmap.iter().enumerate() {
            if i < other.bitmap.len() {
                let other_word = other.bitmap[i].load(Ordering::Relaxed);
                let old = word.fetch_or(other_word, Ordering::Relaxed);
                let newly_set = (other_word & !old).count_ones() as usize;
                new_bits += newly_set;
            }
        }

        if new_bits > 0 {
            self.bits_set.fetch_add(new_bits, Ordering::Relaxed);
        }

        new_bits
    }

    /// Get total number of bits
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Export to Vec<bool>
    pub fn to_vec(&self) -> Vec<bool> {
        (0..self.num_bits).map(|i| self.is_set(i)).collect()
    }

    /// Set multiple bits from hash (for constraint coverage)
    pub fn set_from_hash(&self, hash: u64) -> bool {
        // Use multiple bits per hash for better distribution
        let mut any_new = false;
        for i in 0..4 {
            let bit = ((hash >> (i * 16)) % self.num_bits as u64) as usize;
            if self.set(bit) {
                any_new = true;
            }
        }
        any_new
    }
}

/// Lock-free corpus with concurrent access
#[derive(Debug)]
pub struct LockFreeCorpus {
    /// Test cases organized by priority
    high_priority: LockFreeTestQueue,
    mid_priority: LockFreeTestQueue,
    low_priority: LockFreeTestQueue,
    /// Coverage bitmap
    coverage: AtomicCoverageBitmap,
    /// Total unique inputs seen
    unique_inputs: AtomicU64,
    /// Next input ID
    next_id: AtomicU64,
}

impl LockFreeCorpus {
    /// Create a new corpus with given coverage bitmap size
    pub fn new(coverage_bits: usize) -> Self {
        Self {
            high_priority: LockFreeTestQueue::new(),
            mid_priority: LockFreeTestQueue::new(),
            low_priority: LockFreeTestQueue::new(),
            coverage: AtomicCoverageBitmap::new(coverage_bits),
            unique_inputs: AtomicU64::new(0),
            next_id: AtomicU64::new(0),
        }
    }

    /// Add a test case with priority based on coverage impact
    pub fn add(&self, test_case: TestCase, coverage_hash: u64) -> bool {
        let is_new = self.coverage.set_from_hash(coverage_hash);

        // Track ID
        let _id = self.next_id.fetch_add(1, Ordering::Relaxed);

        if is_new {
            self.unique_inputs.fetch_add(1, Ordering::Relaxed);
            self.high_priority.push(test_case);
        } else {
            // Distribute to other queues based on generation (proxy for energy)
            let generation = test_case.metadata.generation;
            if generation < 10 {
                // Fresh test cases go to mid priority
                self.mid_priority.push(test_case);
            } else {
                self.low_priority.push(test_case);
            }
        }

        is_new
    }

    /// Select next test case (priority-based)
    pub fn select(&self) -> Option<TestCase> {
        // Try high priority first
        if let Some(tc) = self.high_priority.pop() {
            return Some(tc);
        }

        // Then mid priority
        if let Some(tc) = self.mid_priority.pop() {
            return Some(tc);
        }

        // Finally low priority
        self.low_priority.pop()
    }

    /// Select multiple test cases
    pub fn select_batch(&self, count: usize) -> Vec<TestCase> {
        let mut batch = Vec::with_capacity(count);

        // Fill from queues in priority order
        batch.extend(self.high_priority.pop_batch(count - batch.len()));
        if batch.len() < count {
            batch.extend(self.mid_priority.pop_batch(count - batch.len()));
        }
        if batch.len() < count {
            batch.extend(self.low_priority.pop_batch(count - batch.len()));
        }

        batch
    }

    /// Get total size across all queues
    pub fn len(&self) -> usize {
        self.high_priority.len() + self.mid_priority.len() + self.low_priority.len()
    }

    /// Check if corpus is empty
    pub fn is_empty(&self) -> bool {
        self.high_priority.is_empty()
            && self.mid_priority.is_empty()
            && self.low_priority.is_empty()
    }

    /// Get coverage percentage
    pub fn coverage_percentage(&self) -> f64 {
        self.coverage.coverage_percentage()
    }

    /// Get number of unique inputs
    pub fn unique_count(&self) -> u64 {
        self.unique_inputs.load(Ordering::Relaxed)
    }

    /// Get coverage bitmap reference
    pub fn coverage(&self) -> &AtomicCoverageBitmap {
        &self.coverage
    }

    /// Merge coverage from another corpus
    pub fn merge_coverage(&self, other: &LockFreeCorpus) -> usize {
        self.coverage.merge(&other.coverage)
    }

    /// Get queue sizes
    pub fn queue_sizes(&self) -> (usize, usize, usize) {
        (
            self.high_priority.len(),
            self.mid_priority.len(),
            self.low_priority.len(),
        )
    }
}

/// Shared corpus for multi-worker fuzzing
pub type SharedLockFreeCorpus = Arc<LockFreeCorpus>;

/// Create a shared lock-free corpus
pub fn create_shared_corpus(coverage_bits: usize) -> SharedLockFreeCorpus {
    Arc::new(LockFreeCorpus::new(coverage_bits))
}

#[cfg(test)]
#[path = "lockfree_tests.rs"]
mod tests;
