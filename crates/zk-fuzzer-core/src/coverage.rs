//! Coverage tracking for guided fuzzing
//!
//! Implements coverage-guided fuzzing by tracking which constraints
//! are exercised during circuit execution.

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use zk_core::ExecutionCoverage;

/// Global coverage tracker for the fuzzing campaign
///
/// Phase 0 Fix: Extended to track edge coverage (constraint transitions),
/// path coverage (execution traces), and value coverage (constraint values).
#[derive(Debug)]
pub struct CoverageTracker {
    /// Map of constraint ID to hit count
    constraint_hits: RwLock<HashMap<usize, u64>>,
    /// Set of unique coverage hashes seen
    unique_coverages: RwLock<HashSet<u64>>,
    /// Total number of constraints in the circuit
    total_constraints: usize,
    /// Maximum coverage achieved
    max_coverage: RwLock<usize>,
    /// Number of times new coverage was discovered
    new_coverage_count: RwLock<u64>,

    // Phase 0 Fix: Extended coverage metrics
    /// Edge coverage: tracks transitions between consecutive constraints (from -> to)
    edge_hits: RwLock<HashMap<(usize, usize), u64>>,
    /// Path coverage: tracks execution path hashes (sequence of constraints)
    path_hashes: RwLock<HashSet<u64>>,
    /// Value coverage: tracks value buckets seen for each constraint
    /// Key: constraint_id, Value: set of value bucket hashes
    value_buckets: RwLock<HashMap<usize, HashSet<u8>>>,
}

impl CoverageTracker {
    pub fn new(total_constraints: usize) -> Self {
        Self {
            constraint_hits: RwLock::new(HashMap::new()),
            unique_coverages: RwLock::new(HashSet::new()),
            total_constraints,
            max_coverage: RwLock::new(0),
            new_coverage_count: RwLock::new(0),
            // Phase 0 Fix: Initialize extended coverage tracking
            edge_hits: RwLock::new(HashMap::new()),
            path_hashes: RwLock::new(HashSet::new()),
            value_buckets: RwLock::new(HashMap::new()),
        }
    }

    /// Record a constraint hit
    pub fn record_hit(&self, constraint_id: usize) {
        let mut hits = self.constraint_hits.write();
        *hits.entry(constraint_id).or_insert(0) += 1;

        // Update max coverage
        let current_coverage = hits.len();
        let mut max = self.max_coverage.write();
        if current_coverage > *max {
            *max = current_coverage;
        }
    }

    /// Record multiple constraint hits from an execution
    ///
    /// Phase 0 Fix: Now also records edge coverage (transitions) and path coverage.
    pub fn record_execution(&self, coverage: &ExecutionCoverage) -> bool {
        let satisfied_constraints = &coverage.satisfied_constraints;
        let evaluated_constraints = if coverage.evaluated_constraints.is_empty() {
            satisfied_constraints
        } else {
            &coverage.evaluated_constraints
        };

        // Check if this is new coverage
        let is_new_constraint_coverage = self.record_coverage_hash(coverage.coverage_hash);

        // Record individual hits
        {
            let mut hits = self.constraint_hits.write();
            for &constraint_id in satisfied_constraints {
                *hits.entry(constraint_id).or_insert(0) += 1;
            }

            // Update max coverage
            let current_coverage = hits.len();
            let mut max = self.max_coverage.write();
            if current_coverage > *max {
                *max = current_coverage;
            }
        }

        // Phase 0 Fix: Record edge coverage (transitions between constraints)
        let is_new_edge = self.record_edges(evaluated_constraints);

        // Phase 0 Fix: Record path coverage (execution trace hash)
        let is_new_path = self.record_path(evaluated_constraints);

        // Phase 0 Fix: Record value bucket coverage
        let mut is_new_value = false;
        for (constraint_id, bucket) in &coverage.value_buckets {
            if self.record_value_bucket(*constraint_id, *bucket) {
                is_new_value = true;
            }
        }

        // Return true if any new coverage was discovered
        is_new_constraint_coverage || is_new_edge || is_new_path || is_new_value
    }

    /// Phase 0 Fix: Record edge coverage - transitions between consecutive constraints
    fn record_edges(&self, constraints: &[usize]) -> bool {
        if constraints.len() < 2 {
            return false;
        }

        let mut edges = self.edge_hits.write();
        let mut found_new = false;

        for window in constraints.windows(2) {
            let edge = (window[0], window[1]);
            let count = edges.entry(edge).or_insert(0);
            if *count == 0 {
                found_new = true;
            }
            *count += 1;
        }

        found_new
    }

    /// Phase 0 Fix: Record path coverage - hash of execution trace
    fn record_path(&self, constraints: &[usize]) -> bool {
        use sha2::{Digest, Sha256};

        // Use first N constraints as path signature (prevent explosion)
        let path_prefix: Vec<_> = constraints.iter().take(32).copied().collect();

        let mut hasher = Sha256::new();
        for c in &path_prefix {
            hasher.update(c.to_le_bytes());
        }
        let hash = hasher.finalize();
        let path_hash = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);

        let mut paths = self.path_hashes.write();
        paths.insert(path_hash)
    }

    /// Phase 0 Fix: Record value bucket coverage for a constraint
    ///
    /// Groups constraint values into buckets to detect different value ranges.
    /// This helps find edge cases like boundary values, zero, max, etc.
    pub fn record_value(&self, constraint_id: usize, value_bytes: &[u8]) -> bool {
        let bucket = Self::compute_value_bucket(value_bytes);
        self.record_value_bucket(constraint_id, bucket)
    }

    fn record_value_bucket(&self, constraint_id: usize, bucket: u8) -> bool {
        let mut buckets = self.value_buckets.write();
        let constraint_buckets = buckets.entry(constraint_id).or_default();
        constraint_buckets.insert(bucket)
    }

    fn compute_value_bucket(value_bytes: &[u8]) -> u8 {
        if value_bytes.is_empty() {
            return 0;
        }
        let first_nonzero = value_bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(value_bytes.len());
        let byte: u8 = value_bytes.get(first_nonzero).copied().unwrap_or_default();
        (first_nonzero as u8).wrapping_add(byte)
    }

    /// Record a coverage hash when constraint-level coverage is unavailable
    ///
    /// Returns true if this hash represents new coverage.
    pub fn record_coverage_hash(&self, coverage_hash: u64) -> bool {
        let mut unique = self.unique_coverages.write();
        if unique.insert(coverage_hash) {
            *self.new_coverage_count.write() += 1;
            true
        } else {
            false
        }
    }

    /// Get the current coverage percentage
    pub fn coverage_percentage(&self) -> f64 {
        if self.total_constraints == 0 {
            return 0.0;
        }

        let hits = self.constraint_hits.read();
        (hits.len() as f64 / self.total_constraints as f64) * 100.0
    }

    /// Get the number of unique constraints hit
    pub fn unique_constraints_hit(&self) -> usize {
        self.constraint_hits.read().len()
    }

    /// Get the list of constraint IDs that have been hit
    pub fn constraint_ids(&self) -> Vec<usize> {
        self.constraint_hits.read().keys().copied().collect()
    }

    /// Get the total number of constraint evaluations
    pub fn total_hits(&self) -> u64 {
        self.constraint_hits.read().values().sum()
    }

    /// Get constraints that have never been hit
    pub fn uncovered_constraints(&self) -> Vec<usize> {
        let hits = self.constraint_hits.read();
        (0..self.total_constraints)
            .filter(|id| !hits.contains_key(id))
            .collect()
    }

    /// Get the number of unique coverage patterns seen
    pub fn unique_coverage_patterns(&self) -> usize {
        self.unique_coverages.read().len()
    }

    /// Get the number of times new coverage was discovered
    pub fn new_coverage_count(&self) -> u64 {
        *self.new_coverage_count.read()
    }

    /// Get a snapshot of current coverage stats
    pub fn snapshot(&self) -> CoverageSnapshot {
        CoverageSnapshot {
            constraints_hit: self.unique_constraints_hit(),
            total_constraints: self.total_constraints,
            coverage_percentage: self.coverage_percentage(),
            unique_patterns: self.unique_coverage_patterns(),
            new_coverage_discoveries: self.new_coverage_count(),
            // Phase 0 Fix: Include extended coverage in snapshot
            unique_edges: self.unique_edges(),
            unique_paths: self.unique_paths(),
            value_buckets_hit: self.total_value_buckets(),
        }
    }

    /// Reset the coverage tracker
    pub fn reset(&self) {
        *self.constraint_hits.write() = HashMap::new();
        *self.unique_coverages.write() = HashSet::new();
        *self.max_coverage.write() = 0;
        *self.new_coverage_count.write() = 0;
        // Phase 0 Fix: Reset extended coverage
        *self.edge_hits.write() = HashMap::new();
        *self.path_hashes.write() = HashSet::new();
        *self.value_buckets.write() = HashMap::new();
    }

    // Phase 0 Fix: Extended coverage accessors

    /// Get number of unique edges (constraint transitions) discovered
    pub fn unique_edges(&self) -> usize {
        self.edge_hits.read().len()
    }

    /// Get number of unique execution paths discovered
    pub fn unique_paths(&self) -> usize {
        self.path_hashes.read().len()
    }

    /// Get total number of value buckets hit across all constraints
    pub fn total_value_buckets(&self) -> usize {
        self.value_buckets.read().values().map(|s| s.len()).sum()
    }

    /// Get edges that have never been hit (sparse representation)
    /// Returns edges with hit count > 0 for analysis
    pub fn edge_coverage(&self) -> HashMap<(usize, usize), u64> {
        self.edge_hits.read().clone()
    }
}

/// Snapshot of coverage statistics
///
/// Phase 0 Fix: Extended to include edge, path, and value coverage.
#[derive(Debug, Clone)]
pub struct CoverageSnapshot {
    pub constraints_hit: usize,
    pub total_constraints: usize,
    pub coverage_percentage: f64,
    pub unique_patterns: usize,
    pub new_coverage_discoveries: u64,
    // Phase 0 Fix: Extended coverage metrics
    pub unique_edges: usize,
    pub unique_paths: usize,
    pub value_buckets_hit: usize,
}

impl std::fmt::Display for CoverageSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} constraints ({:.1}%), {} patterns, {} edges, {} paths, {} new",
            self.constraints_hit,
            self.total_constraints,
            self.coverage_percentage,
            self.unique_patterns,
            self.unique_edges,
            self.unique_paths,
            self.new_coverage_discoveries
        )
    }
}

/// Energy scheduler for prioritizing test cases
///
/// Uses coverage information to assign "energy" (number of mutations)
/// to test cases. Cases that discover new coverage get more energy.
pub struct EnergyScheduler {
    /// Base energy for all test cases
    base_energy: usize,
    /// Bonus energy for cases that discovered new coverage
    new_coverage_bonus: usize,
    /// Decay factor for old test cases
    decay_factor: f64,
}

impl EnergyScheduler {
    pub fn new() -> Self {
        Self {
            base_energy: 10,
            new_coverage_bonus: 50,
            decay_factor: 0.9,
        }
    }

    pub fn with_base_energy(mut self, energy: usize) -> Self {
        self.base_energy = energy;
        self
    }

    pub fn with_new_coverage_bonus(mut self, bonus: usize) -> Self {
        self.new_coverage_bonus = bonus;
        self
    }

    /// Calculate energy for a test case
    pub fn calculate_energy(&self, discovered_new_coverage: bool, age: usize) -> usize {
        let mut energy = self.base_energy;

        if discovered_new_coverage {
            energy += self.new_coverage_bonus;
        }

        // Apply decay based on age
        let decay = self.decay_factor.powi(age as i32);
        (energy as f64 * decay).round() as usize
    }
}

impl Default for EnergyScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe shared coverage tracker
pub type SharedCoverageTracker = Arc<CoverageTracker>;

/// Create a new shared coverage tracker
pub fn create_coverage_tracker(total_constraints: usize) -> SharedCoverageTracker {
    Arc::new(CoverageTracker::new(total_constraints))
}

#[cfg(test)]
#[path = "coverage_tests.rs"]
mod tests;
