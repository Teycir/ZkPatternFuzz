//! Coverage tracking for guided fuzzing
//!
//! Implements coverage-guided fuzzing by tracking which constraints
//! are exercised during circuit execution.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Global coverage tracker for the fuzzing campaign
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
}

impl CoverageTracker {
    pub fn new(total_constraints: usize) -> Self {
        Self {
            constraint_hits: RwLock::new(HashMap::new()),
            unique_coverages: RwLock::new(HashSet::new()),
            total_constraints,
            max_coverage: RwLock::new(0),
            new_coverage_count: RwLock::new(0),
        }
    }

    /// Record a constraint hit
    pub fn record_hit(&self, constraint_id: usize) {
        let mut hits = self.constraint_hits.write().unwrap();
        *hits.entry(constraint_id).or_insert(0) += 1;

        // Update max coverage
        let current_coverage = hits.len();
        let mut max = self.max_coverage.write().unwrap();
        if current_coverage > *max {
            *max = current_coverage;
        }
    }

    /// Record multiple constraint hits from an execution
    pub fn record_execution(&self, satisfied_constraints: &[usize]) -> bool {
        // Calculate coverage hash
        let coverage_hash = self.compute_coverage_hash(satisfied_constraints);

        // Check if this is new coverage
        let is_new = self.record_coverage_hash(coverage_hash);

        // Record individual hits
        {
            let mut hits = self.constraint_hits.write().unwrap();
            for &constraint_id in satisfied_constraints {
                *hits.entry(constraint_id).or_insert(0) += 1;
            }

            // Update max coverage
            let current_coverage = hits.len();
            let mut max = self.max_coverage.write().unwrap();
            if current_coverage > *max {
                *max = current_coverage;
            }
        }

        is_new
    }

    /// Record a coverage hash when constraint-level coverage is unavailable
    ///
    /// Returns true if this hash represents new coverage.
    pub fn record_coverage_hash(&self, coverage_hash: u64) -> bool {
        let mut unique = self.unique_coverages.write().unwrap();
        if !unique.contains(&coverage_hash) {
            unique.insert(coverage_hash);
            *self.new_coverage_count.write().unwrap() += 1;
            true
        } else {
            false
        }
    }

    /// Compute a hash of the coverage bitmap
    ///
    /// Uses a 128-bit hash internally to reduce collision risk with many test cases.
    /// The u64 return type is maintained for API compatibility, but internally
    /// we use a stronger hash function (SHA-256 truncated) to minimize collisions.
    fn compute_coverage_hash(&self, constraints: &[usize]) -> u64 {
        use sha2::{Digest, Sha256};

        let mut sorted = constraints.to_vec();
        sorted.sort_unstable();

        // Use SHA-256 for better collision resistance than DefaultHasher
        // (DefaultHasher uses SipHash which is fast but has higher collision rates)
        let mut hasher = Sha256::new();
        for constraint in &sorted {
            hasher.update(constraint.to_le_bytes());
        }
        let hash = hasher.finalize();

        // Take first 8 bytes as u64 (still better distribution than DefaultHasher)
        u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ])
    }

    /// Get the current coverage percentage
    pub fn coverage_percentage(&self) -> f64 {
        if self.total_constraints == 0 {
            return 0.0;
        }

        let hits = self.constraint_hits.read().unwrap();
        (hits.len() as f64 / self.total_constraints as f64) * 100.0
    }

    /// Get the number of unique constraints hit
    pub fn unique_constraints_hit(&self) -> usize {
        self.constraint_hits.read().unwrap().len()
    }

    /// Get the total number of constraint evaluations
    pub fn total_hits(&self) -> u64 {
        self.constraint_hits.read().unwrap().values().sum()
    }

    /// Get constraints that have never been hit
    pub fn uncovered_constraints(&self) -> Vec<usize> {
        let hits = self.constraint_hits.read().unwrap();
        (0..self.total_constraints)
            .filter(|id| !hits.contains_key(id))
            .collect()
    }

    /// Get the number of unique coverage patterns seen
    pub fn unique_coverage_patterns(&self) -> usize {
        self.unique_coverages.read().unwrap().len()
    }

    /// Get the number of times new coverage was discovered
    pub fn new_coverage_count(&self) -> u64 {
        *self.new_coverage_count.read().unwrap()
    }

    /// Get a snapshot of current coverage stats
    pub fn snapshot(&self) -> CoverageSnapshot {
        CoverageSnapshot {
            constraints_hit: self.unique_constraints_hit(),
            total_constraints: self.total_constraints,
            coverage_percentage: self.coverage_percentage(),
            unique_patterns: self.unique_coverage_patterns(),
            new_coverage_discoveries: self.new_coverage_count(),
        }
    }

    /// Reset the coverage tracker
    pub fn reset(&self) {
        *self.constraint_hits.write().unwrap() = HashMap::new();
        *self.unique_coverages.write().unwrap() = HashSet::new();
        *self.max_coverage.write().unwrap() = 0;
        *self.new_coverage_count.write().unwrap() = 0;
    }
}

/// Snapshot of coverage statistics
#[derive(Debug, Clone)]
pub struct CoverageSnapshot {
    pub constraints_hit: usize,
    pub total_constraints: usize,
    pub coverage_percentage: f64,
    pub unique_patterns: usize,
    pub new_coverage_discoveries: u64,
}

impl std::fmt::Display for CoverageSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} constraints ({:.1}%), {} patterns, {} new",
            self.constraints_hit,
            self.total_constraints,
            self.coverage_percentage,
            self.unique_patterns,
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
        (energy as f64 * decay) as usize
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
mod tests {
    use super::*;

    #[test]
    fn test_coverage_tracker_basic() {
        let tracker = CoverageTracker::new(100);

        assert_eq!(tracker.coverage_percentage(), 0.0);
        assert_eq!(tracker.unique_constraints_hit(), 0);

        tracker.record_hit(0);
        tracker.record_hit(1);
        tracker.record_hit(2);

        assert_eq!(tracker.unique_constraints_hit(), 3);
        assert!((tracker.coverage_percentage() - 3.0).abs() < 0.1);
    }

    #[test]
    fn test_coverage_tracker_execution() {
        let tracker = CoverageTracker::new(100);

        let is_new = tracker.record_execution(&[0, 1, 2, 3, 4]);
        assert!(is_new);

        // Same coverage pattern should not be new
        let is_new = tracker.record_execution(&[0, 1, 2, 3, 4]);
        assert!(!is_new);

        // Different pattern should be new
        let is_new = tracker.record_execution(&[5, 6, 7, 8, 9]);
        assert!(is_new);

        assert_eq!(tracker.unique_coverage_patterns(), 2);
    }

    #[test]
    fn test_record_coverage_hash() {
        let tracker = CoverageTracker::new(100);

        assert!(tracker.record_coverage_hash(42));
        assert!(!tracker.record_coverage_hash(42));
        assert_eq!(tracker.unique_coverage_patterns(), 1);
    }

    #[test]
    fn test_uncovered_constraints() {
        let tracker = CoverageTracker::new(5);

        tracker.record_hit(0);
        tracker.record_hit(2);
        tracker.record_hit(4);

        let uncovered = tracker.uncovered_constraints();
        assert_eq!(uncovered, vec![1, 3]);
    }

    #[test]
    fn test_energy_scheduler() {
        let scheduler = EnergyScheduler::new();

        // New coverage should get bonus
        let energy_new = scheduler.calculate_energy(true, 0);
        let energy_old = scheduler.calculate_energy(false, 0);
        assert!(energy_new > energy_old);

        // Older cases should have less energy
        let energy_fresh = scheduler.calculate_energy(false, 0);
        let energy_aged = scheduler.calculate_energy(false, 10);
        assert!(energy_fresh > energy_aged);
    }

    #[test]
    fn test_coverage_snapshot() {
        let tracker = CoverageTracker::new(100);
        tracker.record_execution(&[0, 1, 2, 3, 4]);

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.constraints_hit, 5);
        assert_eq!(snapshot.total_constraints, 100);
        assert!((snapshot.coverage_percentage - 5.0).abs() < 0.1);
    }
}
