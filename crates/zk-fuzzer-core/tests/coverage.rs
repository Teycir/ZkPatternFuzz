use zk_core::ExecutionCoverage;
use zk_fuzzer_core::coverage::{CoverageTracker, EnergyScheduler};

fn coverage_for(constraints: &[usize]) -> ExecutionCoverage {
    ExecutionCoverage::with_constraints(constraints.to_vec(), constraints.to_vec())
}

#[test]
fn coverage_tracker_basic() {
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
fn coverage_tracker_execution() {
    let tracker = CoverageTracker::new(100);

    let is_new = tracker.record_execution(&coverage_for(&[0, 1, 2, 3, 4]));
    assert!(is_new);

    // Same coverage pattern should not be new.
    let is_new = tracker.record_execution(&coverage_for(&[0, 1, 2, 3, 4]));
    assert!(!is_new);

    // Different pattern should be new.
    let is_new = tracker.record_execution(&coverage_for(&[5, 6, 7, 8, 9]));
    assert!(is_new);

    assert_eq!(tracker.unique_coverage_patterns(), 2);
}

#[test]
fn record_coverage_hash() {
    let tracker = CoverageTracker::new(100);

    assert!(tracker.record_coverage_hash(42));
    assert!(!tracker.record_coverage_hash(42));
    assert_eq!(tracker.unique_coverage_patterns(), 1);
}

#[test]
fn uncovered_constraints() {
    let tracker = CoverageTracker::new(5);

    tracker.record_hit(0);
    tracker.record_hit(2);
    tracker.record_hit(4);

    let uncovered = tracker.uncovered_constraints();
    assert_eq!(uncovered, vec![1, 3]);
}

#[test]
fn energy_scheduler() {
    let scheduler = EnergyScheduler::new();

    // New coverage should get bonus.
    let energy_new = scheduler.calculate_energy(true, 0);
    let energy_old = scheduler.calculate_energy(false, 0);
    assert!(energy_new > energy_old);

    // Older cases should have less energy.
    let energy_fresh = scheduler.calculate_energy(false, 0);
    let energy_aged = scheduler.calculate_energy(false, 10);
    assert!(energy_fresh > energy_aged);
}

#[test]
fn energy_scheduler_rounding_preserves_small_energy() {
    let scheduler = EnergyScheduler::new()
        .with_base_energy(1)
        .with_new_coverage_bonus(0);
    let energy = scheduler.calculate_energy(false, 1);
    assert_eq!(energy, 1);
}

#[test]
fn coverage_snapshot() {
    let tracker = CoverageTracker::new(100);
    tracker.record_execution(&coverage_for(&[0, 1, 2, 3, 4]));

    let snapshot = tracker.snapshot();
    assert_eq!(snapshot.constraints_hit, 5);
    assert_eq!(snapshot.total_constraints, 100);
    assert!((snapshot.coverage_percentage - 5.0).abs() < 0.1);
}
