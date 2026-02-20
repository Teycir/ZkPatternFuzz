use super::*;

#[test]
fn test_fuzzing_stats() {
    let stats = FuzzingStats {
        executions: 1000,
        crashes: 5,
        coverage_percentage: 75.5,
        ..FuzzingStats::default()
    };

    assert_eq!(stats.executions, 1000);
    assert_eq!(stats.crashes, 5);
}

#[test]
fn test_simple_progress_tracker() {
    let mut tracker = SimpleProgressTracker::new().with_log_interval(Duration::from_millis(100));

    let stats = FuzzingStats {
        executions: 100,
        crashes: 1,
        coverage_percentage: 50.0,
        ..Default::default()
    };

    tracker.update(stats);
    assert_eq!(tracker.stats.executions, 100);
}
