
use super::*;

#[test]
fn test_tracker_creation() {
    let tracker = OracleDiversityTracker::with_standard_oracles();
    let stats = tracker.stats();

    assert!(stats.registered_count >= 10);
    assert_eq!(stats.fired_count, 0);
    assert_eq!(stats.coverage_percent, 0.0);
}

#[test]
fn test_record_fire() {
    let mut tracker = OracleDiversityTracker::new();
    tracker.register_oracle("test_oracle");

    tracker.record_fire("test_oracle", "pattern_1");
    tracker.record_fire("test_oracle", "pattern_2");
    tracker.record_fire("test_oracle", "pattern_1"); // Duplicate

    let stats = tracker.stats();

    assert_eq!(stats.fired_count, 1);
    assert_eq!(stats.unique_patterns, 2);
    assert_eq!(stats.total_fires, 3);
    assert_eq!(stats.coverage_percent, 100.0);
}

#[test]
fn test_diversity_score() {
    let mut tracker = OracleDiversityTracker::new();
    tracker.register_oracle("oracle_1");
    tracker.register_oracle("oracle_2");
    tracker.register_oracle("oracle_3");

    // Fire only one oracle
    tracker.record_fire("oracle_1", "p1");
    let stats_1 = tracker.stats();

    // Fire all oracles
    tracker.record_fire("oracle_2", "p2");
    tracker.record_fire("oracle_3", "p3");
    let stats_2 = tracker.stats();

    // Diversity should increase
    assert!(stats_2.diversity_score > stats_1.diversity_score);
}

#[test]
fn test_recommendations() {
    let mut tracker = OracleDiversityTracker::new();
    tracker.register_oracle("enabled_oracle");
    tracker.register_oracle("disabled_oracle");

    tracker.record_fire("enabled_oracle", "p1");

    let recommendations = tracker.recommendations();

    assert!(!recommendations.is_empty());
    assert!(recommendations
        .iter()
        .any(|r| r.description.contains("disabled_oracle")));
}

#[test]
fn test_finding_recording() {
    let mut tracker = OracleDiversityTracker::with_standard_oracles();

    let finding = Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::Critical,
        description: "Test finding".to_string(),
        poc: zk_core::ProofOfConcept::default(),
        location: Some("test.circom:42".to_string()),
    };

    tracker.record_finding(&finding);

    let stats = tracker.stats();
    assert!(stats.fired_count > 0);
    assert!(stats.unique_patterns > 0);
}
