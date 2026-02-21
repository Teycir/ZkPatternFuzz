use std::time::Duration;
use zk_core::{AttackType, Finding, ProofOfConcept, Severity};
use zk_fuzzer::fuzzer::adaptive_attack_scheduler::NearMissType;
use zk_fuzzer::fuzzer::{
    AdaptiveScheduler, AdaptiveSchedulerConfig, AttackResults, NearMissEvent,
};

#[test]
fn test_scheduler_initialization() {
    let mut scheduler = AdaptiveScheduler::new();
    scheduler.initialize(&[AttackType::Underconstrained, AttackType::Soundness]);

    assert_eq!(scheduler.scores().len(), 2);
    assert!(scheduler.scores().values().all(|&s| s > 0.0));
}

#[test]
fn test_score_update_with_findings() {
    let mut scheduler = AdaptiveScheduler::new();
    scheduler.initialize(&[AttackType::Underconstrained]);

    let initial_score = *scheduler
        .scores()
        .get(&AttackType::Underconstrained)
        .unwrap();

    let results = AttackResults {
        attack_type: AttackType::Underconstrained,
        new_coverage: 5,
        findings: vec![Finding {
            attack_type: AttackType::Underconstrained,
            severity: Severity::Critical,
            description: "Test".to_string(),
            poc: ProofOfConcept::default(),
            location: None,
        }],
        near_misses: vec![],
        iterations: 100,
        duration: Duration::from_secs(10),
    };

    scheduler.update_scores(&results);

    let new_score = *scheduler
        .scores()
        .get(&AttackType::Underconstrained)
        .unwrap();
    assert!(new_score > initial_score);
}

#[test]
fn test_budget_allocation() {
    let mut scheduler = AdaptiveScheduler::new();
    scheduler.initialize(&[
        AttackType::Underconstrained,
        AttackType::Soundness,
        AttackType::Collision,
    ]);

    let budget = scheduler.allocate_budget(Duration::from_secs(300));

    assert_eq!(budget.len(), 3);
    let total_ms: u128 = budget.values().map(Duration::as_millis).sum();
    assert_eq!(total_ms, Duration::from_secs(300).as_millis());
}

#[test]
fn test_budget_allocation_normalizes_when_min_fraction_oversubscribed() {
    let mut scheduler = AdaptiveScheduler::with_config(AdaptiveSchedulerConfig {
        min_budget_fraction: 0.40,
        max_budget_fraction: 0.90,
        ..AdaptiveSchedulerConfig::default()
    });
    scheduler.initialize(&[
        AttackType::Underconstrained,
        AttackType::Soundness,
        AttackType::Collision,
    ]);

    let budget = scheduler.allocate_budget(Duration::from_secs(10));
    assert_eq!(budget.len(), 3);
    let total_ms: u128 = budget.values().map(Duration::as_millis).sum();
    assert_eq!(total_ms, Duration::from_secs(10).as_millis());
}

#[test]
fn test_yaml_suggestions() {
    let mut scheduler = AdaptiveScheduler::new();
    scheduler.initialize(&[AttackType::Underconstrained]);

    // Add a near-miss through the public update path.
    let mut results = AttackResults::new(AttackType::Underconstrained);
    results.near_misses.push(NearMissEvent {
        event_type: NearMissType::AlmostOutOfRange,
        distance: 0.1,
        description: "0x1fffffffffffffff".to_string(),
    });
    scheduler.update_scores(&results);

    let suggestions = scheduler.suggest_yaml_edits();
    assert!(!suggestions.is_empty());
}
