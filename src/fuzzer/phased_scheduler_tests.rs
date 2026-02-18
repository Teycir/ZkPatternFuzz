use super::*;

#[test]
fn test_schedule_builder() {
    let scheduler = ScheduleBuilder::new()
        .exploration(60)
        .deep_testing(300)
        .build();

    assert_eq!(scheduler.phases.len(), 2);
    assert_eq!(scheduler.phases[0].phase, "exploration");
    assert_eq!(scheduler.phases[1].phase, "deep_testing");
}

#[test]
fn test_parse_attack_type() {
    assert_eq!(
        PhasedScheduler::parse_attack_type("underconstrained"),
        Some(AttackType::Underconstrained)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("SOUNDNESS"),
        Some(AttackType::Soundness)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("arithmetic_overflow"),
        Some(AttackType::ArithmeticOverflow)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("trusted_setup"),
        Some(AttackType::TrustedSetup)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("mev"),
        Some(AttackType::Mev)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("front_running"),
        Some(AttackType::FrontRunning)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("batch_verification"),
        Some(AttackType::BatchVerification)
    );
    assert_eq!(PhasedScheduler::parse_attack_type("unknown"), None);
}

#[test]
fn test_early_termination_critical_findings() {
    let condition = EarlyTerminateCondition {
        on_critical_findings: Some(3),
        on_coverage_percent: None,
        on_stale_seconds: None,
    };

    let mut checker = EarlyTerminationChecker::new(condition);

    assert!(checker.check(0.0, 1).is_none());
    assert!(checker.check(0.0, 1).is_none());
    assert!(checker.check(0.0, 1).is_some()); // 3rd critical finding
}

#[test]
fn test_early_termination_coverage() {
    let condition = EarlyTerminateCondition {
        on_critical_findings: None,
        on_coverage_percent: Some(80.0),
        on_stale_seconds: None,
    };

    let mut checker = EarlyTerminationChecker::new(condition);

    assert!(checker.check(50.0, 0).is_none());
    assert!(checker.check(75.0, 0).is_none());
    assert!(checker.check(80.0, 0).is_some()); // Coverage target reached
}
