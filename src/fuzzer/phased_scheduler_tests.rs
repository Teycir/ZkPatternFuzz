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
    assert_eq!(
        PhasedScheduler::parse_attack_type("sidechannel_advanced"),
        Some(AttackType::SidechannelAdvanced)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("quantum_resistance"),
        Some(AttackType::QuantumResistance)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("privacy_advanced"),
        Some(AttackType::PrivacyAdvanced)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("defi_advanced"),
        Some(AttackType::DefiAdvanced)
    );
    assert_eq!(
        PhasedScheduler::parse_attack_type("circom_static_lint"),
        Some(AttackType::CircomStaticLint)
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

#[test]
fn test_schedule_fail_on_findings_severity() {
    let scheduler = PhasedScheduler::new(vec![]);
    let phase = SchedulePhase {
        phase: "static_prepass".to_string(),
        duration_sec: 15,
        attacks: vec!["quantum_resistance".to_string()],
        max_iterations: Some(1),
        early_terminate: None,
        fail_on_findings: vec![zk_core::Severity::Critical, zk_core::Severity::High],
        carry_corpus: true,
        mutation_weights: HashMap::new(),
    };

    let result = PhaseResult {
        phase_name: "static_prepass".to_string(),
        duration: std::time::Duration::from_secs(1),
        findings: vec![Finding {
            attack_type: AttackType::QuantumResistance,
            severity: zk_core::Severity::High,
            description: "static finding".to_string(),
            poc: zk_core::ProofOfConcept {
                witness_a: Vec::new(),
                witness_b: None,
                public_inputs: Vec::new(),
                proof: None,
            },
            location: Some("mock.circom".to_string()),
        }],
        coverage_percentage: 0.0,
        corpus_size: 0,
        early_terminated: false,
        termination_reason: None,
    };

    assert!(scheduler.should_terminate_schedule(&result, &phase));
}
