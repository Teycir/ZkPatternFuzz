use std::collections::HashMap;
use std::path::PathBuf;

use tokio::sync::RwLock;
use zk_core::{AttackType, FieldElement, Finding, Framework, ProofOfConcept, Severity};
use zk_fuzzer::config::v2::{EarlyTerminateCondition, SchedulePhase};
use zk_fuzzer::config::{
    AdditionalConfig, Attack, Campaign, FuzzConfig, FuzzStrategy, Input, Parameters,
    ReportingConfig, Target,
};
use zk_fuzzer::fuzzer::phased_scheduler::{
    EarlyTerminationChecker, PhaseExecutionResult, PhasedScheduler, ScheduleBuilder,
};

fn base_config() -> FuzzConfig {
    FuzzConfig {
        campaign: Campaign {
            name: "phased scheduler test".to_string(),
            version: "1.0".to_string(),
            target: Target {
                framework: Framework::Circom,
                circuit_path: PathBuf::from("fixtures/test.circom"),
                main_component: "Main".to_string(),
            },
            parameters: Parameters {
                field: "bn254".to_string(),
                max_constraints: 1000,
                timeout_seconds: 10,
                additional: AdditionalConfig::default(),
            },
        },
        attacks: vec![Attack {
            attack_type: AttackType::Underconstrained,
            description: "test".to_string(),
            plugin: None,
            config: serde_yaml::Value::Null,
        }],
        inputs: vec![Input {
            name: "x".to_string(),
            input_type: "field".to_string(),
            fuzz_strategy: FuzzStrategy::Random,
            constraints: vec![],
            interesting: vec![],
            length: None,
        }],
        mutations: vec![],
        oracles: vec![],
        reporting: ReportingConfig::default(),
        chains: vec![],
    }
}

#[tokio::test]
async fn test_schedule_builder_executes_two_phases() {
    let scheduler = ScheduleBuilder::new()
        .exploration(60)
        .deep_testing(300)
        .build();

    let results = scheduler
        .execute(
            &base_config(),
            |_phase_config, _corpus: std::sync::Arc<RwLock<Vec<Vec<FieldElement>>>>| async {
                Ok(PhaseExecutionResult {
                    findings: vec![],
                    coverage_percentage: 10.0,
                    corpus_size: 1,
                    early_terminated: false,
                    termination_reason: None,
                })
            },
        )
        .await
        .expect("scheduler execution should succeed");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].phase_name, "exploration");
    assert_eq!(results[1].phase_name, "deep_testing");
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
    assert!(checker.check(0.0, 1).is_some());
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
    assert!(checker.check(80.0, 0).is_some());
}

#[tokio::test]
async fn test_schedule_fail_on_findings_severity() {
    let scheduler = PhasedScheduler::new(vec![
        SchedulePhase {
            phase: "static_prepass".to_string(),
            duration_sec: 15,
            attacks: vec!["quantum_resistance".to_string()],
            max_iterations: Some(1),
            early_terminate: None,
            fail_on_findings: vec![Severity::Critical, Severity::High],
            carry_corpus: true,
            mutation_weights: HashMap::new(),
        },
        SchedulePhase {
            phase: "should_not_run".to_string(),
            duration_sec: 15,
            attacks: vec!["underconstrained".to_string()],
            max_iterations: Some(1),
            early_terminate: None,
            fail_on_findings: vec![],
            carry_corpus: true,
            mutation_weights: HashMap::new(),
        },
    ]);

    let findings = vec![Finding {
        attack_type: AttackType::QuantumResistance,
        severity: Severity::High,
        description: "static finding".to_string(),
        poc: ProofOfConcept {
            witness_a: Vec::new(),
            witness_b: None,
            public_inputs: Vec::new(),
            proof: None,
        },
        location: Some("sample.circom".to_string()),
    }];

    let results = scheduler
        .execute(
            &base_config(),
            move |_phase_config, _corpus: std::sync::Arc<RwLock<Vec<Vec<FieldElement>>>>| {
                let findings = findings.clone();
                async move {
                    Ok(PhaseExecutionResult {
                        findings,
                        coverage_percentage: 0.0,
                        corpus_size: 0,
                        early_terminated: false,
                        termination_reason: None,
                    })
                }
            },
        )
        .await
        .expect("schedule execution should succeed");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].phase_name, "static_prepass");
}
