use super::super::attack_runner_budget::{deterministic_attack_cap, strict_attack_floor};
use super::FuzzingEngine;
use zk_core::{AttackType, Finding, ProofOfConcept, Severity};

#[test]
fn deterministic_cap_enabled_by_default_in_evidence_mode() {
    let mut additional = crate::config::AdditionalConfig::default();
    additional.insert(
        "fuzzing_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(20)),
    );

    let (cap, iterations, multiplier) =
        deterministic_attack_cap(&additional, true, 1, "underconstrained_witness_pairs_cap")
            .expect("cap should be enabled");
    assert_eq!(iterations, 20);
    assert_eq!(multiplier, 4);
    assert_eq!(cap, 80);
}

#[test]
fn deterministic_cap_can_be_disabled_explicitly() {
    let mut additional = crate::config::AdditionalConfig::default();
    additional.insert(
        "evidence_deterministic_runtime".to_string(),
        serde_yaml::Value::Bool(false),
    );
    additional.insert(
        "fuzzing_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(20)),
    );

    let cap = deterministic_attack_cap(&additional, true, 1, "underconstrained_witness_pairs_cap");
    assert!(cap.is_none());
}

#[test]
fn per_attack_cap_overrides_global_cap() {
    let mut additional = crate::config::AdditionalConfig::default();
    additional.insert(
        "fuzzing_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(20)),
    );
    additional.insert(
        "underconstrained_witness_pairs_cap".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(33)),
    );

    let (cap, _, _) =
        deterministic_attack_cap(&additional, true, 1, "underconstrained_witness_pairs_cap")
            .expect("cap should be enabled");
    assert_eq!(cap, 33);
}

#[test]
fn strict_attack_floor_applies_in_strict_mode() {
    let mut additional = crate::config::AdditionalConfig::default();
    additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );

    let effective = strict_attack_floor(&additional, 200, 1000, "soundness.forge_attempts");
    assert_eq!(effective, 1000);
}

#[test]
fn strict_attack_floor_does_not_apply_when_not_strict() {
    let additional = crate::config::AdditionalConfig::default();
    let effective = strict_attack_floor(&additional, 200, 1000, "soundness.forge_attempts");
    assert_eq!(effective, 200);
}

#[test]
fn strict_attack_floor_keeps_higher_configured_values() {
    let mut additional = crate::config::AdditionalConfig::default();
    additional.insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));

    let effective = strict_attack_floor(&additional, 2500, 1000, "soundness.forge_attempts");
    assert_eq!(effective, 2500);
}

#[test]
fn strict_attack_floor_is_skipped_in_deterministic_runtime_mode() {
    let mut additional = crate::config::AdditionalConfig::default();
    additional.insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));
    additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    additional.insert(
        "evidence_deterministic_runtime".to_string(),
        serde_yaml::Value::Bool(true),
    );

    let effective = strict_attack_floor(&additional, 200, 1000, "soundness.forge_attempts");
    assert_eq!(effective, 200);
}

#[test]
fn engine_dispatch_has_no_not_yet_implemented_fallback() {
    let source = format!(
        "{}\n{}\n{}",
        include_str!("mod.rs"),
        include_str!("run_lifecycle.rs"),
        include_str!("run_dispatch.rs")
    );
    assert!(
        !source.contains("not yet implemented"),
        "engine dispatch should not rely on generic 'not yet implemented' fallback"
    );
    assert!(
        source.contains("AttackType::BitDecomposition =>"),
        "BitDecomposition should be routed explicitly in engine dispatch"
    );
}

#[test]
fn has_static_source_evidence_accepts_quantum_and_circom_lint() {
    let quantum = Finding {
        attack_type: AttackType::QuantumResistance,
        severity: Severity::High,
        description: "quantum source match".to_string(),
        poc: ProofOfConcept {
            witness_a: Vec::new(),
            witness_b: None,
            public_inputs: Vec::new(),
            proof: None,
        },
        location: Some("circuit.circom:12".to_string()),
    };
    assert!(FuzzingEngine::has_static_source_evidence(&quantum));

    let circom_lint = Finding {
        attack_type: AttackType::CircomStaticLint,
        severity: Severity::Critical,
        description: "missing constraint".to_string(),
        poc: ProofOfConcept {
            witness_a: Vec::new(),
            witness_b: None,
            public_inputs: Vec::new(),
            proof: None,
        },
        location: Some("circuit.circom:22".to_string()),
    };
    assert!(FuzzingEngine::has_static_source_evidence(&circom_lint));
}

#[test]
fn has_static_source_evidence_requires_location() {
    let finding = Finding {
        attack_type: AttackType::CircomStaticLint,
        severity: Severity::High,
        description: "missing constraint".to_string(),
        poc: ProofOfConcept {
            witness_a: Vec::new(),
            witness_b: None,
            public_inputs: Vec::new(),
            proof: None,
        },
        location: None,
    };
    assert!(!FuzzingEngine::has_static_source_evidence(&finding));
}
