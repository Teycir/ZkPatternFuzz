use super::*;
use crate::config::{Attack, AttackType};

#[test]
fn test_missing_circuit_path_is_critical() {
    let config = FuzzConfig::default_v2();
    let report = check_0day_readiness(&config);

    assert!(!report.ready_for_evidence);
    assert!(report
        .warnings
        .iter()
        .any(|w| w.level == ReadinessLevel::Critical && w.category == "Target"));
}

#[test]
fn test_low_iterations_warning() {
    let mut config = FuzzConfig::default_v2();
    config.campaign.parameters.additional.insert(
        "max_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(100)),
    );

    let report = check_0day_readiness(&config);
    assert!(report
        .warnings
        .iter()
        .any(|w| w.category == "Fuzzing" && w.message.contains("too low")));
}

#[test]
fn test_evidence_mode_without_validation() {
    let mut config = FuzzConfig::default_v2();
    config
        .campaign
        .parameters
        .additional
        .insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));
    config.campaign.parameters.additional.insert(
        "oracle_validation".to_string(),
        serde_yaml::Value::Bool(false),
    );

    let report = check_0day_readiness(&config);
    assert!(report
        .warnings
        .iter()
        .any(|w| w.category == "Evidence" && w.level == ReadinessLevel::High));
}

#[test]
fn test_soundness_missing_forge_attempts_uses_runner_default() {
    let mut config = FuzzConfig::default_v2();
    config.campaign.parameters.additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.attacks.push(Attack {
        attack_type: AttackType::Soundness,
        description: "soundness".to_string(),
        plugin: None,
        config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
    });

    let report = check_0day_readiness(&config);
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.message.contains("0 forge_attempts")),
        "missing forge_attempts should not be treated as zero"
    );
}

#[test]
fn test_soundness_explicit_zero_forge_attempts_is_critical_in_strict_mode() {
    let mut config = FuzzConfig::default_v2();
    config.campaign.parameters.additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.attacks.push(Attack {
        attack_type: AttackType::Soundness,
        description: "soundness".to_string(),
        plugin: None,
        config: serde_yaml::from_str("forge_attempts: 0").expect("valid yaml"),
    });

    let report = check_0day_readiness(&config);
    assert!(report.warnings.iter().any(|w| {
        w.level == ReadinessLevel::Critical && w.message.contains("0 forge_attempts")
    }));
}

#[test]
fn test_strict_readiness_accepts_required_attacks_from_schedule() {
    let mut config = FuzzConfig::default_v2();
    config.campaign.parameters.additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "strict_backend".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "oracle_validation".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "v2_schedule".to_string(),
        serde_yaml::from_str(
            r#"
- phase: strict
  duration_sec: 60
  attacks:
    - underconstrained
    - soundness
    - constraint_inference
    - metamorphic
    - constraint_slice
    - spec_inference
    - witness_collision
"#,
        )
        .expect("schedule yaml should parse"),
    );

    let report = check_0day_readiness(&config);
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.message.contains("Missing required attack: soundness")),
    );
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.message.contains("Missing required attack: underconstrained")),
    );
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.message.contains("Missing required novel attack:")),
    );
}

#[test]
fn test_strict_readiness_accepts_schedule_attack_aliases() {
    let mut config = FuzzConfig::default_v2();
    config.campaign.parameters.additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "strict_backend".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "oracle_validation".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "v2_schedule".to_string(),
        serde_yaml::from_str(
            r#"
- phase: strict
  duration_sec: 60
  attacks:
    - underconstrained
    - soundness
    - constraintinference
    - metamorphic
    - constraintslice
    - specinference
    - witnesscollision
"#,
        )
        .expect("schedule yaml should parse"),
    );

    let report = check_0day_readiness(&config);
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.message.contains("Missing required novel attack:")),
        "schedule aliases should satisfy strict novel-attack requirements"
    );
}
