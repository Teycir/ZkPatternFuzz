use super::*;

#[test]
fn quantum_resistance_default_config_includes_common_primitives() {
    let config = QuantumResistanceConfig::default();
    assert!(
        config
            .vulnerable_primitives
            .iter()
            .any(|p| p.name == "RSA")
    );
    assert!(
        config
            .vulnerable_primitives
            .iter()
            .any(|p| p.name == "ECDSA")
    );
}

#[test]
fn quantum_resistance_scans_source_patterns() {
    let attack = QuantumResistanceAttack::new(QuantumResistanceConfig::default());
    let findings = attack.scan_source(
        "component Main { signal input sig; // uses ecdsa_verify helper }",
        Some("mock.circom".to_string()),
        &[FieldElement::from_u64(1)],
    );

    assert!(!findings.is_empty());
    assert!(
        findings
            .iter()
            .any(|f| f.attack_type == AttackType::QuantumResistance)
    );
}

#[test]
fn quantum_resistance_uses_word_boundary_matching() {
    let attack = QuantumResistanceAttack::new(QuantumResistanceConfig::default());
    let findings = attack.scan_source(
        "template Main() { signal input x; // brsa and ecdsa_verifyx are not primitives }",
        Some("mock.circom".to_string()),
        &[FieldElement::from_u64(1)],
    );

    assert!(findings.is_empty());
}

#[test]
fn quantum_resistance_supports_static_findings_without_witness_generation() {
    let attack = QuantumResistanceAttack::new(QuantumResistanceConfig::default());
    let findings = attack.scan_source(
        "template Main() { /* rsa_verify path */ }",
        Some("static.circom".to_string()),
        &[],
    );

    assert!(!findings.is_empty());
    let finding = &findings[0];
    assert_eq!(finding.attack_type, AttackType::QuantumResistance);
    assert!(finding.poc.witness_a.is_empty());
    assert!(finding.location.is_some());
}
