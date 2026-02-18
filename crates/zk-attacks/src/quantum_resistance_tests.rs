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
