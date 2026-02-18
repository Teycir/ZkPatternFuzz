
use super::*;
use zk_core::AttackType;
use zk_core::ProofOfConcept;

#[test]
fn test_report_creation() {
    let findings = vec![Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::Critical,
        description: "Test finding".to_string(),
        poc: ProofOfConcept::default(),
        location: None,
    }];

    let report = FuzzReport::new(
        "test_campaign".to_string(),
        findings,
        CoverageMap::default(),
        ReportingConfig::default(),
    );

    assert!(report.has_critical_findings());
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn test_finding_serialization_roundtrip() {
    let original = Finding {
        attack_type: AttackType::Collision,
        severity: Severity::High,
        description: "Test collision finding".to_string(),
        poc: ProofOfConcept::default(),
        location: Some("test_circuit.circom:42".to_string()),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&original).expect("Failed to serialize Finding");

    // Deserialize back
    let deserialized: Finding = serde_json::from_str(&json).expect("Failed to deserialize Finding");

    assert_eq!(deserialized.attack_type, AttackType::Collision);
    assert_eq!(deserialized.severity, Severity::High);
    assert_eq!(deserialized.description, "Test collision finding");
    assert_eq!(
        deserialized.location,
        Some("test_circuit.circom:42".to_string())
    );
}

#[test]
fn test_finding_deserialization_from_json() {
    // Note: Severity uses lowercase per serde rename_all = "lowercase"
    let json = r#"{
            "attack_type": "Soundness",
            "severity": "critical",
            "description": "Proof forgery detected",
            "location": null,
            "poc_witness_a": ["0x0000000000000000000000000000000000000000000000000000000000000001"]
        }"#;

    let finding: Finding = serde_json::from_str(json).expect("Failed to deserialize");

    assert_eq!(finding.attack_type, AttackType::Soundness);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.description, "Proof forgery detected");
    assert!(finding.location.is_none());
    assert_eq!(finding.poc.witness_a.len(), 1);
}
