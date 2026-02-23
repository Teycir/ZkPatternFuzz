use zk_core::{AttackType, CoverageMap, FieldElement, Finding, ProofOfConcept, Severity};
use zk_fuzzer::config::ReportingConfig;
use zk_fuzzer::reporting::FuzzReport;

#[test]
fn test_report_creation() {
    let findings = vec![Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::Critical,
        description: "Test finding".to_string(),
        poc: ProofOfConcept::default(),
        location: None,
        class: None,
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
        class: None,
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

#[test]
fn test_finding_roundtrip_preserves_counterexample_fields() {
    let original = Finding {
        attack_type: AttackType::ConstraintInference,
        severity: Severity::High,
        description: "Invariant counterexample".to_string(),
        poc: ProofOfConcept {
            witness_a: vec![FieldElement::from_u64(1)],
            witness_b: Some(vec![FieldElement::from_u64(2)]),
            public_inputs: vec![FieldElement::from_u64(3)],
            proof: Some(vec![7, 8, 9]),
        },
        location: Some("Invariant: sample".to_string()),
        class: None,
    };

    let json = serde_json::to_string(&original).expect("serialize finding with counterexample");
    assert!(json.contains("\"poc_public_inputs\""));

    let deserialized: Finding =
        serde_json::from_str(&json).expect("deserialize finding with counterexample");
    assert_eq!(deserialized.poc.witness_a.len(), 1);
    assert_eq!(deserialized.poc.witness_b.as_ref().map(Vec::len), Some(1));
    assert_eq!(deserialized.poc.public_inputs.len(), 1);
    assert_eq!(
        deserialized.poc.public_inputs[0].to_hex(),
        FieldElement::from_u64(3).to_hex()
    );
    assert_eq!(deserialized.poc.proof, Some(vec![7, 8, 9]));
}

#[test]
fn test_markdown_report_includes_counterexample_public_outputs() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    let findings = vec![Finding {
        attack_type: AttackType::ConstraintInference,
        severity: Severity::High,
        description: "Invariant violation with counterexample".to_string(),
        poc: ProofOfConcept {
            witness_a: vec![zk_core::FieldElement::from_u64(9)],
            witness_b: None,
            public_inputs: vec![zk_core::FieldElement::from_u64(42)],
            proof: Some(vec![1, 2, 3]),
        },
        location: Some("Invariant: auto_spec_range_x".to_string()),
        class: None,
    }];

    let config = ReportingConfig {
        output_dir: temp_dir.path().to_path_buf(),
        formats: vec!["markdown".to_string()],
        include_poc: true,
        ..ReportingConfig::default()
    };

    let report = FuzzReport::new(
        "test_campaign".to_string(),
        findings,
        CoverageMap::default(),
        config,
    );
    report.save_to_files().expect("save markdown report");

    let markdown = std::fs::read_to_string(temp_dir.path().join("report.md"))
        .expect("read generated markdown report");
    assert!(markdown.contains("Public Inputs/Outputs:"));
    assert!(markdown.contains("0x000000000000000000000000000000000000000000000000000000000000002a"));
    assert!(markdown.contains("Proof Bytes: 3"));
}
