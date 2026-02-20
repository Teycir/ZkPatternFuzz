use super::*;
use zk_core::ProofOfConcept;

#[test]
fn test_sarif_builder() {
    let findings = vec![Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::Critical,
        description: "Test finding".to_string(),
        poc: ProofOfConcept::default(),
        location: Some("test.circom:42".to_string()),
    }];

    let report = SarifBuilder::new("zk-fuzzer", "0.1.0")
        .with_circuit_path("circuits/test.circom")
        .add_findings(&findings)
        .build();

    assert_eq!(report.version, SARIF_VERSION);
    assert_eq!(report.runs.len(), 1);
    assert_eq!(report.runs[0].results.len(), 1);
    assert_eq!(report.runs[0].results[0].rule_id, "ZK001");
}

#[test]
fn test_severity_to_level() {
    assert_eq!(SarifLevel::from(Severity::Critical), SarifLevel::Error);
    assert_eq!(SarifLevel::from(Severity::High), SarifLevel::Error);
    assert_eq!(SarifLevel::from(Severity::Medium), SarifLevel::Warning);
    assert_eq!(SarifLevel::from(Severity::Low), SarifLevel::Note);
    assert_eq!(SarifLevel::from(Severity::Info), SarifLevel::Note);
}

#[test]
fn test_parse_location() {
    let loc = parse_location("test.circom:42:10");
    let phys = loc.physical_location.unwrap();
    assert_eq!(
        phys.artifact_location.unwrap().uri,
        Some("test.circom".to_string())
    );
    let region = phys.region.unwrap();
    assert_eq!(region.start_line, Some(42));
    assert_eq!(region.start_column, Some(10));
}

#[test]
fn test_parse_location_windows_path_with_line_and_column() {
    let loc = parse_location("C:\\repo\\test.circom:12:3");
    let phys = loc.physical_location.unwrap();
    assert_eq!(
        phys.artifact_location.unwrap().uri,
        Some("C:\\repo\\test.circom".to_string())
    );
    let region = phys.region.unwrap();
    assert_eq!(region.start_line, Some(12));
    assert_eq!(region.start_column, Some(3));
}

#[test]
fn test_parse_location_invalid_suffix_keeps_plain_path() {
    let loc = parse_location("test.circom:not_a_number");
    let phys = loc.physical_location.unwrap();
    assert_eq!(
        phys.artifact_location.unwrap().uri,
        Some("test.circom:not_a_number".to_string())
    );
    assert!(phys.region.is_none());
}

#[test]
fn test_attack_type_to_rule_id() {
    assert_eq!(
        attack_type_to_rule_id(&AttackType::Underconstrained),
        "ZK001"
    );
    assert_eq!(attack_type_to_rule_id(&AttackType::Collision), "ZK004");
    assert_eq!(attack_type_to_rule_id(&AttackType::Boundary), "ZK005");
}

#[test]
fn test_generate_rules() {
    let rules = generate_rules();
    assert!(rules.len() >= 10);

    // All rules should have IDs starting with ZK
    assert!(rules.iter().all(|r| r.id.starts_with("ZK")));

    // All rules should have descriptions
    assert!(rules.iter().all(|r| r.short_description.is_some()));
}

#[test]
fn test_sarif_serialization() {
    let report = SarifBuilder::new("test", "1.0.0").build();
    let json = report.to_json().unwrap();

    // Should contain required fields
    assert!(json.contains("$schema"));
    assert!(json.contains("version"));
    assert!(json.contains("runs"));
}

#[test]
fn test_detect_mime_type() {
    assert_eq!(
        detect_mime_type("test.circom"),
        Some("text/x-circom".to_string())
    );
    assert_eq!(detect_mime_type("test.nr"), Some("text/x-noir".to_string()));
    assert_eq!(detect_mime_type("test.rs"), Some("text/x-rust".to_string()));
    assert_eq!(
        detect_mime_type("test.json"),
        Some("application/json".to_string())
    );
}

#[test]
fn test_hamming_fingerprint() {
    let findings = vec![Finding {
        attack_type: AttackType::Collision,
        severity: Severity::High,
        description: "Test collision".to_string(),
        poc: ProofOfConcept::default(),
        location: None,
    }];

    let report = SarifBuilder::new("test", "1.0.0")
        .add_findings(&findings)
        .build();

    let result = &report.runs[0].results[0];
    assert!(result.fingerprints.is_some());
}
