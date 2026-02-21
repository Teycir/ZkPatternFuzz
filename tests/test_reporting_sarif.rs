use zk_core::{AttackType, Finding, ProofOfConcept, Severity};
use zk_fuzzer::reporting::sarif::{SarifBuilder, SarifLevel, SARIF_VERSION};

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
fn test_location_parsing_from_finding_location() {
    let finding = Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::High,
        description: "location parsing".to_string(),
        poc: ProofOfConcept::default(),
        location: Some("test.circom:42:10".to_string()),
    };
    let report = SarifBuilder::new("test", "1.0.0")
        .add_findings(&[finding])
        .build();
    let loc = &report.runs[0].results[0].locations[0];
    let phys = loc
        .physical_location
        .as_ref()
        .expect("physical location should exist");
    assert_eq!(
        phys.artifact_location
            .as_ref()
            .expect("artifact location")
            .uri,
        Some("test.circom".to_string())
    );
    let region = phys.region.as_ref().expect("region should exist");
    assert_eq!(region.start_line, Some(42));
    assert_eq!(region.start_column, Some(10));
}

#[test]
fn test_location_parsing_windows_path_with_line_and_column() {
    let finding = Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::High,
        description: "windows path parsing".to_string(),
        poc: ProofOfConcept::default(),
        location: Some("C:\\repo\\test.circom:12:3".to_string()),
    };
    let report = SarifBuilder::new("test", "1.0.0")
        .add_findings(&[finding])
        .build();
    let loc = &report.runs[0].results[0].locations[0];
    let phys = loc
        .physical_location
        .as_ref()
        .expect("physical location should exist");
    assert_eq!(
        phys.artifact_location
            .as_ref()
            .expect("artifact location")
            .uri,
        Some("C:\\repo\\test.circom".to_string())
    );
    let region = phys.region.as_ref().expect("region should exist");
    assert_eq!(region.start_line, Some(12));
    assert_eq!(region.start_column, Some(3));
}

#[test]
fn test_location_parsing_invalid_suffix_keeps_plain_path() {
    let finding = Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::High,
        description: "invalid suffix path parsing".to_string(),
        poc: ProofOfConcept::default(),
        location: Some("test.circom:not_a_number".to_string()),
    };
    let report = SarifBuilder::new("test", "1.0.0")
        .add_findings(&[finding])
        .build();
    let loc = &report.runs[0].results[0].locations[0];
    let phys = loc
        .physical_location
        .as_ref()
        .expect("physical location should exist");
    assert_eq!(
        phys.artifact_location
            .as_ref()
            .expect("artifact location")
            .uri,
        Some("test.circom:not_a_number".to_string())
    );
    assert!(phys.region.is_none());
}

#[test]
fn test_rules_generated_on_build() {
    let report = SarifBuilder::new("test", "1.0.0").build();
    let rules = &report.runs[0].tool.driver.rules;
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
    let report = SarifBuilder::new("test", "1.0.0")
        .with_circuit_path("test.circom")
        .build();
    let artifact = &report.runs[0].artifacts[0];
    assert_eq!(artifact.mime_type, Some("text/x-circom".to_string()));
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
