use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zk_core::Severity;
use zk_fuzzer::cve::{
    AffectedCircuit, CveDatabase, CvePattern, DetectionConfig, RegressionTestConfig,
    RemediationInfo,
};

fn test_pattern(pattern: &str) -> CvePattern {
    CvePattern {
        id: "ZK-TEST-001".to_string(),
        name: "Test Vulnerability".to_string(),
        severity: "high".to_string(),
        cvss_score: Some(8.0),
        affected_circuits: vec![AffectedCircuit {
            pattern: pattern.to_string(),
            versions: vec!["*".to_string()],
        }],
        sources: vec!["Test Source".to_string()],
        description: "Test description".to_string(),
        detection: DetectionConfig {
            oracle: "test_oracle".to_string(),
            attack_type: "boundary".to_string(),
            procedure: vec![],
        },
        regression_test: RegressionTestConfig {
            enabled: true,
            circuit_path: "test.circom".to_string(),
            test_cases: vec![],
            assertion: "Test assertion".to_string(),
        },
        remediation: RemediationInfo {
            description: "Test remediation".to_string(),
            code_example: None,
            recommendations: vec![],
            references: vec![],
        },
    }
}

fn write_temp_yaml(contents: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("zkf_cve_{}.yaml", stamp));
    fs::write(&path, contents).expect("write temp yaml");
    path
}

#[test]
fn load_database_from_yaml_string() {
    let yaml = r#"
version: "1.0"
last_updated: "2026-02-05"
vulnerabilities:
  - id: "ZK-TEST-001"
    name: "Test Vulnerability"
    severity: high
    affected_circuits:
      - pattern: "test_circuit"
        versions: ["*"]
    sources:
      - "Test Source"
    description: "Test description"
    detection:
      oracle: test_oracle
      attack_type: boundary
      procedure: []
    regression_test:
      enabled: true
      circuit_path: "test.circom"
      test_cases: []
      assertion: "Test assertion"
    remediation:
      description: "Test remediation"
"#;
    let db: CveDatabase = serde_yaml::from_str(yaml).expect("parse yaml");
    assert_eq!(db.vulnerabilities.len(), 1);
    assert_eq!(db.vulnerabilities[0].id, "ZK-TEST-001");
}

#[test]
fn pattern_matching_supports_plain_regex_and_glob() {
    let plain = test_pattern("tornado*");
    assert!(plain.affects_circuit("tornado-core"));
    assert!(!plain.affects_circuit("semaphore"));

    let regex = test_pattern("regex:tornado[-_/]?core");
    assert!(regex.affects_circuit("tornado-core"));
    assert!(regex.affects_circuit("Tornado_Core"));

    let glob = test_pattern("circomlib/*eddsa*");
    assert!(glob.affects_circuit("circomlib/v2/eddsa_utils.circom"));
    assert!(!glob.affects_circuit("circomlib/poseidon.circom"));
}

#[test]
fn severity_enum_maps_critical() {
    let mut pattern = test_pattern("test");
    pattern.severity = "critical".to_string();
    assert_eq!(pattern.severity_enum(), Severity::Critical);
}

#[test]
fn strict_fixture_validation_accepts_unambiguous_fixture() {
    let yaml = r#"
version: "1.0"
last_updated: "2026-02-15"
vulnerabilities:
  - id: "ZK-STRICT-OK"
    name: "Strict Fixture OK"
    severity: "high"
    affected_circuits:
      - pattern: "strict_ok"
        versions: ["*"]
    sources: []
    description: "strict fixture"
    detection:
      oracle: "range"
      attack_type: "boundary"
      procedure: []
    regression_test:
      enabled: true
      circuit_path: "tests/circuits/safe/simple_multiplier.circom"
      test_cases:
        - name: "valid_case"
          inputs:
            a: "0x2"
            b: "3"
          expected_result: "valid"
      assertion: "fixture"
    remediation:
      description: "n/a"
"#;

    let path = write_temp_yaml(yaml);
    let result = CveDatabase::load_strict(&path);
    let _ = fs::remove_file(path);
    assert!(result.is_ok(), "expected strict fixture to be accepted");
}

#[test]
fn strict_fixture_validation_rejects_ambiguous_fixture() {
    let yaml = r#"
version: "1.0"
last_updated: "2026-02-15"
vulnerabilities:
  - id: "ZK-STRICT-BAD"
    name: "Strict Fixture Bad"
    severity: "high"
    affected_circuits:
      - pattern: "strict_bad"
        versions: ["*"]
    sources: []
    description: "strict fixture"
    detection:
      oracle: "range"
      attack_type: "boundary"
      procedure: []
    regression_test:
      enabled: true
      circuit_path: "tests/circuits/safe/simple_multiplier.circom"
      test_cases:
        - name: "ambiguous_case"
          inputs:
            a: "US"
          expected_result: "maybe"
      assertion: "fixture"
    remediation:
      description: "n/a"
"#;

    let path = write_temp_yaml(yaml);
    let result = CveDatabase::load_strict(&path);
    let _ = fs::remove_file(path);
    assert!(result.is_err(), "expected strict fixture to be rejected");
}
