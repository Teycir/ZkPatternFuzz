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

#[test]
fn strict_fixture_validation_rejects_unresolved_circuit_path_placeholder() {
    let missing_var = "ZKFUZZER_CVE_PATH_MISSING";
    std::env::remove_var(missing_var);
    let yaml = format!(
        r#"
version: "1.0"
last_updated: "2026-02-22"
vulnerabilities:
  - id: "ZK-STRICT-ENV-BAD"
    name: "Strict Fixture Env Path Bad"
    severity: "high"
    affected_circuits:
      - pattern: "strict_env_bad"
        versions: ["*"]
    sources: []
    description: "strict fixture"
    detection:
      oracle: "range"
      attack_type: "boundary"
      procedure: []
    regression_test:
      enabled: true
      circuit_path: "${{{}}}/tests/circuits/safe/simple_multiplier.circom"
      test_cases:
        - name: "valid_case"
          inputs:
            a: "0x2"
          expected_result: "valid"
      assertion: "fixture"
    remediation:
      description: "n/a"
"#,
        missing_var
    );

    let path = write_temp_yaml(&yaml);
    let result = CveDatabase::load_strict(&path);
    let _ = fs::remove_file(path);
    assert!(result.is_err(), "expected unresolved env placeholder rejection");
    let error = result.err().expect("strict load should fail").to_string();
    assert!(
        error.contains("unresolved env placeholder"),
        "expected unresolved placeholder message, got: {}",
        error
    );
}

#[test]
fn strict_fixture_validation_rejects_defaulted_placeholder_when_env_missing() {
    let missing_var = "ZKFUZZER_CVE_PATH_MISSING_WITH_DEFAULT";
    std::env::remove_var(missing_var);
    let yaml = format!(
        r#"
version: "1.0"
last_updated: "2026-02-22"
vulnerabilities:
  - id: "ZK-STRICT-ENV-DEFAULT-BAD"
    name: "Strict Fixture Env Default Bad"
    severity: "high"
    affected_circuits:
      - pattern: "strict_env_default_bad"
        versions: ["*"]
    sources: []
    description: "strict fixture"
    detection:
      oracle: "range"
      attack_type: "boundary"
      procedure: []
    regression_test:
      enabled: true
      circuit_path: "${{{}:-tests/circuits/safe/simple_multiplier.circom}}"
      test_cases:
        - name: "valid_case"
          inputs:
            a: "0x2"
          expected_result: "valid"
      assertion: "fixture"
    remediation:
      description: "n/a"
"#,
        missing_var
    );

    let path = write_temp_yaml(&yaml);
    let result = CveDatabase::load_strict(&path);
    let _ = fs::remove_file(path);
    assert!(
        result.is_err(),
        "expected strict mode to reject unresolved default placeholder"
    );
}

#[test]
fn regression_test_generation_expands_env_circuit_path() {
    let home = std::env::var("HOME").expect("HOME environment variable must be set");
    let yaml = r#"
version: "1.0"
last_updated: "2026-02-22"
vulnerabilities:
  - id: "ZK-STRICT-ENV-EXPAND"
    name: "Strict Fixture Env Expand"
    severity: "high"
    affected_circuits:
      - pattern: "strict_env_expand"
        versions: ["*"]
    sources: []
    description: "strict fixture"
    detection:
      oracle: "range"
      attack_type: "boundary"
      procedure: []
    regression_test:
      enabled: true
      circuit_path: "${HOME}/tests/circuits/safe/simple_multiplier.circom"
      test_cases:
        - name: "valid_case"
          inputs:
            a: "0x2"
          expected_result: "valid"
      assertion: "fixture"
    remediation:
      description: "n/a"
"#;

    let path = write_temp_yaml(yaml);
    let db = CveDatabase::load(&path).expect("load test cve yaml");
    let _ = fs::remove_file(path);
    let tests = db.generate_regression_tests();
    assert_eq!(tests.len(), 1, "expected one regression test");
    assert!(
        tests[0].circuit_path.starts_with(&home),
        "expected HOME to expand in circuit path, got {}",
        tests[0].circuit_path
    );
    assert!(
        !tests[0].circuit_path.contains("${HOME}"),
        "expected placeholder to be expanded"
    );
}
