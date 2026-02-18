use super::*;
use rand::SeedableRng;

#[test]
fn test_load_cve_database() {
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
    let db: CveDatabase = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(db.vulnerabilities.len(), 1);
    assert_eq!(db.vulnerabilities[0].id, "ZK-TEST-001");
}

#[test]
fn test_pattern_matching() {
    let pattern = CvePattern {
        id: "ZK-TEST-001".to_string(),
        name: "Test".to_string(),
        severity: "high".to_string(),
        cvss_score: Some(8.0),
        affected_circuits: vec![AffectedCircuit {
            pattern: "tornado*".to_string(),
            versions: vec!["*".to_string()],
        }],
        sources: vec![],
        description: "Test".to_string(),
        detection: DetectionConfig {
            oracle: "test".to_string(),
            attack_type: "boundary".to_string(),
            procedure: vec![],
        },
        regression_test: RegressionTestConfig {
            enabled: true,
            circuit_path: "test.circom".to_string(),
            test_cases: vec![],
            assertion: "".to_string(),
        },
        remediation: RemediationInfo {
            description: "Test".to_string(),
            code_example: None,
            recommendations: vec![],
            references: vec![],
        },
    };

    assert!(pattern.affects_circuit("tornado-core"));
    assert!(pattern.affects_circuit("tornado-cash"));
    assert!(!pattern.affects_circuit("semaphore"));
}

#[test]
fn test_pattern_matching_supports_regex_prefix() {
    let pattern = CvePattern {
        id: "ZK-TEST-REGEX".to_string(),
        name: "Regex Test".to_string(),
        severity: "high".to_string(),
        cvss_score: Some(8.0),
        affected_circuits: vec![AffectedCircuit {
            pattern: "regex:tornado[-_/]?core".to_string(),
            versions: vec!["*".to_string()],
        }],
        sources: vec![],
        description: "Test".to_string(),
        detection: DetectionConfig {
            oracle: "test".to_string(),
            attack_type: "boundary".to_string(),
            procedure: vec![],
        },
        regression_test: RegressionTestConfig {
            enabled: true,
            circuit_path: "test.circom".to_string(),
            test_cases: vec![],
            assertion: "".to_string(),
        },
        remediation: RemediationInfo {
            description: "Test".to_string(),
            code_example: None,
            recommendations: vec![],
            references: vec![],
        },
    };

    assert!(pattern.affects_circuit("tornado-core"));
    assert!(pattern.affects_circuit("Tornado_Core"));
    assert!(pattern.affects_circuit("cat3_privacy/tornado/core/withdraw.circom"));
}

#[test]
fn test_pattern_matching_supports_glob_wildcards() {
    let pattern = CvePattern {
        id: "ZK-TEST-GLOB".to_string(),
        name: "Glob Test".to_string(),
        severity: "high".to_string(),
        cvss_score: Some(8.0),
        affected_circuits: vec![AffectedCircuit {
            pattern: "circomlib/*eddsa*".to_string(),
            versions: vec!["*".to_string()],
        }],
        sources: vec![],
        description: "Test".to_string(),
        detection: DetectionConfig {
            oracle: "test".to_string(),
            attack_type: "boundary".to_string(),
            procedure: vec![],
        },
        regression_test: RegressionTestConfig {
            enabled: true,
            circuit_path: "test.circom".to_string(),
            test_cases: vec![],
            assertion: "".to_string(),
        },
        remediation: RemediationInfo {
            description: "Test".to_string(),
            code_example: None,
            recommendations: vec![],
            references: vec![],
        },
    };

    assert!(pattern.affects_circuit("circomlib/eddsa.circom"));
    assert!(pattern.affects_circuit("CIRCOMLIB/v2/eddsa_utils.circom"));
    assert!(!pattern.affects_circuit("circomlib/poseidon.circom"));
}

#[test]
fn test_pattern_matching_is_resilient_to_separator_changes() {
    let pattern = CvePattern {
        id: "ZK-TEST-NORMALIZED".to_string(),
        name: "Normalized Test".to_string(),
        severity: "high".to_string(),
        cvss_score: Some(8.0),
        affected_circuits: vec![AffectedCircuit {
            pattern: "zkevm-circuits".to_string(),
            versions: vec!["*".to_string()],
        }],
        sources: vec![],
        description: "Test".to_string(),
        detection: DetectionConfig {
            oracle: "test".to_string(),
            attack_type: "boundary".to_string(),
            procedure: vec![],
        },
        regression_test: RegressionTestConfig {
            enabled: true,
            circuit_path: "test.circom".to_string(),
            test_cases: vec![],
            assertion: "".to_string(),
        },
        remediation: RemediationInfo {
            description: "Test".to_string(),
            code_example: None,
            recommendations: vec![],
            references: vec![],
        },
    };

    assert!(pattern.affects_circuit("zkevm_circuits"));
    assert!(pattern.affects_circuit("cat2/rollups/zkevm.circuits/main.circom"));
    assert!(!pattern.affects_circuit("tornado_core"));
}

#[test]
fn test_severity_conversion() {
    let pattern = CvePattern {
        id: "".to_string(),
        name: "".to_string(),
        severity: "critical".to_string(),
        cvss_score: None,
        affected_circuits: vec![],
        sources: vec![],
        description: "".to_string(),
        detection: DetectionConfig {
            oracle: "".to_string(),
            attack_type: "".to_string(),
            procedure: vec![],
        },
        regression_test: RegressionTestConfig {
            enabled: false,
            circuit_path: "".to_string(),
            test_cases: vec![],
            assertion: "".to_string(),
        },
        remediation: RemediationInfo {
            description: "".to_string(),
            code_example: None,
            recommendations: vec![],
            references: vec![],
        },
    };

    assert_eq!(pattern.severity_enum(), Severity::Critical);
}

#[test]
fn test_parse_value_string_rejects_ascii_literals() {
    let mut rng = StdRng::seed_from_u64(7);
    let modulus = [0u8; 32];
    let err = parse_value_string("US", &modulus, &mut rng, None).unwrap_err();
    assert!(err.contains("Unsupported string literal"));
}

#[test]
fn test_parse_value_string_accepts_odd_hex_nibbles() {
    let mut rng = StdRng::seed_from_u64(7);
    let modulus = [0u8; 32];
    let values = parse_value_string("0x2", &modulus, &mut rng, None).unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], FieldElement::from_u64(2));
}

#[test]
fn test_parse_yaml_number_handles_negative_values_mod_field() {
    let mut modulus = [0u8; 32];
    modulus[31] = 5; // tiny field: p = 5
    let n = serde_yaml::Number::from(-1);
    let values = parse_yaml_number(&n, &modulus).unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], FieldElement::from_u64(4));
}

#[test]
fn test_parse_value_string_rejects_ellipsis_placeholder() {
    let mut rng = StdRng::seed_from_u64(7);
    let modulus = [0u8; 32];
    let err = parse_value_string("...", &modulus, &mut rng, Some(3)).unwrap_err();
    assert!(err.contains("Unsupported string literal"));
}

#[test]
fn test_strict_fixture_validation_accepts_unambiguous_cases() {
    let yaml = r#"
version: "1.0"
last_updated: "2026-02-15"
vulnerabilities:
  - id: "ZK-STRICT-OK"
    name: "Strict Fixture OK"
    severity: "high"
    affected_circuits:
      - pattern: "test*"
        versions: ["*"]
    sources: []
    description: "Strict fixture"
    detection:
      oracle: "test"
      attack_type: "soundness"
      procedure: []
    regression_test:
      enabled: true
      circuit_path: "test.circom"
      test_cases:
        - name: "ok_case"
          inputs:
            a: "0x2"
            b: [1, 2, 3]
          expected_result: "invalid_proof"
      assertion: "strict"
    remediation:
      description: "none"
      recommendations: []
      references: []
"#;
    let db: CveDatabase = serde_yaml::from_str(yaml).unwrap();
    assert!(db.validate_regression_fixtures_strict().is_ok());
}

#[test]
fn test_strict_fixture_validation_rejects_ambiguous_expected_result_and_input() {
    let yaml = r#"
version: "1.0"
last_updated: "2026-02-15"
vulnerabilities:
  - id: "ZK-STRICT-BAD"
    name: "Strict Fixture Bad"
    severity: "high"
    affected_circuits:
      - pattern: "test*"
        versions: ["*"]
    sources: []
    description: "Strict fixture"
    detection:
      oracle: "test"
      attack_type: "soundness"
      procedure: []
    regression_test:
      enabled: true
      circuit_path: "test.circom"
      test_cases:
        - name: "bad_case"
          inputs:
            country: "US"
          expected_result: "different_hashes"
      assertion: "strict"
    remediation:
      description: "none"
      recommendations: []
      references: []
"#;
    let db: CveDatabase = serde_yaml::from_str(yaml).unwrap();
    let err = db
        .validate_regression_fixtures_strict()
        .unwrap_err()
        .to_string();
    assert!(err.contains("ambiguous expected_result"));
    assert!(err.contains("ambiguous string input"));
}

fn routing_test_database(oracle: &str, attack_type: &str) -> CveDatabase {
    let yaml = format!(
        r#"
version: "1.0"
last_updated: "2026-02-18"
vulnerabilities:
  - id: "ZK-ROUTE-001"
    name: "Routing test"
    severity: "high"
    affected_circuits:
      - pattern: "test"
        versions: ["*"]
    sources: []
    description: "Routing fixture"
    detection:
      oracle: "{oracle}"
      attack_type: "{attack_type}"
      procedure: []
    regression_test:
      enabled: false
      circuit_path: "test.circom"
      test_cases: []
      assertion: "n/a"
    remediation:
      description: "n/a"
      recommendations: []
      references: []
"#,
        oracle = oracle,
        attack_type = attack_type
    );
    serde_yaml::from_str(&yaml).expect("routing fixture yaml should parse")
}

#[test]
fn test_cve_oracle_routes_underconstrained_alias() {
    let oracle = CveOracle::new(routing_test_database(
        "underconstrained",
        "underconstrained",
    ));

    let tc_a = TestCase {
        inputs: vec![FieldElement::from_u64(1), FieldElement::from_u64(2)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let tc_b = TestCase {
        inputs: vec![FieldElement::from_u64(3), FieldElement::from_u64(4)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let output = vec![FieldElement::from_u64(777)];

    assert!(oracle.check(&tc_a, &output).is_none());
    assert!(
        oracle.check(&tc_b, &output).is_some(),
        "underconstrained alias should route through semantic ensemble"
    );
}

#[test]
fn test_cve_oracle_falls_back_to_attack_type_route() {
    let oracle = CveOracle::new(routing_test_database("unknown_oracle", "underconstrained"));

    let tc_a = TestCase {
        inputs: vec![FieldElement::from_u64(11), FieldElement::from_u64(22)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let tc_b = TestCase {
        inputs: vec![FieldElement::from_u64(33), FieldElement::from_u64(44)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let output = vec![FieldElement::from_u64(1234)];

    assert!(oracle.check(&tc_a, &output).is_none());
    assert!(
        oracle.check(&tc_b, &output).is_some(),
        "attack_type should be used as fallback route when oracle label is unknown"
    );
}

#[test]
fn test_regression_result_infra_failure_detection() {
    let result = RegressionTestResult {
        cve_id: "ZK-INFRA-001".to_string(),
        passed: false,
        test_results: vec![
            TestCaseResult {
                name: "a".to_string(),
                passed: false,
                message: Some(
                    "Executor creation failed: No Circom constraints available".to_string(),
                ),
            },
            TestCaseResult {
                name: "b".to_string(),
                passed: false,
                message: Some("Executor creation failed: snarkjs not found".to_string()),
            },
        ],
    };
    assert!(result.is_infrastructure_failure());
}

#[test]
fn test_regression_result_infra_failure_rejects_semantic_failures() {
    let result = RegressionTestResult {
        cve_id: "ZK-INFRA-002".to_string(),
        passed: false,
        test_results: vec![TestCaseResult {
            name: "a".to_string(),
            passed: false,
            message: Some("Expected valid but execution failed".to_string()),
        }],
    };
    assert!(!result.is_infrastructure_failure());
}

#[test]
fn test_build_inputs_for_test_zero_fills_when_fixture_is_partial() {
    let mut rng = StdRng::seed_from_u64(11);
    let tc = GeneratedTestCase {
        name: "partial_fixture".to_string(),
        inputs: vec![("pathIndices".to_string(), serde_yaml::Value::Number(1.into()))],
        expected_result: "valid_proof".to_string(),
        expected_valid: Some(true),
    };

    let modulus = [0u8; 32];
    let inputs = build_inputs_for_test(&tc, &[], 3, &modulus, &mut rng)
        .expect("partial fixture should be zero-filled to executor arity");

    assert_eq!(inputs.len(), 3);
    assert_eq!(inputs[0], FieldElement::from_u64(1));
    assert_eq!(inputs[1], FieldElement::zero());
    assert_eq!(inputs[2], FieldElement::zero());
}

#[test]
fn test_build_inputs_for_test_truncates_oversized_fixture() {
    let mut rng = StdRng::seed_from_u64(17);
    let tc = GeneratedTestCase {
        name: "oversized_fixture".to_string(),
        inputs: vec![(
            "witness".to_string(),
            serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::Number(1.into()),
                serde_yaml::Value::Number(2.into()),
                serde_yaml::Value::Number(3.into()),
            ]),
        )],
        expected_result: "valid_proof".to_string(),
        expected_valid: Some(true),
    };

    let modulus = [0u8; 32];
    let inputs = build_inputs_for_test(&tc, &[], 2, &modulus, &mut rng)
        .expect("oversized fixture should be truncated to executor arity");
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[0], FieldElement::from_u64(1));
    assert_eq!(inputs[1], FieldElement::from_u64(2));
}

#[test]
fn test_build_inputs_for_test_zero_fills_missing_named_spec_inputs() {
    let mut rng = StdRng::seed_from_u64(23);
    let tc = GeneratedTestCase {
        name: "named_partial_fixture".to_string(),
        inputs: vec![("a".to_string(), serde_yaml::Value::Number(7.into()))],
        expected_result: "valid_proof".to_string(),
        expected_valid: Some(true),
    };

    let input_specs = vec![
        InputSpec {
            name: "a".to_string(),
            length: None,
            is_array: false,
        },
        InputSpec {
            name: "b".to_string(),
            length: None,
            is_array: false,
        },
    ];

    let modulus = [0u8; 32];
    let inputs = build_inputs_for_test(&tc, &input_specs, 2, &modulus, &mut rng)
        .expect("missing named inputs should be zero-filled");
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[0], FieldElement::from_u64(7));
    assert_eq!(inputs[1], FieldElement::zero());
}
