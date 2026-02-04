//! Integration tests for ZK-Fuzzer
//!
//! These tests verify the fuzzer can detect known vulnerabilities
//! in intentionally vulnerable test circuits.

use std::io::Write;
use tempfile::NamedTempFile;
use zk_fuzzer::executor::{CircuitExecutor, MockCircuitExecutor};
use zk_fuzzer::fuzzer::FieldElement;
use zk_fuzzer::attacks::{Attack, AttackContext, CircuitInfo, UnderconstrainedDetector};
use zk_fuzzer::FuzzConfig;

// ============================================================================
// Underconstrained Detection Tests
// ============================================================================

/// Test that the fuzzer detects obviously underconstrained circuits
#[tokio::test]
async fn test_detects_underconstrained_mock() {
    // Create an underconstrained mock (more inputs than constraints)
    let executor = MockCircuitExecutor::new("underconstrained_test", 10, 2)
        .with_constraints(5);

    // This circuit should be flagged as likely underconstrained
    assert!(executor.is_likely_underconstrained());

    let info = executor.circuit_info();
    assert!(info.degrees_of_freedom() > 0);
}

/// Test that properly constrained circuits are not flagged
#[tokio::test]
async fn test_properly_constrained_not_flagged() {
    // Create a properly constrained mock
    let executor = MockCircuitExecutor::new("proper_test", 5, 2)
        .with_constraints(10);

    assert!(!executor.is_likely_underconstrained());

    let info = executor.circuit_info();
    assert!(info.degrees_of_freedom() <= 0);
}

/// Test the underconstrained detector attack module
#[test]
fn test_underconstrained_detector() {
    let detector = UnderconstrainedDetector::new(100);

    // Test with underconstrained circuit info
    let context = AttackContext {
        circuit_info: CircuitInfo {
            name: "test".to_string(),
            num_constraints: 5,
            num_private_inputs: 10,
            num_public_inputs: 2,
            num_outputs: 1,
        },
        samples: 100,
        timeout_seconds: 60,
    };

    let findings = detector.run(&context);
    assert!(!findings.is_empty(), "Should detect underconstrained circuit");
}

/// Test that the detector does not flag properly constrained circuits
#[test]
fn test_underconstrained_detector_no_false_positive() {
    let detector = UnderconstrainedDetector::new(100);

    let context = AttackContext {
        circuit_info: CircuitInfo {
            name: "test".to_string(),
            num_constraints: 20,
            num_private_inputs: 10,
            num_public_inputs: 2,
            num_outputs: 1,
        },
        samples: 100,
        timeout_seconds: 60,
    };

    let findings = detector.run(&context);
    
    // Should not flag DOF issue (but might find other issues in real implementation)
    let dof_findings: Vec<_> = findings.iter()
        .filter(|f| f.description.contains("DOF"))
        .collect();
    assert!(dof_findings.is_empty(), "Should not flag DOF issue for properly constrained");
}

// ============================================================================
// Collision Detection Tests
// ============================================================================

/// Test that the fuzzer can detect output collisions using underconstrained mock
/// An underconstrained circuit produces the same output for different inputs
#[tokio::test]
async fn test_detects_collisions_in_mock() {
    // Create an underconstrained mock - this WILL produce collisions
    // because it only uses the first input to compute output
    let executor = MockCircuitExecutor::new("collision_test", 2, 1)
        .with_underconstrained(true);

    // Execute with same first input but different second input
    let inputs_a = vec![
        FieldElement::from_u64(42),
        FieldElement::from_u64(1),
    ];
    let inputs_b = vec![
        FieldElement::from_u64(42),  // Same first input
        FieldElement::from_u64(999), // Different second input
    ];

    let result_a = executor.execute_sync(&inputs_a);
    let result_b = executor.execute_sync(&inputs_b);

    assert!(result_a.success);
    assert!(result_b.success);

    // Outputs should be identical (collision) because only first input is used
    assert_eq!(result_a.outputs, result_b.outputs, 
        "Underconstrained mock should produce same output for different inputs");

    // But inputs are different
    assert_ne!(inputs_a, inputs_b, "Inputs should be different");
}

/// Test that normal circuits don't produce false collision positives
#[tokio::test]
async fn test_no_false_collisions() {
    // Create a normal mock (no collision simulation)
    let executor = MockCircuitExecutor::new("normal_test", 2, 1);

    let mut outputs = std::collections::HashSet::new();

    for i in 0..100u64 {
        let inputs = vec![
            FieldElement::from_u64(i),
            FieldElement::from_u64(i * 2 + 1),
        ];

        let result = executor.execute_sync(&inputs);
        let output_hash: Vec<u8> = result.outputs.iter()
            .flat_map(|fe| fe.0.to_vec())
            .collect();

        outputs.insert(output_hash);
    }

    // Each unique input should produce unique output
    assert_eq!(outputs.len(), 100, "Normal mock should produce unique outputs");
}

// ============================================================================
// Configuration Validation Tests
// ============================================================================

/// Create a temporary YAML config file for testing
fn create_temp_config(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file
}

/// Test loading a valid configuration
#[test]
fn test_load_valid_config() {
    let config_content = r#"
campaign:
  name: "Test Campaign"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Main"

attacks:
  - type: underconstrained
    description: "Test attack"
    config:
      witness_pairs: 100

inputs:
  - name: "input1"
    type: "field"
    fuzz_strategy: random
"#;

    let file = create_temp_config(config_content);
    let config = FuzzConfig::from_yaml(file.path().to_str().unwrap());
    
    assert!(config.is_ok(), "Should load valid config");
    let config = config.unwrap();
    assert_eq!(config.campaign.name, "Test Campaign");
    assert_eq!(config.attacks.len(), 1);
    assert_eq!(config.inputs.len(), 1);
}

/// Test that missing required fields cause validation errors
#[test]
fn test_missing_attacks_fails() {
    let config_content = r#"
campaign:
  name: "Test Campaign"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Main"

attacks: []

inputs:
  - name: "input1"
    type: "field"
"#;

    let file = create_temp_config(config_content);
    let config = FuzzConfig::from_yaml(file.path().to_str().unwrap());
    
    assert!(config.is_err(), "Should fail with empty attacks");
}

/// Test that missing inputs cause validation errors
#[test]
fn test_missing_inputs_fails() {
    let config_content = r#"
campaign:
  name: "Test Campaign"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Main"

attacks:
  - type: underconstrained
    description: "Test"

inputs: []
"#;

    let file = create_temp_config(config_content);
    let config = FuzzConfig::from_yaml(file.path().to_str().unwrap());
    
    assert!(config.is_err(), "Should fail with empty inputs");
}

/// Test all attack types are recognized
#[test]
fn test_all_attack_types() {
    let config_content = r#"
campaign:
  name: "Test"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Main"

attacks:
  - type: underconstrained
    description: "test"
  - type: soundness
    description: "test"
  - type: arithmetic_overflow
    description: "test"
  - type: collision
    description: "test"
  - type: boundary
    description: "test"

inputs:
  - name: "x"
    type: "field"
"#;

    let file = create_temp_config(config_content);
    let config = FuzzConfig::from_yaml(file.path().to_str().unwrap());
    
    assert!(config.is_ok());
    assert_eq!(config.unwrap().attacks.len(), 5);
}

/// Test all fuzz strategies are recognized
#[test]
fn test_all_fuzz_strategies() {
    let config_content = r#"
campaign:
  name: "Test"
  version: "1.0"
  target:
    framework: mock
    circuit_path: "./test.circom"
    main_component: "Main"

attacks:
  - type: underconstrained
    description: "test"

inputs:
  - name: "a"
    type: "field"
    fuzz_strategy: random
  - name: "b"
    type: "field"
    fuzz_strategy: interesting_values
    interesting: ["0x0", "0x1"]
  - name: "c"
    type: "field"
    fuzz_strategy: mutation
  - name: "d"
    type: "field"
    fuzz_strategy: exhaustive_if_small
"#;

    let file = create_temp_config(config_content);
    let config = FuzzConfig::from_yaml(file.path().to_str().unwrap());
    
    assert!(config.is_ok());
    assert_eq!(config.unwrap().inputs.len(), 4);
}

/// Test framework types are recognized
#[test]
fn test_framework_types() {
    let frameworks = vec!["circom", "noir", "halo2", "cairo", "mock"];
    
    for fw in frameworks {
        let config_content = format!(r#"
campaign:
  name: "Test"
  version: "1.0"
  target:
    framework: {}
    circuit_path: "./test.circom"
    main_component: "Main"

attacks:
  - type: underconstrained
    description: "test"

inputs:
  - name: "x"
    type: "field"
"#, fw);

        let file = create_temp_config(&config_content);
        let config = FuzzConfig::from_yaml(file.path().to_str().unwrap());
        assert!(config.is_ok(), "Framework {} should be recognized", fw);
    }
}

// ============================================================================
// Executor Tests
// ============================================================================

#[test]
fn test_executor_basic_operations() {
    let executor = MockCircuitExecutor::new("test", 3, 1);
    
    assert_eq!(executor.name(), "test");
    assert_eq!(executor.num_private_inputs(), 3);
    assert_eq!(executor.num_public_inputs(), 1);
    
    let inputs = vec![
        FieldElement::zero(),
        FieldElement::one(),
        FieldElement::from_u64(42),
    ];
    
    let result = executor.execute_sync(&inputs);
    assert!(result.success);
    assert!(!result.outputs.is_empty());
}

#[test]
fn test_proof_generation_and_verification() {
    let executor = MockCircuitExecutor::new("test", 2, 1);
    
    let witness = vec![FieldElement::one(), FieldElement::from_u64(100)];
    
    let proof = executor.prove(&witness).unwrap();
    assert!(!proof.is_empty());
    
    // Verification should succeed with the same inputs used to generate the proof
    let verified = executor.verify(&proof, &witness).unwrap();
    assert!(verified);
    
    // Verification should FAIL with different inputs (soundness property)
    let different_inputs = vec![FieldElement::from_u64(42)];
    let should_fail = executor.verify(&proof, &different_inputs).unwrap();
    assert!(!should_fail, "Proof should not verify with different inputs");
}

// ============================================================================
// Field Element Tests
// ============================================================================

#[test]
fn test_field_element_operations() {
    // Test zero
    let zero = FieldElement::zero();
    assert_eq!(zero.0, [0u8; 32]);
    
    // Test one
    let one = FieldElement::one();
    assert_eq!(one.0[31], 1);
    assert!(one.0[0..31].iter().all(|&b| b == 0));
    
    // Test from_u64
    let val = FieldElement::from_u64(256);
    assert_eq!(val.0[30], 1);
    assert_eq!(val.0[31], 0);
    
    // Test hex encoding/decoding
    let fe = FieldElement::from_hex("0xdead").unwrap();
    let hex = fe.to_hex();
    assert!(hex.contains("dead"));
}

#[test]
fn test_field_element_random() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    let mut rng = StdRng::seed_from_u64(42);
    
    let a = FieldElement::random(&mut rng);
    let b = FieldElement::random(&mut rng);
    
    // Random elements should be different
    assert_ne!(a, b);
}
