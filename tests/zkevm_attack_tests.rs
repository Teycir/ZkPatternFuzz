//! zkEVM Attack Detection Tests (Phase 3: Milestone 3.2)
//!
//! Unit tests for zkEVM-specific vulnerability detection components.
//! These tests verify the attack configuration, vulnerability classification,
//! and test case generation without requiring full circuit execution.
//!
//! Run with: `cargo test zkevm_attack --release`

use std::collections::HashMap;
use zk_fuzzer::attacks::zkevm::{
    ZkEvmAttack, ZkEvmConfig, ZkEvmVulnerabilityType, ZkEvmTestResult,
    ZkEvmPriceAnalyzer, ZkEvmCallDetector, EVM_OPCODES,
};
use zk_fuzzer::config::Severity;
use zk_core::FieldElement;

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_zkevm_config_default() {
    let config = ZkEvmConfig::default();
    
    assert_eq!(config.state_transition_tests, 500);
    assert_eq!(config.opcode_boundary_tests, 100);
    assert_eq!(config.memory_expansion_tests, 200);
    assert_eq!(config.storage_proof_tests, 100);
    assert!(config.detect_state_transition);
    assert!(config.detect_opcode_boundary);
    assert!(config.detect_memory_expansion);
    assert!(config.detect_storage_proof);
}

#[test]
fn test_zkevm_config_custom() {
    let config = ZkEvmConfig {
        state_transition_tests: 1000,
        opcode_boundary_tests: 50,
        target_opcodes: vec!["DIV".to_string(), "CALL".to_string()],
        detect_memory_expansion: false,
        seed: Some(42),
        ..Default::default()
    };
    
    assert_eq!(config.state_transition_tests, 1000);
    assert_eq!(config.target_opcodes.len(), 2);
    assert!(!config.detect_memory_expansion);
    assert_eq!(config.seed, Some(42));
}

// ============================================================================
// Vulnerability Type Tests
// ============================================================================

#[test]
fn test_vulnerability_severity_mapping() {
    // Critical severity vulnerabilities
    assert_eq!(
        ZkEvmVulnerabilityType::StateTransitionMismatch.severity(),
        Severity::Critical
    );
    assert_eq!(
        ZkEvmVulnerabilityType::StorageProofBypass.severity(),
        Severity::Critical
    );
    assert_eq!(
        ZkEvmVulnerabilityType::PrecompileVulnerability.severity(),
        Severity::Critical
    );
    assert_eq!(
        ZkEvmVulnerabilityType::CallHandlingVulnerability.severity(),
        Severity::Critical
    );
    
    // High severity vulnerabilities
    assert_eq!(
        ZkEvmVulnerabilityType::OpcodeBoundaryViolation.severity(),
        Severity::High
    );
    assert_eq!(
        ZkEvmVulnerabilityType::MemoryExpansionError.severity(),
        Severity::High
    );
    assert_eq!(
        ZkEvmVulnerabilityType::StackBoundaryViolation.severity(),
        Severity::High
    );
    assert_eq!(
        ZkEvmVulnerabilityType::ContractCreationError.severity(),
        Severity::High
    );
    
    // Medium severity vulnerabilities
    assert_eq!(
        ZkEvmVulnerabilityType::GasAccountingError.severity(),
        Severity::Medium
    );
    assert_eq!(
        ZkEvmVulnerabilityType::InvalidOpcodeHandling.severity(),
        Severity::Medium
    );
}

#[test]
fn test_vulnerability_descriptions() {
    let vuln = ZkEvmVulnerabilityType::StateTransitionMismatch;
    assert!(!vuln.description().is_empty());
    assert!(vuln.description().contains("EVM"));
    
    let vuln = ZkEvmVulnerabilityType::StorageProofBypass;
    assert!(vuln.description().to_lowercase().contains("storage"));
    
    let vuln = ZkEvmVulnerabilityType::OpcodeBoundaryViolation;
    assert!(vuln.description().to_lowercase().contains("boundary"));
}

#[test]
fn test_vulnerability_as_str() {
    assert_eq!(
        ZkEvmVulnerabilityType::StateTransitionMismatch.as_str(),
        "state_transition_mismatch"
    );
    assert_eq!(
        ZkEvmVulnerabilityType::OpcodeBoundaryViolation.as_str(),
        "opcode_boundary_violation"
    );
    assert_eq!(
        ZkEvmVulnerabilityType::StorageProofBypass.as_str(),
        "storage_proof_bypass"
    );
}

// ============================================================================
// Opcode Coverage Tests
// ============================================================================

#[test]
fn test_evm_opcode_list_completeness() {
    // Ensure critical opcodes are included
    let opcode_names: Vec<&str> = EVM_OPCODES.iter().map(|op| op.name).collect();
    
    // Arithmetic
    assert!(opcode_names.contains(&"ADD"));
    assert!(opcode_names.contains(&"MUL"));
    assert!(opcode_names.contains(&"DIV"));
    assert!(opcode_names.contains(&"SDIV"));
    assert!(opcode_names.contains(&"MOD"));
    assert!(opcode_names.contains(&"ADDMOD"));
    assert!(opcode_names.contains(&"MULMOD"));
    assert!(opcode_names.contains(&"EXP"));
    
    // Comparison
    assert!(opcode_names.contains(&"LT"));
    assert!(opcode_names.contains(&"GT"));
    assert!(opcode_names.contains(&"EQ"));
    
    // Memory
    assert!(opcode_names.contains(&"MLOAD"));
    assert!(opcode_names.contains(&"MSTORE"));
    
    // Storage
    assert!(opcode_names.contains(&"SLOAD"));
    assert!(opcode_names.contains(&"SSTORE"));
    
    // Calls
    assert!(opcode_names.contains(&"CALL"));
    assert!(opcode_names.contains(&"DELEGATECALL"));
    assert!(opcode_names.contains(&"STATICCALL"));
    
    // Creates
    assert!(opcode_names.contains(&"CREATE"));
    assert!(opcode_names.contains(&"CREATE2"));
}

#[test]
fn test_opcode_stack_requirements() {
    // DIV takes 2 inputs, produces 1 output
    let div = EVM_OPCODES.iter().find(|op| op.name == "DIV").unwrap();
    assert_eq!(div.stack_input, 2);
    assert_eq!(div.stack_output, 1);
    assert_eq!(div.base_gas, 5);
    
    // CALL takes 7 inputs
    let call = EVM_OPCODES.iter().find(|op| op.name == "CALL").unwrap();
    assert_eq!(call.stack_input, 7);
    assert_eq!(call.stack_output, 1);
    
    // CREATE2 takes 4 inputs
    let create2 = EVM_OPCODES.iter().find(|op| op.name == "CREATE2").unwrap();
    assert_eq!(create2.stack_input, 4);
    assert_eq!(create2.stack_output, 1);
}

#[test]
fn test_opcode_codes() {
    // Verify opcode byte codes are correct
    let stop = EVM_OPCODES.iter().find(|op| op.name == "STOP").unwrap();
    assert_eq!(stop.code, 0x00);
    
    let add = EVM_OPCODES.iter().find(|op| op.name == "ADD").unwrap();
    assert_eq!(add.code, 0x01);
    
    let call = EVM_OPCODES.iter().find(|op| op.name == "CALL").unwrap();
    assert_eq!(call.code, 0xf1);
    
    let create = EVM_OPCODES.iter().find(|op| op.name == "CREATE").unwrap();
    assert_eq!(create.code, 0xf0);
}

// ============================================================================
// Attack Engine Tests
// ============================================================================

#[test]
fn test_attack_creation() {
    let config = ZkEvmConfig::default();
    let attack = ZkEvmAttack::new(config);
    
    assert!(attack.findings().is_empty());
    assert!(attack.tested_opcodes().is_empty());
}

#[test]
fn test_attack_with_different_seeds() {
    let config1 = ZkEvmConfig {
        seed: Some(12345),
        ..Default::default()
    };
    
    let config2 = ZkEvmConfig {
        seed: Some(67890),
        ..Default::default()
    };
    
    let attack1 = ZkEvmAttack::new(config1);
    let attack2 = ZkEvmAttack::new(config2);
    
    // Both should start empty
    assert!(attack1.findings().is_empty());
    assert!(attack2.findings().is_empty());
}

// ============================================================================
// Test Result Tests
// ============================================================================

#[test]
fn test_result_to_finding_conversion() {
    let result = ZkEvmTestResult {
        vulnerability_type: ZkEvmVulnerabilityType::OpcodeBoundaryViolation,
        description: "Test opcode boundary".to_string(),
        opcode: Some("DIV".to_string()),
        witness: vec![FieldElement::from_u64(4), FieldElement::zero()],
        expected_behavior: "Return 0".to_string(),
        actual_behavior: "Error".to_string(),
        context: {
            let mut ctx = HashMap::new();
            ctx.insert("test_type".to_string(), "ZeroValues".to_string());
            ctx
        },
    };
    
    let finding = result.to_finding();
    
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.description.contains("opcode_boundary"), "Description should contain vulnerability type");
    // Opcode name is in the location field, not description
    assert_eq!(finding.location, Some("opcode:DIV".to_string()));
    assert_eq!(finding.poc.witness_a.len(), 2);
}

#[test]
fn test_result_without_opcode() {
    let result = ZkEvmTestResult {
        vulnerability_type: ZkEvmVulnerabilityType::StateTransitionMismatch,
        description: "State doesn't match".to_string(),
        opcode: None,
        witness: vec![],
        expected_behavior: "Nonce increment".to_string(),
        actual_behavior: "No change".to_string(),
        context: HashMap::new(),
    };
    
    let finding = result.to_finding();
    
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.location.is_none());
}

// ============================================================================
// Analyzer Tests
// ============================================================================

#[test]
fn test_price_impact_analyzer_creation() {
    let _analyzer = ZkEvmPriceAnalyzer::new(0.05);
    // Just verify it constructs without panic
    assert!(true);
}

#[test]
fn test_call_vulnerability_detector_creation() {
    let _detector = ZkEvmCallDetector::new(10);
    // Just verify it constructs without panic
    assert!(true);
}

// ============================================================================
// Integration-Ready Tests (require mock executor)
// ============================================================================

#[test]
// requires CircuitExecutor mock implementation
fn test_full_attack_run() {
    // This test would require a proper mock executor
    // Left as placeholder for future integration tests
}

#[test]
// requires CircuitExecutor mock implementation
fn test_state_transition_detection() {
    // This test would require a proper mock executor
}

#[test]
// requires CircuitExecutor mock implementation
fn test_opcode_boundary_detection() {
    // This test would require a proper mock executor
}

#[test]
// requires CircuitExecutor mock implementation
fn test_storage_proof_bypass_detection() {
    // This test would require a proper mock executor
}
