//! Recursive SNARK Attack Tests (Phase 3: Milestone 3.4)
//!
//! Tests for recursive proof system vulnerability detection.
//!
//! Run with: `cargo test recursive_attack --release -- --nocapture`

use std::collections::HashSet;
use zk_core::{FieldElement, Severity};
use zk_fuzzer::attacks::recursive::{
    AccumulatorState, Halo2AccumulationAnalyzer, NovaAnalyzer, RecursiveAttack,
    RecursiveAttackConfig, RecursiveStep, RecursiveSystem, RecursiveVulnerabilityType,
    SupernovaAnalyzer,
};

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_recursive_attack_config_default() {
    let config = RecursiveAttackConfig::default();

    assert_eq!(config.max_recursion_depth, 10);
    assert_eq!(config.base_case_tests, 500);
    assert_eq!(config.accumulator_overflow_tests, 1000);
    assert_eq!(config.vk_substitution_tests, 500);
    assert_eq!(config.folding_attack_tests, 1000);
    assert!(config.detect_base_case_bypass);
    assert!(config.detect_accumulator_overflow);
    assert!(config.detect_vk_substitution);
    assert!(config.detect_folding_attacks);
    assert_eq!(config.recursive_systems.len(), 5);
    assert_eq!(config.accumulator_bit_widths.len(), 4);
    assert_eq!(config.timeout_ms, 60000);
}

#[test]
fn test_recursive_attack_config_custom() {
    let config = RecursiveAttackConfig {
        max_recursion_depth: 20,
        base_case_tests: 100,
        accumulator_overflow_tests: 200,
        vk_substitution_tests: 100,
        folding_attack_tests: 200,
        detect_base_case_bypass: true,
        detect_accumulator_overflow: false,
        detect_vk_substitution: true,
        detect_folding_attacks: false,
        recursive_systems: vec![RecursiveSystem::Nova],
        accumulator_bit_widths: vec![254],
        timeout_ms: 30000,
        seed: Some(123),
    };

    assert_eq!(config.max_recursion_depth, 20);
    assert_eq!(config.recursive_systems.len(), 1);
    assert!(!config.detect_accumulator_overflow);
    assert!(!config.detect_folding_attacks);
    assert_eq!(config.seed, Some(123));
}

// ============================================================================
// Recursive System Tests
// ============================================================================

#[test]
fn test_recursive_system_properties() {
    // Folding systems
    assert!(RecursiveSystem::Nova.uses_folding());
    assert!(RecursiveSystem::Supernova.uses_folding());
    assert!(RecursiveSystem::Sangria.uses_folding());
    assert!(RecursiveSystem::ProtoStar.uses_folding());
    assert!(!RecursiveSystem::Halo2Recursive.uses_folding());

    // Accumulation systems
    assert!(RecursiveSystem::Halo2Recursive.uses_accumulation());
    assert!(RecursiveSystem::ProtoStar.uses_accumulation());
    assert!(!RecursiveSystem::Nova.uses_accumulation());
    assert!(!RecursiveSystem::Supernova.uses_accumulation());
    assert!(!RecursiveSystem::Sangria.uses_accumulation());
}

#[test]
fn test_recursive_system_names() {
    assert_eq!(RecursiveSystem::Nova.as_str(), "nova");
    assert_eq!(RecursiveSystem::Supernova.as_str(), "supernova");
    assert_eq!(RecursiveSystem::Halo2Recursive.as_str(), "halo2_recursive");
    assert_eq!(RecursiveSystem::Sangria.as_str(), "sangria");
    assert_eq!(RecursiveSystem::ProtoStar.as_str(), "protostar");
}

#[test]
fn test_recursive_system_descriptions() {
    assert!(!RecursiveSystem::Nova.description().is_empty());
    assert!(!RecursiveSystem::Supernova.description().is_empty());
    assert!(!RecursiveSystem::Halo2Recursive.description().is_empty());
    assert!(RecursiveSystem::Nova.description().contains("folding"));
    assert!(RecursiveSystem::Halo2Recursive
        .description()
        .contains("accumulation"));
}

// ============================================================================
// Vulnerability Type Tests
// ============================================================================

#[test]
fn test_vulnerability_severities() {
    // Critical vulnerabilities
    assert_eq!(
        RecursiveVulnerabilityType::BaseCaseBypass.severity(),
        Severity::Critical
    );
    assert_eq!(
        RecursiveVulnerabilityType::AccumulatorForgery.severity(),
        Severity::Critical
    );
    assert_eq!(
        RecursiveVulnerabilityType::VKSubstitution.severity(),
        Severity::Critical
    );

    // High vulnerabilities
    assert_eq!(
        RecursiveVulnerabilityType::FoldingMismatch.severity(),
        Severity::High
    );
    assert_eq!(
        RecursiveVulnerabilityType::InvalidStateTransition.severity(),
        Severity::High
    );
    assert_eq!(
        RecursiveVulnerabilityType::RelaxedInstanceManipulation.severity(),
        Severity::High
    );

    // Medium vulnerabilities
    assert_eq!(
        RecursiveVulnerabilityType::AccumulatorOverflow.severity(),
        Severity::Medium
    );
    assert_eq!(
        RecursiveVulnerabilityType::DepthLimitBypass.severity(),
        Severity::Medium
    );
    assert_eq!(
        RecursiveVulnerabilityType::RunningInstanceCorruption.severity(),
        Severity::Medium
    );

    // Low vulnerabilities
    assert_eq!(
        RecursiveVulnerabilityType::CrossCircuitRecursion.severity(),
        Severity::Low
    );
}

#[test]
fn test_vulnerability_type_strings() {
    assert_eq!(
        RecursiveVulnerabilityType::BaseCaseBypass.as_str(),
        "base_case_bypass"
    );
    assert_eq!(
        RecursiveVulnerabilityType::AccumulatorOverflow.as_str(),
        "accumulator_overflow"
    );
    assert_eq!(
        RecursiveVulnerabilityType::VKSubstitution.as_str(),
        "vk_substitution"
    );
    assert_eq!(
        RecursiveVulnerabilityType::FoldingMismatch.as_str(),
        "folding_mismatch"
    );
}

#[test]
fn test_vulnerability_descriptions() {
    for vuln_type in [
        RecursiveVulnerabilityType::BaseCaseBypass,
        RecursiveVulnerabilityType::AccumulatorOverflow,
        RecursiveVulnerabilityType::VKSubstitution,
        RecursiveVulnerabilityType::FoldingMismatch,
        RecursiveVulnerabilityType::InvalidStateTransition,
        RecursiveVulnerabilityType::DepthLimitBypass,
        RecursiveVulnerabilityType::CrossCircuitRecursion,
        RecursiveVulnerabilityType::AccumulatorForgery,
        RecursiveVulnerabilityType::RelaxedInstanceManipulation,
        RecursiveVulnerabilityType::RunningInstanceCorruption,
    ] {
        let desc = vuln_type.description();
        assert!(!desc.is_empty(), "Description for {:?} is empty", vuln_type);
        assert!(
            desc.len() > 20,
            "Description for {:?} is too short: {}",
            vuln_type,
            desc
        );
    }
}

// ============================================================================
// Accumulator State Tests
// ============================================================================

#[test]
fn test_accumulator_state_new_base_case() {
    let acc = AccumulatorState::new_base_case(4);

    assert_eq!(acc.counter, 0);
    assert_eq!(acc.instance.len(), 4);
    assert_eq!(acc.running_acc.len(), 4);
    assert!(acc.error_term.is_some());

    // All values should be zero
    for val in &acc.instance {
        assert!(val.is_zero());
    }
    for val in &acc.running_acc {
        assert!(val.is_zero());
    }
    assert!(acc.error_term.as_ref().unwrap().is_zero());
}

#[test]
fn test_accumulator_state_folding() {
    let acc = AccumulatorState::new_base_case(3);

    let new_instance = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];
    let challenge = FieldElement::from_u64(5);

    let folded = acc.fold_with(&new_instance, &challenge);

    assert_eq!(folded.counter, 1);
    assert_eq!(folded.instance.len(), 3);
    assert_eq!(folded.running_acc.len(), 3);

    // New instance should be stored
    assert_eq!(folded.instance, new_instance);
}

#[test]
fn test_accumulator_state_multiple_folds() {
    let mut acc = AccumulatorState::new_base_case(2);

    for i in 1..=5 {
        let new_instance = vec![FieldElement::from_u64(i), FieldElement::from_u64(i * 2)];
        let challenge = FieldElement::from_u64(i + 10);
        acc = acc.fold_with(&new_instance, &challenge);

        assert_eq!(acc.counter, i);
    }

    assert_eq!(acc.counter, 5);
}

// ============================================================================
// Recursive Step Tests
// ============================================================================

#[test]
fn test_recursive_step_base_case() {
    let inputs = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];

    let step = RecursiveStep {
        step_index: 0,
        public_inputs: inputs.clone(),
        witness: inputs.clone(),
        accumulator: Some(AccumulatorState::new_base_case(2)),
        is_base_case: true,
        vk_hash: [0u8; 32],
    };

    assert!(step.is_base_case);
    assert_eq!(step.step_index, 0);
    assert_eq!(step.public_inputs.len(), 2);
    assert!(step.accumulator.is_some());
    assert_eq!(step.accumulator.as_ref().unwrap().counter, 0);
}

#[test]
fn test_recursive_step_intermediate() {
    let inputs = vec![FieldElement::from_u64(10)];

    let step = RecursiveStep {
        step_index: 5,
        public_inputs: inputs.clone(),
        witness: inputs.clone(),
        accumulator: None,
        is_base_case: false,
        vk_hash: [1u8; 32],
    };

    assert!(!step.is_base_case);
    assert_eq!(step.step_index, 5);
    assert!(step.accumulator.is_none());
    assert_eq!(step.vk_hash, [1u8; 32]);
}

// ============================================================================
// Recursive Attack Tests
// ============================================================================

#[test]
fn test_recursive_attack_creation() {
    let config = RecursiveAttackConfig::default();
    let _attack = RecursiveAttack::new(config);
}

#[test]
fn test_recursive_attack_with_seed() {
    let config = RecursiveAttackConfig {
        seed: Some(12345),
        ..RecursiveAttackConfig::default()
    };

    let _attack1 = RecursiveAttack::new(config.clone());
    let _attack2 = RecursiveAttack::new(config);
}

// ============================================================================
// Nova Analyzer Tests
// ============================================================================

#[test]
fn test_nova_analyzer_relaxed_r1cs_vulnerability() {
    let config = RecursiveAttackConfig::default();
    let analyzer = NovaAnalyzer::new(config);

    let instance = vec![FieldElement::from_u64(1)];
    let witness = vec![FieldElement::from_u64(2)];

    // Non-zero error term indicates potential vulnerability
    let non_zero_error = FieldElement::from_u64(1);
    assert!(analyzer.check_relaxed_r1cs_vulnerability(&instance, &witness, &non_zero_error));

    // Zero error term is valid (satisfied constraint)
    let zero_error = FieldElement::zero();
    assert!(!analyzer.check_relaxed_r1cs_vulnerability(&instance, &witness, &zero_error));
}

#[test]
fn test_nova_analyzer_ivc_state_corruption() {
    let config = RecursiveAttackConfig::default();
    let analyzer = NovaAnalyzer::new(config);

    let running_instance = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
    let step_outputs = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];

    // Matching lengths - no corruption
    assert!(!analyzer.detect_ivc_state_corruption(&running_instance, &step_outputs));

    // Mismatched lengths - potential corruption
    let mismatched_outputs = vec![FieldElement::from_u64(1)];
    assert!(analyzer.detect_ivc_state_corruption(&running_instance, &mismatched_outputs));
}

// ============================================================================
// Supernova Analyzer Tests
// ============================================================================

#[test]
fn test_supernova_analyzer_opcode_selection() {
    let config = RecursiveAttackConfig::default();
    let analyzer = SupernovaAnalyzer::new(config);

    let valid_opcodes = vec![0, 1, 2, 3, 4];

    // Valid opcode selection
    assert!(!analyzer.check_opcode_selection_vulnerability(0, &valid_opcodes));
    assert!(!analyzer.check_opcode_selection_vulnerability(2, &valid_opcodes));
    assert!(!analyzer.check_opcode_selection_vulnerability(4, &valid_opcodes));

    // Invalid opcode selection (out of range)
    assert!(analyzer.check_opcode_selection_vulnerability(5, &valid_opcodes));
    assert!(analyzer.check_opcode_selection_vulnerability(100, &valid_opcodes));
    assert!(analyzer.check_opcode_selection_vulnerability(usize::MAX, &valid_opcodes));
}

#[test]
fn test_supernova_analyzer_instruction_set_escape() {
    let config = RecursiveAttackConfig::default();
    let analyzer = SupernovaAnalyzer::new(config);

    let instruction_count = 10;

    // Valid instruction indices
    assert!(!analyzer.detect_instruction_set_escape(0, instruction_count));
    assert!(!analyzer.detect_instruction_set_escape(5, instruction_count));
    assert!(!analyzer.detect_instruction_set_escape(9, instruction_count));

    // Invalid (escape) instruction indices
    assert!(analyzer.detect_instruction_set_escape(10, instruction_count));
    assert!(analyzer.detect_instruction_set_escape(100, instruction_count));
}

// ============================================================================
// Halo2 Accumulation Analyzer Tests
// ============================================================================

#[test]
fn test_halo2_analyzer_commitment_binding() {
    let config = RecursiveAttackConfig::default();
    let analyzer = Halo2AccumulationAnalyzer::new(config);

    let expected_opening = vec![FieldElement::from_u64(1)];

    // All-zero commitment is invalid (not binding)
    let zero_commitment = vec![0u8; 32];
    assert!(analyzer.check_commitment_binding(&zero_commitment, &expected_opening));

    // Non-zero commitment is valid
    let valid_commitment = vec![1u8; 32];
    assert!(!analyzer.check_commitment_binding(&valid_commitment, &expected_opening));

    // Mixed commitment with some zeros
    let mut mixed_commitment = vec![0u8; 32];
    mixed_commitment[0] = 1;
    assert!(!analyzer.check_commitment_binding(&mixed_commitment, &expected_opening));
}

#[test]
fn test_halo2_analyzer_split_accumulator() {
    let config = RecursiveAttackConfig::default();
    let analyzer = Halo2AccumulationAnalyzer::new(config);

    let left_acc = AccumulatorState::new_base_case(2);
    let right_acc = AccumulatorState::new_base_case(2);

    // Same counter - no vulnerability
    assert!(!analyzer.detect_split_accumulator_vulnerability(&left_acc, &right_acc));

    // Different counters - potential vulnerability
    let mut advanced_acc = AccumulatorState::new_base_case(2);
    advanced_acc.counter = 5;
    assert!(analyzer.detect_split_accumulator_vulnerability(&left_acc, &advanced_acc));
}

// ============================================================================
// Integration Tests (Ignored - Require Fixture Backend)
// ============================================================================

#[test]
// requires fixture backend setup
fn test_recursive_attack_full_run() {
    use zk_fuzzer::executor::FixtureCircuitExecutor;

    let config = RecursiveAttackConfig {
        max_recursion_depth: 5,
        base_case_tests: 10,
        accumulator_overflow_tests: 10,
        vk_substitution_tests: 10,
        folding_attack_tests: 10,
        ..Default::default()
    };

    let mut attack = RecursiveAttack::new(config);
    let executor = FixtureCircuitExecutor::new("fixture", 4, 0);
    let inputs = vec![FieldElement::from_u64(1); 4];

    let rt = tokio::runtime::Runtime::new().unwrap();
    let findings = rt
        .block_on(async { attack.run(&executor, &inputs) })
        .unwrap();

    println!("Found {} findings", findings.len());
    for finding in &findings {
        println!(
            "  - [{:?}] {}",
            finding.severity,
            finding.description.chars().take(50).collect::<String>()
        );
    }
}

#[test]
// requires fixture backend setup
fn test_base_case_bypass_detection() {
    use zk_fuzzer::executor::FixtureCircuitExecutor;

    let config = RecursiveAttackConfig {
        detect_base_case_bypass: true,
        detect_accumulator_overflow: false,
        detect_vk_substitution: false,
        detect_folding_attacks: false,
        base_case_tests: 100,
        ..Default::default()
    };

    let mut attack = RecursiveAttack::new(config);
    let executor = FixtureCircuitExecutor::new("fixture", 4, 0);
    let inputs = vec![FieldElement::from_u64(1); 4];

    let rt = tokio::runtime::Runtime::new().unwrap();
    let findings = rt
        .block_on(async { attack.run(&executor, &inputs) })
        .unwrap();

    // Check for base case bypass findings
    let base_case_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.description.contains("base_case"))
        .collect();

    println!("Base case bypass findings: {}", base_case_findings.len());
}

#[test]
// requires fixture backend setup
fn test_folding_attack_detection() {
    use zk_fuzzer::executor::FixtureCircuitExecutor;

    let config = RecursiveAttackConfig {
        detect_base_case_bypass: false,
        detect_accumulator_overflow: false,
        detect_vk_substitution: false,
        detect_folding_attacks: true,
        folding_attack_tests: 100,
        recursive_systems: vec![RecursiveSystem::Nova, RecursiveSystem::Supernova],
        ..Default::default()
    };

    let mut attack = RecursiveAttack::new(config);
    let executor = FixtureCircuitExecutor::new("fixture", 4, 0);
    let inputs = vec![FieldElement::from_u64(1); 4];

    let rt = tokio::runtime::Runtime::new().unwrap();
    let findings = rt
        .block_on(async { attack.run(&executor, &inputs) })
        .unwrap();

    // Check for folding-related findings
    let folding_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.description.contains("folding") || f.description.contains("Folding"))
        .collect();

    println!("Folding attack findings: {}", folding_findings.len());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_empty_inputs() {
    let acc = AccumulatorState::new_base_case(0);
    assert_eq!(acc.instance.len(), 0);
    assert_eq!(acc.running_acc.len(), 0);
}

#[test]
fn test_large_recursion_depth() {
    let config = RecursiveAttackConfig {
        max_recursion_depth: 1000,
        ..Default::default()
    };

    assert_eq!(config.max_recursion_depth, 1000);
}

#[test]
fn test_all_systems_enabled() {
    let config = RecursiveAttackConfig::default();

    let systems: HashSet<_> = config.recursive_systems.iter().collect();
    assert!(systems.contains(&RecursiveSystem::Nova));
    assert!(systems.contains(&RecursiveSystem::Supernova));
    assert!(systems.contains(&RecursiveSystem::Halo2Recursive));
    assert!(systems.contains(&RecursiveSystem::Sangria));
    assert!(systems.contains(&RecursiveSystem::ProtoStar));
}

#[test]
fn test_vulnerability_type_uniqueness() {
    let vuln_types = [
        RecursiveVulnerabilityType::BaseCaseBypass,
        RecursiveVulnerabilityType::AccumulatorOverflow,
        RecursiveVulnerabilityType::VKSubstitution,
        RecursiveVulnerabilityType::FoldingMismatch,
        RecursiveVulnerabilityType::InvalidStateTransition,
        RecursiveVulnerabilityType::DepthLimitBypass,
        RecursiveVulnerabilityType::CrossCircuitRecursion,
        RecursiveVulnerabilityType::AccumulatorForgery,
        RecursiveVulnerabilityType::RelaxedInstanceManipulation,
        RecursiveVulnerabilityType::RunningInstanceCorruption,
    ];

    // All string representations should be unique
    let strings: HashSet<_> = vuln_types.iter().map(|v| v.as_str()).collect();
    assert_eq!(strings.len(), vuln_types.len());

    // All descriptions should be unique
    let descriptions: HashSet<_> = vuln_types.iter().map(|v| v.description()).collect();
    assert_eq!(descriptions.len(), vuln_types.len());
}
