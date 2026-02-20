use super::*;

#[test]
fn test_differential_tester_creation() {
    let config = ZkEvmDifferentialConfig::default();
    let tester = ZkEvmDifferentialTester::new(config);
    assert_eq!(tester.stats().total_tests, 0);
}

#[test]
fn test_mismatch_type_classification() {
    let config = ZkEvmDifferentialConfig::default();
    let tester = ZkEvmDifferentialTester::new(config);

    let outcome_diff = vec![StateDifference {
        description: "Execution outcome differs".to_string(),
        zkevm_value: "true".to_string(),
        reference_value: "false".to_string(),
        location: None,
    }];
    assert_eq!(
        tester.classify_mismatch(&outcome_diff),
        MismatchType::OutcomeMismatch
    );

    let storage_diff = vec![StateDifference {
        description: "Storage slot value differs".to_string(),
        zkevm_value: "0x01".to_string(),
        reference_value: "0x02".to_string(),
        location: Some("addr:slot".to_string()),
    }];
    assert_eq!(
        tester.classify_mismatch(&storage_diff),
        MismatchType::StorageMismatch
    );
}

#[test]
fn test_precompile_addresses() {
    assert_eq!(precompiles::ECRECOVER[19], 0x01);
    assert_eq!(precompiles::SHA256[19], 0x02);
    assert_eq!(precompiles::ECPAIRING[19], 0x08);
}

#[test]
fn test_precompile_generator() {
    let generator = PrecompileTestGenerator::new(42);
    let ecrecover_tests = generator.ecrecover_edge_cases();
    assert!(!ecrecover_tests.is_empty());
    assert_eq!(ecrecover_tests[0].to, Some(precompiles::ECRECOVER));
}

#[test]
fn test_severity_classification() {
    let config = ZkEvmDifferentialConfig::default();
    let tester = ZkEvmDifferentialTester::new(config);

    assert_eq!(
        tester.classify_severity(&MismatchType::OutcomeMismatch, &[]),
        Severity::Critical
    );
    assert_eq!(
        tester.classify_severity(&MismatchType::StorageMismatch, &[]),
        Severity::High
    );
    assert_eq!(
        tester.classify_severity(&MismatchType::GasMismatch, &[]),
        Severity::Low
    );
}
