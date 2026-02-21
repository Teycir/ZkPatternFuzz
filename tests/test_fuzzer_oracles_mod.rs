use zk_core::{FieldElement, TestCase};
use zk_fuzzer::fuzzer::{CombinedSemanticOracle, OracleConfig};

#[test]
fn test_combined_oracle_empty() {
    let mut oracle = CombinedSemanticOracle::new();
    let test_case = TestCase {
        inputs: vec![FieldElement::zero()],
        expected_output: None,
        metadata: Default::default(),
    };
    let output = vec![FieldElement::one()];

    // No oracles added, should return None
    assert!(oracle.check(&test_case, &output).is_none());
}

#[test]
fn test_combined_oracle_with_all_oracles_has_expected_members() {
    let oracle = CombinedSemanticOracle::with_all_oracles(OracleConfig::default());
    let stats = oracle.stats();
    assert_eq!(stats.len(), 4);
}
