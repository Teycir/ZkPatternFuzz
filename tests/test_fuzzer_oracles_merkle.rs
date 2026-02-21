use zk_core::{FieldElement, TestCase};
use zk_fuzzer::fuzzer::{MerkleOracle, OracleConfig, SemanticOracle};

fn make_merkle_test_case(leaf: u64, path_elements: &[u64], path_indices: &[u64]) -> TestCase {
    let mut inputs = vec![FieldElement::from_u64(leaf)];
    for &elem in path_elements {
        inputs.push(FieldElement::from_u64(elem));
    }
    for &idx in path_indices {
        inputs.push(FieldElement::from_u64(idx));
    }
    TestCase {
        inputs,
        expected_output: None,
        metadata: Default::default(),
    }
}

#[test]
fn test_no_issue_normal_proof() {
    let config = OracleConfig::default();
    let mut oracle = MerkleOracle::new(config).with_expected_depth(3);

    let tc = make_merkle_test_case(123, &[1, 2, 3], &[0, 1, 0]);
    let output = vec![FieldElement::from_u64(999)]; // root

    assert!(oracle.check(&tc, &output).is_none());
}

#[test]
fn test_path_length_bypass_detected() {
    let config = OracleConfig::default();
    let mut oracle = MerkleOracle::new(config).with_expected_depth(3);

    // Path with only 2 elements instead of 3
    let tc = make_merkle_test_case(123, &[1, 2], &[0, 1]);
    let output = vec![FieldElement::from_u64(999)];

    let finding = oracle.check(&tc, &output);
    assert!(finding.is_some());
    assert!(finding.unwrap().description.contains("PATH LENGTH"));
}

#[test]
fn test_multiple_paths_detected() {
    let config = OracleConfig::default();
    let mut oracle = MerkleOracle::new(config);

    // Same root, same leaf, different paths
    let tc1 = make_merkle_test_case(100, &[1, 2, 3], &[0, 0, 0]);
    let tc2 = make_merkle_test_case(100, &[4, 5, 6], &[1, 1, 1]);

    // Same output (root)
    let output = vec![FieldElement::from_u64(999)];

    // First should pass
    assert!(oracle.check(&tc1, &output).is_none());

    // Second with different path should detect issue
    let finding = oracle.check(&tc2, &output);
    assert!(finding.is_some());
    assert!(finding.unwrap().description.contains("MULTIPLE"));
}

#[test]
fn test_identical_siblings_warning() {
    let config = OracleConfig::default();
    let mut oracle = MerkleOracle::new(config);

    // Path with identical consecutive siblings
    let tc = make_merkle_test_case(100, &[5, 5, 3], &[0, 1, 0]);
    let output = vec![FieldElement::from_u64(999)];

    let finding = oracle.check(&tc, &output);
    assert!(finding.is_some());
    assert!(finding.unwrap().description.contains("IDENTICAL"));
}
