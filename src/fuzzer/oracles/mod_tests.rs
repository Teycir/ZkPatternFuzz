use super::*;

#[test]
fn test_compute_entropy() {
    // All same byte -> 0 entropy
    let low_entropy = vec![0u8; 100];
    assert!(compute_entropy(&low_entropy) < 0.01);

    // All different bytes -> high entropy
    let high_entropy: Vec<u8> = (0..=255).collect();
    assert!(compute_entropy(&high_entropy) > 0.9);

    // Empty -> 0 entropy
    assert_eq!(compute_entropy(&[]), 0.0);
}

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
