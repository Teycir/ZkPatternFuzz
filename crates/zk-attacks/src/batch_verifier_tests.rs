use super::*;

#[test]
fn test_batch_verifier_creation() {
    let verifier = BatchVerifier::new();
    assert_eq!(verifier.config.max_batch_size, 256);
}

#[test]
fn test_empty_batch() {
    let verifier = BatchVerifier::new();
    let result = verifier.verify_batch(&[], &[], AggregationMethod::NaiveBatch);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.batch_passed);
    assert!(result.individual_results.is_empty());
}

#[test]
fn test_batch_size_limit() {
    let config = BatchVerifierConfig {
        max_batch_size: 10,
        ..Default::default()
    };
    let verifier = BatchVerifier::with_config(config);

    let proofs: Vec<SerializedProof> = (0..15)
        .map(|i| SerializedProof {
            data: vec![i as u8],
            proof_system: ProofSystem::Groth16,
            circuit_id: "test".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..15).map(|_| PublicInputs::new(vec![])).collect();

    let result = verifier.verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch);
    assert!(result.is_err());
}

#[test]
fn test_rlc_coefficient_generation() {
    let verifier = BatchVerifier::new();
    let coeffs = verifier.generate_rlc_coefficients(5);
    assert_eq!(coeffs.len(), 5);
    for coeff in coeffs {
        assert_eq!(coeff.len(), 32);
    }
}

#[test]
fn test_aggregation_method_as_str() {
    assert_eq!(AggregationMethod::NaiveBatch.as_str(), "naive_batch");
    assert_eq!(AggregationMethod::SnarkPack.as_str(), "snarkpack");
    assert_eq!(
        AggregationMethod::Groth16Aggregation.as_str(),
        "groth16_aggregation"
    );
}
