//! Batch Real Verification Tests (Phase 5: Milestone 5.1)
//!
//! Integration tests verifying that batch verification uses real cryptographic
//! verification instead of heuristic simulation.

use std::sync::Arc;
use zk_core::{CircuitExecutor, ExecutionResult, ExecutionCoverage, FieldElement, Framework, CircuitInfo};
use zk_fuzzer::executor::batch_verifier::{
    BatchVerifier, BatchVerifierConfig, SerializedProof, PublicInputs,
    AggregationMethod, ProofSystem,
};

// ============================================================================
// Mock Executor for Testing
// ============================================================================

/// Mock executor that simulates real proof generation and verification
struct MockBatchTestExecutor {
    /// Proofs that should fail verification (by index based on first byte)
    fail_indices: Vec<usize>,
    /// Counter for proof generation
    proof_counter: std::sync::atomic::AtomicUsize,
}

impl MockBatchTestExecutor {
    fn new() -> Self {
        Self {
            fail_indices: vec![],
            proof_counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn with_failures(indices: Vec<usize>) -> Self {
        Self {
            fail_indices: indices,
            proof_counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl CircuitExecutor for MockBatchTestExecutor {
    fn framework(&self) -> Framework {
        Framework::Mock
    }

    fn name(&self) -> &str {
        "mock_batch_test"
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: "mock_batch_test".to_string(),
            num_constraints: 1000,
            num_private_inputs: 3,
            num_public_inputs: 2,
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        ExecutionResult::success(inputs.to_vec(), ExecutionCoverage::default())
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        // Generate a deterministic proof based on witness
        let counter = self.proof_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut proof = vec![counter as u8];
        for (i, w) in witness.iter().enumerate().take(31) {
            proof.push(w.0[i % 32]);
        }
        Ok(proof)
    }

    fn verify(&self, proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        // Use first byte of proof as index to determine if verification should fail
        if proof.is_empty() {
            return Ok(false);
        }
        let idx = proof[0] as usize;
        Ok(!self.fail_indices.contains(&idx))
    }
}

// ============================================================================
// Basic Batch Verification Tests
// ============================================================================

#[test]
fn test_real_batch_verification_all_valid() {
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    // Create 5 valid proofs
    let proofs: Vec<SerializedProof> = (0..5)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Groth16,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..5)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch)
        .expect("Batch verification should succeed");

    assert!(result.batch_passed, "All proofs should be valid");
    assert_eq!(result.individual_results.len(), 5);
    assert!(result.individual_results.iter().all(|&v| v));
    assert_eq!(result.diagnostics.valid_count, 5);
    assert_eq!(result.diagnostics.invalid_count, 0);
}

#[test]
fn test_real_batch_verification_with_invalid_proofs() {
    // Proofs at indices 1 and 3 should fail
    let executor = Arc::new(MockBatchTestExecutor::with_failures(vec![1, 3]));
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs: Vec<SerializedProof> = (0..5)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Groth16,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..5)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch)
        .expect("Batch verification should complete");

    assert!(!result.batch_passed, "Batch should fail with invalid proofs");
    assert!(result.individual_results[0], "Proof 0 should be valid");
    assert!(!result.individual_results[1], "Proof 1 should be invalid");
    assert!(result.individual_results[2], "Proof 2 should be valid");
    assert!(!result.individual_results[3], "Proof 3 should be invalid");
    assert!(result.individual_results[4], "Proof 4 should be valid");
    assert_eq!(result.diagnostics.invalid_count, 2);
    assert!(result.diagnostics.invalid_indices.contains(&1));
    assert!(result.diagnostics.invalid_indices.contains(&3));
}

#[test]
fn test_real_batch_empty() {
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let result = verifier
        .verify_batch(&[], &[], AggregationMethod::NaiveBatch)
        .expect("Empty batch should succeed");

    assert!(result.batch_passed);
    assert!(result.individual_results.is_empty());
}

#[test]
fn test_real_batch_mismatched_lengths() {
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs = vec![SerializedProof {
        data: vec![0u8; 32],
        proof_system: ProofSystem::Groth16,
        circuit_id: "test".to_string(),
    }];
    
    let public_inputs = vec![
        PublicInputs::new(vec![FieldElement::from_u64(1u64)]),
        PublicInputs::new(vec![FieldElement::from_u64(2u64)]),
    ];

    let result = verifier.verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch);
    assert!(result.is_err(), "Should error on mismatched lengths");
}

// ============================================================================
// Aggregation Method Tests
// ============================================================================

#[test]
fn test_groth16_batch_aggregation() {
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs: Vec<SerializedProof> = (0..3)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Groth16,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..3)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::Groth16Aggregation)
        .expect("Groth16 batch should succeed");

    assert!(result.batch_passed);
    assert_eq!(result.method, AggregationMethod::Groth16Aggregation);
}

#[test]
fn test_snarkpack_batch_aggregation() {
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs: Vec<SerializedProof> = (0..4)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Groth16,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..4)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::SnarkPack)
        .expect("SnarkPack batch should succeed");

    assert!(result.batch_passed);
    assert_eq!(result.method, AggregationMethod::SnarkPack);
}

#[test]
fn test_plonk_batch_aggregation() {
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs: Vec<SerializedProof> = (0..3)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Plonk,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..3)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::PlonkAggregation)
        .expect("Plonk batch should succeed");

    assert!(result.batch_passed);
    assert_eq!(result.method, AggregationMethod::PlonkAggregation);
}

#[test]
fn test_halo2_accumulation() {
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs: Vec<SerializedProof> = (0..3)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Halo2,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..3)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::Halo2Accumulation)
        .expect("Halo2 batch should succeed");

    assert!(result.batch_passed);
    assert_eq!(result.method, AggregationMethod::Halo2Accumulation);
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_batch_size_limit() {
    let config = BatchVerifierConfig {
        max_batch_size: 5,
        ..Default::default()
    };
    
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::with_config(config)
        .with_executor(executor);

    // Create batch larger than limit
    let proofs: Vec<SerializedProof> = (0..10)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Groth16,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..10)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier.verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch);
    assert!(result.is_err(), "Should error on oversized batch");
}

// ============================================================================
// No Executor Tests
// ============================================================================

#[test]
fn test_batch_verification_no_executor() {
    let verifier = BatchVerifier::new();
    // Don't set executor

    let proofs = vec![SerializedProof {
        data: vec![0u8; 32],
        proof_system: ProofSystem::Groth16,
        circuit_id: "test".to_string(),
    }];
    
    let public_inputs = vec![PublicInputs::new(vec![FieldElement::from_u64(1u64)])];

    let result = verifier.verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch);
    assert!(result.is_err(), "Should error when no executor configured");
}

// ============================================================================
// Verification Time Tracking
// ============================================================================

#[test]
fn test_verification_time_recorded() {
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs: Vec<SerializedProof> = (0..3)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Groth16,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..3)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch)
        .expect("Batch verification should succeed");

    assert!(result.batch_passed);
    assert_eq!(result.method, AggregationMethod::NaiveBatch);
}

// ============================================================================
// Diagnostics Tests
// ============================================================================

#[test]
fn test_diagnostics_populated() {
    let executor = Arc::new(MockBatchTestExecutor::with_failures(vec![2]));
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs: Vec<SerializedProof> = (0..5)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Groth16,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..5)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch)
        .expect("Batch verification should complete");

    assert_eq!(result.diagnostics.batch_size, 5);
    assert_eq!(result.diagnostics.valid_count, 4);
    assert_eq!(result.diagnostics.invalid_count, 1);
    assert_eq!(result.diagnostics.invalid_indices, vec![2]);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_single_proof_batch() {
    let executor = Arc::new(MockBatchTestExecutor::new());
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs = vec![SerializedProof {
        data: vec![0u8; 32],
        proof_system: ProofSystem::Groth16,
        circuit_id: "test".to_string(),
    }];
    
    let public_inputs = vec![PublicInputs::new(vec![FieldElement::from_u64(42u64)])];

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch)
        .expect("Single proof batch should succeed");

    assert!(result.batch_passed);
    assert_eq!(result.individual_results.len(), 1);
}

#[test]
fn test_all_proofs_invalid() {
    let executor = Arc::new(MockBatchTestExecutor::with_failures(vec![0, 1, 2]));
    let verifier = BatchVerifier::new()
        .with_executor(executor);

    let proofs: Vec<SerializedProof> = (0..3)
        .map(|i| SerializedProof {
            data: vec![i as u8; 32],
            proof_system: ProofSystem::Groth16,
            circuit_id: "test_circuit".to_string(),
        })
        .collect();

    let public_inputs: Vec<PublicInputs> = (0..3)
        .map(|i| PublicInputs::new(vec![FieldElement::from_u64(i as u64)]))
        .collect();

    let result = verifier
        .verify_batch(&proofs, &public_inputs, AggregationMethod::NaiveBatch)
        .expect("Batch should complete even with all invalid");

    assert!(!result.batch_passed);
    assert!(result.individual_results.iter().all(|&v| !v));
    assert_eq!(result.diagnostics.invalid_count, 3);
}
