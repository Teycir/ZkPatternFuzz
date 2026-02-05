//! Recursive Proof Testing
//!
//! Tests circuits that verify other proofs (recursive SNARKs).

use crate::executor::CircuitExecutor;
use crate::fuzzer::FieldElement;
use std::sync::Arc;

/// Recursive proof tester
pub struct RecursiveTester {
    /// The circuit that verifies proofs
    verifier_circuit: Option<Arc<dyn CircuitExecutor>>,
    /// Maximum recursion depth to test
    max_depth: usize,
    /// Proof accumulator (for testing accumulation schemes)
    accumulated_proofs: Vec<Vec<u8>>,
}

impl RecursiveTester {
    pub fn new(max_depth: usize) -> Self {
        Self {
            verifier_circuit: None,
            max_depth,
            accumulated_proofs: Vec::new(),
        }
    }

    pub fn with_verifier(mut self, verifier: Arc<dyn CircuitExecutor>) -> Self {
        self.verifier_circuit = Some(verifier);
        self
    }

    /// Test recursive proof verification
    pub fn test_recursion(&self, base_inputs: &[FieldElement], depth: usize) -> RecursionResult {
        let verifier = match &self.verifier_circuit {
            Some(v) => v,
            None => return RecursionResult::Error("No verifier circuit set".to_string()),
        };

        if depth > self.max_depth {
            return RecursionResult::DepthExceeded(self.max_depth);
        }

        // Generate base proof
        let base_proof = match verifier.prove(base_inputs) {
            Ok(p) => p,
            Err(e) => return RecursionResult::Error(format!("Base proof failed: {}", e)),
        };

        // Recursively verify
        let mut current_proof = base_proof;
        let mut public_inputs = base_inputs.to_vec();

        for d in 0..depth {
            // Create inputs for recursive verification
            // (proof is typically encoded as field elements in recursive SNARKs)
            let proof_as_inputs = self.encode_proof_as_inputs(&current_proof);

            // Combine public inputs with proof encoding
            let mut recursive_inputs = public_inputs.clone();
            recursive_inputs.extend(proof_as_inputs);

            // Execute verifier circuit
            let result = verifier.execute_sync(&recursive_inputs);

            if !result.success {
                return RecursionResult::VerificationFailed {
                    depth: d,
                    error: result.error.unwrap_or_else(|| "Unknown".to_string()),
                };
            }

            // Generate proof of verification
            match verifier.prove(&recursive_inputs) {
                Ok(p) => current_proof = p,
                Err(e) => {
                    return RecursionResult::Error(format!(
                        "Recursive proof at depth {} failed: {}",
                        d, e
                    ))
                }
            }

            // Update public inputs (typically hash of previous + new data)
            public_inputs = result.outputs;
        }

        RecursionResult::Success {
            final_proof: current_proof,
            final_outputs: public_inputs,
            depth,
        }
    }

    /// Test accumulator scheme
    pub fn test_accumulation(
        &mut self,
        proofs: Vec<Vec<u8>>,
        public_inputs_list: Vec<Vec<FieldElement>>,
    ) -> AccumulationResult {
        let verifier = match &self.verifier_circuit {
            Some(v) => v,
            None => return AccumulationResult::Error("No verifier circuit set".to_string()),
        };

        // Simulate accumulator verification
        // In a real IVC/PCD scheme, this would accumulate proofs

        for (i, (proof, public_inputs)) in proofs.iter().zip(public_inputs_list.iter()).enumerate()
        {
            match verifier.verify(proof, public_inputs) {
                Ok(true) => {
                    self.accumulated_proofs.push(proof.clone());
                }
                Ok(false) => {
                    return AccumulationResult::VerificationFailed {
                        index: i,
                        reason: "Proof verification returned false".to_string(),
                    };
                }
                Err(e) => {
                    return AccumulationResult::VerificationFailed {
                        index: i,
                        reason: e.to_string(),
                    };
                }
            }
        }

        AccumulationResult::Success {
            num_accumulated: self.accumulated_proofs.len(),
        }
    }

    /// Encode proof bytes as field elements (simplified)
    fn encode_proof_as_inputs(&self, proof: &[u8]) -> Vec<FieldElement> {
        // Simple encoding: pack every 31 bytes into a field element
        // (leaving room for field modulus)
        proof
            .chunks(31)
            .map(|chunk| {
                let mut bytes = [0u8; 32];
                bytes[32 - chunk.len()..].copy_from_slice(chunk);
                FieldElement(bytes)
            })
            .collect()
    }

    /// Test for recursive soundness issues
    pub fn test_soundness(&self, rng: &mut impl rand::Rng) -> Vec<RecursiveSoundnessIssue> {
        let mut issues = Vec::new();

        let verifier = match &self.verifier_circuit {
            Some(v) => v,
            None => return issues,
        };

        // Test 1: Can we verify a proof of a false statement?
        let false_inputs: Vec<FieldElement> = (0..verifier.num_private_inputs())
            .map(|_| FieldElement::random(rng))
            .collect();

        // Try to create a "proof" of random garbage
        let fake_proof: Vec<u8> = std::iter::repeat([0xde, 0xad, 0xbe, 0xef])
            .flatten()
            .take(256)
            .collect();

        if let Ok(true) = verifier.verify(&fake_proof, &false_inputs) {
            issues.push(RecursiveSoundnessIssue {
                issue_type: SoundnessIssueType::FakeProofAccepted,
                description: "Verifier accepted a fake proof".to_string(),
            });
        }

        // Test 2: Does the verifier properly check proof format?
        let truncated_proof = vec![0u8; 16]; // Too short
        match verifier.verify(&truncated_proof, &false_inputs) {
            Ok(true) => {
                issues.push(RecursiveSoundnessIssue {
                    issue_type: SoundnessIssueType::MalformedProofAccepted,
                    description: "Verifier accepted truncated proof".to_string(),
                });
            }
            Err(e) => {
                // Good - verifier rejected with error
                tracing::debug!("Verifier correctly rejected truncated proof: {}", e);
            }
            Ok(false) => {
                // Good - verifier rejected
            }
        }

        issues
    }
}

/// Result of recursive proof testing
#[derive(Debug, Clone)]
pub enum RecursionResult {
    Success {
        final_proof: Vec<u8>,
        final_outputs: Vec<FieldElement>,
        depth: usize,
    },
    DepthExceeded(usize),
    VerificationFailed {
        depth: usize,
        error: String,
    },
    Error(String),
}

/// Result of accumulation testing
#[derive(Debug, Clone)]
pub enum AccumulationResult {
    Success { num_accumulated: usize },
    VerificationFailed { index: usize, reason: String },
    Error(String),
}

/// Soundness issue in recursive verification
#[derive(Debug, Clone)]
pub struct RecursiveSoundnessIssue {
    pub issue_type: SoundnessIssueType,
    pub description: String,
}

/// Type of soundness issue
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoundnessIssueType {
    FakeProofAccepted,
    MalformedProofAccepted,
    RecursionBypass,
    AccumulatorMalleability,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_recursive_tester_creation() {
        let tester = RecursiveTester::new(5);
        assert_eq!(tester.max_depth, 5);
        assert!(tester.verifier_circuit.is_none());
    }

    #[test]
    fn test_recursive_verification() {
        let verifier = Arc::new(MockCircuitExecutor::new("verifier", 10, 2));
        let tester = RecursiveTester::new(3).with_verifier(verifier);

        let inputs = vec![FieldElement::one(); 10];
        let result = tester.test_recursion(&inputs, 2);

        match result {
            RecursionResult::Success { depth, .. } => {
                assert_eq!(depth, 2);
            }
            other => panic!("Expected success, got {:?}", other),
        }
    }

    #[test]
    fn test_soundness_checking() {
        let verifier = Arc::new(MockCircuitExecutor::new("verifier", 5, 2));
        let tester = RecursiveTester::new(3).with_verifier(verifier);

        let mut rng = StdRng::seed_from_u64(42);
        let issues = tester.test_soundness(&mut rng);

        // Mock executor should reject fake proofs
        assert!(issues.is_empty(), "Expected no soundness issues in mock");
    }
}
