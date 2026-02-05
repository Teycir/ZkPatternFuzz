//! Proof Verification Fuzzing
//!
//! Tests the verifier itself with malformed proofs to find:
//! - Proof malleability (can valid proofs be modified and still verify?)
//! - Verifier edge case handling
//! - Soundness violations

use super::{Attack, AttackContext};
use crate::config::{AttackType, Severity};
use crate::executor::CircuitExecutor;
use crate::fuzzer::{FieldElement, Finding, ProofOfConcept};
use rand::Rng;
use std::sync::Arc;

/// Proof verification fuzzer
pub struct VerificationFuzzer {
    /// Number of malleability tests
    malleability_tests: usize,
    /// Number of malformed proof tests
    malformed_tests: usize,
    /// Number of edge case tests
    edge_case_tests: usize,
    /// Mutation rate for proof bytes
    mutation_rate: f64,
}

impl Default for VerificationFuzzer {
    fn default() -> Self {
        Self {
            malleability_tests: 1000,
            malformed_tests: 1000,
            edge_case_tests: 500,
            mutation_rate: 0.05,
        }
    }
}

impl VerificationFuzzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_malleability_tests(mut self, count: usize) -> Self {
        self.malleability_tests = count;
        self
    }

    pub fn with_malformed_tests(mut self, count: usize) -> Self {
        self.malformed_tests = count;
        self
    }

    pub fn with_edge_case_tests(mut self, count: usize) -> Self {
        self.edge_case_tests = count;
        self
    }

    pub fn with_mutation_rate(mut self, rate: f64) -> Self {
        self.mutation_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Run verification fuzzing against an executor
    pub fn fuzz(&self, executor: &Arc<dyn CircuitExecutor>, rng: &mut impl Rng) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Generate a valid proof first
        let valid_inputs: Vec<FieldElement> = (0..executor.num_private_inputs())
            .map(|_| FieldElement::random(rng))
            .collect();

        let valid_proof = match executor.prove(&valid_inputs) {
            Ok(proof) => proof,
            Err(e) => {
                tracing::warn!("Failed to generate valid proof: {}", e);
                return findings;
            }
        };

        let public_inputs: Vec<FieldElement> = valid_inputs
            .iter()
            .take(executor.num_public_inputs())
            .cloned()
            .collect();

        // Test 1: Proof Malleability
        findings.extend(self.test_malleability(executor, &valid_proof, &public_inputs, rng));

        // Test 2: Malformed Proofs
        findings.extend(self.test_malformed_proofs(executor, &valid_proof, &public_inputs, rng));

        // Test 3: Edge Cases
        findings.extend(self.test_edge_cases(executor, &valid_proof, &public_inputs));

        findings
    }

    /// Test if valid proofs can be modified and still verify (malleability)
    fn test_malleability(
        &self,
        executor: &Arc<dyn CircuitExecutor>,
        valid_proof: &[u8],
        public_inputs: &[FieldElement],
        rng: &mut impl Rng,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for _ in 0..self.malleability_tests {
            let mutated = self.mutate_proof(valid_proof, rng);

            // Skip if mutation produced identical proof
            if mutated == valid_proof {
                continue;
            }

            match executor.verify(&mutated, public_inputs) {
                Ok(true) => {
                    // Mutated proof verified! This is a malleability issue
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::High,
                        description: format!(
                            "Proof malleability detected: modified proof still verifies. \
                             Original size: {} bytes, mutated: {} bytes",
                            valid_proof.len(),
                            mutated.len()
                        ),
                        poc: ProofOfConcept {
                            witness_a: public_inputs.to_vec(),
                            witness_b: None,
                            public_inputs: public_inputs.to_vec(),
                            proof: Some(mutated),
                        },
                        location: None,
                    });
                }
                Ok(false) => {
                    // Expected behavior - mutated proof rejected
                }
                Err(_) => {
                    // Verifier error - might be interesting for robustness
                }
            }
        }

        findings
    }

    /// Test verifier with malformed proofs
    fn test_malformed_proofs(
        &self,
        executor: &Arc<dyn CircuitExecutor>,
        valid_proof: &[u8],
        public_inputs: &[FieldElement],
        rng: &mut impl Rng,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Generate various malformed proofs
        let malformed_proofs = self.generate_malformed_proofs(valid_proof, rng);

        for (description, malformed) in malformed_proofs {
            match executor.verify(&malformed, public_inputs) {
                Ok(true) => {
                    // Malformed proof verified! Critical issue
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::Critical,
                        description: format!(
                            "Malformed proof accepted: {}. Size: {} bytes",
                            description,
                            malformed.len()
                        ),
                        poc: ProofOfConcept {
                            witness_a: public_inputs.to_vec(),
                            witness_b: None,
                            public_inputs: public_inputs.to_vec(),
                            proof: Some(malformed),
                        },
                        location: None,
                    });
                }
                Ok(false) => {
                    // Expected - malformed proof rejected
                }
                Err(e) => {
                    // Check if error handling is graceful
                    let error_msg = e.to_string();
                    if error_msg.contains("panic") || error_msg.contains("unwrap") {
                        findings.push(Finding {
                            attack_type: AttackType::Boundary,
                            severity: Severity::Medium,
                            description: format!(
                                "Verifier panics on malformed proof ({}): {}",
                                description, error_msg
                            ),
                            poc: ProofOfConcept {
                                witness_a: vec![],
                                witness_b: None,
                                public_inputs: public_inputs.to_vec(),
                                proof: Some(malformed),
                            },
                            location: None,
                        });
                    }
                }
            }
        }

        findings
    }

    /// Test edge cases in verification
    fn test_edge_cases(
        &self,
        executor: &Arc<dyn CircuitExecutor>,
        _valid_proof: &[u8],
        public_inputs: &[FieldElement],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Edge case: Empty proof
        if let Ok(true) = executor.verify(&[], public_inputs) {
            findings.push(Finding {
                attack_type: AttackType::Soundness,
                severity: Severity::Critical,
                description: "Empty proof accepted by verifier".to_string(),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        // Edge case: Empty public inputs
        if let Ok(true) = executor.verify(&[0u8; 256], &[]) {
            findings.push(Finding {
                attack_type: AttackType::Soundness,
                severity: Severity::Critical,
                description: "Proof verified with empty public inputs".to_string(),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        // Edge case: Zero proof
        let zero_proof = vec![0u8; 256];
        if let Ok(true) = executor.verify(&zero_proof, public_inputs) {
            findings.push(Finding {
                attack_type: AttackType::Soundness,
                severity: Severity::Critical,
                description: "All-zero proof accepted by verifier".to_string(),
                poc: ProofOfConcept {
                    witness_a: vec![],
                    witness_b: None,
                    public_inputs: public_inputs.to_vec(),
                    proof: Some(zero_proof),
                },
                location: None,
            });
        }

        // Edge case: All-ones proof
        let ones_proof = vec![0xffu8; 256];
        if let Ok(true) = executor.verify(&ones_proof, public_inputs) {
            findings.push(Finding {
                attack_type: AttackType::Soundness,
                severity: Severity::Critical,
                description: "All-ones proof accepted by verifier".to_string(),
                poc: ProofOfConcept {
                    witness_a: vec![],
                    witness_b: None,
                    public_inputs: public_inputs.to_vec(),
                    proof: Some(ones_proof),
                },
                location: None,
            });
        }

        // Additional edge cases based on edge_case_tests count
        // Test various proof sizes
        let test_sizes = vec![0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
        let num_size_tests = (self.edge_case_tests / 3).min(test_sizes.len());

        for size in test_sizes.iter().take(num_size_tests) {
            let edge_proof = vec![0x42u8; *size];
            if let Ok(true) = executor.verify(&edge_proof, public_inputs) {
                findings.push(Finding {
                    attack_type: AttackType::Soundness,
                    severity: Severity::High,
                    description: format!("Proof of size {} accepted by verifier", size),
                    poc: ProofOfConcept {
                        witness_a: vec![],
                        witness_b: None,
                        public_inputs: public_inputs.to_vec(),
                        proof: Some(edge_proof),
                    },
                    location: None,
                });
            }
        }

        findings
    }

    /// Mutate a proof by flipping random bits
    fn mutate_proof(&self, proof: &[u8], rng: &mut impl Rng) -> Vec<u8> {
        let mut mutated = proof.to_vec();

        for byte in &mut mutated {
            if rng.gen::<f64>() < self.mutation_rate {
                let bit = rng.gen_range(0..8);
                *byte ^= 1 << bit;
            }
        }

        mutated
    }

    /// Generate various malformed proofs for testing
    fn generate_malformed_proofs(
        &self,
        valid_proof: &[u8],
        rng: &mut impl Rng,
    ) -> Vec<(&'static str, Vec<u8>)> {
        let mut proofs = Vec::new();

        // Truncated proof
        if valid_proof.len() > 10 {
            proofs.push(("truncated", valid_proof[..10].to_vec()));
        }

        // Extended proof with garbage
        let mut extended = valid_proof.to_vec();
        extended.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        proofs.push(("extended with garbage", extended));

        // Proof with wrong length
        proofs.push(("too short", vec![0u8; 16]));
        proofs.push(("too long", vec![0u8; 1024]));

        // Single byte mutation at critical positions
        for pos in [0, 32, 64, valid_proof.len().saturating_sub(1)] {
            if pos < valid_proof.len() {
                let mut mutated = valid_proof.to_vec();
                mutated[pos] ^= 0xff;
                proofs.push(("single byte flip", mutated));
            }
        }

        // Random garbage
        for _ in 0..10 {
            let len = rng.gen_range(1..512);
            let garbage: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            proofs.push(("random garbage", garbage));
        }

        proofs
    }
}

impl Attack for VerificationFuzzer {
    fn run(&self, _context: &AttackContext) -> Vec<Finding> {
        // This attack requires an executor, which should be passed separately
        // The main fuzzing is done via the `fuzz` method
        Vec::new()
    }

    fn attack_type(&self) -> AttackType {
        AttackType::VerificationFuzzing
    }

    fn description(&self) -> &str {
        "Proof verification fuzzing: tests verifier with malformed and mutated proofs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_verification_fuzzer_creation() {
        let fuzzer = VerificationFuzzer::new()
            .with_malleability_tests(100)
            .with_malformed_tests(100);

        assert_eq!(fuzzer.malleability_tests, 100);
        assert_eq!(fuzzer.malformed_tests, 100);
    }

    #[test]
    fn test_verification_fuzzing() {
        let fuzzer = VerificationFuzzer::new()
            .with_malleability_tests(10)
            .with_malformed_tests(10);

        let executor: Arc<dyn CircuitExecutor> = Arc::new(MockCircuitExecutor::new("test", 2, 1));
        let mut rng = StdRng::seed_from_u64(42);

        let findings = fuzzer.fuzz(&executor, &mut rng);

        // Mock executor should reject malformed proofs
        // So we expect no critical findings for properly implemented verifier
        for finding in &findings {
            println!("Finding: {:?} - {}", finding.severity, finding.description);
        }
    }
}
