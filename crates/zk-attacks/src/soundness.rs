//! Soundness attack detection
//!
//! Soundness attacks attempt to create valid proofs for false statements.
//! A sound proof system should never accept a proof for an invalid statement.
//!
//! The soundness attack is implemented directly in the fuzzer engine
//! (see `FuzzingEngine::run_soundness_attack()`).

use super::{Attack, AttackContext};
use crate::registry::{AttackMetadata, AttackPlugin};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity};

/// Soundness tester for proof systems
pub struct SoundnessTester {
    /// Number of forgery attempts
    forge_attempts: usize,
    /// Mutation rate for proof modification
    mutation_rate: f64,
}

impl Default for SoundnessTester {
    fn default() -> Self {
        Self {
            forge_attempts: 1000,
            mutation_rate: 0.1,
        }
    }
}

impl SoundnessTester {
    /// Create a new soundness tester
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of forgery attempts
    pub fn with_forge_attempts(mut self, attempts: usize) -> Self {
        self.forge_attempts = attempts;
        self
    }

    /// Set the mutation rate for proof modification
    pub fn with_mutation_rate(mut self, rate: f64) -> Self {
        self.mutation_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Get the configured forgery attempts
    pub fn forge_attempts(&self) -> usize {
        self.forge_attempts
    }

    /// Get the configured mutation rate
    pub fn mutation_rate(&self) -> f64 {
        self.mutation_rate
    }
}

impl Attack for SoundnessTester {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let dof = context.circuit_info.degrees_of_freedom();
        if dof > 0 {
            findings.push(Finding {
                attack_type: AttackType::Soundness,
                severity: Severity::High,
                description: format!(
                    "Circuit '{}' has positive degrees of freedom ({}) - may be vulnerable to soundness attacks",
                    context.circuit_info.name, dof
                ),
                poc: ProofOfConcept::default(),
                location: None,
                class: None,
            });
        }

        let Some(executor) = context.executor.as_ref() else {
            return findings;
        };

        let mut rng = StdRng::seed_from_u64(42);
        let total_inputs = executor.num_public_inputs() + executor.num_private_inputs();
        let valid_inputs: Vec<FieldElement> = (0..total_inputs)
            .map(|_| FieldElement::random(&mut rng))
            .collect();

        let valid_proof = match executor.prove(&valid_inputs) {
            Ok(proof) => proof,
            Err(e) => {
                tracing::warn!("SoundnessTester: failed to generate valid proof: {}", e);
                return findings;
            }
        };

        let public_inputs: Vec<FieldElement> = valid_inputs
            .iter()
            .take(executor.num_public_inputs())
            .cloned()
            .collect();

        if valid_proof.is_empty() {
            return findings;
        }

        let attempts = self.forge_attempts.max(1);
        let proof_attempts = attempts / 2;
        let input_attempts = attempts - proof_attempts;

        // Attempt 1: mutate proof bytes and check if verification still passes.
        for _ in 0..proof_attempts {
            let mutated = mutate_proof_bytes(&valid_proof, self.mutation_rate, &mut rng);
            if mutated == valid_proof {
                continue;
            }

            match executor.verify(&mutated, &public_inputs) {
                Ok(true) => {
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::High,
                        description: format!(
                            "Proof malleability: mutated proof verified for '{}' ({} -> {} bytes)",
                            context.circuit_info.name,
                            valid_proof.len(),
                            mutated.len()
                        ),
                        poc: ProofOfConcept {
                            witness_a: valid_inputs.clone(),
                            witness_b: None,
                            public_inputs: public_inputs.clone(),
                            proof: Some(mutated),
                        },
                        location: None,
                        class: None,
                    });
                    break;
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::debug!("SoundnessTester: verifier error on mutated proof: {}", e);
                }
            }
        }

        // Attempt 2: keep proof fixed, mutate public inputs (should fail verification).
        for _ in 0..input_attempts {
            let mut forged_inputs = public_inputs.clone();
            if forged_inputs.is_empty() {
                break;
            }
            let idx = rng.gen_range(0..forged_inputs.len());
            let mut mutated = forged_inputs[idx].to_bytes();
            let byte_idx = rng.gen_range(0..mutated.len());
            mutated[byte_idx] ^= 1u8 << rng.gen_range(0..8);
            forged_inputs[idx] = FieldElement(mutated);

            match executor.verify(&valid_proof, &forged_inputs) {
                Ok(true) => {
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::Critical,
                        description: format!(
                            "Soundness failure: proof verified with forged public inputs in '{}'",
                            context.circuit_info.name
                        ),
                        poc: ProofOfConcept {
                            witness_a: valid_inputs.clone(),
                            witness_b: None,
                            public_inputs: forged_inputs,
                            proof: Some(valid_proof.clone()),
                        },
                        location: None,
                        class: None,
                    });
                    break;
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::debug!("SoundnessTester: verifier error on forged inputs: {}", e);
                }
            }
        }

        findings
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Soundness
    }

    fn description(&self) -> &str {
        "Attempt to forge proofs for invalid statements"
    }
}

impl AttackPlugin for SoundnessTester {
    fn metadata(&self) -> AttackMetadata {
        AttackMetadata::new("soundness", self.description(), "0.1.0")
    }
}

fn mutate_proof_bytes(proof: &[u8], mutation_rate: f64, rng: &mut impl Rng) -> Vec<u8> {
    let mut mutated = proof.to_vec();
    for byte in &mut mutated {
        if rng.gen::<f64>() < mutation_rate {
            *byte ^= 1u8 << rng.gen_range(0..8);
        }
    }

    if mutated == proof && !mutated.is_empty() {
        let idx = rng.gen_range(0..mutated.len());
        mutated[idx] ^= 0x01;
    }

    mutated
}
