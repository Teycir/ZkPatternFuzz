//! Proof Malleability Scanner (P0)
//!
//! Detects whether mutated proofs still verify. This targets verifier
//! malleability rather than prover soundness.

use num_bigint::BigUint;
use rand::Rng;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Types of proof mutations to attempt
#[derive(Debug, Clone, Copy)]
pub enum ProofMutation {
    /// Flip random bits in the proof
    BitFlip { byte_index: usize, bit_mask: u8 },
    /// Negate a 32-byte scalar (s -> p - s)
    ScalarNegation { offset: usize },
    /// Swap two 32-byte chunks (e.g., swap proof elements)
    ChunkSwap { offset_a: usize, offset_b: usize },
    /// Zero out a 32-byte chunk
    ZeroChunk { offset: usize },
    /// Duplicate first proof element over second
    DuplicateElement {
        src_offset: usize,
        dst_offset: usize,
    },
    /// Add 1 to a scalar field element
    ScalarIncrement { offset: usize },
    /// Truncate proof by N bytes
    Truncate { keep_bytes: usize },
}

/// Result of a single malleability test
#[derive(Debug, Clone)]
pub struct MalleabilityResult {
    pub mutation: ProofMutation,
    pub original_proof: Vec<u8>,
    pub mutated_proof: Vec<u8>,
    pub verified: bool,
    pub public_inputs: Vec<FieldElement>,
}

pub struct ProofMalleabilityScanner {
    /// Number of random bit-flip mutations per proof
    random_mutations: usize,
    /// Whether to test structured mutations (negate, swap, zero)
    structured_mutations: bool,
    /// Number of valid proofs to generate before mutating
    proof_samples: usize,
}

impl Default for ProofMalleabilityScanner {
    fn default() -> Self {
        Self {
            random_mutations: 100,
            structured_mutations: true,
            proof_samples: 10,
        }
    }
}

impl ProofMalleabilityScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_random_mutations(mut self, n: usize) -> Self {
        self.random_mutations = n;
        self
    }

    pub fn with_structured_mutations(mut self, enabled: bool) -> Self {
        self.structured_mutations = enabled;
        self
    }

    pub fn with_proof_samples(mut self, n: usize) -> Self {
        self.proof_samples = n;
        self
    }

    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if self.proof_samples == 0 || witnesses.is_empty() {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let info = executor.circuit_info();
        let modulus = executor.field_modulus();

        for witness in witnesses.iter().take(self.proof_samples) {
            if witness.len() < info.num_public_inputs {
                continue;
            }

            // Step 1: Generate a valid proof
            let proof = match executor.prove(witness) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Step 2: Extract public inputs from witness
            let public_inputs: Vec<FieldElement> = witness[..info.num_public_inputs].to_vec();

            // Step 3: Verify the original proof passes
            match executor.verify(&proof, &public_inputs) {
                Ok(true) => {}
                _ => continue,
            }

            // Step 4: Generate and test mutations
            let mutations = self.generate_mutations(&proof);
            for mutation in mutations {
                let mutated = self.apply_mutation(&proof, &mutation, &modulus);
                if mutated == proof {
                    continue;
                }

                match executor.verify(&mutated, &public_inputs) {
                    Ok(true) => {
                        findings.push(Finding {
                            attack_type: AttackType::Soundness,
                            severity: Severity::Critical,
                            description: format!(
                                "Proof malleability: {:?} on {}-byte proof still verifies",
                                mutation,
                                proof.len()
                            ),
                            poc: ProofOfConcept {
                                witness_a: witness.clone(),
                                witness_b: None,
                                public_inputs: public_inputs.clone(),
                                proof: Some(mutated),
                            },
                            location: None,
                        });
                    }
                    _ => {}
                }
            }
        }

        findings
    }

    fn generate_mutations(&self, proof: &[u8]) -> Vec<ProofMutation> {
        let mut mutations = Vec::new();
        if proof.is_empty() {
            return mutations;
        }

        let mut rng = rand::thread_rng();

        if self.structured_mutations {
            let chunk_count = proof.len() / 32;
            for i in 0..chunk_count {
                let offset = i * 32;
                mutations.push(ProofMutation::ScalarNegation { offset });
                mutations.push(ProofMutation::ZeroChunk { offset });
                mutations.push(ProofMutation::ScalarIncrement { offset });

                for j in (i + 1)..chunk_count {
                    mutations.push(ProofMutation::ChunkSwap {
                        offset_a: i * 32,
                        offset_b: j * 32,
                    });
                }
            }

            if chunk_count >= 2 {
                mutations.push(ProofMutation::DuplicateElement {
                    src_offset: 0,
                    dst_offset: 32,
                });
            }

            for keep in [32usize, 64, 128, proof.len().saturating_sub(1)] {
                if keep > 0 && keep < proof.len() {
                    mutations.push(ProofMutation::Truncate { keep_bytes: keep });
                }
            }
        }

        for _ in 0..self.random_mutations {
            let byte_idx = rng.gen_range(0..proof.len());
            let bit = 1u8 << rng.gen_range(0..8);
            mutations.push(ProofMutation::BitFlip {
                byte_index: byte_idx,
                bit_mask: bit,
            });
        }

        mutations
    }

    fn apply_mutation(
        &self,
        proof: &[u8],
        mutation: &ProofMutation,
        modulus: &[u8; 32],
    ) -> Vec<u8> {
        let mut mutated = proof.to_vec();

        match mutation {
            ProofMutation::BitFlip {
                byte_index,
                bit_mask,
            } => {
                if *byte_index < mutated.len() {
                    mutated[*byte_index] ^= bit_mask;
                }
            }
            ProofMutation::ScalarNegation { offset } => {
                if offset + 32 <= mutated.len() {
                    let p = BigUint::from_bytes_be(modulus);
                    if p > BigUint::from(0u32) {
                        let mut scalar = [0u8; 32];
                        scalar.copy_from_slice(&mutated[*offset..*offset + 32]);
                        let s = BigUint::from_bytes_be(&scalar);
                        let s_mod = &s % &p;
                        let neg = if s_mod == BigUint::from(0u32) {
                            BigUint::from(0u32)
                        } else {
                            &p - &s_mod
                        };
                        let bytes = neg.to_bytes_be();
                        let start = 32usize.saturating_sub(bytes.len());
                        mutated[*offset..*offset + 32].fill(0);
                        mutated[*offset + start..*offset + 32].copy_from_slice(&bytes);
                    }
                }
            }
            ProofMutation::ChunkSwap { offset_a, offset_b } => {
                if offset_a + 32 <= mutated.len() && offset_b + 32 <= mutated.len() {
                    let (a, b) = if offset_a < offset_b {
                        let (left, right) = mutated.split_at_mut(*offset_b);
                        (&mut left[*offset_a..*offset_a + 32], &mut right[..32])
                    } else {
                        let (left, right) = mutated.split_at_mut(*offset_a);
                        (&mut right[..32], &mut left[*offset_b..*offset_b + 32])
                    };
                    a.swap_with_slice(b);
                }
            }
            ProofMutation::ZeroChunk { offset } => {
                if offset + 32 <= mutated.len() {
                    mutated[*offset..*offset + 32].fill(0);
                }
            }
            ProofMutation::ScalarIncrement { offset } => {
                if offset + 32 <= mutated.len() {
                    for i in (0..32).rev() {
                        let (val, overflow) = mutated[*offset + i].overflowing_add(1);
                        mutated[*offset + i] = val;
                        if !overflow {
                            break;
                        }
                    }
                }
            }
            ProofMutation::Truncate { keep_bytes } => {
                mutated.truncate(*keep_bytes);
            }
            ProofMutation::DuplicateElement {
                src_offset,
                dst_offset,
            } => {
                if src_offset + 32 <= mutated.len() && dst_offset + 32 <= mutated.len() {
                    let src: Vec<u8> = mutated[*src_offset..*src_offset + 32].to_vec();
                    mutated[*dst_offset..*dst_offset + 32].copy_from_slice(&src);
                }
            }
        }

        mutated
    }
}
