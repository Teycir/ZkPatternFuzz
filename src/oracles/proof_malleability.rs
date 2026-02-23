//! Proof Malleability Scanner (P0)
//!
//! Detects whether mutated proofs still verify. This targets verifier
//! malleability rather than prover soundness.

use num_bigint::BigUint;
use rand::Rng;
use serde_json::Value;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Types of proof mutations to attempt
#[derive(Debug, Clone, Copy)]
pub enum ProofMutation {
    /// Flip random bits in the proof (negative-control lane).
    BitFlip { byte_index: usize, bit_mask: u8 },
    /// Groth16-specific malleability transform: negate both A and B.
    /// For pairing equations this preserves e(A, B) on the left-hand side.
    Groth16NegateAAndB,
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
            // Keep byte-noise as a small negative-control lane by default.
            random_mutations: 8,
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

    pub fn with_negative_control_random_mutations(mut self, n: usize) -> Self {
        self.random_mutations = n;
        self
    }

    pub fn with_structured_mutations(mut self, enabled: bool) -> Self {
        self.structured_mutations = enabled;
        self
    }

    pub fn with_algebraic_mutations(mut self, enabled: bool) -> Self {
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
                Err(err) => {
                    tracing::debug!("Skipping witness due to proof generation error: {}", err);
                    continue;
                }
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

                if let Ok(true) = executor.verify(&mutated, &public_inputs) {
                    let (severity, lane) = if matches!(mutation, ProofMutation::BitFlip { .. }) {
                        (Severity::High, "negative-control")
                    } else {
                        (Severity::Critical, "algebraic")
                    };
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity,
                        description: format!(
                            "Proof malleability ({lane}): {:?} on {}-byte proof still verifies",
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
                        class: None,
                    });
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
            if is_groth16_snarkjs_proof(proof) {
                mutations.push(ProofMutation::Groth16NegateAAndB);
            } else {
                tracing::debug!(
                    "Skipping algebraic proof mutation: unsupported proof encoding ({} bytes)",
                    proof.len()
                );
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
            ProofMutation::Groth16NegateAAndB => {
                if let Some(transformed) = mutate_groth16_negate_a_and_b(proof, modulus) {
                    mutated = transformed;
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

fn is_groth16_snarkjs_proof(proof: &[u8]) -> bool {
    let Ok(parsed) = serde_json::from_slice::<Value>(proof) else {
        return false;
    };
    parsed.pointer("/pi_a/1").is_some()
        && parsed.pointer("/pi_b/1/0").is_some()
        && parsed.pointer("/pi_b/1/1").is_some()
}

fn mutate_groth16_negate_a_and_b(proof: &[u8], modulus: &[u8; 32]) -> Option<Vec<u8>> {
    let mut parsed = serde_json::from_slice::<Value>(proof).ok()?;
    let p = BigUint::from_bytes_be(modulus);
    if p == BigUint::from(0u32) {
        return None;
    }

    negate_json_scalar_at_pointer(&mut parsed, "/pi_a/1", &p)?;
    negate_json_scalar_at_pointer(&mut parsed, "/pi_b/1/0", &p)?;
    negate_json_scalar_at_pointer(&mut parsed, "/pi_b/1/1", &p)?;

    serde_json::to_vec(&parsed).ok()
}

fn negate_json_scalar_at_pointer(root: &mut Value, pointer: &str, modulus: &BigUint) -> Option<()> {
    let target = root.pointer_mut(pointer)?;
    let scalar = parse_json_biguint_scalar(target)?;
    let scalar_mod = scalar % modulus;
    let neg = if scalar_mod == BigUint::from(0u32) {
        BigUint::from(0u32)
    } else {
        modulus - scalar_mod
    };
    *target = Value::String(neg.to_str_radix(10));
    Some(())
}

fn parse_json_biguint_scalar(value: &Value) -> Option<BigUint> {
    match value {
        Value::String(s) => parse_biguint_scalar_string(s),
        Value::Number(n) => BigUint::parse_bytes(n.to_string().as_bytes(), 10),
        _ => None,
    }
}

fn parse_biguint_scalar_string(raw: &str) -> Option<BigUint> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return BigUint::parse_bytes(hex.as_bytes(), 16);
    }

    BigUint::parse_bytes(trimmed.as_bytes(), 10)
}
