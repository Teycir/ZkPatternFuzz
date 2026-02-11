//! Nullifier Replay Scanner (P1)
//!
//! Tests if the same nullifier can be used with different private inputs to
//! produce valid proofs/outputs.

use num_bigint::BigUint;
use rand::RngCore;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Heuristic for identifying nullifier wire indices
pub struct NullifierHeuristic;

impl NullifierHeuristic {
    /// Detect probable nullifier wires from circuit metadata/labels
    pub fn detect(executor: &dyn CircuitExecutor) -> Vec<usize> {
        let info = executor.circuit_info();
        let mut candidates = Vec::new();

        if let Some(inspector) = executor.constraint_inspector() {
            let constraints = inspector.get_constraints();
            for c in &constraints {
                if let Some(desc) = &c.description {
                    let lower = desc.to_lowercase();
                    if lower.contains("nullifier") || lower.contains("serial") || lower.contains("nonce") {
                        for (wire, _) in &c.a_terms {
                            candidates.push(*wire);
                        }
                        for (wire, _) in &c.b_terms {
                            candidates.push(*wire);
                        }
                        for (wire, _) in &c.c_terms {
                            candidates.push(*wire);
                        }
                    }
                }
            }

            let labels = inspector.wire_labels();
            for (wire, label) in labels {
                let lower = label.to_lowercase();
                if lower.contains("nullifier") || lower.contains("serial") || lower.contains("nonce") {
                    candidates.push(wire);
                }
            }
        }

        if candidates.is_empty() && info.num_public_inputs > 0 {
            candidates.push(0);
        }

        candidates.sort_unstable();
        candidates.dedup();
        candidates
    }
}

pub struct NullifierReplayScanner {
    /// Number of different private input sets to try per nullifier
    replay_attempts: usize,
    /// Manually specified nullifier indices (overrides heuristic)
    nullifier_indices: Option<Vec<usize>>,
    /// Base witnesses to try
    base_samples: usize,
}

impl Default for NullifierReplayScanner {
    fn default() -> Self {
        Self {
            replay_attempts: 50,
            nullifier_indices: None,
            base_samples: 10,
        }
    }
}

impl NullifierReplayScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_replay_attempts(mut self, attempts: usize) -> Self {
        self.replay_attempts = attempts;
        self
    }

    pub fn with_nullifier_indices(mut self, indices: Vec<usize>) -> Self {
        self.nullifier_indices = Some(indices);
        self
    }

    pub fn with_base_samples(mut self, samples: usize) -> Self {
        self.base_samples = samples;
        self
    }

    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        base_witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if self.replay_attempts == 0 || self.base_samples == 0 {
            return Vec::new();
        }

        let info = executor.circuit_info();
        let nullifier_wires = self
            .nullifier_indices
            .clone()
            .unwrap_or_else(|| NullifierHeuristic::detect(executor));

        if nullifier_wires.is_empty() {
            return Vec::new();
        }

        let modulus = BigUint::from_bytes_be(&executor.field_modulus());
        let mut findings = Vec::new();
        let mut rng = rand::thread_rng();

        for base in base_witnesses.iter().take(self.base_samples) {
            let base_result = executor.execute_sync(base);
            if !base_result.success {
                continue;
            }

            let nullifier_values: Vec<(usize, FieldElement)> = nullifier_wires
                .iter()
                .filter(|&&idx| idx < base.len())
                .map(|&idx| (idx, base[idx].clone()))
                .collect();

            for _ in 0..self.replay_attempts {
                let mut modified = base.clone();

                for (i, elem) in modified.iter_mut().enumerate() {
                    let is_nullifier = nullifier_values.iter().any(|(idx, _)| *idx == i);
                    let is_public = i < info.num_public_inputs;
                    if !is_nullifier && !is_public {
                        *elem = random_field_element(&mut rng, &modulus);
                    }
                }

                let replay_result = executor.execute_sync(&modified);
                if replay_result.success
                    && replay_result.outputs == base_result.outputs
                    && modified != *base
                {
                    findings.push(Finding {
                        attack_type: AttackType::Collision,
                        severity: Severity::Critical,
                        description: format!(
                            "Nullifier replay: different private inputs produce identical outputs with same nullifier at wire(s) {:?}. Circuit may allow double-spending.",
                            nullifier_wires
                        ),
                        poc: ProofOfConcept {
                            witness_a: base.clone(),
                            witness_b: Some(modified),
                            public_inputs: Vec::new(),
                            proof: None,
                        },
                        location: None,
                    });
                    break;
                }
            }
        }

        findings
    }
}

fn random_field_element(rng: &mut impl RngCore, modulus: &BigUint) -> FieldElement {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);

    if modulus == &BigUint::from(0u32) {
        return FieldElement(bytes);
    }

    let value = BigUint::from_bytes_be(&bytes) % modulus;
    FieldElement::from_bytes(&value.to_bytes_be())
}
