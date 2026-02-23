//! Cross-Backend Differential Oracle (P1)
//!
//! Compares circuit execution across two different backends.

use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

pub struct CrossBackendDifferential {
    /// Number of witnesses to compare
    sample_count: usize,
    /// Tolerance for output comparison (0 = exact match required)
    tolerance_bits: usize,
}

impl Default for CrossBackendDifferential {
    fn default() -> Self {
        Self {
            sample_count: 100,
            tolerance_bits: 0,
        }
    }
}

impl CrossBackendDifferential {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sample_count(mut self, n: usize) -> Self {
        self.sample_count = n;
        self
    }

    pub fn with_tolerance_bits(mut self, bits: usize) -> Self {
        self.tolerance_bits = bits;
        self
    }

    pub fn run(
        &self,
        executor_a: &dyn CircuitExecutor,
        executor_b: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if self.sample_count == 0 {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let info_a = executor_a.circuit_info();
        let info_b = executor_b.circuit_info();

        if info_a.num_constraints != info_b.num_constraints {
            findings.push(Finding {
                attack_type: AttackType::Differential,
                severity: Severity::Medium,
                description: format!(
                    "Constraint count mismatch: {} ({}) vs {} ({})",
                    executor_a.name(),
                    info_a.num_constraints,
                    executor_b.name(),
                    info_b.num_constraints
                ),
                poc: Default::default(),
                location: None,
                class: None,
            });
        }

        for (idx, witness) in witnesses.iter().take(self.sample_count).enumerate() {
            let result_a = executor_a.execute_sync(witness);
            let result_b = executor_b.execute_sync(witness);

            if result_a.success != result_b.success {
                findings.push(Finding {
                    attack_type: AttackType::Differential,
                    severity: Severity::Critical,
                    description: format!(
                        "Acceptance divergence on witness {}: {} accepts={}, {} accepts={}",
                        idx,
                        executor_a.name(),
                        result_a.success,
                        executor_b.name(),
                        result_b.success
                    ),
                    poc: ProofOfConcept {
                        witness_a: witness.clone(),
                        witness_b: None,
                        public_inputs: Vec::new(),
                        proof: None,
                    },
                    location: None,
                    class: None,
                });
                continue;
            }

            if !result_a.success {
                continue;
            }

            if result_a.outputs.len() != result_b.outputs.len() {
                findings.push(Finding {
                    attack_type: AttackType::Differential,
                    severity: Severity::High,
                    description: format!(
                        "Output count mismatch on witness {}: {} has {} outputs, {} has {}",
                        idx,
                        executor_a.name(),
                        result_a.outputs.len(),
                        executor_b.name(),
                        result_b.outputs.len()
                    ),
                    poc: ProofOfConcept {
                        witness_a: witness.clone(),
                        witness_b: None,
                        public_inputs: Vec::new(),
                        proof: None,
                    },
                    location: None,
                    class: None,
                });
                continue;
            }

            for (out_idx, (a, b)) in result_a
                .outputs
                .iter()
                .zip(result_b.outputs.iter())
                .enumerate()
            {
                if a != b {
                    let hamming = hamming_distance_bits(&a.0, &b.0);
                    if self.tolerance_bits > 0 && hamming <= self.tolerance_bits {
                        continue;
                    }

                    findings.push(Finding {
                        attack_type: AttackType::Differential,
                        severity: Severity::Critical,
                        description: format!(
                            "Output divergence on witness {}, output {}: {} vs {} (Hamming distance: {} bits)",
                            idx,
                            out_idx,
                            executor_a.name(),
                            executor_b.name(),
                            hamming
                        ),
                        poc: ProofOfConcept {
                            witness_a: witness.clone(),
                            witness_b: None,
                            public_inputs: Vec::new(),
                            proof: None,
                        },
                        location: None,
                        class: None,
                    });
                }
            }
        }

        findings
    }
}

fn hamming_distance_bits(a: &[u8; 32], b: &[u8; 32]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}
