//! Determinism Oracle (P0)
//!
//! Detects non-deterministic circuit execution by re-running the same witness
//! and comparing outputs and success flags.

use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

pub struct DeterminismOracle {
    /// Number of times to re-execute each witness
    repetitions: usize,
    /// Number of witnesses to test
    sample_count: usize,
}

impl Default for DeterminismOracle {
    fn default() -> Self {
        Self {
            repetitions: 5,
            sample_count: 50,
        }
    }
}

impl DeterminismOracle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_repetitions(mut self, n: usize) -> Self {
        self.repetitions = n;
        self
    }

    pub fn with_sample_count(mut self, n: usize) -> Self {
        self.sample_count = n;
        self
    }

    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if self.repetitions < 2 || self.sample_count == 0 {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (w_idx, witness) in witnesses.iter().take(self.sample_count).enumerate() {
            let baseline = executor.execute_sync(witness);
            if !baseline.success {
                continue;
            }
            let scoped_public_inputs: Vec<FieldElement> = witness
                .iter()
                .take(executor.circuit_info().num_public_inputs)
                .cloned()
                .collect();

            for rep in 1..self.repetitions {
                let result = executor.execute_sync(witness);
                if result.outputs != baseline.outputs {
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::Critical,
                        description: format!(
                            "Non-deterministic execution: witness {} produced different outputs on repetition {} vs baseline",
                            w_idx, rep
                        ),
                        poc: ProofOfConcept {
                            witness_a: witness.clone(),
                            witness_b: None,
                            public_inputs: scoped_public_inputs.clone(),
                            proof: None,
                        },
                        location: None,
                        class: None,
                    });
                    break;
                }

                if result.success != baseline.success {
                    findings.push(Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::Critical,
                        description: format!(
                            "Non-deterministic constraint satisfaction: witness {} succeeded={} on baseline but succeeded={} on rep {}",
                            w_idx, baseline.success, result.success, rep
                        ),
                        poc: ProofOfConcept {
                            witness_a: witness.clone(),
                            witness_b: None,
                            public_inputs: scoped_public_inputs.clone(),
                            proof: None,
                        },
                        location: None,
                        class: None,
                    });
                    break;
                }
            }
        }

        findings
    }
}
