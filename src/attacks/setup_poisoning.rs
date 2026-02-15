//! Trusted Setup Poisoning Detector (P2)
//!
//! Tests if proofs from one setup verify under a different verification key.

use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

pub struct SetupPoisoningDetector {
    /// Number of cross-verification attempts
    attempts: usize,
}

impl Default for SetupPoisoningDetector {
    fn default() -> Self {
        Self { attempts: 10 }
    }
}

impl SetupPoisoningDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_attempts(mut self, attempts: usize) -> Self {
        self.attempts = attempts;
        self
    }

    /// Run cross-verification between two executor instances with different setups
    pub fn run(
        &self,
        executor_a: &dyn CircuitExecutor,
        executor_b: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if self.attempts == 0 {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let info = executor_a.circuit_info();

        for (idx, witness) in witnesses.iter().take(self.attempts).enumerate() {
            let proof_a = match executor_a.prove(witness) {
                Ok(p) => p,
                Err(err) => {
                    tracing::debug!(
                        "Skipping witness {} due to setup-A proof generation error: {}",
                        idx,
                        err
                    );
                    continue;
                }
            };

            if witness.len() < info.num_public_inputs {
                continue;
            }

            let public_inputs: Vec<FieldElement> = witness[..info.num_public_inputs].to_vec();

            if let Ok(true) = executor_b.verify(&proof_a, &public_inputs) {
                findings.push(Finding {
                    attack_type: AttackType::Soundness,
                    severity: Severity::Critical,
                    description: format!(
                        "Cross-setup verification succeeded: proof from setup A verified under setup B's key (witness {}). Trusted setup may be compromised or verification key is not binding",
                        idx
                    ),
                    poc: ProofOfConcept {
                        witness_a: witness.clone(),
                        witness_b: None,
                        public_inputs,
                        proof: Some(proof_a),
                    },
                    location: None,
                });
            }
        }

        findings
    }
}
