//! Input Canonicalization Checker (P2)
//!
//! Tests if non-canonical input representations are handled correctly.

use num_bigint::BigUint;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

pub struct CanonicalizationChecker {
    /// Test x vs x+p (field wrap)
    test_field_wrap: bool,
    /// Test x vs p-x (additive inverse)
    test_additive_inverse: bool,
    /// Test negative zero (p itself)
    test_negative_zero: bool,
    /// Number of witnesses to test
    sample_count: usize,
}

impl Default for CanonicalizationChecker {
    fn default() -> Self {
        Self {
            test_field_wrap: true,
            test_additive_inverse: false,
            test_negative_zero: true,
            sample_count: 20,
        }
    }
}

impl CanonicalizationChecker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_field_wrap(mut self, enabled: bool) -> Self {
        self.test_field_wrap = enabled;
        self
    }

    pub fn with_additive_inverse(mut self, enabled: bool) -> Self {
        self.test_additive_inverse = enabled;
        self
    }

    pub fn with_negative_zero(mut self, enabled: bool) -> Self {
        self.test_negative_zero = enabled;
        self
    }

    pub fn with_sample_count(mut self, count: usize) -> Self {
        self.sample_count = count;
        self
    }

    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if self.sample_count == 0 {
            return Vec::new();
        }

        let modulus = executor.field_modulus();
        let p = BigUint::from_bytes_be(&modulus);
        if p == BigUint::from(0u32) {
            return Vec::new();
        }

        let mut findings = Vec::new();

        let num_public_inputs = executor.circuit_info().num_public_inputs;
        for (w_idx, witness) in witnesses.iter().take(self.sample_count).enumerate() {
            let baseline = executor.execute_sync(witness);
            if !baseline.success {
                continue;
            }

            let scoped_public_inputs: Vec<FieldElement> =
                witness.iter().take(num_public_inputs).cloned().collect();
            let testable_inputs = num_public_inputs.min(witness.len());
            for input_idx in 0..testable_inputs {
                let x = BigUint::from_bytes_be(&witness[input_idx].0);

                if self.test_field_wrap {
                    let x_plus_p = &x + &p;
                    if let Some(fe) = to_field_element(&x_plus_p) {
                        let mut modified = witness.clone();
                        modified[input_idx] = fe;
                        let result = executor.execute_sync(&modified);
                        if result.success && result.outputs != baseline.outputs {
                            findings.push(Finding {
                                attack_type: AttackType::Boundary,
                                severity: Severity::High,
                                description: format!(
                                    "Non-canonical input accepted with different output: witness {} input[{}] = x+p produces different result than x",
                                    w_idx, input_idx
                                ),
                                poc: ProofOfConcept {
                                    witness_a: witness.clone(),
                                    witness_b: Some(modified),
                                    public_inputs: scoped_public_inputs.clone(),
                                    proof: None,
                                },
                                location: None,
                                class: None,
                            });
                        }
                    }
                }

                if self.test_negative_zero && x == BigUint::from(0u32) {
                    if let Some(fe) = to_field_element(&p) {
                        let mut modified = witness.clone();
                        modified[input_idx] = fe;
                        let result = executor.execute_sync(&modified);
                        if result.success && result.outputs != baseline.outputs {
                            findings.push(Finding {
                                attack_type: AttackType::Boundary,
                                severity: Severity::High,
                                description: format!(
                                    "Negative zero (p) treated differently from 0 at input[{}] (witness {})",
                                    input_idx, w_idx
                                ),
                                poc: ProofOfConcept {
                                    witness_a: witness.clone(),
                                    witness_b: Some(modified),
                                    public_inputs: scoped_public_inputs.clone(),
                                    proof: None,
                                },
                                location: None,
                                class: None,
                            });
                        }
                    }
                }

                if self.test_additive_inverse && x != BigUint::from(0u32) {
                    let inv = &p - (&x % &p);
                    if let Some(fe) = to_field_element(&inv) {
                        let mut modified = witness.clone();
                        modified[input_idx] = fe;
                        let result = executor.execute_sync(&modified);
                        if result.success && result.outputs == baseline.outputs {
                            findings.push(Finding {
                                attack_type: AttackType::Boundary,
                                severity: Severity::Low,
                                description: format!(
                                    "Additive inverse treated identically at input[{}] (witness {}). Input may be ignored or sign handling is missing",
                                    input_idx, w_idx
                                ),
                                poc: ProofOfConcept {
                                    witness_a: witness.clone(),
                                    witness_b: Some(modified),
                                    public_inputs: scoped_public_inputs.clone(),
                                    proof: None,
                                },
                                location: None,
                                class: None,
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

fn to_field_element(value: &BigUint) -> Option<FieldElement> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    Some(FieldElement::from_bytes(&bytes))
}
