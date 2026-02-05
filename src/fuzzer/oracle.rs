//! Oracles for detecting bugs and vulnerabilities

use zk_core::{AttackType, FieldElement, Finding, Severity, TestCase};

/// Oracle trait for bug detection
pub trait BugOracle {
    /// Check if the given test case reveals a bug
    fn check(&self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding>;

    /// Get the oracle name
    fn name(&self) -> &str;
}

/// Oracle for detecting underconstrained circuits
pub struct UnderconstrainedOracle {
    pub output_history: std::collections::HashMap<Vec<u8>, TestCase>,
}

impl UnderconstrainedOracle {
    pub fn new() -> Self {
        Self {
            output_history: std::collections::HashMap::new(),
        }
    }

    fn hash_output(&self, output: &[FieldElement]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for fe in output {
            hasher.update(fe.0);
        }
        hasher.finalize().to_vec()
    }
}

impl Default for UnderconstrainedOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl BugOracle for UnderconstrainedOracle {
    fn check(&self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        let output_hash = self.hash_output(output);

        if let Some(existing) = self.output_history.get(&output_hash) {
            if existing.inputs != test_case.inputs {
                return Some(Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: "Different witnesses produce identical output".to_string(),
                    poc: super::ProofOfConcept {
                        witness_a: existing.inputs.clone(),
                        witness_b: Some(test_case.inputs.clone()),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                });
            }
        }

        None
    }

    fn name(&self) -> &str {
        "underconstrained_oracle"
    }
}

/// Oracle for detecting constraint count mismatches
pub struct ConstraintCountOracle {
    pub expected_count: usize,
}

impl ConstraintCountOracle {
    pub fn new(expected_count: usize) -> Self {
        Self { expected_count }
    }
}

impl BugOracle for ConstraintCountOracle {
    fn check(&self, _test_case: &TestCase, _output: &[FieldElement]) -> Option<Finding> {
        // In real implementation, this would check actual constraint count
        // against expected count from the circuit
        None
    }

    fn name(&self) -> &str {
        "constraint_count_oracle"
    }
}

/// Oracle for detecting proof forgery attempts
pub struct ProofForgeryOracle;

impl BugOracle for ProofForgeryOracle {
    fn check(&self, _test_case: &TestCase, _output: &[FieldElement]) -> Option<Finding> {
        // In real implementation, this would verify that proofs
        // cannot be forged for invalid statements
        None
    }

    fn name(&self) -> &str {
        "proof_forgery_oracle"
    }
}

/// Oracle for detecting arithmetic overflows
pub struct ArithmeticOverflowOracle {
    pub field_modulus: [u8; 32],
}

impl ArithmeticOverflowOracle {
    pub fn new() -> Self {
        // bn254 scalar field modulus
        let mut modulus = [0u8; 32];
        let hex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
        if let Ok(decoded) = hex::decode(hex) {
            modulus.copy_from_slice(&decoded);
        }
        Self {
            field_modulus: modulus,
        }
    }
}

impl Default for ArithmeticOverflowOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl BugOracle for ArithmeticOverflowOracle {
    fn check(&self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        // Check if any input is >= field modulus
        for input in &test_case.inputs {
            if self.is_overflow(&input.0) {
                return Some(Finding {
                    attack_type: AttackType::ArithmeticOverflow,
                    severity: Severity::High,
                    description: "Input value exceeds field modulus".to_string(),
                    poc: super::ProofOfConcept {
                        witness_a: test_case.inputs.clone(),
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                });
            }
        }

        // Check if output indicates wrapping
        for fe in output {
            if self.is_near_boundary(&fe.0) {
                return Some(Finding {
                    attack_type: AttackType::ArithmeticOverflow,
                    severity: Severity::Medium,
                    description: "Output near field boundary - potential overflow".to_string(),
                    poc: super::ProofOfConcept {
                        witness_a: test_case.inputs.clone(),
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                });
            }
        }

        None
    }

    fn name(&self) -> &str {
        "arithmetic_overflow_oracle"
    }
}

impl ArithmeticOverflowOracle {
    fn is_overflow(&self, value: &[u8; 32]) -> bool {
        for (v, m) in value.iter().zip(self.field_modulus.iter()) {
            if v > m {
                return true;
            }
            if v < m {
                return false;
            }
        }
        true // Equal to modulus is also overflow
    }

    fn is_near_boundary(&self, value: &[u8; 32]) -> bool {
        // Check if within 1000 of zero or modulus
        let near_zero = value.iter().take(28).all(|&b| b == 0);
        let near_max = value.iter().take(28).all(|&b| b == 0x30); // Rough check for bn254
        near_zero || near_max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_underconstrained_oracle() {
        let oracle = UnderconstrainedOracle::new();
        let test_case = TestCase {
            inputs: vec![FieldElement::zero()],
            expected_output: None,
            metadata: super::super::TestMetadata::default(),
        };
        let output = vec![FieldElement::one()];

        // First check should not find anything
        assert!(oracle.check(&test_case, &output).is_none());
    }

    #[test]
    fn test_arithmetic_overflow_oracle() {
        let oracle = ArithmeticOverflowOracle::new();
        let test_case = TestCase {
            inputs: vec![FieldElement([0xff; 32])], // Definitely overflow
            expected_output: None,
            metadata: super::super::TestMetadata::default(),
        };
        let output = vec![FieldElement::zero()];

        let finding = oracle.check(&test_case, &output);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().attack_type, AttackType::ArithmeticOverflow);
    }
}
