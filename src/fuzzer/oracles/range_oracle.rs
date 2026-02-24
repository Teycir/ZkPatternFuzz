//! Range Proof Oracle
//!
//! Detects vulnerabilities in range proof circuits:
//! - **Range Bypass**: Values outside claimed range accepted
//! - **Boundary Issues**: Off-by-one at range boundaries
//! - **Negative Value Acceptance**: Underflow causing large values
//! - **Overflow Issues**: Values wrapping around field modulus
//!
//! Used in: Confidential transactions, age verification, balance checks

use super::{OracleConfig, OracleStats, SemanticOracle};
use num_bigint::BigUint;
use zk_core::constants::bn254_modulus_biguint;
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity, TestCase};

/// Oracle for detecting range proof vulnerabilities
pub struct RangeProofOracle {
    /// Expected range bounds (if known)
    expected_min: Option<BigUint>,
    expected_max: Option<BigUint>,
    /// Field modulus
    field_modulus: BigUint,
    /// Track values that passed verification
    accepted_values: Vec<(BigUint, Vec<FieldElement>)>,
    /// Statistics
    stats: OracleStats,
}

impl RangeProofOracle {
    pub fn new(config: OracleConfig) -> Self {
        Self::new_with_biguint(config, bn254_modulus_biguint().clone())
    }

    pub fn new_with_modulus(config: OracleConfig, field_modulus: [u8; 32]) -> Self {
        let modulus = BigUint::from_bytes_be(&field_modulus);
        let modulus = if modulus == BigUint::from(0u8) {
            bn254_modulus_biguint().clone()
        } else {
            modulus
        };
        Self::new_with_biguint(config, modulus)
    }

    fn new_with_biguint(_config: OracleConfig, field_modulus: BigUint) -> Self {
        Self {
            expected_min: None,
            expected_max: None,
            field_modulus,
            accepted_values: Vec::new(),
            stats: OracleStats::default(),
        }
    }

    /// Set expected range [min, max)
    pub fn with_range(mut self, min: u64, max: u64) -> Self {
        self.expected_min = Some(BigUint::from(min));
        self.expected_max = Some(BigUint::from(max));
        self
    }

    /// Set expected bit width (range [0, 2^bits))
    pub fn with_bits(mut self, bits: u32) -> Self {
        self.expected_min = Some(BigUint::from(0u64));
        self.expected_max = Some(BigUint::from(1u64) << bits);
        self
    }

    /// Extract value being range-checked from inputs
    fn extract_value(&self, inputs: &[FieldElement]) -> Option<BigUint> {
        inputs.first().map(|fe| fe.to_biguint())
    }

    fn has_expected_range(&self) -> bool {
        matches!((&self.expected_min, &self.expected_max), (Some(_), Some(_)))
    }

    /// Check if value is outside expected range
    fn check_range_bypass(&self, value: &BigUint, inputs: &[FieldElement]) -> Option<Finding> {
        let (min, max) = match (&self.expected_min, &self.expected_max) {
            (Some(min), Some(max)) => (min, max),
            _ => return None,
        };

        if value < min {
            return Some(Finding {
                attack_type: AttackType::ArithmeticOverflow,
                severity: Severity::Critical,
                description: format!(
                    "RANGE PROOF BYPASS: VALUE BELOW MINIMUM!\n\
                     Value: {}\n\
                     Expected minimum: {}\n\
                     Expected maximum: {}\n\n\
                     IMPACT: Values outside the expected range are accepted.\n\
                     This could allow negative balances, underflow attacks, etc.",
                    value, min, max
                ),
                poc: ProofOfConcept {
                    witness_a: inputs.to_vec(),
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                },
                location: Some("range_lower_bound".to_string()),
                class: None,
            });
        }

        if value >= max {
            return Some(Finding {
                attack_type: AttackType::ArithmeticOverflow,
                severity: Severity::Critical,
                description: format!(
                    "RANGE PROOF BYPASS: VALUE ABOVE MAXIMUM!\n\
                     Value: {}\n\
                     Expected minimum: {}\n\
                     Expected maximum: {}\n\n\
                     IMPACT: Values outside the expected range are accepted.\n\
                     This could allow overflow attacks, excessive transfers, etc.",
                    value, min, max
                ),
                poc: ProofOfConcept {
                    witness_a: inputs.to_vec(),
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                },
                location: Some("range_upper_bound".to_string()),
                class: None,
            });
        }

        None
    }

    /// Check for boundary issues (off-by-one)
    fn check_boundary_issues(&self, value: &BigUint, inputs: &[FieldElement]) -> Option<Finding> {
        // Check if value is exactly at field modulus boundary
        let half_modulus = &self.field_modulus / 2u32;

        // Values near p/2 might wrap to negative in signed interpretation
        let distance_from_half = if value > &half_modulus {
            value - &half_modulus
        } else {
            &half_modulus - value
        };

        if distance_from_half < BigUint::from(1000u64) && value > &half_modulus {
            return Some(Finding {
                attack_type: AttackType::ArithmeticOverflow,
                severity: Severity::High,
                description: format!(
                    "POTENTIAL SIGNED INTERPRETATION ISSUE!\n\
                     Value {} is near the field midpoint.\n\
                     In signed arithmetic, this could be interpreted as negative.\n\n\
                     IMPACT: If the value is used in signed comparisons,\n\
                     it may be treated as a large negative number.",
                    value
                ),
                poc: ProofOfConcept {
                    witness_a: inputs.to_vec(),
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                },
                location: Some("signed_boundary".to_string()),
                class: None,
            });
        }

        // Check for values very close to field modulus (potential wrap)
        // Only check if value is within valid field range
        if value <= &self.field_modulus {
            let distance_from_modulus = &self.field_modulus - value;
            if distance_from_modulus < BigUint::from(1000u64) {
                return Some(Finding {
                    attack_type: AttackType::ArithmeticOverflow,
                    severity: Severity::High,
                    description: format!(
                        "VALUE NEAR FIELD MODULUS BOUNDARY!\n\
                     Value is only {} away from the field modulus.\n\
                     Adding small values may cause wrap-around to near zero.\n\n\
                     IMPACT: Arithmetic operations may produce unexpected results\n\
                     due to modular arithmetic wrapping.",
                        distance_from_modulus
                    ),
                    poc: ProofOfConcept {
                        witness_a: inputs.to_vec(),
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: Some("modulus_boundary".to_string()),
                    class: None,
                });
            }
        }

        None
    }

    /// Detect inconsistent range acceptance
    fn check_range_consistency(
        &mut self,
        value: &BigUint,
        inputs: &[FieldElement],
    ) -> Option<Finding> {
        // If we have accepted values, check for gaps that shouldn't exist
        if self.accepted_values.len() < 10 {
            self.accepted_values.push((value.clone(), inputs.to_vec()));
            return None;
        }

        // Find min and max accepted values
        let min_accepted = self.accepted_values.iter().map(|(v, _)| v).min()?;
        let max_accepted = self.accepted_values.iter().map(|(v, _)| v).max()?;

        // If current value is way outside the "normal" range, flag it
        let range = max_accepted - min_accepted;
        if range > BigUint::from(0u64) {
            let ratio = if value > max_accepted {
                (value - min_accepted) * 100u32 / &range
            } else if value < min_accepted {
                (max_accepted - value) * 100u32 / &range
            } else {
                BigUint::from(100u64)
            };

            if ratio > BigUint::from(1000u64) {
                return Some(Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Medium,
                    description: format!(
                        "RANGE INCONSISTENCY DETECTED!\n\
                         Accepted value {} is significantly outside\n\
                         the previously observed range [{}, {}].\n\n\
                         This may indicate missing range constraints.",
                        value, min_accepted, max_accepted
                    ),
                    poc: ProofOfConcept {
                        witness_a: inputs.to_vec(),
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: Some("range_consistency".to_string()),
                    class: None,
                });
            }
        }

        // Keep only recent values
        if self.accepted_values.len() > 100 {
            self.accepted_values.drain(0..1);
        }
        self.accepted_values.push((value.clone(), inputs.to_vec()));

        None
    }
}

impl SemanticOracle for RangeProofOracle {
    fn check(&mut self, test_case: &TestCase, _output: &[FieldElement]) -> Option<Finding> {
        self.stats.checks += 1;

        let value = self.extract_value(&test_case.inputs)?;

        // Range semantics are target-specific. If no explicit range is configured,
        // this oracle stays silent to avoid generic field-element false positives.
        if !self.has_expected_range() {
            self.stats.observations += 1;
            return None;
        }

        // Check 1: Explicit range bypass (if range is known)
        if let Some(finding) = self.check_range_bypass(&value, &test_case.inputs) {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Check 2: Boundary issues
        if let Some(finding) = self.check_boundary_issues(&value, &test_case.inputs) {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Check 3: Range consistency
        if let Some(finding) = self.check_range_consistency(&value, &test_case.inputs) {
            self.stats.findings += 1;
            return Some(finding);
        }

        self.stats.observations += 1;
        None
    }

    fn name(&self) -> &str {
        "range_proof_oracle"
    }

    fn attack_type(&self) -> AttackType {
        AttackType::ArithmeticOverflow
    }

    fn reset(&mut self) {
        self.accepted_values.clear();
        self.stats = OracleStats::default();
    }

    fn stats(&self) -> OracleStats {
        let mut stats = self.stats.clone();
        stats.memory_bytes = self.accepted_values.len() * 64;
        stats
    }
}
