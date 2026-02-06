//! Oracles for detecting bugs and vulnerabilities

use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity, TestCase};

/// Oracle trait for bug detection
pub trait BugOracle: Send + Sync {
    /// Check if the given test case reveals a bug
    /// Uses &mut self to allow stateful oracles that track execution history
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding>;

    /// Get the oracle name
    fn name(&self) -> &str;
    
    /// Reset the oracle state (optional, for stateful oracles)
    fn reset(&mut self) {}
    
    /// Get statistics about this oracle (optional)
    fn stats(&self) -> Option<OracleStatistics> {
        None
    }
}

/// Statistics from oracle execution
#[derive(Debug, Clone, Default)]
pub struct OracleStatistics {
    pub executions: u64,
    pub findings: u64,
    pub unique_outputs_seen: u64,
}

/// Oracle for detecting underconstrained circuits
/// 
/// This oracle tracks execution history to detect when different witnesses
/// produce identical outputs - a strong indicator of missing constraints.
/// 
/// # Critical Fix (Phase 0)
/// 
/// The oracle is now stateful and records each execution's output hash.
/// The `check()` method uses `&mut self` to allow recording, which is
/// essential for detecting collisions across multiple executions.
pub struct UnderconstrainedOracle {
    /// Maps output hash -> first test case that produced it
    pub output_history: std::collections::HashMap<Vec<u8>, TestCase>,
    /// Number of collisions detected
    pub collision_count: u64,
    /// Optional: fixed public inputs for proper underconstrained testing
    pub fixed_public_inputs: Option<Vec<FieldElement>>,
    /// Number of public inputs (used to scope collisions to identical public inputs)
    pub num_public_inputs: Option<usize>,
}

impl UnderconstrainedOracle {
    pub fn new() -> Self {
        Self {
            output_history: std::collections::HashMap::new(),
            collision_count: 0,
            fixed_public_inputs: None,
            num_public_inputs: None,
        }
    }
    
    /// Create oracle with fixed public inputs for proper underconstrained testing
    /// 
    /// When testing for underconstrained circuits, public inputs should be held
    /// constant while varying private inputs. This ensures we're testing the
    /// correct hypothesis: "multiple private witnesses for same public inputs".
    pub fn with_fixed_public_inputs(mut self, public_inputs: Vec<FieldElement>) -> Self {
        self.fixed_public_inputs = Some(public_inputs);
        self.num_public_inputs = Some(self.fixed_public_inputs.as_ref().map(|v| v.len()).unwrap_or(0));
        self
    }
    
    /// Configure how many inputs are public (to scope collisions correctly)
    pub fn with_public_input_count(mut self, num_public: usize) -> Self {
        self.num_public_inputs = Some(num_public);
        self
    }

    fn hash_output(&self, output: &[FieldElement]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for fe in output {
            hasher.update(fe.0);
        }
        hasher.finalize().to_vec()
    }
    
    fn hash_inputs(&self, inputs: &[FieldElement]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for fe in inputs {
            hasher.update(fe.0);
        }
        hasher.finalize().to_vec()
    }
    
    fn public_inputs<'a>(&self, test_case: &'a TestCase) -> &'a [FieldElement] {
        let num_public = self.num_public_inputs.unwrap_or(0);
        if num_public == 0 || test_case.inputs.is_empty() {
            &test_case.inputs[..0]
        } else {
            let end = num_public.min(test_case.inputs.len());
            &test_case.inputs[..end]
        }
    }
    
    fn combined_key(&self, output: &[FieldElement], public_inputs: &[FieldElement]) -> Vec<u8> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(&self.hash_output(output));
        key.extend_from_slice(&self.hash_inputs(public_inputs));
        key
    }
    
    /// Record an output for future collision detection
    /// This is the key method that was missing - stateful recording
    pub fn record_output(&mut self, test_case: TestCase, output: &[FieldElement]) {
        let public_inputs = self.public_inputs(&test_case);
        let key = self.combined_key(output, public_inputs);
        // Only record if we haven't seen this output for these public inputs before
        self.output_history.entry(key).or_insert(test_case);
    }
    
    /// Check if a test case matches the fixed public inputs (if set)
    pub fn matches_fixed_public_inputs(&self, test_case: &TestCase, num_public: usize) -> bool {
        match &self.fixed_public_inputs {
            Some(fixed) => {
                if test_case.inputs.len() < num_public || fixed.len() != num_public {
                    return false;
                }
                test_case.inputs[..num_public] == fixed[..]
            }
            None => true, // No fixed inputs, all pass
        }
    }
    
    /// Get the number of unique outputs seen
    pub fn unique_outputs(&self) -> usize {
        self.output_history.len()
    }
}

impl Default for UnderconstrainedOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl BugOracle for UnderconstrainedOracle {
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        let num_public = self.num_public_inputs.unwrap_or(0);
        if !self.matches_fixed_public_inputs(test_case, num_public) {
            return None;
        }

        let public_inputs = self.public_inputs(test_case);
        let key = self.combined_key(output, public_inputs);

        // Check for collision within same public inputs
        if let Some(existing) = self.output_history.get(&key) {
            if existing.inputs != test_case.inputs {
                self.collision_count += 1;
                return Some(Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: format!(
                        "Different witnesses produce identical output (collision #{}, {} unique outputs seen)",
                        self.collision_count,
                        self.output_history.len()
                    ),
                    poc: ProofOfConcept {
                        witness_a: existing.inputs.clone(),
                        witness_b: Some(test_case.inputs.clone()),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                });
            }
        } else {
            // Record this new output - THIS IS THE CRITICAL FIX
            self.record_output(test_case.clone(), output);
        }

        None
    }

    fn name(&self) -> &str {
        "underconstrained_oracle"
    }
    
    fn reset(&mut self) {
        self.output_history.clear();
        self.collision_count = 0;
    }
    
    fn stats(&self) -> Option<OracleStatistics> {
        Some(OracleStatistics {
            executions: self.output_history.len() as u64,
            findings: self.collision_count,
            unique_outputs_seen: self.output_history.len() as u64,
        })
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
    fn check(&mut self, _test_case: &TestCase, _output: &[FieldElement]) -> Option<Finding> {
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
    fn check(&mut self, _test_case: &TestCase, _output: &[FieldElement]) -> Option<Finding> {
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
        Self::new_with_modulus(default_bn254_modulus())
    }
    
    /// Create oracle with an explicit field modulus
    pub fn new_with_modulus(field_modulus: [u8; 32]) -> Self {
        Self { field_modulus }
    }
}

fn default_bn254_modulus() -> [u8; 32] {
    let mut modulus = [0u8; 32];
    let hex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    if let Ok(decoded) = hex::decode(hex) {
        modulus.copy_from_slice(&decoded);
    }
    modulus
}

impl Default for ArithmeticOverflowOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl BugOracle for ArithmeticOverflowOracle {
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        // Check if any input is >= field modulus
        for input in &test_case.inputs {
            if self.is_overflow(&input.0) {
                return Some(Finding {
                    attack_type: AttackType::ArithmeticOverflow,
                    severity: Severity::High,
                    description: "Input value exceeds field modulus".to_string(),
                    poc: ProofOfConcept {
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
                    poc: ProofOfConcept {
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

/// Adapter to wrap SemanticOracle as BugOracle
/// 
/// This allows semantic oracles to be used with the core engine's oracle system.
pub struct SemanticOracleAdapter {
    inner: Box<dyn zk_core::SemanticOracle>,
}

impl SemanticOracleAdapter {
    pub fn new(oracle: Box<dyn zk_core::SemanticOracle>) -> Self {
        Self { inner: oracle }
    }
}

impl BugOracle for SemanticOracleAdapter {
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        self.inner.check(test_case, output)
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
    
    fn reset(&mut self) {
        self.inner.reset();
    }
    
    fn stats(&self) -> Option<OracleStatistics> {
        let inner_stats = self.inner.stats();
        Some(OracleStatistics {
            executions: inner_stats.checks,
            findings: inner_stats.findings,
            unique_outputs_seen: inner_stats.observations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_underconstrained_oracle() {
        let mut oracle = UnderconstrainedOracle::new();
        let test_case = TestCase {
            inputs: vec![FieldElement::zero()],
            expected_output: None,
            metadata: zk_core::TestMetadata::default(),
        };
        let output = vec![FieldElement::one()];

        // First check should not find anything
        assert!(oracle.check(&test_case, &output).is_none());
    }

    #[test]
    fn test_underconstrained_oracle_scopes_public_inputs() {
        let mut oracle = UnderconstrainedOracle::new().with_public_input_count(1);
        let output = vec![FieldElement::one()];

        let tc_a = TestCase {
            inputs: vec![FieldElement::from_u64(1), FieldElement::from_u64(10)],
            expected_output: None,
            metadata: zk_core::TestMetadata::default(),
        };

        let tc_b = TestCase {
            inputs: vec![FieldElement::from_u64(2), FieldElement::from_u64(20)],
            expected_output: None,
            metadata: zk_core::TestMetadata::default(),
        };

        let tc_c = TestCase {
            inputs: vec![FieldElement::from_u64(1), FieldElement::from_u64(99)],
            expected_output: None,
            metadata: zk_core::TestMetadata::default(),
        };

        // Different public inputs: should not collide
        assert!(oracle.check(&tc_a, &output).is_none());
        assert!(oracle.check(&tc_b, &output).is_none());

        // Same public input, different private input: should collide
        let finding = oracle.check(&tc_c, &output);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().attack_type, AttackType::Underconstrained);
    }

    #[test]
    fn test_arithmetic_overflow_oracle() {
        let mut oracle = ArithmeticOverflowOracle::new();
        let test_case = TestCase {
            inputs: vec![FieldElement([0xff; 32])], // Definitely overflow
            expected_output: None,
            metadata: zk_core::TestMetadata::default(),
        };
        let output = vec![FieldElement::zero()];

        let finding = oracle.check(&test_case, &output);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().attack_type, AttackType::ArithmeticOverflow);
    }
}
