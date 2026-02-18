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

    /// Whether this oracle maintains state across executions
    ///
    /// Stateful oracles may not be suitable for single-case validation.
    fn is_stateful(&self) -> bool {
        false
    }

    /// The primary attack type this oracle detects (if known)
    ///
    /// Used to select applicable oracles during validation.
    fn attack_type(&self) -> Option<AttackType> {
        None
    }

    /// Check using a known constraint count when available.
    fn check_with_count(&mut self, _test_case: &TestCase, _count: usize) -> Option<Finding> {
        None
    }

    /// Whether this oracle requires a constraint count to operate.
    fn requires_constraint_count(&self) -> bool {
        false
    }

    /// Check proof verification outcomes (soundness-focused oracles).
    fn check_with_verification(
        &mut self,
        _original_inputs: &[FieldElement],
        _mutated_inputs: &[FieldElement],
        _proof: &[u8],
        _verified: bool,
    ) -> Option<Finding> {
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
        let public_len = match self.fixed_public_inputs.as_ref() {
            Some(values) => values.len(),
            None => 0,
        };
        self.num_public_inputs = Some(public_len);
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
        let num_public = self.num_public_inputs.unwrap_or_default();
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
        let num_public = self.num_public_inputs.unwrap_or_default();
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

    fn is_stateful(&self) -> bool {
        true
    }

    fn attack_type(&self) -> Option<AttackType> {
        Some(AttackType::Underconstrained)
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
///
/// # Phase 0 Fix: Make Oracle Evidence-Producing
///
/// This oracle is now stateful and tracks the actual constraint count from
/// executions. It produces findings when:
/// 1. The actual constraint count differs from expected
/// 2. The constraint count varies between executions (dynamic constraints)
///
/// **IMPORTANT**: This oracle requires integration with the executor's
/// constraint inspector to get actual constraint counts. Without this,
/// it cannot produce evidence and will log a warning.
pub struct ConstraintCountOracle {
    pub expected_count: usize,
    /// Minimum observed constraint count (incremental tracking)
    min_count: Option<usize>,
    /// Maximum observed constraint count (incremental tracking)
    max_count: Option<usize>,
    /// Last observed constraint count
    last_count: Option<usize>,
    /// Whether we've warned about missing constraint inspector
    warned_no_inspector: bool,
    /// Number of checks performed
    check_count: u64,
    /// Number of findings produced
    finding_count: u64,
}

impl ConstraintCountOracle {
    pub fn new(expected_count: usize) -> Self {
        Self {
            expected_count,
            min_count: None,
            max_count: None,
            last_count: None,
            warned_no_inspector: false,
            check_count: 0,
            finding_count: 0,
        }
    }

    /// Record an observed constraint count from execution
    ///
    /// This should be called by the engine with data from the executor's
    /// constraint inspector.
    pub fn record_constraint_count(&mut self, count: usize) {
        self.min_count = Some(match self.min_count {
            Some(minimum) => minimum.min(count),
            None => count,
        });
        self.max_count = Some(match self.max_count {
            Some(maximum) => maximum.max(count),
            None => count,
        });
        self.last_count = Some(count);
    }

    /// Check if constraint count is anomalous
    ///
    /// Returns Some(finding) if:
    /// - Count differs significantly from expected
    /// - Count varies between executions (shouldn't happen for static circuits)
    pub fn check_with_count(&mut self, test_case: &TestCase, count: usize) -> Option<Finding> {
        self.check_count += 1;

        // Update incremental min/max tracking
        self.min_count = Some(match self.min_count {
            Some(minimum) => minimum.min(count),
            None => count,
        });
        self.max_count = Some(match self.max_count {
            Some(maximum) => maximum.max(count),
            None => count,
        });
        self.last_count = Some(count);

        // Check if count differs from expected
        if count != self.expected_count {
            self.finding_count += 1;
            return Some(Finding {
                attack_type: AttackType::Underconstrained, // Constraint count mismatch often indicates underconstrained
                severity: Severity::High,
                description: format!(
                    "Constraint count mismatch: expected {}, observed {}. \
                     This may indicate missing constraints or dynamic constraint generation.",
                    self.expected_count, count
                ),
                poc: ProofOfConcept {
                    witness_a: test_case.inputs.clone(),
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                },
                location: None,
            });
        }

        // Check for variance in observed counts (shouldn't vary for static circuits)
        if let (Some(min), Some(max)) = (self.min_count, self.max_count) {
            if min != max {
                self.finding_count += 1;
                return Some(Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: format!(
                        "Constraint count varies between executions ({} to {}). \
                         This indicates dynamic constraints which may be exploitable.",
                        min, max
                    ),
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

    /// Get statistics about this oracle
    pub fn statistics(&self) -> OracleStatistics {
        OracleStatistics {
            executions: self.check_count,
            findings: self.finding_count,
            unique_outputs_seen: if self.min_count.is_some() {
                let max_count = self.max_count.unwrap_or_default();
                let min_count = self.min_count.unwrap_or_default();
                (max_count - min_count + 1) as u64
            } else {
                0
            },
        }
    }
}

impl BugOracle for ConstraintCountOracle {
    fn check(&mut self, _test_case: &TestCase, _output: &[FieldElement]) -> Option<Finding> {
        // Phase 0 Fix: Log warning that this oracle needs integration
        //
        // The basic check() method cannot produce evidence without constraint
        // count data from the executor. The engine should call check_with_count()
        // instead after obtaining the count from the executor's constraint inspector.
        if !self.warned_no_inspector {
            tracing::warn!(
                "ConstraintCountOracle.check() called without constraint count. \
                 This oracle requires integration with the executor's constraint inspector. \
                 Use check_with_count() after obtaining constraint count from the executor."
            );
            self.warned_no_inspector = true;
        }
        self.check_count += 1;
        None
    }

    fn name(&self) -> &str {
        "constraint_count_oracle"
    }

    fn is_stateful(&self) -> bool {
        true
    }

    fn attack_type(&self) -> Option<AttackType> {
        Some(AttackType::Underconstrained)
    }

    fn check_with_count(&mut self, test_case: &TestCase, count: usize) -> Option<Finding> {
        ConstraintCountOracle::check_with_count(self, test_case, count)
    }

    fn requires_constraint_count(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        self.min_count = None;
        self.max_count = None;
        self.last_count = None;
        self.warned_no_inspector = false;
        self.check_count = 0;
        self.finding_count = 0;
    }

    fn stats(&self) -> Option<OracleStatistics> {
        Some(self.statistics())
    }
}

/// Oracle for detecting proof forgery attempts
///
/// # Phase 0 Fix: Make Oracle Evidence-Producing
///
/// This oracle is now stateful and tracks proof/verification attempts.
/// It produces findings when a proof generated for one set of inputs
/// verifies for a different set of public inputs (soundness violation).
///
/// **IMPORTANT**: This oracle requires integration with the executor's
/// prove() and verify() methods to produce evidence. The engine should:
/// 1. Generate a proof for valid inputs
/// 2. Attempt to verify with mutated public inputs
/// 3. Call check_with_verification() with the result
pub struct ProofForgeryOracle {
    /// Number of forgery attempts made
    attempts: u64,
    /// Number of successful forgeries detected
    successful_forgeries: u64,
    /// Whether we've warned about missing integration
    warned_no_integration: bool,
    /// Recent proof/input pairs for cross-verification testing
    proof_history: Vec<(Vec<u8>, Vec<FieldElement>)>,
    /// Maximum history size
    max_history: usize,
}

impl ProofForgeryOracle {
    pub fn new() -> Self {
        Self {
            attempts: 0,
            successful_forgeries: 0,
            warned_no_integration: false,
            proof_history: Vec::new(),
            max_history: 100,
        }
    }

    /// Configure maximum proof history size
    pub fn with_max_history(mut self, size: usize) -> Self {
        self.max_history = size;
        self
    }

    /// Record a proof for later cross-verification testing
    pub fn record_proof(&mut self, proof: Vec<u8>, public_inputs: Vec<FieldElement>) {
        if self.proof_history.len() >= self.max_history {
            self.proof_history.remove(0);
        }
        self.proof_history.push((proof, public_inputs));
    }

    /// Check if a proof verifies for different public inputs (soundness violation)
    ///
    /// # Arguments
    /// * `original_inputs` - The inputs the proof was generated for
    /// * `mutated_inputs` - Different public inputs to verify against
    /// * `proof` - The proof bytes
    /// * `verified` - Whether verification succeeded
    ///
    /// # Returns
    /// Finding if verification succeeded (soundness violation)
    pub fn check_with_verification(
        &mut self,
        original_inputs: &[FieldElement],
        mutated_inputs: &[FieldElement],
        proof: &[u8],
        verified: bool,
    ) -> Option<Finding> {
        self.attempts += 1;

        if verified && original_inputs != mutated_inputs {
            self.successful_forgeries += 1;
            return Some(Finding {
                attack_type: AttackType::Soundness,
                severity: Severity::Critical,
                description: format!(
                    "Proof forgery successful! Proof generated for one set of inputs \
                     verified for different public inputs. This is a critical soundness \
                     violation (forgery #{}).",
                    self.successful_forgeries
                ),
                poc: ProofOfConcept {
                    witness_a: original_inputs.to_vec(),
                    witness_b: Some(mutated_inputs.to_vec()),
                    public_inputs: mutated_inputs.to_vec(),
                    proof: Some(proof.to_vec()),
                },
                location: None,
            });
        }

        None
    }

    /// Get statistics about this oracle
    pub fn statistics(&self) -> OracleStatistics {
        OracleStatistics {
            executions: self.attempts,
            findings: self.successful_forgeries,
            unique_outputs_seen: self.proof_history.len() as u64,
        }
    }
}

impl Default for ProofForgeryOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl BugOracle for ProofForgeryOracle {
    fn check(&mut self, _test_case: &TestCase, _output: &[FieldElement]) -> Option<Finding> {
        // Phase 0 Fix: Log warning that this oracle needs integration
        //
        // The basic check() method cannot produce evidence without proof/verification
        // data from the executor. The engine should:
        // 1. Call executor.prove() to generate a proof
        // 2. Call executor.verify() with mutated inputs
        // 3. Call check_with_verification() with the results
        if !self.warned_no_integration {
            tracing::warn!(
                "ProofForgeryOracle.check() called without proof verification data. \
                 This oracle requires integration with the executor's prove/verify methods. \
                 Use check_with_verification() after attempting proof forgery."
            );
            self.warned_no_integration = true;
        }
        self.attempts += 1;
        None
    }

    fn name(&self) -> &str {
        "proof_forgery_oracle"
    }

    fn is_stateful(&self) -> bool {
        true
    }

    fn attack_type(&self) -> Option<AttackType> {
        Some(AttackType::Soundness)
    }

    fn check_with_verification(
        &mut self,
        original_inputs: &[FieldElement],
        mutated_inputs: &[FieldElement],
        proof: &[u8],
        verified: bool,
    ) -> Option<Finding> {
        ProofForgeryOracle::check_with_verification(
            self,
            original_inputs,
            mutated_inputs,
            proof,
            verified,
        )
    }

    fn reset(&mut self) {
        self.attempts = 0;
        self.successful_forgeries = 0;
        self.warned_no_integration = false;
        self.proof_history.clear();
    }

    fn stats(&self) -> Option<OracleStatistics> {
        Some(self.statistics())
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

    fn attack_type(&self) -> Option<AttackType> {
        Some(AttackType::ArithmeticOverflow)
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

    fn is_stateful(&self) -> bool {
        true
    }

    fn attack_type(&self) -> Option<AttackType> {
        Some(self.inner.attack_type())
    }
}

#[cfg(test)]
#[path = "oracle_tests.rs"]
mod tests;
