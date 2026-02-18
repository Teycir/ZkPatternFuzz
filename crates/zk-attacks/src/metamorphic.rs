//! Metamorphic Oracle Implementation
//!
//! Tests circuit behavior under input transformations that should preserve
//! or predictably change outputs. Detects logic bugs that may not be caught
//! by traditional constraint testing.
//!
//! # Concept
//!
//! Metamorphic testing applies transformations to inputs and checks if the
//! outputs change as expected. For example:
//! - Permuting Merkle siblings should change the root
//! - Scaling inputs should scale outputs proportionally
//! - Negating signature S component should fail verification
//!
//! # Phase 0 Fix: Circuit-Type-Aware Relations
//!
//! Generic linear relations (scale, negate) don't apply to nonlinear ZK circuits
//! like hashes and Merkle trees. This module now supports circuit-type detection
//! to apply only semantically appropriate metamorphic relations:
//!
//! - **Hash circuits**: Avalanche property (small input change → large output change)
//! - **Merkle circuits**: Leaf sensitivity, path order matters
//! - **Signature circuits**: Message binding, S component sensitivity
//! - **Range/Arithmetic**: Scaling, boundary testing
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::attacks::metamorphic::{MetamorphicOracle, CircuitType};
//!
//! // Circuit-type-aware oracle (Phase 0 fix)
//! let oracle = MetamorphicOracle::new()
//!     .with_circuit_type(CircuitType::Hash)
//!     .with_circuit_aware_relations();
//!
//! let result = oracle.test(&executor, &witness)?;
//! ```

use std::collections::HashMap;
use zk_core::{
    AttackType, CircuitExecutor, ExecutionResult, FieldElement, Finding, ProofOfConcept, Severity,
};

/// Circuit type for selecting appropriate metamorphic relations
///
/// # Phase 0 Fix
///
/// Generic linear relations (scale, negate) cause false positives on nonlinear
/// circuits. This enum enables circuit-type-aware relation selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitType {
    /// Hash circuits (Poseidon, MiMC, Pedersen) - nonlinear, avalanche property
    Hash,
    /// Merkle tree circuits - path ordering, leaf sensitivity
    Merkle,
    /// Signature circuits (EdDSA, ECDSA) - message binding, point validation
    Signature,
    /// Range proof circuits - boundary testing, scaling
    Range,
    /// Arithmetic/Linear circuits - scaling, additive properties
    Arithmetic,
    /// Nullifier circuits - uniqueness, non-replayability
    Nullifier,
    /// Commitment circuits - binding, hiding properties
    Commitment,
    /// Unknown/General - use only identity and permutation tests
    Unknown,
}

impl CircuitType {
    /// Detect circuit type from circuit name or labels
    pub fn detect_from_name(name: &str) -> Self {
        let name_lower = name.to_lowercase();

        if name_lower.contains("hash")
            || name_lower.contains("poseidon")
            || name_lower.contains("mimc")
            || name_lower.contains("pedersen")
        {
            CircuitType::Hash
        } else if name_lower.contains("merkle") || name_lower.contains("tree") {
            CircuitType::Merkle
        } else if name_lower.contains("sig")
            || name_lower.contains("eddsa")
            || name_lower.contains("ecdsa")
            || name_lower.contains("schnorr")
        {
            CircuitType::Signature
        } else if name_lower.contains("range")
            || name_lower.contains("bound")
            || name_lower.contains("bit")
        {
            CircuitType::Range
        } else if name_lower.contains("nullifier") || name_lower.contains("nullify") {
            CircuitType::Nullifier
        } else if name_lower.contains("commit") || name_lower.contains("hiding") {
            CircuitType::Commitment
        } else if name_lower.contains("add")
            || name_lower.contains("mul")
            || name_lower.contains("linear")
        {
            CircuitType::Arithmetic
        } else {
            CircuitType::Unknown
        }
    }

    /// Check if linear transforms (scale, negate) are appropriate for this circuit type
    pub fn supports_linear_transforms(&self) -> bool {
        matches!(self, CircuitType::Arithmetic | CircuitType::Range)
    }
}

/// Expected behavior after transformation
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedBehavior {
    /// Output should remain unchanged
    OutputUnchanged,
    /// Output should change
    OutputChanged,
    /// Output should be scaled by a factor
    OutputScaled(FieldElement),
    /// Specific outputs should match
    OutputEquals(Vec<FieldElement>),
    /// Circuit should reject (constraint failure)
    ShouldReject,
    /// Circuit should accept
    ShouldAccept,
    /// Custom predicate
    Custom(String),
}

/// Input transformation types
#[derive(Debug, Clone)]
pub enum Transform {
    /// Permute input indices: original positions -> new positions
    PermuteInputs {
        from_indices: Vec<usize>,
        to_indices: Vec<usize>,
    },
    /// Scale specific inputs by a constant
    ScaleInputs {
        indices: Vec<usize>,
        factor: FieldElement,
    },
    /// Add constant to specific inputs
    AddToInputs {
        indices: Vec<usize>,
        value: FieldElement,
    },
    /// Negate specific inputs (multiply by -1 in field)
    NegateInputs { indices: Vec<usize> },
    /// Swap two inputs
    SwapInputs { index_a: usize, index_b: usize },
    /// Set inputs to specific values
    SetInputs {
        assignments: HashMap<usize, FieldElement>,
    },
    /// Bit flip at specific position
    BitFlipInput { index: usize, bit_position: usize },
    /// Double an input value
    DoubleInput { index: usize },
    /// Identity (no change, for testing)
    Identity,
    /// Chain multiple transforms
    Chain(Vec<Transform>),
}

impl Transform {
    /// Apply transformation to witness
    pub fn apply(&self, witness: &[FieldElement]) -> Vec<FieldElement> {
        let mut result = witness.to_vec();

        match self {
            Transform::PermuteInputs {
                from_indices,
                to_indices,
            } => {
                assert_eq!(from_indices.len(), to_indices.len());
                let temp: Vec<FieldElement> = from_indices
                    .iter()
                    .map(|&i| match witness.get(i).cloned() {
                        Some(value) => value,
                        None => FieldElement::zero(),
                    })
                    .collect();
                for (i, &to) in to_indices.iter().enumerate() {
                    if to < result.len() {
                        result[to] = temp[i].clone();
                    }
                }
            }
            Transform::ScaleInputs { indices, factor } => {
                for &i in indices {
                    if i < result.len() {
                        result[i] = result[i].mul(factor);
                    }
                }
            }
            Transform::AddToInputs { indices, value } => {
                for &i in indices {
                    if i < result.len() {
                        result[i] = result[i].add(value);
                    }
                }
            }
            Transform::NegateInputs { indices } => {
                for &i in indices {
                    if i < result.len() {
                        result[i] = result[i].neg();
                    }
                }
            }
            Transform::SwapInputs { index_a, index_b } => {
                if *index_a < result.len() && *index_b < result.len() {
                    result.swap(*index_a, *index_b);
                }
            }
            Transform::SetInputs { assignments } => {
                for (&i, val) in assignments {
                    if i < result.len() {
                        result[i] = val.clone();
                    }
                }
            }
            Transform::BitFlipInput {
                index,
                bit_position,
            } => {
                if *index < result.len() {
                    let mut bytes = result[*index].to_bytes();
                    let byte_idx = bit_position / 8;
                    let bit_idx = bit_position % 8;
                    if byte_idx < bytes.len() {
                        bytes[byte_idx] ^= 1 << bit_idx;
                        result[*index] = FieldElement::from_bytes(&bytes);
                    }
                }
            }
            Transform::DoubleInput { index } => {
                if *index < result.len() {
                    result[*index] = result[*index].add(&result[*index]);
                }
            }
            Transform::Identity => {}
            Transform::Chain(transforms) => {
                for t in transforms {
                    result = t.apply(&result);
                }
            }
        }

        result
    }

    /// Get description of the transform
    pub fn description(&self) -> String {
        match self {
            Transform::PermuteInputs { from_indices, .. } => {
                format!("permute inputs {:?}", from_indices)
            }
            Transform::ScaleInputs { indices, factor } => {
                format!("scale inputs {:?} by {}", indices, factor.to_hex())
            }
            Transform::AddToInputs { indices, value } => {
                format!("add {} to inputs {:?}", value.to_hex(), indices)
            }
            Transform::NegateInputs { indices } => {
                format!("negate inputs {:?}", indices)
            }
            Transform::SwapInputs { index_a, index_b } => {
                format!("swap inputs {} and {}", index_a, index_b)
            }
            Transform::SetInputs { assignments } => {
                format!("set {} input values", assignments.len())
            }
            Transform::BitFlipInput {
                index,
                bit_position,
            } => {
                format!("flip bit {} of input {}", bit_position, index)
            }
            Transform::DoubleInput { index } => {
                format!("double input {}", index)
            }
            Transform::Identity => "identity (no change)".to_string(),
            Transform::Chain(transforms) => {
                format!("chain of {} transforms", transforms.len())
            }
        }
    }
}

/// A metamorphic relation to test
#[derive(Debug, Clone)]
pub struct MetamorphicRelation {
    /// Name of the relation
    pub name: String,
    /// Transform to apply
    pub transform: Transform,
    /// Expected behavior
    pub expected: ExpectedBehavior,
    /// Severity if violated
    pub severity: Severity,
    /// Description
    pub description: Option<String>,
}

impl MetamorphicRelation {
    /// Create a new relation
    pub fn new(name: &str, transform: Transform, expected: ExpectedBehavior) -> Self {
        Self {
            name: name.to_string(),
            transform,
            expected,
            severity: Severity::High,
            description: None,
        }
    }

    /// Set severity
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }
}

/// Metamorphic oracle for ZK circuits
pub struct MetamorphicOracle {
    relations: Vec<MetamorphicRelation>,
    tolerance: f64,
    /// Phase 0 Fix: Circuit type for appropriate relation selection
    circuit_type: Option<CircuitType>,
}

impl Default for MetamorphicOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl MetamorphicOracle {
    /// Create a new metamorphic oracle
    pub fn new() -> Self {
        Self {
            relations: Vec::new(),
            tolerance: 0.0001,
            circuit_type: None,
        }
    }

    /// Set circuit type for appropriate relation selection (Phase 0 fix)
    pub fn with_circuit_type(mut self, circuit_type: CircuitType) -> Self {
        self.circuit_type = Some(circuit_type);
        self
    }

    /// Detect and set circuit type from name
    pub fn with_circuit_type_from_name(mut self, name: &str) -> Self {
        self.circuit_type = Some(CircuitType::detect_from_name(name));
        self
    }

    /// Add a metamorphic relation
    pub fn with_relation(mut self, relation: MetamorphicRelation) -> Self {
        self.relations.push(relation);
        self
    }

    /// Add circuit-type-aware relations (Phase 0 fix)
    ///
    /// Only adds relations that are semantically appropriate for the circuit type,
    /// avoiding false positives from applying linear transforms to nonlinear circuits.
    pub fn with_circuit_aware_relations(mut self) -> Self {
        let circuit_type = match self.circuit_type {
            Some(value) => value,
            None => CircuitType::Unknown,
        };

        // Universal: Identity should always preserve output
        self.relations.push(
            MetamorphicRelation::new(
                "identity_preservation",
                Transform::Identity,
                ExpectedBehavior::OutputUnchanged,
            )
            .with_severity(Severity::Critical)
            .with_description("Same input should produce same output"),
        );

        // Add circuit-type-specific relations
        match circuit_type {
            CircuitType::Hash => {
                // Hash: Avalanche property - any bit flip should change output significantly
                self.relations.push(
                    MetamorphicRelation::new(
                        "hash_avalanche",
                        Transform::BitFlipInput {
                            index: 0,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::Critical)
                    .with_description("Hash avalanche: single bit flip should change output"),
                );
            }
            CircuitType::Merkle => {
                // Merkle: Leaf order matters
                self.relations.push(
                    MetamorphicRelation::new(
                        "merkle_leaf_sensitivity",
                        Transform::SwapInputs {
                            index_a: 0,
                            index_b: 1,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::Critical)
                    .with_description("Swapping Merkle leaves should change root"),
                );
                // Merkle: Path indices must be binary (bit flip should reject)
                self.relations.push(
                    MetamorphicRelation::new(
                        "merkle_path_binary",
                        Transform::SetInputs {
                            assignments: [(0, FieldElement::from_u64(2))].into_iter().collect(),
                        },
                        ExpectedBehavior::ShouldReject,
                    )
                    .with_severity(Severity::High)
                    .with_description("Non-binary path index should be rejected"),
                );
            }
            CircuitType::Signature => {
                // Signature: Message binding - changing message should fail
                self.relations.push(
                    MetamorphicRelation::new(
                        "signature_message_binding",
                        Transform::BitFlipInput {
                            index: 0,
                            bit_position: 0,
                        },
                        ExpectedBehavior::ShouldReject,
                    )
                    .with_severity(Severity::Critical)
                    .with_description("Signature should not verify with modified message"),
                );
            }
            CircuitType::Range | CircuitType::Arithmetic => {
                // Only apply linear transforms to linear/range circuits
                self.relations.push(
                    MetamorphicRelation::new(
                        "scaling_sensitivity",
                        Transform::ScaleInputs {
                            indices: vec![0],
                            factor: FieldElement::from_u64(2),
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::Medium)
                    .with_description("Scaling input should change output"),
                );
                self.relations.push(
                    MetamorphicRelation::new(
                        "negation_sensitivity",
                        Transform::NegateInputs { indices: vec![0] },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Negating input should change output"),
                );
            }
            CircuitType::Nullifier => {
                // Nullifier: Same inputs should produce same nullifier
                self.relations.push(
                    MetamorphicRelation::new(
                        "nullifier_determinism",
                        Transform::Identity,
                        ExpectedBehavior::OutputUnchanged,
                    )
                    .with_severity(Severity::Critical)
                    .with_description("Same inputs should produce same nullifier"),
                );
                // Any change should produce different nullifier
                self.relations.push(
                    MetamorphicRelation::new(
                        "nullifier_uniqueness",
                        Transform::BitFlipInput {
                            index: 0,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::Critical)
                    .with_description("Different inputs should produce different nullifier"),
                );
            }
            CircuitType::Commitment => {
                // Commitment: Binding property - same value + randomness = same commitment
                self.relations.push(
                    MetamorphicRelation::new(
                        "commitment_binding",
                        Transform::Identity,
                        ExpectedBehavior::OutputUnchanged,
                    )
                    .with_severity(Severity::Critical)
                    .with_description("Same inputs should produce same commitment"),
                );
            }
            CircuitType::Unknown => {
                // For unknown circuits, only test basic properties
                // Don't add scale/negate as they cause false positives on nonlinear circuits
                self.relations.push(
                    MetamorphicRelation::new(
                        "basic_sensitivity",
                        Transform::SwapInputs {
                            index_a: 0,
                            index_b: 1,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::Medium)
                    .with_description("Swapping inputs should generally change output"),
                );
            }
        }

        self
    }

    /// Add standard ZK relations (legacy behavior - use with_circuit_aware_relations instead)
    ///
    /// # Warning
    ///
    /// This method applies generic linear transforms that may cause false positives
    /// on nonlinear circuits (hashes, Merkle trees). Consider using
    /// `with_circuit_aware_relations()` instead for better accuracy.
    #[deprecated(
        since = "0.2.0",
        note = "Use with_circuit_aware_relations() for better accuracy on nonlinear circuits"
    )]
    pub fn with_standard_relations(mut self) -> Self {
        // Permutation invariance (should change output for Merkle)
        self.relations.push(
            MetamorphicRelation::new(
                "permutation_sensitivity",
                Transform::SwapInputs {
                    index_a: 0,
                    index_b: 1,
                },
                ExpectedBehavior::OutputChanged,
            )
            .with_severity(Severity::Critical)
            .with_description("Swapping inputs should change output for most circuits"),
        );

        // Scaling (for linear circuits)
        // Phase 0 Note: This causes false positives on hash/Merkle circuits
        self.relations.push(
            MetamorphicRelation::new(
                "scaling_check",
                Transform::ScaleInputs {
                    indices: vec![0],
                    factor: FieldElement::from_u64(2),
                },
                ExpectedBehavior::OutputChanged,
            )
            .with_severity(Severity::Medium),
        );

        // Identity should preserve
        self.relations.push(
            MetamorphicRelation::new(
                "identity_preservation",
                Transform::Identity,
                ExpectedBehavior::OutputUnchanged,
            )
            .with_severity(Severity::Critical)
            .with_description("Same input should produce same output"),
        );

        // Negation (should change for most circuits)
        // Phase 0 Note: This causes false positives on hash/Merkle circuits
        self.relations.push(
            MetamorphicRelation::new(
                "negation_sensitivity",
                Transform::NegateInputs { indices: vec![0] },
                ExpectedBehavior::OutputChanged,
            )
            .with_severity(Severity::High),
        );

        self
    }

    /// Set tolerance for floating point comparisons
    pub fn with_tolerance(mut self, tolerance: f64) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Test all relations against an executor
    pub async fn test_all(
        &self,
        executor: &dyn CircuitExecutor,
        base_witness: &[FieldElement],
    ) -> Vec<MetamorphicTestResult> {
        let mut results = Vec::new();

        // Get base execution result
        let base_result = executor.execute(base_witness).await;

        for relation in &self.relations {
            let result = self
                .test_relation(executor, base_witness, &base_result, relation)
                .await;
            results.push(result);
        }

        results
    }

    /// Test a single relation
    async fn test_relation(
        &self,
        executor: &dyn CircuitExecutor,
        base_witness: &[FieldElement],
        base_result: &ExecutionResult,
        relation: &MetamorphicRelation,
    ) -> MetamorphicTestResult {
        // Apply transform
        let transformed_witness = relation.transform.apply(base_witness);

        // Execute transformed
        let transformed_result = executor.execute(&transformed_witness).await;

        // Check expected behavior
        let (passed, violation_reason) =
            self.check_expected(base_result, &transformed_result, &relation.expected);

        MetamorphicTestResult {
            relation_name: relation.name.clone(),
            passed,
            violation_reason,
            base_witness: base_witness.to_vec(),
            transformed_witness,
            severity: relation.severity,
        }
    }

    /// Check if expected behavior was observed
    fn check_expected(
        &self,
        base: &ExecutionResult,
        transformed: &ExecutionResult,
        expected: &ExpectedBehavior,
    ) -> (bool, Option<String>) {
        match expected {
            ExpectedBehavior::OutputUnchanged => {
                if base.success && transformed.success {
                    if base.outputs == transformed.outputs {
                        (true, None)
                    } else {
                        (
                            false,
                            Some("Output changed when it should have stayed the same".to_string()),
                        )
                    }
                } else {
                    (false, Some("Execution failed".to_string()))
                }
            }
            ExpectedBehavior::OutputChanged => {
                if base.success && transformed.success {
                    if base.outputs != transformed.outputs {
                        (true, None)
                    } else {
                        (
                            false,
                            Some("Output unchanged when it should have changed".to_string()),
                        )
                    }
                } else if base.success && !transformed.success {
                    (true, None) // Changed to failure is "changed"
                } else {
                    (false, Some("Base execution failed".to_string()))
                }
            }
            ExpectedBehavior::OutputScaled(factor) => {
                if base.success && transformed.success {
                    let all_scaled = base
                        .outputs
                        .iter()
                        .zip(transformed.outputs.iter())
                        .all(|(bo, to)| bo.mul(factor) == *to);
                    if all_scaled {
                        (true, None)
                    } else {
                        (false, Some("Output not scaled as expected".to_string()))
                    }
                } else {
                    (false, Some("Execution failed".to_string()))
                }
            }
            ExpectedBehavior::OutputEquals(expected_outputs) => {
                if transformed.success {
                    if &transformed.outputs == expected_outputs {
                        (true, None)
                    } else {
                        (
                            false,
                            Some(format!(
                                "Output {:?} != expected {:?}",
                                transformed.outputs, expected_outputs
                            )),
                        )
                    }
                } else {
                    (false, Some("Execution failed".to_string()))
                }
            }
            ExpectedBehavior::ShouldReject => {
                if !transformed.success {
                    (true, None)
                } else {
                    (
                        false,
                        Some("Circuit accepted when it should have rejected".to_string()),
                    )
                }
            }
            ExpectedBehavior::ShouldAccept => {
                if transformed.success {
                    (true, None)
                } else {
                    (
                        false,
                        Some(format!(
                            "Circuit rejected when it should have accepted: {:?}",
                            transformed.error
                        )),
                    )
                }
            }
            ExpectedBehavior::Custom(desc) => {
                // Custom predicates can't be automatically checked
                (true, Some(format!("Custom check required: {}", desc)))
            }
        }
    }

    /// Convert test results to findings
    pub fn to_findings(&self, results: &[MetamorphicTestResult]) -> Vec<Finding> {
        results
            .iter()
            .filter(|r| !r.passed)
            .map(|r| Finding {
                attack_type: AttackType::Metamorphic,
                severity: r.severity,
                description: format!(
                    "Metamorphic relation '{}' violated: {}",
                    r.relation_name,
                    r.violation_reason.as_deref().unwrap_or("unknown")
                ),
                poc: ProofOfConcept {
                    witness_a: r.base_witness.clone(),
                    witness_b: Some(r.transformed_witness.clone()),
                    public_inputs: vec![],
                    proof: None,
                },
                location: None,
            })
            .collect()
    }
}

/// Result of a metamorphic test
#[derive(Debug, Clone)]
pub struct MetamorphicTestResult {
    pub relation_name: String,
    pub passed: bool,
    pub violation_reason: Option<String>,
    pub base_witness: Vec<FieldElement>,
    pub transformed_witness: Vec<FieldElement>,
    pub severity: Severity,
}

/// Statistics from metamorphic testing
#[derive(Debug, Clone, Default)]
pub struct MetamorphicStats {
    pub relations_tested: usize,
    pub relations_passed: usize,
    pub relations_failed: usize,
    pub critical_failures: usize,
}

impl MetamorphicOracle {
    /// Compute statistics from results
    pub fn stats(&self, results: &[MetamorphicTestResult]) -> MetamorphicStats {
        MetamorphicStats {
            relations_tested: results.len(),
            relations_passed: results.iter().filter(|r| r.passed).count(),
            relations_failed: results.iter().filter(|r| !r.passed).count(),
            critical_failures: results
                .iter()
                .filter(|r| !r.passed && r.severity == Severity::Critical)
                .count(),
        }
    }
}

#[cfg(test)]
#[path = "metamorphic_tests.rs"]
mod tests;
