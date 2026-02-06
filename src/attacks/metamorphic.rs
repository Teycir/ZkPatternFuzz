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
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::attacks::metamorphic::{MetamorphicOracle, Transform};
//!
//! let oracle = MetamorphicOracle::new()
//!     .with_transform(Transform::PermutInputs(vec![0, 1, 2], vec![2, 0, 1]))
//!     .with_expected(ExpectedBehavior::OutputUnchanged);
//!
//! let result = oracle.test(&executor, &witness)?;
//! ```

use std::collections::HashMap;
use zk_core::{
    AttackType, CircuitExecutor, ExecutionResult, FieldElement, Finding, 
    ProofOfConcept, Severity,
};

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
    NegateInputs {
        indices: Vec<usize>,
    },
    /// Swap two inputs
    SwapInputs {
        index_a: usize,
        index_b: usize,
    },
    /// Set inputs to specific values
    SetInputs {
        assignments: HashMap<usize, FieldElement>,
    },
    /// Bit flip at specific position
    BitFlipInput {
        index: usize,
        bit_position: usize,
    },
    /// Double an input value
    DoubleInput {
        index: usize,
    },
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
            Transform::PermuteInputs { from_indices, to_indices } => {
                assert_eq!(from_indices.len(), to_indices.len());
                let temp: Vec<FieldElement> = from_indices
                    .iter()
                    .map(|&i| witness.get(i).cloned().unwrap_or_default())
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
            Transform::BitFlipInput { index, bit_position } => {
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
            Transform::BitFlipInput { index, bit_position } => {
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
        }
    }

    /// Add a metamorphic relation
    pub fn with_relation(mut self, relation: MetamorphicRelation) -> Self {
        self.relations.push(relation);
        self
    }

    /// Add standard ZK relations
    pub fn with_standard_relations(mut self) -> Self {
        // Permutation invariance (should change output for Merkle)
        self.relations.push(MetamorphicRelation::new(
            "permutation_sensitivity",
            Transform::SwapInputs { index_a: 0, index_b: 1 },
            ExpectedBehavior::OutputChanged,
        ).with_severity(Severity::Critical)
         .with_description("Swapping inputs should change output for most circuits"));

        // Scaling (for linear circuits)
        self.relations.push(MetamorphicRelation::new(
            "scaling_check",
            Transform::ScaleInputs {
                indices: vec![0],
                factor: FieldElement::from_u64(2),
            },
            ExpectedBehavior::OutputChanged,
        ).with_severity(Severity::Medium));

        // Identity should preserve
        self.relations.push(MetamorphicRelation::new(
            "identity_preservation",
            Transform::Identity,
            ExpectedBehavior::OutputUnchanged,
        ).with_severity(Severity::Critical)
         .with_description("Same input should produce same output"));

        // Negation (should change for most circuits)
        self.relations.push(MetamorphicRelation::new(
            "negation_sensitivity",
            Transform::NegateInputs { indices: vec![0] },
            ExpectedBehavior::OutputChanged,
        ).with_severity(Severity::High));

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
            let result = self.test_relation(executor, base_witness, &base_result, relation).await;
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
        let (passed, violation_reason) = self.check_expected(
            base_result,
            &transformed_result,
            &relation.expected,
        );

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
                        (false, Some("Output changed when it should have stayed the same".to_string()))
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
                        (false, Some("Output unchanged when it should have changed".to_string()))
                    }
                } else if base.success && !transformed.success {
                    (true, None) // Changed to failure is "changed"
                } else {
                    (false, Some("Base execution failed".to_string()))
                }
            }
            ExpectedBehavior::OutputScaled(factor) => {
                if base.success && transformed.success {
                    let all_scaled = base.outputs.iter().zip(transformed.outputs.iter()).all(|(bo, to)| {
                        bo.mul(factor) == *to
                    });
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
                        (false, Some(format!("Output {:?} != expected {:?}", transformed.outputs, expected_outputs)))
                    }
                } else {
                    (false, Some("Execution failed".to_string()))
                }
            }
            ExpectedBehavior::ShouldReject => {
                if !transformed.success {
                    (true, None)
                } else {
                    (false, Some("Circuit accepted when it should have rejected".to_string()))
                }
            }
            ExpectedBehavior::ShouldAccept => {
                if transformed.success {
                    (true, None)
                } else {
                    (false, Some(format!("Circuit rejected when it should have accepted: {:?}", transformed.error)))
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
            critical_failures: results.iter()
                .filter(|r| !r.passed && r.severity == Severity::Critical)
                .count(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_identity() {
        let witness = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
        ];

        let result = Transform::Identity.apply(&witness);
        assert_eq!(witness, result);
    }

    #[test]
    fn test_transform_swap() {
        let witness = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
        ];

        let result = Transform::SwapInputs { index_a: 0, index_b: 2 }.apply(&witness);
        
        assert_eq!(result[0], FieldElement::from_u64(3));
        assert_eq!(result[1], FieldElement::from_u64(2));
        assert_eq!(result[2], FieldElement::from_u64(1));
    }

    #[test]
    fn test_transform_negate() {
        let witness = vec![FieldElement::from_u64(42)];
        let result = Transform::NegateInputs { indices: vec![0] }.apply(&witness);
        
        assert_ne!(result[0], witness[0]);
    }

    #[test]
    fn test_transform_chain() {
        let witness = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
        ];

        let chain = Transform::Chain(vec![
            Transform::SwapInputs { index_a: 0, index_b: 1 },
            Transform::DoubleInput { index: 0 },
        ]);

        let result = chain.apply(&witness);
        
        // After swap: [2, 1], after double index 0: [4, 1]
        assert_eq!(result[0], FieldElement::from_u64(4));
        assert_eq!(result[1], FieldElement::from_u64(1));
    }

    #[test]
    fn test_oracle_creation() {
        let oracle = MetamorphicOracle::new()
            .with_standard_relations()
            .with_tolerance(0.001);

        assert!(!oracle.relations.is_empty());
    }

    #[test]
    fn test_metamorphic_relation() {
        let relation = MetamorphicRelation::new(
            "test_swap",
            Transform::SwapInputs { index_a: 0, index_b: 1 },
            ExpectedBehavior::OutputChanged,
        )
        .with_severity(Severity::Critical)
        .with_description("Test description");

        assert_eq!(relation.name, "test_swap");
        assert_eq!(relation.severity, Severity::Critical);
        assert!(relation.description.is_some());
    }
}
