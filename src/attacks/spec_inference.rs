//! Spec Inference Oracle
//!
//! Automatically infers expected circuit properties (specifications) by sampling
//! valid witnesses, then generates test cases that violate the inferred specs.
//!
//! # Concept
//!
//! 1. Sample many valid input/output pairs
//! 2. Infer relations (linear, range, bitwise)
//! 3. Generate inputs that violate inferred specs
//! 4. If circuit accepts violating inputs → missing constraint
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::attacks::spec_inference::SpecInferenceOracle;
//!
//! let oracle = SpecInferenceOracle::new()
//!     .with_sample_count(1000);
//!
//! let specs = oracle.infer_specs(&executor, &sample_inputs).await?;
//! for spec in specs {
//!     println!("Inferred: {:?}", spec);
//! }
//! ```

use std::collections::HashMap;
use zk_core::{
    AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity,
};
use rand::Rng;

/// Types of specifications that can be inferred
#[derive(Debug, Clone)]
pub enum InferredSpec {
    /// Linear relation: sum(coeffs[i] * inputs[i]) + constant = output
    LinearRelation {
        input_indices: Vec<usize>,
        coefficients: Vec<FieldElement>,
        constant: FieldElement,
        output_index: usize,
        confidence: f64,
    },
    /// Range check: min <= value <= max
    RangeCheck {
        input_index: usize,
        observed_min: u64,
        observed_max: u64,
        inferred_bits: usize,
        confidence: f64,
    },
    /// Bitwise constraint: value fits in n bits
    BitwiseConstraint {
        input_index: usize,
        bit_length: usize,
        confidence: f64,
    },
    /// Constant: input/output always has this value
    ConstantValue {
        wire_index: usize,
        value: FieldElement,
        confidence: f64,
    },
    /// Non-zero: value is never zero
    NonZero {
        wire_index: usize,
        confidence: f64,
    },
    /// Equality: two wires always have same value
    Equality {
        wire_a: usize,
        wire_b: usize,
        confidence: f64,
    },
    /// Inequality: two wires never have same value
    Inequality {
        wire_a: usize,
        wire_b: usize,
        confidence: f64,
    },
}

impl InferredSpec {
    /// Get confidence of the inference
    pub fn confidence(&self) -> f64 {
        match self {
            InferredSpec::LinearRelation { confidence, .. } => *confidence,
            InferredSpec::RangeCheck { confidence, .. } => *confidence,
            InferredSpec::BitwiseConstraint { confidence, .. } => *confidence,
            InferredSpec::ConstantValue { confidence, .. } => *confidence,
            InferredSpec::NonZero { confidence, .. } => *confidence,
            InferredSpec::Equality { confidence, .. } => *confidence,
            InferredSpec::Inequality { confidence, .. } => *confidence,
        }
    }

    /// Get description of the spec
    pub fn description(&self) -> String {
        match self {
            InferredSpec::LinearRelation { input_indices, output_index, .. } => {
                format!("Linear relation from inputs {:?} to output {}", input_indices, output_index)
            }
            InferredSpec::RangeCheck { input_index, observed_min, observed_max, .. } => {
                format!("Range check on input {}: {} to {}", input_index, observed_min, observed_max)
            }
            InferredSpec::BitwiseConstraint { input_index, bit_length, .. } => {
                format!("Bitwise constraint on input {}: {} bits", input_index, bit_length)
            }
            InferredSpec::ConstantValue { wire_index, value, .. } => {
                format!("Constant value at wire {}: {}", wire_index, value.to_hex())
            }
            InferredSpec::NonZero { wire_index, .. } => {
                format!("Non-zero constraint on wire {}", wire_index)
            }
            InferredSpec::Equality { wire_a, wire_b, .. } => {
                format!("Equality: wire {} == wire {}", wire_a, wire_b)
            }
            InferredSpec::Inequality { wire_a, wire_b, .. } => {
                format!("Inequality: wire {} != wire {}", wire_a, wire_b)
            }
        }
    }
}

/// A sample of inputs and outputs
#[derive(Debug, Clone)]
pub struct ExecutionSample {
    pub inputs: Vec<FieldElement>,
    pub outputs: Vec<FieldElement>,
}

/// Spec inference oracle
pub struct SpecInferenceOracle {
    /// Number of samples to collect
    sample_count: usize,
    /// Minimum confidence threshold
    confidence_threshold: f64,
    /// Number of violation attempts per spec
    violation_attempts: usize,
}

impl Default for SpecInferenceOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl SpecInferenceOracle {
    /// Create a new spec inference oracle
    pub fn new() -> Self {
        Self {
            sample_count: 500,
            confidence_threshold: 0.9,
            violation_attempts: 100,
        }
    }

    /// Set sample count
    pub fn with_sample_count(mut self, count: usize) -> Self {
        self.sample_count = count;
        self
    }

    /// Set confidence threshold
    pub fn with_confidence_threshold(mut self, threshold: f64) -> Self {
        self.confidence_threshold = threshold;
        self
    }

    /// Collect execution samples
    pub async fn collect_samples(
        &self,
        executor: &dyn CircuitExecutor,
        input_generator: impl Fn(&mut rand::rngs::ThreadRng) -> Vec<FieldElement>,
    ) -> Vec<ExecutionSample> {
        let mut samples = Vec::new();
        let mut rng = rand::thread_rng();

        for _ in 0..self.sample_count {
            let inputs = input_generator(&mut rng);
            
            if let Ok(result) = executor.execute(&inputs).await {
                samples.push(ExecutionSample {
                    inputs,
                    outputs: result.outputs,
                });
            }
        }

        samples
    }

    /// Infer specifications from samples
    pub fn infer_specs(&self, samples: &[ExecutionSample]) -> Vec<InferredSpec> {
        let mut specs = Vec::new();

        if samples.is_empty() {
            return specs;
        }

        let num_inputs = samples[0].inputs.len();
        let num_outputs = samples[0].outputs.len();

        // Infer range checks on inputs
        specs.extend(self.infer_range_checks(samples, num_inputs));

        // Infer non-zero constraints
        specs.extend(self.infer_non_zero(samples, num_inputs + num_outputs));

        // Infer constant values
        specs.extend(self.infer_constants(samples, num_outputs));

        // Infer equalities
        specs.extend(self.infer_equalities(samples, num_inputs));

        // Filter by confidence
        specs.retain(|s| s.confidence() >= self.confidence_threshold);

        specs
    }

    /// Infer range checks from samples
    fn infer_range_checks(&self, samples: &[ExecutionSample], num_inputs: usize) -> Vec<InferredSpec> {
        let mut specs = Vec::new();

        for input_idx in 0..num_inputs {
            let values: Vec<u64> = samples.iter()
                .filter_map(|s| s.inputs.get(input_idx))
                .filter_map(|fe| fe.to_u64())
                .collect();

            if values.is_empty() {
                continue;
            }

            let min = *values.iter().min().unwrap();
            let max = *values.iter().max().unwrap();

            // Infer bit length
            let bit_length = if max > 0 {
                (64 - max.leading_zeros()) as usize
            } else {
                1
            };

            // Check if all values fit in power of 2 range
            let expected_max = (1u64 << bit_length) - 1;
            let fits_power_of_2 = max <= expected_max;

            if fits_power_of_2 && bit_length <= 64 {
                specs.push(InferredSpec::RangeCheck {
                    input_index: input_idx,
                    observed_min: min,
                    observed_max: max,
                    inferred_bits: bit_length,
                    confidence: 0.95,
                });
            }
        }

        specs
    }

    /// Infer non-zero constraints
    fn infer_non_zero(&self, samples: &[ExecutionSample], total_wires: usize) -> Vec<InferredSpec> {
        let mut specs = Vec::new();
        let num_inputs = samples.get(0).map(|s| s.inputs.len()).unwrap_or(0);

        for wire_idx in 0..total_wires.min(num_inputs) {
            let all_nonzero = samples.iter().all(|s| {
                s.inputs.get(wire_idx)
                    .map(|fe| !fe.is_zero())
                    .unwrap_or(true)
            });

            if all_nonzero && samples.len() >= 10 {
                specs.push(InferredSpec::NonZero {
                    wire_index: wire_idx,
                    confidence: 1.0 - (1.0 / samples.len() as f64),
                });
            }
        }

        specs
    }

    /// Infer constant outputs
    fn infer_constants(&self, samples: &[ExecutionSample], num_outputs: usize) -> Vec<InferredSpec> {
        let mut specs = Vec::new();

        for output_idx in 0..num_outputs {
            let first_value = samples.get(0)
                .and_then(|s| s.outputs.get(output_idx))
                .cloned();

            if let Some(ref expected) = first_value {
                let all_same = samples.iter().all(|s| {
                    s.outputs.get(output_idx)
                        .map(|v| v == expected)
                        .unwrap_or(false)
                });

                if all_same && samples.len() >= 10 {
                    specs.push(InferredSpec::ConstantValue {
                        wire_index: output_idx + samples[0].inputs.len(),
                        value: expected.clone(),
                        confidence: 1.0 - (1.0 / samples.len() as f64),
                    });
                }
            }
        }

        specs
    }

    /// Infer equality relations between inputs
    fn infer_equalities(&self, samples: &[ExecutionSample], num_inputs: usize) -> Vec<InferredSpec> {
        let mut specs = Vec::new();

        for i in 0..num_inputs {
            for j in (i + 1)..num_inputs {
                let all_equal = samples.iter().all(|s| {
                    s.inputs.get(i) == s.inputs.get(j)
                });

                let all_different = samples.iter().all(|s| {
                    s.inputs.get(i) != s.inputs.get(j)
                });

                if all_equal && samples.len() >= 10 {
                    specs.push(InferredSpec::Equality {
                        wire_a: i,
                        wire_b: j,
                        confidence: 1.0 - (1.0 / samples.len() as f64),
                    });
                }

                if all_different && samples.len() >= 10 {
                    specs.push(InferredSpec::Inequality {
                        wire_a: i,
                        wire_b: j,
                        confidence: 0.95, // Lower confidence for inequality
                    });
                }
            }
        }

        specs
    }

    /// Generate violation attempts for a spec
    pub fn generate_violations(
        &self,
        spec: &InferredSpec,
        base_witness: &[FieldElement],
        rng: &mut impl Rng,
    ) -> Vec<Vec<FieldElement>> {
        let mut violations = Vec::new();

        for _ in 0..self.violation_attempts {
            let violation = self.generate_single_violation(spec, base_witness, rng);
            if let Some(v) = violation {
                violations.push(v);
            }
        }

        violations
    }

    /// Generate a single violation attempt
    fn generate_single_violation(
        &self,
        spec: &InferredSpec,
        base_witness: &[FieldElement],
        rng: &mut impl Rng,
    ) -> Option<Vec<FieldElement>> {
        let mut witness = base_witness.to_vec();

        match spec {
            InferredSpec::RangeCheck { input_index, inferred_bits, .. } => {
                if *input_index < witness.len() {
                    // Set to a value outside the range
                    let overflow_value = 1u64.checked_shl(*inferred_bits as u32)
                        .unwrap_or(u64::MAX);
                    witness[*input_index] = FieldElement::from_u64(overflow_value + rng.gen_range(1..1000));
                }
            }
            InferredSpec::NonZero { wire_index, .. } => {
                if *wire_index < witness.len() {
                    witness[*wire_index] = FieldElement::zero();
                }
            }
            InferredSpec::Equality { wire_a, wire_b, .. } => {
                if *wire_a < witness.len() && *wire_b < witness.len() {
                    // Make them different
                    witness[*wire_b] = witness[*wire_a].add(&FieldElement::one());
                }
            }
            InferredSpec::Inequality { wire_a, wire_b, .. } => {
                if *wire_a < witness.len() && *wire_b < witness.len() {
                    // Make them equal
                    witness[*wire_b] = witness[*wire_a].clone();
                }
            }
            InferredSpec::ConstantValue { wire_index, value, .. } => {
                if *wire_index < witness.len() {
                    // Set to a different value
                    witness[*wire_index] = value.add(&FieldElement::one());
                }
            }
            _ => return None,
        }

        Some(witness)
    }

    /// Run the full spec inference attack
    pub async fn run(
        &self,
        executor: &dyn CircuitExecutor,
        initial_witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut rng = rand::thread_rng();

        // Collect samples from initial witnesses
        let mut samples = Vec::new();
        for witness in initial_witnesses {
            if let Ok(result) = executor.execute(witness).await {
                samples.push(ExecutionSample {
                    inputs: witness.clone(),
                    outputs: result.outputs,
                });
            }
        }

        if samples.is_empty() {
            return findings;
        }

        // Infer specs
        let specs = self.infer_specs(&samples);

        tracing::info!("Inferred {} specifications", specs.len());

        // Test each spec
        for spec in &specs {
            let base_witness = &samples[0].inputs;
            let violations = self.generate_violations(spec, base_witness, &mut rng);

            for violation in violations {
                // If circuit accepts the violation, we found a bug
                if let Ok(_result) = executor.execute(&violation).await {
                    findings.push(Finding {
                        attack_type: AttackType::SpecInference,
                        severity: Severity::High,
                        description: format!(
                            "Circuit accepted input violating inferred spec: {}",
                            spec.description()
                        ),
                        poc: ProofOfConcept {
                            witness_a: violation,
                            witness_b: Some(base_witness.clone()),
                            public_inputs: vec![],
                            proof: None,
                        },
                        location: None,
                    });
                    break; // One violation per spec is enough
                }
            }
        }

        findings
    }
}

/// Statistics from spec inference
#[derive(Debug, Clone, Default)]
pub struct SpecInferenceStats {
    pub samples_collected: usize,
    pub specs_inferred: usize,
    pub violations_found: usize,
    pub specs_by_type: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inferred_spec_confidence() {
        let spec = InferredSpec::RangeCheck {
            input_index: 0,
            observed_min: 0,
            observed_max: 255,
            inferred_bits: 8,
            confidence: 0.95,
        };

        assert!((spec.confidence() - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_oracle_creation() {
        let oracle = SpecInferenceOracle::new()
            .with_sample_count(1000)
            .with_confidence_threshold(0.85);

        assert_eq!(oracle.sample_count, 1000);
        assert!((oracle.confidence_threshold - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_infer_range_checks() {
        let oracle = SpecInferenceOracle::new();

        let samples: Vec<ExecutionSample> = (0..100)
            .map(|i| ExecutionSample {
                inputs: vec![FieldElement::from_u64(i % 256)],
                outputs: vec![FieldElement::from_u64(i)],
            })
            .collect();

        let specs = oracle.infer_range_checks(&samples, 1);

        assert!(!specs.is_empty());
        if let InferredSpec::RangeCheck { inferred_bits, .. } = &specs[0] {
            assert!(*inferred_bits <= 8);
        }
    }
}
