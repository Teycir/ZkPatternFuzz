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

use rand::Rng;
use std::collections::HashMap;
use std::time::Instant;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

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
    NonZero { wire_index: usize, confidence: f64 },
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
            InferredSpec::LinearRelation {
                input_indices,
                output_index,
                ..
            } => {
                format!(
                    "Linear relation from inputs {:?} to output {}",
                    input_indices, output_index
                )
            }
            InferredSpec::RangeCheck {
                input_index,
                observed_min,
                observed_max,
                ..
            } => {
                format!(
                    "Range check on input {}: {} to {}",
                    input_index, observed_min, observed_max
                )
            }
            InferredSpec::BitwiseConstraint {
                input_index,
                bit_length,
                ..
            } => {
                format!(
                    "Bitwise constraint on input {}: {} bits",
                    input_index, bit_length
                )
            }
            InferredSpec::ConstantValue {
                wire_index, value, ..
            } => {
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
    /// Fraction of samples reserved for validation
    validation_split: f64,
    /// Minimum fraction of validation samples that must satisfy the spec
    validation_threshold: f64,
    /// Minimum samples required before inferring specs
    min_samples: usize,
    /// Optional wire labels (index -> name) to guide inference
    wire_labels: HashMap<usize, String>,
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
            validation_split: 0.2,
            validation_threshold: 0.98,
            min_samples: 30,
            wire_labels: HashMap::new(),
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

    /// Provide wire labels to guide inference
    pub fn with_wire_labels(mut self, labels: HashMap<usize, String>) -> Self {
        self.wire_labels = labels;
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

            let result = executor.execute(&inputs).await;
            if result.success {
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

        if samples.is_empty() || samples.len() < self.min_samples {
            return specs;
        }

        let (train_samples, validation_samples) = self.split_samples(samples);
        if train_samples.is_empty() {
            return specs;
        }

        let num_inputs = train_samples[0].inputs.len();
        let num_outputs = train_samples[0].outputs.len();

        // Infer range checks on inputs
        specs.extend(self.infer_range_checks(train_samples, num_inputs));

        // Infer non-zero constraints
        specs.extend(self.infer_non_zero(train_samples, num_inputs + num_outputs));

        // Infer constant values
        specs.extend(self.infer_constants(train_samples, num_outputs));

        // Infer equalities
        specs.extend(self.infer_equalities(train_samples, num_inputs));

        // Filter by confidence
        specs.retain(|s| s.confidence() >= self.confidence_threshold);

        // Remove specs that cannot be acted upon
        specs.retain(|s| self.is_actionable(s, num_inputs));

        // Validate on holdout samples to reduce false positives
        if !validation_samples.is_empty() {
            specs.retain(|spec| {
                self.spec_support_ratio(spec, validation_samples, num_inputs)
                    .map(|ratio| ratio >= self.validation_threshold)
                    .unwrap_or(false)
            });
        }

        specs
    }

    /// Infer range checks from samples
    fn infer_range_checks(
        &self,
        samples: &[ExecutionSample],
        num_inputs: usize,
    ) -> Vec<InferredSpec> {
        let mut specs = Vec::new();
        let min_unique = 4usize;

        for input_idx in 0..num_inputs {
            let values: Vec<u64> = samples
                .iter()
                .filter_map(|s| s.inputs.get(input_idx))
                .filter_map(|fe| fe.to_u64())
                .collect();

            if values.is_empty() {
                continue;
            }

            let min = *values.iter().min().unwrap();
            let max = *values.iter().max().unwrap();
            let unique_count = values
                .iter()
                .copied()
                .collect::<std::collections::HashSet<u64>>()
                .len();

            if unique_count < min_unique {
                continue;
            }

            // Infer bit length
            let bit_length = if max > 0 {
                (64 - max.leading_zeros()) as usize
            } else {
                1
            };

            // Check if all values fit in power of 2 range
            let expected_max = (1u64 << bit_length) - 1;
            let fits_power_of_2 = max <= expected_max;
            let coverage_ratio = if expected_max > 0 {
                (max as f64) / (expected_max as f64)
            } else {
                0.0
            };

            if fits_power_of_2 && bit_length <= 64 && coverage_ratio >= 0.25 {
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
        let num_inputs = samples.first().map(|s| s.inputs.len()).unwrap_or(0);
        if self.wire_labels.is_empty() {
            return specs;
        }

        for wire_idx in 0..total_wires.min(num_inputs) {
            if !self.label_suggests_nonzero(wire_idx) {
                continue;
            }

            let values: Vec<u64> = samples
                .iter()
                .filter_map(|s| s.inputs.get(wire_idx))
                .filter_map(|fe| fe.to_u64())
                .collect();
            if values.is_empty() {
                continue;
            }

            let min = *values.iter().min().unwrap_or(&u64::MAX);
            if min > 3 {
                // No evidence of a small-domain input; skip to reduce false positives.
                continue;
            }

            let all_nonzero = samples.iter().all(|s| {
                s.inputs
                    .get(wire_idx)
                    .map(|fe| !fe.is_zero())
                    .unwrap_or(true)
            });

            if all_nonzero && samples.len() >= self.min_samples {
                specs.push(InferredSpec::NonZero {
                    wire_index: wire_idx,
                    confidence: 1.0 - (1.0 / samples.len() as f64),
                });
            }
        }

        specs
    }

    /// Infer constant outputs
    fn infer_constants(
        &self,
        samples: &[ExecutionSample],
        num_outputs: usize,
    ) -> Vec<InferredSpec> {
        let mut specs = Vec::new();

        for output_idx in 0..num_outputs {
            let first_value = samples
                .first()
                .and_then(|s| s.outputs.get(output_idx))
                .cloned();

            if let Some(ref expected) = first_value {
                let all_same = samples.iter().all(|s| {
                    s.outputs
                        .get(output_idx)
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
    fn infer_equalities(
        &self,
        samples: &[ExecutionSample],
        num_inputs: usize,
    ) -> Vec<InferredSpec> {
        let mut specs = Vec::new();
        let min_unique = 4usize;
        let max_unique_for_inequality = 16usize;

        let mut unique_counts: Vec<usize> = Vec::with_capacity(num_inputs);
        for input_idx in 0..num_inputs {
            let unique = samples
                .iter()
                .filter_map(|s| s.inputs.get(input_idx))
                .cloned()
                .collect::<std::collections::HashSet<_>>()
                .len();
            unique_counts.push(unique);
        }

        for i in 0..num_inputs {
            for j in (i + 1)..num_inputs {
                let all_equal = samples.iter().all(|s| s.inputs.get(i) == s.inputs.get(j));

                let all_different = samples.iter().all(|s| s.inputs.get(i) != s.inputs.get(j));

                if all_equal && samples.len() >= 10 {
                    if unique_counts[i] < min_unique || unique_counts[j] < min_unique {
                        continue;
                    }
                    specs.push(InferredSpec::Equality {
                        wire_a: i,
                        wire_b: j,
                        confidence: 1.0 - (1.0 / samples.len() as f64),
                    });
                }

                if all_different && samples.len() >= 10 {
                    if unique_counts[i] > max_unique_for_inequality
                        || unique_counts[j] > max_unique_for_inequality
                    {
                        continue;
                    }
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
        let mut modified = false;

        match spec {
            InferredSpec::RangeCheck {
                input_index,
                inferred_bits,
                ..
            } => {
                if *input_index < witness.len() {
                    // Set to a value outside the range
                    let overflow_value = 1u64
                        .checked_shl(*inferred_bits as u32)
                        .unwrap_or(u64::MAX)
                        .saturating_add(rng.gen_range(1..1000));
                    witness[*input_index] = FieldElement::from_u64(overflow_value);
                    modified = true;
                }
            }
            InferredSpec::NonZero { wire_index, .. } => {
                if *wire_index < witness.len() {
                    witness[*wire_index] = FieldElement::zero();
                    modified = true;
                }
            }
            InferredSpec::Equality { wire_a, wire_b, .. } => {
                if *wire_a < witness.len() && *wire_b < witness.len() {
                    // Make them different
                    let mut new_value = witness[*wire_a].add(&FieldElement::one());
                    if new_value == witness[*wire_b] {
                        new_value = new_value.add(&FieldElement::one());
                    }
                    witness[*wire_b] = new_value;
                    modified = true;
                }
            }
            InferredSpec::Inequality { wire_a, wire_b, .. } => {
                if *wire_a < witness.len() && *wire_b < witness.len() {
                    // Make them equal
                    if witness[*wire_b] != witness[*wire_a] {
                        witness[*wire_b] = witness[*wire_a].clone();
                        modified = true;
                    }
                }
            }
            InferredSpec::ConstantValue {
                wire_index, value, ..
            } => {
                if *wire_index < witness.len() {
                    // Set to a different value
                    witness[*wire_index] = value.add(&FieldElement::one());
                    modified = true;
                }
            }
            _ => return None,
        }

        if modified {
            Some(witness)
        } else {
            None
        }
    }

    fn split_samples<'a>(
        &self,
        samples: &'a [ExecutionSample],
    ) -> (&'a [ExecutionSample], &'a [ExecutionSample]) {
        if samples.len() < self.min_samples {
            return (samples, &[]);
        }
        let mut validation_count = (samples.len() as f64 * self.validation_split) as usize;
        if validation_count == 0 {
            validation_count = 1;
        }
        if validation_count >= samples.len() {
            return (&samples[..1], &samples[1..]);
        }
        let split_idx = samples.len() - validation_count;
        (&samples[..split_idx], &samples[split_idx..])
    }

    fn is_actionable(&self, spec: &InferredSpec, num_inputs: usize) -> bool {
        match spec {
            InferredSpec::RangeCheck { input_index, .. } => *input_index < num_inputs,
            InferredSpec::BitwiseConstraint { input_index, .. } => *input_index < num_inputs,
            InferredSpec::NonZero { wire_index, .. } => *wire_index < num_inputs,
            InferredSpec::ConstantValue { wire_index, .. } => *wire_index < num_inputs,
            InferredSpec::Equality { wire_a, wire_b, .. }
            | InferredSpec::Inequality { wire_a, wire_b, .. } => {
                *wire_a < num_inputs && *wire_b < num_inputs
            }
            InferredSpec::LinearRelation { input_indices, .. } => {
                input_indices.iter().all(|idx| *idx < num_inputs)
            }
        }
    }

    fn spec_support_ratio(
        &self,
        spec: &InferredSpec,
        samples: &[ExecutionSample],
        num_inputs: usize,
    ) -> Option<f64> {
        let mut evaluated = 0usize;
        let mut supported = 0usize;
        for sample in samples {
            let Some(holds) = self.spec_holds(spec, sample, num_inputs) else {
                continue;
            };
            evaluated += 1;
            if holds {
                supported += 1;
            }
        }
        if evaluated == 0 {
            None
        } else {
            Some(supported as f64 / evaluated as f64)
        }
    }

    fn spec_holds(
        &self,
        spec: &InferredSpec,
        sample: &ExecutionSample,
        num_inputs: usize,
    ) -> Option<bool> {
        match spec {
            InferredSpec::RangeCheck {
                input_index,
                inferred_bits,
                ..
            } => {
                let value = sample.inputs.get(*input_index)?.to_u64()?;
                if *inferred_bits >= 64 {
                    return Some(false);
                }
                let max = (1u64 << *inferred_bits) - 1;
                Some(value <= max)
            }
            InferredSpec::BitwiseConstraint {
                input_index,
                bit_length,
                ..
            } => {
                let value = sample.inputs.get(*input_index)?.to_u64()?;
                if *bit_length >= 64 {
                    return Some(false);
                }
                let max = (1u64 << *bit_length) - 1;
                Some(value <= max)
            }
            InferredSpec::NonZero { wire_index, .. } => {
                let value = sample.inputs.get(*wire_index)?;
                Some(!value.is_zero())
            }
            InferredSpec::ConstantValue {
                wire_index, value, ..
            } => {
                if *wire_index < num_inputs {
                    Some(sample.inputs.get(*wire_index)? == value)
                } else {
                    let out_idx = wire_index.saturating_sub(num_inputs);
                    Some(sample.outputs.get(out_idx)? == value)
                }
            }
            InferredSpec::Equality { wire_a, wire_b, .. } => {
                Some(sample.inputs.get(*wire_a)? == sample.inputs.get(*wire_b)?)
            }
            InferredSpec::Inequality { wire_a, wire_b, .. } => {
                Some(sample.inputs.get(*wire_a)? != sample.inputs.get(*wire_b)?)
            }
            InferredSpec::LinearRelation { .. } => None,
        }
    }

    fn label_suggests_nonzero(&self, wire_idx: usize) -> bool {
        let Some(label) = self.wire_labels.get(&wire_idx) else {
            return false;
        };
        let lower = label.to_lowercase();
        let patterns = [
            "nullifier",
            "root",
            "commit",
            "hash",
            "signature",
            "sig",
            "pubkey",
            "publickey",
            "pk",
        ];
        patterns.iter().any(|p| lower.contains(p))
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
            let result = executor.execute(witness).await;
            if result.success {
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

        let start = Instant::now();

        // Test each spec
        for (spec_idx, spec) in specs.iter().enumerate() {
            if spec_idx == 0 || (spec_idx % 100 == 0) {
                tracing::info!(
                    "Spec inference progress: {}/{} specs tested (elapsed {:?})",
                    spec_idx,
                    specs.len(),
                    start.elapsed()
                );
            }

            let base_witness = &samples[0].inputs;
            let violations = self.generate_violations(spec, base_witness, &mut rng);

            for violation in violations {
                // If circuit accepts the violation, we found a bug
                let result = executor.execute(&violation).await;
                if result.success {
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
    use rand::SeedableRng;

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

    #[test]
    fn test_constant_output_violation_is_not_actionable() {
        let oracle = SpecInferenceOracle::new();
        let spec = InferredSpec::ConstantValue {
            wire_index: 5,
            value: FieldElement::one(),
            confidence: 1.0,
        };
        let base = vec![FieldElement::zero(); 2];
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let violations = oracle.generate_violations(&spec, &base, &mut rng);
        assert!(violations.is_empty());
    }
}
