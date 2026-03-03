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
//! use zk_fuzzer::oracles::spec_inference::SpecInferenceOracle;
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
use std::collections::{HashMap, HashSet};
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
    /// Optional cap on inferred specs to validate (runtime guardrail)
    max_specs: Option<usize>,
    /// Fraction of samples reserved for validation
    validation_split: f64,
    /// Minimum fraction of validation samples that must satisfy the spec
    validation_threshold: f64,
    /// Minimum samples required before inferring specs
    min_samples: usize,
    /// Optional wire labels (index -> name) to guide inference
    wire_labels: HashMap<usize, String>,
}

/// Result of a spec inference run with both generated specs and findings.
#[derive(Debug, Clone, Default)]
pub struct SpecInferenceRunResult {
    pub samples_collected: usize,
    pub inferred_specs: Vec<InferredSpec>,
    pub findings: Vec<Finding>,
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
            max_specs: None,
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

    /// Set violation attempts per spec (clamped to at least 1)
    pub fn with_violation_attempts(mut self, attempts: usize) -> Self {
        self.violation_attempts = attempts.max(1);
        self
    }

    /// Cap how many inferred specs are tested for violations.
    pub fn with_max_specs(mut self, max_specs: usize) -> Self {
        self.max_specs = Some(max_specs.max(1));
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
        specs.retain(|s| self.is_actionable(s, num_inputs, num_outputs));

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

            let (Some(&min), Some(&max)) = (values.iter().min(), values.iter().max()) else {
                continue;
            };
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
            let expected_max = if bit_length >= 64 {
                u64::MAX
            } else {
                (1u64 << bit_length) - 1
            };
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

            let Some(&min) = values.iter().min() else {
                continue;
            };
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
        let mut seen = HashSet::new();
        let mut duplicate_streak = 0usize;
        let attempt_budget = self
            .violation_attempts
            .min(self.max_useful_attempts(spec))
            .max(1);

        for _ in 0..attempt_budget {
            let violation = self.generate_single_violation(spec, base_witness, rng);
            if let Some(v) = violation {
                if seen.insert(v.clone()) {
                    violations.push(v);
                    duplicate_streak = 0;
                } else {
                    duplicate_streak = duplicate_streak.saturating_add(1);
                    if duplicate_streak >= 4 {
                        break;
                    }
                }
            }
        }

        violations
    }

    fn max_useful_attempts(&self, spec: &InferredSpec) -> usize {
        match spec {
            InferredSpec::RangeCheck { .. } | InferredSpec::BitwiseConstraint { .. } => 16,
            InferredSpec::LinearRelation { .. } => 8,
            InferredSpec::NonZero { .. }
            | InferredSpec::ConstantValue { .. }
            | InferredSpec::Equality { .. }
            | InferredSpec::Inequality { .. } => 2,
        }
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
                } else {
                    // Output-wire constraints are exercised by perturbing an input witness.
                    modified = self.perturb_random_input(&mut witness, rng);
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
                } else {
                    modified = self.perturb_random_input(&mut witness, rng);
                }
            }
            InferredSpec::Inequality { wire_a, wire_b, .. } => {
                if *wire_a < witness.len() && *wire_b < witness.len() {
                    // Make them equal
                    if witness[*wire_b] != witness[*wire_a] {
                        witness[*wire_b] = witness[*wire_a].clone();
                        modified = true;
                    }
                } else {
                    modified = self.perturb_random_input(&mut witness, rng);
                }
            }
            InferredSpec::ConstantValue {
                wire_index, value, ..
            } => {
                if *wire_index < witness.len() {
                    // Set to a different value
                    witness[*wire_index] = value.add(&FieldElement::one());
                    modified = true;
                } else {
                    // Output-wire constants require input perturbation and post-exec checking.
                    modified = self.perturb_random_input(&mut witness, rng);
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

    fn perturb_random_input(&self, witness: &mut [FieldElement], rng: &mut impl Rng) -> bool {
        if witness.is_empty() {
            return false;
        }
        let idx = rng.gen_range(0..witness.len());
        let delta = FieldElement::from_u64(rng.gen_range(1..1024));
        let mut candidate = witness[idx].add(&delta);
        if candidate == witness[idx] {
            candidate = candidate.add(&FieldElement::one());
        }
        witness[idx] = candidate;
        true
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

    fn is_actionable(&self, spec: &InferredSpec, num_inputs: usize, num_outputs: usize) -> bool {
        let total_wires = num_inputs.saturating_add(num_outputs);
        match spec {
            InferredSpec::RangeCheck { input_index, .. } => *input_index < num_inputs,
            InferredSpec::BitwiseConstraint { input_index, .. } => *input_index < num_inputs,
            InferredSpec::NonZero { wire_index, .. } => *wire_index < total_wires,
            InferredSpec::ConstantValue { wire_index, .. } => *wire_index < total_wires,
            InferredSpec::Equality { wire_a, wire_b, .. }
            | InferredSpec::Inequality { wire_a, wire_b, .. } => {
                *wire_a < total_wires && *wire_b < total_wires
            }
            InferredSpec::LinearRelation {
                input_indices,
                output_index,
                ..
            } => input_indices.iter().all(|idx| *idx < num_inputs) && *output_index < num_outputs,
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
                let value = if *wire_index < num_inputs {
                    sample.inputs.get(*wire_index)?
                } else {
                    let out_idx = wire_index.saturating_sub(num_inputs);
                    sample.outputs.get(out_idx)?
                };
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
        self.run_with_progress(executor, initial_witnesses, |_spec_idx, _specs_total| {})
            .await
    }

    /// Run the full spec inference attack with periodic progress callbacks.
    pub async fn run_with_progress<F>(
        &self,
        executor: &dyn CircuitExecutor,
        initial_witnesses: &[Vec<FieldElement>],
        mut on_progress: F,
    ) -> Vec<Finding>
    where
        F: FnMut(usize, usize),
    {
        self.run_with_progress_and_specs(executor, initial_witnesses, |idx, total| {
            on_progress(idx, total)
        })
        .await
        .findings
    }

    /// Run the full spec inference attack and return both inferred specs and findings.
    pub async fn run_with_progress_and_specs<F>(
        &self,
        executor: &dyn CircuitExecutor,
        initial_witnesses: &[Vec<FieldElement>],
        mut on_progress: F,
    ) -> SpecInferenceRunResult
    where
        F: FnMut(usize, usize),
    {
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
            return SpecInferenceRunResult::default();
        }

        // Infer specs
        let mut specs = self.infer_specs(&samples);
        let inferred_total = specs.len();
        if let Some(max_specs) = self.max_specs {
            if specs.len() > max_specs {
                tracing::warn!(
                    "Spec inference max-spec cap applied: inferred {} -> testing {}",
                    specs.len(),
                    max_specs
                );
                specs.truncate(max_specs);
            }
        }

        tracing::info!(
            "Inferred {} specifications (testing {})",
            inferred_total,
            specs.len()
        );

        let start = Instant::now();
        let num_inputs = samples
            .first()
            .map(|sample| sample.inputs.len())
            .unwrap_or_default();

        // Test each spec
        for (spec_idx, spec) in specs.iter().enumerate() {
            on_progress(spec_idx, specs.len());

            if spec_idx == 0 || spec_idx.is_multiple_of(25) || spec_idx + 1 == specs.len() {
                let elapsed = start.elapsed();
                let tested = spec_idx.max(1) as f64;
                let rate = elapsed.as_secs_f64() / tested;
                let remaining_specs = specs.len().saturating_sub(spec_idx);
                let eta = std::time::Duration::from_secs_f64(rate * (remaining_specs as f64));
                tracing::info!(
                    "Spec inference progress: {}/{} specs tested (elapsed {:?}, eta {:?})",
                    spec_idx,
                    specs.len(),
                    elapsed,
                    eta
                );
            }

            let base_witness = &samples[0].inputs;
            let violations = self.generate_violations(spec, base_witness, &mut rng);
            if violations.is_empty() {
                continue;
            }

            for violation in violations {
                // If circuit accepts the violation, we found a bug
                let result = executor.execute(&violation).await;
                if result.success {
                    let execution_sample = ExecutionSample {
                        inputs: violation.clone(),
                        outputs: result.outputs.clone(),
                    };
                    let spec_violated =
                        matches!(self.spec_holds(spec, &execution_sample, num_inputs), Some(false));
                    if !spec_violated {
                        continue;
                    }
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
                        class: None,
                    });
                    break; // One violation per spec is enough
                }
            }
        }

        SpecInferenceRunResult {
            samples_collected: samples.len(),
            inferred_specs: specs,
            findings,
        }
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
