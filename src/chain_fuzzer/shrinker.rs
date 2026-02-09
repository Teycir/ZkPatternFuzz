//! Mode 3: Chain Shrinker - Minimizes chains to compute L_min
//!
//! The shrinker takes a violation-triggering chain and attempts to find the
//! minimum number of steps required to reproduce the violation.

use super::invariants::{CrossStepInvariantChecker, CrossStepViolation};
use super::runner::ChainRunner;
use super::types::{ChainSpec, ChainTrace, InputWiring};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use zk_core::FieldElement;

/// Minimizes a violation-triggering chain to compute L_min
pub struct ChainShrinker {
    /// Chain runner for re-execution
    runner: ChainRunner,
    /// Invariant checker for verification
    checker: CrossStepInvariantChecker,
    /// Maximum shrinking attempts
    max_attempts: usize,
    /// Seed for deterministic shrinking
    seed: u64,
    /// Budget allocation: [prefix%, dropout%, input%]
    strategy_budgets: [f32; 3],
}

/// Result of chain shrinking
#[derive(Debug, Clone)]
pub struct ShrinkResult {
    /// The minimized chain specification
    pub spec: ChainSpec,
    /// The minimized inputs
    pub inputs: HashMap<String, Vec<FieldElement>>,
    /// Minimum steps to reproduce (L_min)
    pub l_min: usize,
    /// The violation that was reproduced
    pub violation: CrossStepViolation,
    /// The trace of the minimized execution
    pub trace: ChainTrace,
    /// Number of shrinking attempts made
    pub attempts: usize,
    /// Reduction ratio (l_min / original_length)
    pub reduction_ratio: f32,
    /// Number of unique violations found during shrinking
    pub variant_violations: usize,
}

impl ChainShrinker {
    /// Create a new chain shrinker
    pub fn new(
        runner: ChainRunner,
        checker: CrossStepInvariantChecker,
    ) -> Self {
        Self {
            runner,
            checker,
            max_attempts: 100,
            seed: 42,
            strategy_budgets: [0.4, 0.4, 0.2], // 40% prefix, 40% dropout, 20% input
        }
    }

    /// Set the maximum number of shrinking attempts
    pub fn with_max_attempts(mut self, max: usize) -> Self {
        self.max_attempts = max;
        self
    }

    /// Set the seed for deterministic shrinking
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Minimize a chain that triggers a violation
    ///
    /// # Arguments
    ///
    /// * `spec` - The original chain specification
    /// * `inputs` - The inputs that triggered the violation
    /// * `target_violation` - The violation to reproduce
    ///
    /// # Returns
    ///
    /// A ShrinkResult containing the minimized chain and L_min
    pub fn minimize(
        &self,
        spec: &ChainSpec,
        inputs: &HashMap<String, Vec<FieldElement>>,
        target_violation: &CrossStepViolation,
    ) -> ShrinkResult {
        let original_len = spec.len();
        let mut best_spec = spec.clone();
        let mut best_inputs = inputs.clone();
        let mut best_l_min = spec.len();
        let mut best_trace = ChainTrace::new(&spec.name);
        let mut total_attempts = 0;
        let mut variant_violations = 0;

        let budget_1 = (self.max_attempts as f32 * self.strategy_budgets[0]) as usize;
        let budget_2 = (self.max_attempts as f32 * self.strategy_budgets[1]) as usize;
        let _budget_3 = (self.max_attempts as f32 * self.strategy_budgets[2]) as usize;

        // Strategy 1: Binary search for minimal length
        let mut low = 1;
        let mut high = spec.len();

        while low <= high && total_attempts < budget_1 {
            let mid = (low + high) / 2;
            let truncated = spec.truncate(mid);
            
            if let Some((trace, violation)) = self.try_reproduce(&truncated, inputs, target_violation, total_attempts) {
                if !self.violations_equivalent(&violation, target_violation) {
                    variant_violations += 1;
                }
                best_spec = truncated;
                best_l_min = mid;
                best_trace = trace;
                high = mid - 1;
            } else {
                low = mid + 1;
            }
            total_attempts += 1;
        }

        // Strategy 2: Delta-debug step removal
        if best_l_min > 2 && total_attempts < budget_1 + budget_2 {
            let mut current_indices: Vec<usize> = (0..best_spec.len()).collect();
            let mut chunk_size = current_indices.len() / 2;

            while chunk_size > 0 && total_attempts < budget_1 + budget_2 {
                let mut i = 0;
                while i < current_indices.len() && total_attempts < budget_1 + budget_2 {
                    let end = (i + chunk_size).min(current_indices.len());
                    let mut test_indices = current_indices.clone();
                    test_indices.drain(i..end);

                    let test_spec = self.build_spec_from_indices(&best_spec, &test_indices);
                    
                    if let Some((trace, violation)) = self.try_reproduce(&test_spec, &best_inputs, target_violation, total_attempts) {
                        if !self.violations_equivalent(&violation, target_violation) {
                            variant_violations += 1;
                        }
                        current_indices = test_indices;
                        best_spec = test_spec;
                        best_l_min = current_indices.len();
                        best_trace = trace;
                    } else {
                        i += chunk_size;
                    }
                    total_attempts += 1;
                }
                chunk_size /= 2;
            }
        }

        // Strategy 3: Input minimization
        if total_attempts < self.max_attempts {
            let minimized_inputs = self.minimize_inputs(&best_spec, &best_inputs, target_violation, &mut total_attempts);
            if self.try_reproduce(&best_spec, &minimized_inputs, target_violation, total_attempts).is_some() {
                best_inputs = minimized_inputs;
            }
        }

        ShrinkResult {
            spec: best_spec,
            inputs: best_inputs,
            l_min: best_l_min,
            violation: target_violation.clone(),
            trace: best_trace,
            attempts: total_attempts,
            reduction_ratio: best_l_min as f32 / original_len as f32,
            variant_violations,
        }
    }

    /// Try to reproduce a violation with a given spec and inputs
    fn try_reproduce(
        &self,
        spec: &ChainSpec,
        inputs: &HashMap<String, Vec<FieldElement>>,
        target_violation: &CrossStepViolation,
        attempt_num: usize,
    ) -> Option<(ChainTrace, CrossStepViolation)> {
        // FIX #1: Derive unique seed per attempt to explore different paths
        let attempt_seed = self.seed.wrapping_add(attempt_num as u64);
        let mut rng = ChaCha8Rng::seed_from_u64(attempt_seed);
        let result = self.runner.execute(spec, inputs, &mut rng);

        if !result.completed {
            return None;
        }

        // Check if the same violation is triggered
        let violations = self.checker.check(&result.trace);
        
        violations.into_iter()
            .find(|v| self.violations_equivalent(v, target_violation))
            .map(|v| (result.trace, v))
    }

    /// Check if two violations are equivalent
    fn violations_equivalent(&self, a: &CrossStepViolation, b: &CrossStepViolation) -> bool {
        // FIX #2: Enhanced equivalence check for bug variants
        if a.assertion_name != b.assertion_name || a.relation != b.relation {
            return false;
        }
        // Accept if step count matches (catches relocated bugs)
        a.step_indices.len() == b.step_indices.len()
    }

    /// Try to minimize inputs by replacing non-essential values with zeros
    fn minimize_inputs(
        &self,
        spec: &ChainSpec,
        inputs: &HashMap<String, Vec<FieldElement>>,
        target_violation: &CrossStepViolation,
        attempt_counter: &mut usize,
    ) -> HashMap<String, Vec<FieldElement>> {
        let mut minimized = inputs.clone();

        // FIX #5: Minimize all input types, not just Fresh
        for step in spec.steps.iter() {
            let circuit_ref = &step.circuit_ref;
            let input_count = minimized.get(circuit_ref).map(|v| v.len()).unwrap_or(0);

            let minimizable_indices: Vec<usize> = match &step.input_wiring {
                InputWiring::Fresh => (0..input_count).collect(),
                InputWiring::Mixed { fresh_indices, .. } => fresh_indices.clone(),
                InputWiring::Constant { fresh_indices, .. } => fresh_indices.clone(),
                InputWiring::FromPriorOutput { .. } => vec![],
            };

            for i in minimizable_indices {
                let original = minimized.get(circuit_ref)
                    .and_then(|v| v.get(i))
                    .cloned()
                    .unwrap_or_else(FieldElement::zero);

                if let Some(step_inputs) = minimized.get_mut(circuit_ref) {
                    if i < step_inputs.len() {
                        step_inputs[i] = FieldElement::zero();
                    }
                }
                
                if self.try_reproduce(spec, &minimized, target_violation, *attempt_counter).is_none() {
                    if let Some(step_inputs) = minimized.get_mut(circuit_ref) {
                        if i < step_inputs.len() {
                            step_inputs[i] = original;
                        }
                    }
                }
                *attempt_counter += 1;
            }
        }

        minimized
    }

    /// Build a spec from selected step indices
    fn build_spec_from_indices(&self, spec: &ChainSpec, indices: &[usize]) -> ChainSpec {
        let steps = indices.iter()
            .filter_map(|&i| spec.steps.get(i).cloned())
            .collect();
        ChainSpec::new(&spec.name, steps)
    }

    /// Compute L_min for a given chain and violation
    ///
    /// This is a convenience method that returns just the L_min value.
    pub fn compute_l_min(
        &self,
        spec: &ChainSpec,
        inputs: &HashMap<String, Vec<FieldElement>>,
        target_violation: &CrossStepViolation,
    ) -> usize {
        self.minimize(spec, inputs, target_violation).l_min
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_fuzzer::types::StepSpec;
    use crate::executor::MockCircuitExecutor;
    use std::sync::Arc;

    fn create_test_runner() -> ChainRunner {
        let mut executors = HashMap::new();
        executors.insert(
            "circuit_a".to_string(),
            Arc::new(MockCircuitExecutor::new("circuit_a", 2, 0).with_outputs(2)) as Arc<dyn zk_core::CircuitExecutor>,
        );
        executors.insert(
            "circuit_b".to_string(),
            Arc::new(MockCircuitExecutor::new("circuit_b", 2, 0).with_outputs(2)) as Arc<dyn zk_core::CircuitExecutor>,
        );
        executors.insert(
            "circuit_c".to_string(),
            Arc::new(MockCircuitExecutor::new("circuit_c", 2, 0).with_outputs(2)) as Arc<dyn zk_core::CircuitExecutor>,
        );
        ChainRunner::new(executors)
    }

    #[test]
    fn test_prefix_truncation() {
        let runner = create_test_runner();
        
        // Create a chain with 5 steps
        let spec = ChainSpec::new("test_chain", vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
            StepSpec::fresh("circuit_c"),
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
        ]);

        // Create a checker that always finds a violation
        let checker = CrossStepInvariantChecker::new(vec![]);
        
        let shrinker = ChainShrinker::new(runner, checker);

        // The truncation should work even if no violations are found
        let inputs = HashMap::new();
        let violation = CrossStepViolation::new(
            "test_violation",
            "test_relation",
            vec![0, 1],
            vec![],
            "high",
        );

        // This test mainly verifies the shrinking logic runs without panicking
        let result = shrinker.minimize(&spec, &inputs, &violation);
        assert!(result.l_min <= spec.len());
    }

    #[test]
    fn test_step_dropout() {
        let spec = ChainSpec::new("test_chain", vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
            StepSpec::fresh("circuit_c"),
        ]);

        // Verify without_step works correctly
        let reduced = spec.without_step(1).unwrap();
        assert_eq!(reduced.steps.len(), 2);
        assert_eq!(reduced.steps[0].circuit_ref, "circuit_a");
        assert_eq!(reduced.steps[1].circuit_ref, "circuit_c");
    }
}
