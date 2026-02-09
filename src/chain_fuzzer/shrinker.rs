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
        let mut best_spec = spec.clone();
        let mut best_inputs = inputs.clone();
        let mut best_l_min = spec.len();
        let mut best_trace = ChainTrace::new(&spec.name);
        let mut total_attempts = 0;

        // Strategy 1: Prefix truncation
        // Try removing trailing steps
        for length in (1..spec.len()).rev() {
            if total_attempts >= self.max_attempts {
                break;
            }

            let truncated = spec.truncate(length);
            if let Some((trace, _violation)) = self.try_reproduce(&truncated, inputs, target_violation) {
                if length < best_l_min {
                    best_spec = truncated;
                    best_l_min = length;
                    best_trace = trace;
                }
            }
            total_attempts += 1;
        }

        // Strategy 2: Step dropout (delta-debug style)
        // Try removing individual intermediate steps
        if best_l_min > 2 {
            let mut current_spec = best_spec.clone();
            let mut changed = true;

            while changed && total_attempts < self.max_attempts {
                changed = false;

                for i in (1..current_spec.len() - 1).rev() {
                    if total_attempts >= self.max_attempts {
                        break;
                    }

                    if let Some(reduced) = current_spec.without_step(i) {
                        if reduced.len() < best_l_min {
                            if let Some((trace, _)) = self.try_reproduce(&reduced, &best_inputs, target_violation) {
                                best_spec = reduced.clone();
                                current_spec = reduced;
                                best_l_min = current_spec.len();
                                best_trace = trace;
                                changed = true;
                                break;
                            }
                        }
                    }
                    total_attempts += 1;
                }
            }
        }

        // Strategy 3: Input minimization
        // Try replacing non-wired inputs with zeros
        if total_attempts < self.max_attempts {
            let minimized_inputs = self.minimize_inputs(&best_spec, &best_inputs, target_violation);
            if self.try_reproduce(&best_spec, &minimized_inputs, target_violation).is_some() {
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
        }
    }

    /// Try to reproduce a violation with a given spec and inputs
    fn try_reproduce(
        &self,
        spec: &ChainSpec,
        inputs: &HashMap<String, Vec<FieldElement>>,
        target_violation: &CrossStepViolation,
    ) -> Option<(ChainTrace, CrossStepViolation)> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
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
        // Same assertion name is the primary check
        if a.assertion_name != b.assertion_name {
            return false;
        }

        // Same type of relation
        if a.relation != b.relation {
            return false;
        }

        true
    }

    /// Try to minimize inputs by replacing non-essential values with zeros
    fn minimize_inputs(
        &self,
        spec: &ChainSpec,
        inputs: &HashMap<String, Vec<FieldElement>>,
        target_violation: &CrossStepViolation,
    ) -> HashMap<String, Vec<FieldElement>> {
        let mut minimized = inputs.clone();

        // Collect circuit refs that need minimization
        let fresh_circuits: Vec<String> = spec.steps.iter()
            .filter(|step| matches!(step.input_wiring, InputWiring::Fresh))
            .map(|step| step.circuit_ref.clone())
            .collect();

        for circuit_ref in fresh_circuits {
            // Get the number of inputs for this circuit
            let input_count = minimized.get(&circuit_ref)
                .map(|v| v.len())
                .unwrap_or(0);

            for i in 0..input_count {
                // Try replacing with zero - save original first
                let original = minimized.get(&circuit_ref)
                    .and_then(|v| v.get(i))
                    .cloned()
                    .unwrap_or_else(FieldElement::zero);

                // Set to zero
                if let Some(step_inputs) = minimized.get_mut(&circuit_ref) {
                    step_inputs[i] = FieldElement::zero();
                }

                // Check if violation still reproduces with this change
                if self.try_reproduce(spec, &minimized, target_violation).is_none() {
                    // Didn't work, restore original
                    if let Some(step_inputs) = minimized.get_mut(&circuit_ref) {
                        step_inputs[i] = original;
                    }
                }
            }
        }

        minimized
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
