//! Mock circuit executor for testing
//!
//! Provides a mock implementation of CircuitExecutor that simulates
//! circuit execution without requiring actual ZK backends.

use super::{
    CircuitExecutor, ConstraintEquation, ConstraintInspector, ConstraintResult, ExecutionCoverage,
    ExecutionResult, CircuitInfo,
};
use crate::config::Framework;
use crate::fuzzer::FieldElement;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Mock circuit executor for testing without real ZK backends
pub struct MockCircuitExecutor {
    name: String,
    framework: Framework,
    circuit_path: Option<String>,
    num_constraints: usize,
    num_private_inputs: usize,
    num_public_inputs: usize,
    num_outputs: usize,
    execution_count: AtomicUsize,
    /// Simulate underconstrained behavior
    simulate_underconstrained: bool,
    /// Probability of returning same output for different inputs (0.0-1.0)
    collision_probability: f64,
}

impl MockCircuitExecutor {
    pub fn new(name: &str, num_private_inputs: usize, num_public_inputs: usize) -> Self {
        Self {
            name: name.to_string(),
            framework: Framework::Mock,
            circuit_path: None,
            num_constraints: num_private_inputs + num_public_inputs, // Simple heuristic
            num_private_inputs,
            num_public_inputs,
            num_outputs: 1,
            execution_count: AtomicUsize::new(0),
            simulate_underconstrained: false,
            collision_probability: 0.0,
        }
    }

    /// Set the framework type (for simulating specific backends)
    pub fn with_framework(mut self, framework: Framework) -> Self {
        self.framework = framework;
        self
    }

    /// Set the circuit path
    pub fn with_circuit_path(mut self, path: &str) -> Self {
        self.circuit_path = Some(path.to_string());
        self
    }

    /// Set number of constraints
    pub fn with_constraints(mut self, num_constraints: usize) -> Self {
        self.num_constraints = num_constraints;
        self
    }

    /// Set number of outputs
    pub fn with_outputs(mut self, num_outputs: usize) -> Self {
        self.num_outputs = num_outputs;
        self
    }

    /// Enable simulation of underconstrained behavior
    pub fn with_underconstrained(mut self, enabled: bool) -> Self {
        self.simulate_underconstrained = enabled;
        self
    }

    /// Set collision probability for testing collision detection
    pub fn with_collision_probability(mut self, probability: f64) -> Self {
        self.collision_probability = probability.clamp(0.0, 1.0);
        self
    }

    /// Get the number of executions performed
    pub fn execution_count(&self) -> usize {
        self.execution_count.load(Ordering::Relaxed)
    }

    /// Simulate constraint evaluation and generate coverage
    fn simulate_coverage(&self, inputs: &[FieldElement]) -> ExecutionCoverage {
        // Simulate which constraints are hit based on input values
        let mut satisfied = Vec::new();
        let mut evaluated = Vec::new();

        for i in 0..self.num_constraints {
            evaluated.push(i);

            // Simulate constraint satisfaction based on input hash
            let mut hasher = Sha256::new();
            hasher.update([i as u8]);
            for input in inputs {
                hasher.update(input.0);
            }
            let hash = hasher.finalize();

            // Constraint is "satisfied" if first byte of hash is even
            if hash[0] % 2 == 0 {
                satisfied.push(i);
            }
        }

        ExecutionCoverage::with_constraints(satisfied, evaluated)
    }

    /// Compute mock output based on inputs
    fn compute_output(&self, inputs: &[FieldElement]) -> Vec<FieldElement> {
        let mut outputs = Vec::with_capacity(self.num_outputs);

        for output_idx in 0..self.num_outputs {
            let mut hasher = Sha256::new();
            hasher.update([output_idx as u8]);

            // If simulating underconstrained, only hash first input
            if self.simulate_underconstrained && !inputs.is_empty() {
                hasher.update(inputs[0].0);
            } else {
                for input in inputs {
                    hasher.update(input.0);
                }
            }

            let hash = hasher.finalize();
            let mut output_bytes = [0u8; 32];
            output_bytes.copy_from_slice(&hash);

            // Apply collision simulation if enabled
            // Higher probability = more aggressive truncation = more collisions
            if self.collision_probability > 0.0 {
                // For high collision probability, we only keep a few bits of entropy
                // This guarantees collisions for values in same "bucket"
                let keep_bytes = ((1.0 - self.collision_probability) * 32.0) as usize;
                let keep_bytes = keep_bytes.max(1).min(32);
                
                // Zero out most bytes, keeping only a small portion
                for i in keep_bytes..32 {
                    output_bytes[i] = 0;
                }
                
                // For very high collision probability, also reduce remaining entropy
                if self.collision_probability > 0.8 && keep_bytes <= 4 {
                    // Mask to only keep a few bits
                    output_bytes[0] &= 0x0F; // Only 16 possible values
                }
            }

            outputs.push(FieldElement(output_bytes));
        }

        outputs
    }
}

impl ConstraintInspector for MockCircuitExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        let total_inputs = self.num_public_inputs + self.num_private_inputs;
        let output_base = total_inputs;

        if total_inputs == 0 {
            return Vec::new();
        }

        (0..self.num_constraints)
            .map(|i| {
                let a_idx = i % total_inputs;
                let b_idx = (i + 1) % total_inputs;
                let c_idx = output_base + (i % self.num_outputs.max(1));

                ConstraintEquation {
                    id: i,
                    a_terms: vec![(a_idx, FieldElement::one())],
                    b_terms: vec![(b_idx, FieldElement::one())],
                    c_terms: vec![(c_idx, FieldElement::one())],
                    description: Some("mock constraint".to_string()),
                }
            })
            .collect()
    }

    fn check_constraints(&self, _witness: &[FieldElement]) -> Vec<ConstraintResult> {
        self.get_constraints()
            .iter()
            .map(|c| ConstraintResult {
                constraint_id: c.id,
                satisfied: true,
                lhs_value: FieldElement::one(),
                rhs_value: FieldElement::one(),
            })
            .collect()
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        self.get_constraints()
            .iter()
            .map(|c| {
                let mut deps: Vec<usize> = c
                    .a_terms
                    .iter()
                    .chain(c.b_terms.iter())
                    .chain(c.c_terms.iter())
                    .map(|(idx, _)| *idx)
                    .collect();
                deps.sort_unstable();
                deps.dedup();
                deps
            })
            .collect()
    }
}

#[async_trait]
impl CircuitExecutor for MockCircuitExecutor {
    fn framework(&self) -> Framework {
        self.framework
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: self.name.clone(),
            num_constraints: self.num_constraints,
            num_private_inputs: self.num_private_inputs,
            num_public_inputs: self.num_public_inputs,
            num_outputs: self.num_outputs,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        let start = Instant::now();
        self.execution_count.fetch_add(1, Ordering::Relaxed);

        // Compute output
        let outputs = self.compute_output(inputs);

        // Generate coverage information
        let coverage = self.simulate_coverage(inputs);

        ExecutionResult::success(outputs, coverage)
            .with_time(start.elapsed().as_micros() as u64)
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        // Mock proof: hash the witness
        let mut hasher = Sha256::new();
        for w in witness {
            hasher.update(w.0);
        }
        let hash = hasher.finalize();

        // Create a mock proof with some structure
        let mut proof = vec![0u8; 256];
        proof[0..32].copy_from_slice(&hash);
        // Add some "structure" to make it look like a real proof
        proof[32] = 0x01; // Version byte
        proof[33..65].copy_from_slice(&hash); // Duplicate for padding

        Ok(proof)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        // Mock verification: check proof structure and input commitment
        if proof.len() < 64 {
            return Ok(false);
        }

        // Check that version byte is correct
        if proof[32] != 0x01 {
            return Ok(false);
        }

        // Check that public inputs are non-empty (basic sanity check)
        if public_inputs.is_empty() {
            return Ok(false);
        }

        // Verify input commitment matches
        // This makes soundness testing meaningful in mock mode
        let mut hasher = Sha256::new();
        for input in public_inputs {
            hasher.update(input.0);
        }
        let input_hash = hasher.finalize();

        // Proof is valid only if first 32 bytes match input hash
        // This ensures proofs generated for one set of inputs
        // won't verify for different inputs
        Ok(&proof[0..32] == input_hash.as_slice())
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }
}

/// Create a mock executor that simulates an underconstrained circuit
pub fn create_underconstrained_mock(name: &str) -> MockCircuitExecutor {
    MockCircuitExecutor::new(name, 10, 2)
        .with_constraints(5) // Fewer constraints than inputs = underconstrained
        .with_underconstrained(true)
}

/// Create a mock executor that simulates collision-prone circuits
pub fn create_collision_mock(name: &str, collision_rate: f64) -> MockCircuitExecutor {
    MockCircuitExecutor::new(name, 10, 2)
        .with_collision_probability(collision_rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_executor_basic() {
        let executor = MockCircuitExecutor::new("test", 5, 2);

        assert_eq!(executor.name(), "test");
        assert_eq!(executor.num_private_inputs(), 5);
        assert_eq!(executor.num_public_inputs(), 2);
        assert_eq!(executor.framework(), Framework::Mock);
    }

    #[test]
    fn test_mock_execution() {
        let executor = MockCircuitExecutor::new("test", 2, 1);
        let inputs = vec![FieldElement::zero(), FieldElement::one()];

        let result = executor.execute_sync(&inputs);
        assert!(result.success);
        assert!(!result.outputs.is_empty());
        assert!(result.execution_time_us >= 0);
    }

    #[test]
    fn test_execution_count() {
        let executor = MockCircuitExecutor::new("test", 2, 1);
        let inputs = vec![FieldElement::zero()];

        assert_eq!(executor.execution_count(), 0);

        executor.execute_sync(&inputs);
        assert_eq!(executor.execution_count(), 1);

        executor.execute_sync(&inputs);
        executor.execute_sync(&inputs);
        assert_eq!(executor.execution_count(), 3);
    }

    #[test]
    fn test_underconstrained_detection() {
        let constrained = MockCircuitExecutor::new("test", 5, 2)
            .with_constraints(10);
        assert!(!constrained.is_likely_underconstrained());

        let underconstrained = MockCircuitExecutor::new("test", 10, 2)
            .with_constraints(5);
        assert!(underconstrained.is_likely_underconstrained());
    }

    #[test]
    fn test_proof_verification() {
        let executor = MockCircuitExecutor::new("test", 2, 1);
        let witness = vec![FieldElement::one()];

        let proof = executor.prove(&witness).unwrap();
        assert_eq!(proof.len(), 256);

        let public_inputs = vec![FieldElement::one()];
        let verified = executor.verify(&proof, &public_inputs).unwrap();
        assert!(verified);
    }
}
