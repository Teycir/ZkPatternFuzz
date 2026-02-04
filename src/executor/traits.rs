//! Circuit executor traits
//!
//! Defines the core abstraction for executing ZK circuits across different backends.

use super::ExecutionResult;
use crate::config::Framework;
use crate::fuzzer::FieldElement;
use async_trait::async_trait;
use std::sync::Arc;

// Re-export CircuitInfo from attacks for convenience
pub use crate::attacks::CircuitInfo;

/// Core trait for circuit execution
///
/// This trait abstracts the execution of ZK circuits, allowing the fuzzer
/// to work with different backends (Circom, Noir, Halo2, etc.) through
/// a unified interface.
#[async_trait]
pub trait CircuitExecutor: Send + Sync {
    /// Get the framework type
    fn framework(&self) -> Framework;

    /// Get circuit name
    fn name(&self) -> &str;

    /// Get circuit information (constraints, inputs, outputs)
    fn circuit_info(&self) -> CircuitInfo;

    /// Execute the circuit with given inputs synchronously
    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult;

    /// Execute the circuit with given inputs asynchronously
    async fn execute(&self, inputs: &[FieldElement]) -> ExecutionResult {
        self.execute_sync(inputs)
    }

    /// Generate a proof for the given witness
    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>>;

    /// Verify a proof with public inputs
    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool>;

    /// Get the number of constraints in the circuit
    fn num_constraints(&self) -> usize {
        self.circuit_info().num_constraints
    }

    /// Get the number of private inputs
    fn num_private_inputs(&self) -> usize {
        self.circuit_info().num_private_inputs
    }

    /// Get the number of public inputs
    fn num_public_inputs(&self) -> usize {
        self.circuit_info().num_public_inputs
    }

    /// Check if the circuit is properly constrained (heuristic)
    fn is_likely_underconstrained(&self) -> bool {
        self.circuit_info().is_likely_underconstrained()
    }
}

/// Trait for executors that support witness extraction
pub trait WitnessExtractor: CircuitExecutor {
    /// Calculate the full witness for given inputs
    fn calculate_witness(&self, inputs: &[FieldElement]) -> anyhow::Result<Vec<FieldElement>>;

    /// Extract public outputs from a full witness
    fn extract_outputs(&self, witness: &[FieldElement]) -> Vec<FieldElement>;

    /// Extract intermediate signals from a full witness
    fn extract_signals(&self, witness: &[FieldElement]) -> Vec<(String, FieldElement)>;
}

/// Trait for executors that support constraint inspection
pub trait ConstraintInspector: CircuitExecutor {
    /// Get all constraint equations
    fn get_constraints(&self) -> Vec<ConstraintEquation>;

    /// Check which constraints are satisfied by a given witness
    fn check_constraints(&self, witness: &[FieldElement]) -> Vec<ConstraintResult>;

    /// Get constraint dependencies (which signals each constraint uses)
    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>>;
}

/// Representation of a constraint equation (A * B = C form for R1CS)
#[derive(Debug, Clone)]
pub struct ConstraintEquation {
    pub id: usize,
    pub a_terms: Vec<(usize, FieldElement)>, // (signal_index, coefficient)
    pub b_terms: Vec<(usize, FieldElement)>,
    pub c_terms: Vec<(usize, FieldElement)>,
    pub description: Option<String>,
}

/// Result of checking a single constraint
#[derive(Debug, Clone)]
pub struct ConstraintResult {
    pub constraint_id: usize,
    pub satisfied: bool,
    pub lhs_value: FieldElement,
    pub rhs_value: FieldElement,
}

/// Batch executor for parallel execution
#[async_trait]
pub trait BatchExecutor: CircuitExecutor {
    /// Execute multiple test cases in parallel
    async fn execute_batch(&self, inputs: &[Vec<FieldElement>]) -> Vec<ExecutionResult>;

    /// Get the recommended batch size for this executor
    fn recommended_batch_size(&self) -> usize {
        100
    }
}

/// Wrapper to make any CircuitExecutor into a BatchExecutor using Rayon
pub struct ParallelBatchExecutor {
    inner: Arc<dyn CircuitExecutor>,
    batch_size: usize,
}

impl ParallelBatchExecutor {
    pub fn new(executor: Arc<dyn CircuitExecutor>) -> Self {
        Self {
            inner: executor,
            batch_size: 100,
        }
    }

    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Execute a batch of inputs in parallel using Rayon
    pub fn execute_parallel(&self, inputs: &[Vec<FieldElement>]) -> Vec<ExecutionResult> {
        use rayon::prelude::*;

        inputs
            .par_iter()
            .map(|input| self.inner.execute_sync(input))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;

    #[test]
    fn test_parallel_batch_executor() {
        let mock = Arc::new(MockCircuitExecutor::new("test", 2, 1));
        let batch_executor = ParallelBatchExecutor::new(mock);

        let inputs = vec![
            vec![FieldElement::zero(), FieldElement::one()],
            vec![FieldElement::one(), FieldElement::zero()],
            vec![FieldElement::one(), FieldElement::one()],
        ];

        let results = batch_executor.execute_parallel(&inputs);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.success));
    }
}
