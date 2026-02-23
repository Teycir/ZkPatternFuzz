use crate::constants::bn254_modulus_bytes;
use crate::{CircuitInfo, FieldElement, Framework};
use async_trait::async_trait;
use std::sync::Arc;

/// Result of circuit execution with coverage information
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Output field elements
    pub outputs: Vec<FieldElement>,
    /// Constraint coverage information
    pub coverage: ExecutionCoverage,
    /// Execution time in microseconds
    pub execution_time_us: u64,
    /// Whether execution succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

impl ExecutionResult {
    pub fn success(outputs: Vec<FieldElement>, coverage: ExecutionCoverage) -> Self {
        Self {
            outputs,
            coverage,
            execution_time_us: 0,
            success: true,
            error: None,
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            outputs: vec![],
            coverage: ExecutionCoverage::default(),
            execution_time_us: 0,
            success: false,
            error: Some(error),
        }
    }

    pub fn with_time(mut self, time_us: u64) -> Self {
        self.execution_time_us = time_us;
        self
    }

    /// Phase 0 Fix: Check if execution resulted in a crash
    pub fn is_crash(&self) -> bool {
        if self.success {
            return false;
        }
        let Some(err) = &self.error else {
            return false;
        };
        let lower = err.to_lowercase();
        // Heuristic: only treat clear runtime failures as crashes.
        // Avoid classifying ordinary constraint/witness failures as crashes.
        let crash_markers = [
            "panic",
            "segfault",
            "segmentation fault",
            "sigsegv",
            "sigabrt",
            "stack overflow",
            "out of memory",
            "oom",
            "core dumped",
            "illegal instruction",
            "bus error",
        ];
        crash_markers.iter().any(|marker| lower.contains(marker))
    }

    /// Phase 0 Fix: Get error message if execution failed
    pub fn error_message(&self) -> Option<String> {
        self.error.clone()
    }
}

/// Coverage information from a single execution
#[derive(Debug, Clone, Default)]
pub struct ExecutionCoverage {
    /// Constraints that were satisfied
    pub satisfied_constraints: Vec<usize>,
    /// Constraints that were evaluated (may include unsatisfied)
    pub evaluated_constraints: Vec<usize>,
    /// New coverage discovered (constraints hit for first time)
    pub new_coverage: bool,
    /// Coverage bitmap for fast comparison
    pub coverage_hash: u64,
    /// Value buckets observed per constraint (constraint_id, bucket)
    pub value_buckets: Vec<(usize, u8)>,
}

impl ExecutionCoverage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_output_hash(outputs: &[FieldElement]) -> Self {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for fe in outputs {
            hasher.update(fe.0);
        }
        let hash = hasher.finalize();
        let coverage_hash = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);

        Self {
            coverage_hash,
            ..Self::default()
        }
    }

    pub fn with_constraints(satisfied: Vec<usize>, evaluated: Vec<usize>) -> Self {
        use sha2::{Digest, Sha256};

        let mut sorted = satisfied.clone();
        sorted.sort_unstable();
        let mut hasher = Sha256::new();
        for constraint in &sorted {
            hasher.update(constraint.to_le_bytes());
        }
        let hash = hasher.finalize();
        let coverage_hash = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);

        Self {
            satisfied_constraints: satisfied,
            evaluated_constraints: evaluated,
            new_coverage: false,
            coverage_hash,
            value_buckets: Vec::new(),
        }
    }

    pub fn mark_new_coverage(&mut self) {
        self.new_coverage = true;
    }
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

    /// Get constraint inspector if available
    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        None
    }

    /// Get the field modulus for this circuit's arithmetic
    ///
    /// # Phase 0 Fix
    ///
    /// This replaces the hardcoded BN254 modulus with a circuit-specific value.
    /// Different proving systems use different fields (BN254, BLS12-381, Pallas, etc.)
    fn field_modulus(&self) -> [u8; 32] {
        // Default to BN254 scalar field modulus for backwards compatibility
        // Implementations should override for their specific field
        bn254_modulus_bytes()
    }

    /// Get the field prime name (e.g., "bn254", "bls12-381", "pallas")
    fn field_name(&self) -> &str {
        "bn254"
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

    /// Get indices for public inputs in the witness/signal space
    fn public_input_indices(&self) -> Vec<usize> {
        (0..self.num_public_inputs()).collect()
    }

    /// Get indices for private inputs in the witness/signal space
    fn private_input_indices(&self) -> Vec<usize> {
        let total_inputs = self.num_private_inputs();
        let public_inputs = self.num_public_inputs().min(total_inputs);
        (public_inputs..total_inputs).collect()
    }

    /// Get indices for public outputs in the witness/signal space
    fn output_indices(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Get optional wire labels (index -> name) when available
    fn wire_labels(&self) -> std::collections::HashMap<usize, String> {
        std::collections::HashMap::new()
    }
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
