//! Circuit execution abstraction layer
//!
//! Provides a unified interface for executing ZK circuits across different backends.
//! Separates mock execution from real circuit execution for testing and production use.

mod traits;
mod mock;
mod coverage;

pub use traits::*;
pub use mock::*;
pub use coverage::*;

// Re-export CircuitInfo for external use
pub use crate::attacks::CircuitInfo;

use async_trait::async_trait;
use crate::config::Framework;
use crate::fuzzer::FieldElement;
use std::sync::{Arc, OnceLock};

/// Factory for creating circuit executors based on framework type
pub struct ExecutorFactory;

impl ExecutorFactory {
    /// Create an executor for the given framework and circuit
    pub fn create(
        framework: Framework,
        circuit_path: &str,
        main_component: &str,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        match framework {
            Framework::Mock => Ok(Arc::new(MockCircuitExecutor::new(
                main_component,
                10, // default private inputs
                2,  // default public inputs
            ))),
            Framework::Circom => {
                Self::create_circom_executor(circuit_path, main_component)
            }
            Framework::Noir => {
                Self::create_noir_executor(circuit_path, main_component)
            }
            Framework::Halo2 => {
                Self::create_halo2_executor(circuit_path, main_component)
            }
            Framework::Cairo => {
                Self::create_cairo_executor(circuit_path, main_component)
            }
        }
    }

    /// Create a Circom executor
    fn create_circom_executor(
        circuit_path: &str,
        main_component: &str,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        use crate::targets::CircomTarget;

        // Check if circom is available
        match CircomTarget::check_circom_available() {
            Ok(version) => {
                tracing::info!("Using Circom backend: {}", version);
                let executor = CircomExecutor::new(circuit_path, main_component)?;
                Ok(Arc::new(executor))
            }
            Err(e) => {
                tracing::warn!("Circom not available ({}), using mock executor", e);
                Ok(Arc::new(MockCircuitExecutor::new(main_component, 10, 2)
                    .with_framework(Framework::Circom)
                    .with_circuit_path(circuit_path)))
            }
        }
    }

    /// Create a Noir executor
    fn create_noir_executor(
        circuit_path: &str,
        main_component: &str,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        use crate::targets::NoirTarget;

        match NoirTarget::check_nargo_available() {
            Ok(version) => {
                tracing::info!("Using Noir backend: {}", version);
                let executor = NoirExecutor::new(circuit_path)?;
                Ok(Arc::new(executor))
            }
            Err(e) => {
                tracing::warn!("Nargo not available ({}), using mock executor", e);
                Ok(Arc::new(MockCircuitExecutor::new(main_component, 10, 2)
                    .with_framework(Framework::Noir)
                    .with_circuit_path(circuit_path)))
            }
        }
    }

    /// Create a Halo2 executor
    fn create_halo2_executor(
        circuit_path: &str,
        main_component: &str,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        let executor = Halo2Executor::new(circuit_path, main_component)?;
        Ok(Arc::new(executor))
    }

    /// Create a Cairo executor
    fn create_cairo_executor(
        circuit_path: &str,
        main_component: &str,
    ) -> anyhow::Result<Arc<dyn CircuitExecutor>> {
        use crate::targets::CairoTarget;

        match CairoTarget::check_cairo_available() {
            Ok((version, ver_str)) => {
                tracing::info!("Using Cairo backend ({:?}): {}", version, ver_str);
                let executor = CairoExecutor::new(circuit_path)?;
                Ok(Arc::new(executor))
            }
            Err(e) => {
                tracing::warn!("Cairo not available ({}), using mock executor", e);
                Ok(Arc::new(MockCircuitExecutor::new(main_component, 10, 2)
                    .with_framework(Framework::Cairo)
                    .with_circuit_path(circuit_path)))
            }
        }
    }

    /// Create a mock executor for testing
    pub fn create_mock(name: &str, private_inputs: usize, public_inputs: usize) -> Arc<dyn CircuitExecutor> {
        Arc::new(MockCircuitExecutor::new(name, private_inputs, public_inputs))
    }
}

/// Circom executor wrapper
pub struct CircomExecutor {
    target: crate::targets::CircomTarget,
    constraints: OnceLock<Vec<ConstraintEquation>>,
}

impl CircomExecutor {
    pub fn new(circuit_path: &str, main_component: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::CircomTarget::new(circuit_path, main_component)?;
        target.compile()?;
        Ok(Self {
            target,
            constraints: OnceLock::new(),
        })
    }
}

#[async_trait]
impl CircuitExecutor for CircomExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();
        
        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = ExecutionCoverage::with_output_hash(&outputs);
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }
}

impl ConstraintInspector for CircomExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        self.constraints
            .get_or_init(|| self.target.load_constraints().unwrap_or_default())
            .clone()
    }

    fn check_constraints(&self, witness: &[FieldElement]) -> Vec<ConstraintResult> {
        fn eval_linear(terms: &[(usize, FieldElement)], witness: &[FieldElement]) -> FieldElement {
            let mut acc = FieldElement::zero();
            for (idx, coeff) in terms {
                if let Some(value) = witness.get(*idx) {
                    acc = acc.add(&value.mul(coeff));
                }
            }
            acc
        }

        self.get_constraints()
            .iter()
            .map(|c| {
                let a_val = eval_linear(&c.a_terms, witness);
                let b_val = eval_linear(&c.b_terms, witness);
                let c_val = eval_linear(&c.c_terms, witness);
                let lhs = a_val.mul(&b_val);
                ConstraintResult {
                    constraint_id: c.id,
                    satisfied: lhs == c_val,
                    lhs_value: lhs,
                    rhs_value: c_val,
                }
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

    fn public_input_indices(&self) -> Vec<usize> {
        self.target.public_input_indices()
    }

    fn private_input_indices(&self) -> Vec<usize> {
        self.target.private_input_indices()
    }

    fn output_indices(&self) -> Vec<usize> {
        self.target.output_signal_indices()
    }
}

/// Noir executor wrapper
pub struct NoirExecutor {
    target: crate::targets::NoirTarget,
}

impl NoirExecutor {
    pub fn new(project_path: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::NoirTarget::new(project_path)?;
        target.compile()?;
        Ok(Self { target })
    }
}

#[async_trait]
impl CircuitExecutor for NoirExecutor {
    fn framework(&self) -> Framework {
        Framework::Noir
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();
        
        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = ExecutionCoverage::with_output_hash(&outputs);
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }
}

impl ConstraintInspector for NoirExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        self.target.load_constraints().unwrap_or_default()
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

    fn public_input_indices(&self) -> Vec<usize> {
        self.target.public_input_indices()
    }

    fn private_input_indices(&self) -> Vec<usize> {
        self.target.private_input_indices()
    }

    fn output_indices(&self) -> Vec<usize> {
        self.target.output_signal_indices()
    }
}

/// Halo2 executor wrapper
pub struct Halo2Executor {
    target: crate::targets::Halo2Target,
}

impl Halo2Executor {
    pub fn new(circuit_path: &str, _main_component: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::Halo2Target::new(circuit_path)?;
        target.setup()?;
        Ok(Self { target })
    }
}

#[async_trait]
impl CircuitExecutor for Halo2Executor {
    fn framework(&self) -> Framework {
        Framework::Halo2
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();
        
        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = ExecutionCoverage::with_output_hash(&outputs);
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }
}

/// Cairo executor wrapper
pub struct CairoExecutor {
    target: crate::targets::CairoTarget,
}

impl CairoExecutor {
    pub fn new(source_path: &str) -> anyhow::Result<Self> {
        let mut target = crate::targets::CairoTarget::new(source_path)?;
        target.compile()?;
        Ok(Self { target })
    }
}

#[async_trait]
impl CircuitExecutor for CairoExecutor {
    fn framework(&self) -> Framework {
        Framework::Cairo
    }

    fn name(&self) -> &str {
        use crate::targets::TargetCircuit;
        self.target.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        use crate::targets::TargetCircuit;
        CircuitInfo {
            name: self.target.name().to_string(),
            num_constraints: self.target.num_constraints(),
            num_private_inputs: self.target.num_private_inputs(),
            num_public_inputs: self.target.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        use crate::targets::TargetCircuit;
        let start = std::time::Instant::now();
        
        match self.target.execute(inputs) {
            Ok(outputs) => {
                let coverage = ExecutionCoverage::with_output_hash(&outputs);
                ExecutionResult::success(outputs, coverage)
                    .with_time(start.elapsed().as_micros() as u64)
            }
            Err(e) => ExecutionResult::failure(e.to_string()),
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use crate::targets::TargetCircuit;
        self.target.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        use crate::targets::TargetCircuit;
        self.target.verify(proof, public_inputs)
    }
}

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
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ]);

        Self {
            coverage_hash,
            ..Default::default()
        }
    }

    pub fn with_constraints(satisfied: Vec<usize>, evaluated: Vec<usize>) -> Self {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        satisfied.hash(&mut hasher);
        let coverage_hash = hasher.finish();

        Self {
            satisfied_constraints: satisfied,
            evaluated_constraints: evaluated,
            new_coverage: false,
            coverage_hash,
        }
    }

    pub fn mark_new_coverage(&mut self) {
        self.new_coverage = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_factory_mock() {
        let executor = ExecutorFactory::create(
            Framework::Mock,
            "test.circom",
            "TestCircuit",
        ).unwrap();

        assert_eq!(executor.name(), "TestCircuit");
        assert_eq!(executor.framework(), Framework::Mock);
    }

    #[test]
    fn test_execution_result() {
        let result = ExecutionResult::success(
            vec![FieldElement::one()],
            ExecutionCoverage::default(),
        );
        assert!(result.success);
        assert!(result.error.is_none());

        let failure = ExecutionResult::failure("test error".to_string());
        assert!(!failure.success);
        assert_eq!(failure.error, Some("test error".to_string()));
    }
}
