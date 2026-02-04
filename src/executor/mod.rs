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

use crate::config::Framework;
use crate::fuzzer::FieldElement;
use std::sync::Arc;

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
                // For now, use mock with circom-like behavior
                // TODO: Integrate actual circom compiler
                tracing::warn!("Circom backend not fully implemented, using mock executor");
                Ok(Arc::new(MockCircuitExecutor::new(main_component, 10, 2)
                    .with_framework(Framework::Circom)
                    .with_circuit_path(circuit_path)))
            }
            Framework::Noir => {
                tracing::warn!("Noir backend not fully implemented, using mock executor");
                Ok(Arc::new(MockCircuitExecutor::new(main_component, 10, 2)
                    .with_framework(Framework::Noir)
                    .with_circuit_path(circuit_path)))
            }
            Framework::Halo2 => {
                tracing::warn!("Halo2 backend not fully implemented, using mock executor");
                Ok(Arc::new(MockCircuitExecutor::new(main_component, 10, 2)
                    .with_framework(Framework::Halo2)
                    .with_circuit_path(circuit_path)))
            }
            Framework::Cairo => {
                anyhow::bail!("Cairo backend not yet implemented")
            }
        }
    }

    /// Create a mock executor for testing
    pub fn create_mock(name: &str, private_inputs: usize, public_inputs: usize) -> Arc<dyn CircuitExecutor> {
        Arc::new(MockCircuitExecutor::new(name, private_inputs, public_inputs))
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
