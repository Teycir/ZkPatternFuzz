//! Multi-backend executor wrapper for differential testing

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use zk_core::{CircuitExecutor, CircuitInfo, ExecutionResult, FieldElement, Framework};

/// Executor that runs inputs through multiple backends
pub struct MultiBackendExecutor {
    backends: HashMap<Framework, Arc<dyn CircuitExecutor>>,
    primary: Framework,
}

impl MultiBackendExecutor {
    pub fn new(primary: Framework) -> Self {
        Self {
            backends: HashMap::new(),
            primary,
        }
    }

    pub fn add_backend(&mut self, framework: Framework, executor: Arc<dyn CircuitExecutor>) {
        self.backends.insert(framework, executor);
    }

    /// Execute on all backends and return results
    pub fn execute_all(&self, inputs: &[FieldElement]) -> HashMap<Framework, ExecutionResult> {
        self.backends
            .iter()
            .map(|(framework, executor)| (*framework, executor.execute_sync(inputs)))
            .collect()
    }

    /// Execute on all backends in parallel
    pub fn execute_all_parallel(
        &self,
        inputs: &[FieldElement],
    ) -> HashMap<Framework, ExecutionResult> {
        use rayon::prelude::*;

        self.backends
            .par_iter()
            .map(|(framework, executor)| (*framework, executor.execute_sync(inputs)))
            .collect()
    }

    /// Check if all backends agree on the output
    pub fn check_agreement(&self, inputs: &[FieldElement]) -> BackendAgreement {
        let results = self.execute_all(inputs);

        let frameworks: Vec<_> = results.keys().cloned().collect();
        if frameworks.len() < 2 {
            return BackendAgreement::SingleBackend;
        }

        let first = &results[&frameworks[0]];
        let mut all_agree = true;
        let mut execution_mismatch = false;

        for framework in &frameworks[1..] {
            let result = &results[framework];

            if first.success != result.success {
                execution_mismatch = true;
                all_agree = false;
            } else if first.outputs != result.outputs {
                all_agree = false;
            }
        }

        if execution_mismatch {
            BackendAgreement::ExecutionMismatch(results)
        } else if all_agree {
            BackendAgreement::AllAgree
        } else {
            BackendAgreement::OutputMismatch(results)
        }
    }

    /// Get the primary backend's executor
    pub fn primary_executor(&self) -> Option<&Arc<dyn CircuitExecutor>> {
        self.backends.get(&self.primary)
    }

    fn require_primary_executor(&self) -> &Arc<dyn CircuitExecutor> {
        match self.backends.get(&self.primary) {
            Some(executor) => executor,
            None => panic!(
                "MultiBackendExecutor misconfigured: primary backend {:?} was not registered",
                self.primary
            ),
        }
    }
}

/// Result of checking backend agreement
#[derive(Debug)]
pub enum BackendAgreement {
    /// Only one backend configured
    SingleBackend,
    /// All backends agree
    AllAgree,
    /// Backends disagree on output values
    OutputMismatch(HashMap<Framework, ExecutionResult>),
    /// Backends disagree on execution success/failure
    ExecutionMismatch(HashMap<Framework, ExecutionResult>),
}

#[async_trait]
impl CircuitExecutor for MultiBackendExecutor {
    fn framework(&self) -> Framework {
        self.primary
    }

    fn name(&self) -> &str {
        self.require_primary_executor().name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        self.require_primary_executor().circuit_info()
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        self.require_primary_executor().execute_sync(inputs)
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        self.backends
            .get(&self.primary)
            .ok_or_else(|| anyhow::anyhow!("No primary backend"))?
            .prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        self.backends
            .get(&self.primary)
            .ok_or_else(|| anyhow::anyhow!("No primary backend"))?
            .verify(proof, public_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::FixtureCircuitExecutor;

    #[test]
    fn test_multi_backend_executor() {
        let mut multi = MultiBackendExecutor::new(Framework::Circom);
        multi.add_backend(
            Framework::Circom,
            Arc::new(FixtureCircuitExecutor::new("test", 2, 1)),
        );
        multi.add_backend(
            Framework::Noir,
            Arc::new(FixtureCircuitExecutor::new("test", 2, 1).with_framework(Framework::Noir)),
        );

        let inputs = vec![FieldElement::zero(), FieldElement::one()];
        let results = multi.execute_all(&inputs);

        assert_eq!(results.len(), 2);
        assert!(results.values().all(|r| r.success));
    }
}
