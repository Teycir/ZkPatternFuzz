//! Circuit Composition Testing
//!
//! Tests security properties when circuits are composed together.

use std::sync::Arc;
use zk_core::CircuitExecutor;
use zk_core::FieldElement;

/// Composition type for testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionType {
    /// Sequential: output of A feeds into B
    Sequential,
    /// Parallel: A and B run independently, outputs combined
    Parallel,
    /// Recursive: A calls itself
    Recursive,
    /// Aggregated: Multiple proofs combined into one
    Aggregated,
}

/// Composition tester
pub struct CompositionTester {
    composition_type: CompositionType,
    circuits: Vec<Arc<dyn CircuitExecutor>>,
}

impl CompositionTester {
    pub fn new(composition_type: CompositionType) -> Self {
        Self {
            composition_type,
            circuits: Vec::new(),
        }
    }

    pub fn add_circuit(&mut self, executor: Arc<dyn CircuitExecutor>) {
        self.circuits.push(executor);
    }

    /// Test sequential composition
    pub fn test_sequential(
        &self,
        inputs: &[FieldElement],
    ) -> Result<Vec<FieldElement>, CompositionError> {
        if self.circuits.is_empty() {
            return Err(CompositionError::NoCircuits);
        }

        let mut current = inputs.to_vec();

        for (i, circuit) in self.circuits.iter().enumerate() {
            // Adjust input size
            if current.len() < circuit.num_private_inputs() {
                current.resize(circuit.num_private_inputs(), FieldElement::zero());
            } else if current.len() > circuit.num_private_inputs() {
                current.truncate(circuit.num_private_inputs());
            }

            let result = circuit.execute_sync(&current);

            if !result.success {
                return Err(CompositionError::StepFailed {
                    step: i,
                    error: result.error.unwrap_or_else(|| "Unknown error".to_string()),
                });
            }

            current = result.outputs;
        }

        Ok(current)
    }

    /// Test parallel composition
    pub fn test_parallel(
        &self,
        inputs: &[Vec<FieldElement>],
    ) -> Result<Vec<Vec<FieldElement>>, CompositionError> {
        if self.circuits.len() != inputs.len() {
            return Err(CompositionError::InputMismatch {
                expected: self.circuits.len(),
                got: inputs.len(),
            });
        }

        let mut outputs = Vec::new();

        for (i, (circuit, input)) in self.circuits.iter().zip(inputs.iter()).enumerate() {
            let result = circuit.execute_sync(input);

            if !result.success {
                return Err(CompositionError::StepFailed {
                    step: i,
                    error: result.error.unwrap_or_else(|| "Unknown error".to_string()),
                });
            }

            outputs.push(result.outputs);
        }

        Ok(outputs)
    }

    /// Check for composition vulnerabilities
    pub fn check_vulnerabilities(&self) -> Vec<CompositionVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.composition_type == CompositionType::Recursive && self.circuits.len() != 1 {
            vulnerabilities.push(CompositionVulnerability {
                vuln_type: VulnerabilityType::InvalidRecursion,
                description: format!(
                    "Recursive composition expects exactly 1 circuit, found {}",
                    self.circuits.len()
                ),
                circuit_indices: (0..self.circuits.len()).collect(),
            });
        }

        if matches!(
            self.composition_type,
            CompositionType::Sequential | CompositionType::Recursive
        ) {
            // Check for type mismatches between circuits
            for i in 0..self.circuits.len().saturating_sub(1) {
                let current = &self.circuits[i];
                let next = &self.circuits[i + 1];

                // Check if outputs match inputs
                let current_outputs = current.circuit_info().num_outputs;
                let next_inputs = next.num_private_inputs();

                if current_outputs != next_inputs {
                    vulnerabilities.push(CompositionVulnerability {
                        vuln_type: VulnerabilityType::TypeMismatch,
                        description: format!(
                            "Circuit {} outputs {} values but circuit {} expects {} inputs",
                            i,
                            current_outputs,
                            i + 1,
                            next_inputs
                        ),
                        circuit_indices: vec![i, i + 1],
                    });
                }
            }
        }

        // Check for potential information leakage through composition
        // (simplified heuristic)
        for (i, circuit) in self.circuits.iter().enumerate() {
            let info = circuit.circuit_info();
            if info.num_public_inputs > info.num_outputs {
                vulnerabilities.push(CompositionVulnerability {
                    vuln_type: VulnerabilityType::PotentialLeakage,
                    description: format!(
                        "Circuit {} has more public inputs than outputs, potential information sink",
                        i
                    ),
                    circuit_indices: vec![i],
                });
            }
        }

        vulnerabilities
    }
}

/// Error during composition
#[derive(Debug, Clone)]
pub enum CompositionError {
    NoCircuits,
    StepFailed { step: usize, error: String },
    InputMismatch { expected: usize, got: usize },
}

/// Vulnerability found in composition
#[derive(Debug, Clone)]
pub struct CompositionVulnerability {
    pub vuln_type: VulnerabilityType,
    pub description: String,
    pub circuit_indices: Vec<usize>,
}

/// Type of composition vulnerability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnerabilityType {
    /// Type/size mismatch between circuits
    TypeMismatch,
    /// Potential information leakage
    PotentialLeakage,
    /// Constraint count mismatch
    ConstraintMismatch,
    /// Invalid recursion
    InvalidRecursion,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;

    #[test]
    fn test_composition_tester_creation() {
        let tester = CompositionTester::new(CompositionType::Sequential);
        assert!(tester.circuits.is_empty());
    }

    #[test]
    fn test_sequential_composition() {
        let mut tester = CompositionTester::new(CompositionType::Sequential);
        tester.add_circuit(Arc::new(MockCircuitExecutor::new("c1", 2, 1)));
        tester.add_circuit(Arc::new(MockCircuitExecutor::new("c2", 1, 1)));

        let inputs = vec![FieldElement::one(), FieldElement::zero()];
        let result = tester.test_sequential(&inputs);

        assert!(result.is_ok());
    }

    #[test]
    fn test_vulnerability_detection() {
        let mut tester = CompositionTester::new(CompositionType::Sequential);
        // Mismatched circuits (2 outputs, 5 inputs)
        tester.add_circuit(Arc::new(
            MockCircuitExecutor::new("c1", 2, 1).with_outputs(2),
        ));
        tester.add_circuit(Arc::new(MockCircuitExecutor::new("c2", 5, 1)));

        let vulnerabilities = tester.check_vulnerabilities();
        assert!(!vulnerabilities.is_empty());
    }
}
