//! Multi-Circuit Fuzzing Module
//!
//! Tests circuits that interact with each other, such as:
//! - Recursive proofs
//! - Cross-circuit vulnerabilities
//! - Circuit composition security

mod composition;
pub mod recursive;


use crate::config::Severity;
use crate::executor::{CircuitExecutor, ExecutionResult};
use crate::fuzzer::{FieldElement, Finding, ProofOfConcept};
use std::collections::HashMap;
use std::sync::Arc;

/// Multi-circuit test configuration
#[derive(Debug, Clone)]
pub struct MultiCircuitConfig {
    /// Number of composition tests
    pub composition_tests: usize,
    /// Number of recursive tests
    pub recursive_tests: usize,
    /// Maximum recursion depth to test
    pub max_recursion_depth: usize,
    /// Test cross-circuit data flow
    pub test_data_flow: bool,
}

impl Default for MultiCircuitConfig {
    fn default() -> Self {
        Self {
            composition_tests: 500,
            recursive_tests: 100,
            max_recursion_depth: 5,
            test_data_flow: true,
        }
    }
}

/// Multi-circuit fuzzer
pub struct MultiCircuitFuzzer {
    /// Circuits to test
    circuits: HashMap<String, Arc<dyn CircuitExecutor>>,
    /// Configuration
    config: MultiCircuitConfig,
    /// Findings
    findings: Vec<Finding>,
}

impl MultiCircuitFuzzer {
    pub fn new(config: MultiCircuitConfig) -> Self {
        Self {
            circuits: HashMap::new(),
            config,
            findings: Vec::new(),
        }
    }

    /// Add a circuit to the test set
    pub fn add_circuit(&mut self, name: &str, executor: Arc<dyn CircuitExecutor>) {
        self.circuits.insert(name.to_string(), executor);
    }

    /// Run multi-circuit fuzzing
    pub fn run(&mut self, rng: &mut impl rand::Rng) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Test circuit composition
        findings.extend(self.test_composition(rng));

        // Test data flow between circuits
        if self.config.test_data_flow {
            findings.extend(self.test_data_flow(rng));
        }

        self.findings.extend(findings.clone());
        findings
    }

    /// Test circuit composition security
    fn test_composition(&self, rng: &mut impl rand::Rng) -> Vec<Finding> {
        let mut findings = Vec::new();
        let circuit_names: Vec<_> = self.circuits.keys().cloned().collect();

        if circuit_names.len() < 2 {
            return findings;
        }

        for _ in 0..self.config.composition_tests {
            // Pick two circuits
            let idx1 = rng.gen_range(0..circuit_names.len());
            let idx2 = (idx1 + 1) % circuit_names.len();
            
            let circuit1 = &self.circuits[&circuit_names[idx1]];
            let circuit2 = &self.circuits[&circuit_names[idx2]];

            // Generate input for first circuit
            let inputs1: Vec<FieldElement> = (0..circuit1.num_private_inputs())
                .map(|_| FieldElement::random(rng))
                .collect();

            // Execute first circuit
            let result1 = circuit1.execute_sync(&inputs1);

            if !result1.success {
                continue;
            }

            // Use outputs as inputs to second circuit (if compatible)
            let inputs2 = if result1.outputs.len() >= circuit2.num_private_inputs() {
                result1.outputs[..circuit2.num_private_inputs()].to_vec()
            } else {
                // Pad with random values
                let mut inputs = result1.outputs.clone();
                while inputs.len() < circuit2.num_private_inputs() {
                    inputs.push(FieldElement::random(rng));
                }
                inputs
            };

            // Execute second circuit
            let result2 = circuit2.execute_sync(&inputs2);

            // Check for composition issues
            if !result2.success {
                // Composition caused failure - might be interesting
                findings.push(Finding {
                    attack_type: crate::config::AttackType::Boundary,
                    severity: Severity::Medium,
                    description: format!(
                        "Circuit composition failure: {} -> {} failed when chaining outputs",
                        circuit_names[idx1], circuit_names[idx2]
                    ),
                    poc: ProofOfConcept {
                        witness_a: inputs1,
                        witness_b: Some(inputs2),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                });
            }
        }

        findings
    }

    /// Test data flow between circuits for information leakage
    fn test_data_flow(&self, rng: &mut impl rand::Rng) -> Vec<Finding> {
        let mut findings = Vec::new();
        let circuit_names: Vec<_> = self.circuits.keys().cloned().collect();

        // Test if private inputs from one circuit leak through composition
        for name in &circuit_names {
            let circuit = &self.circuits[name];

            // Test with a "marker" value in private input
            let marker = FieldElement::from_u64(0xDEADBEEF);
            let mut inputs: Vec<FieldElement> = (0..circuit.num_private_inputs())
                .map(|_| FieldElement::random(rng))
                .collect();
            
            if !inputs.is_empty() {
                inputs[0] = marker.clone();
            }

            let result = circuit.execute_sync(&inputs);

            if result.success {
                // Check if marker appears in output (potential leakage)
                for (i, output) in result.outputs.iter().enumerate() {
                    if *output == marker {
                        findings.push(Finding {
                            attack_type: crate::config::AttackType::InformationLeakage,
                            severity: Severity::High,
                            description: format!(
                                "Private input appears unchanged in output #{} of circuit '{}'",
                                i, name
                            ),
                            poc: ProofOfConcept {
                                witness_a: inputs.clone(),
                                witness_b: None,
                                public_inputs: vec![],
                                proof: None,
                            },
                            location: Some(format!("{}:output_{}", name, i)),
                        });
                    }
                }
            }
        }

        findings
    }

    /// Get all findings
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}

/// Circuit chain for testing sequential composition
pub struct CircuitChain {
    circuits: Vec<(String, Arc<dyn CircuitExecutor>)>,
}

impl CircuitChain {
    pub fn new() -> Self {
        Self {
            circuits: Vec::new(),
        }
    }

    /// Add a circuit to the chain
    pub fn add(&mut self, name: &str, executor: Arc<dyn CircuitExecutor>) {
        self.circuits.push((name.to_string(), executor));
    }

    /// Execute the chain, passing outputs as inputs
    pub fn execute(&self, initial_inputs: &[FieldElement]) -> ChainResult {
        let mut current_inputs = initial_inputs.to_vec();
        let mut results = Vec::new();

        for (name, executor) in &self.circuits {
            // Ensure we have enough inputs
            while current_inputs.len() < executor.num_private_inputs() {
                current_inputs.push(FieldElement::zero());
            }

            let result = executor.execute_sync(&current_inputs[..executor.num_private_inputs()]);
            
            results.push(ChainStepResult {
                circuit_name: name.clone(),
                inputs: current_inputs[..executor.num_private_inputs()].to_vec(),
                result: result.clone(),
            });

            if !result.success {
                return ChainResult {
                    success: false,
                    steps: results,
                    final_outputs: vec![],
                };
            }

            // Use outputs as next inputs
            current_inputs = result.outputs;
        }

        ChainResult {
            success: true,
            steps: results,
            final_outputs: current_inputs,
        }
    }
}

impl Default for CircuitChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of chain execution
#[derive(Debug, Clone)]
pub struct ChainResult {
    pub success: bool,
    pub steps: Vec<ChainStepResult>,
    pub final_outputs: Vec<FieldElement>,
}

/// Result of a single step in the chain
#[derive(Debug, Clone)]
pub struct ChainStepResult {
    pub circuit_name: String,
    pub inputs: Vec<FieldElement>,
    pub result: ExecutionResult,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_multi_circuit_fuzzer_creation() {
        let config = MultiCircuitConfig::default();
        let fuzzer = MultiCircuitFuzzer::new(config);
        assert!(fuzzer.circuits.is_empty());
    }

    #[test]
    fn test_circuit_chain() {
        let mut chain = CircuitChain::new();
        chain.add("circuit1", Arc::new(MockCircuitExecutor::new("c1", 2, 1)));
        chain.add("circuit2", Arc::new(MockCircuitExecutor::new("c2", 1, 1)));

        let inputs = vec![FieldElement::one(), FieldElement::zero()];
        let result = chain.execute(&inputs);

        assert!(result.success);
        assert_eq!(result.steps.len(), 2);
    }

    #[test]
    fn test_multi_circuit_fuzzing() {
        let config = MultiCircuitConfig {
            composition_tests: 10,
            ..Default::default()
        };
        let mut fuzzer = MultiCircuitFuzzer::new(config);
        
        fuzzer.add_circuit("c1", Arc::new(MockCircuitExecutor::new("c1", 2, 1)));
        fuzzer.add_circuit("c2", Arc::new(MockCircuitExecutor::new("c2", 2, 1)));

        let mut rng = StdRng::seed_from_u64(42);
        let findings = fuzzer.run(&mut rng);

        // May or may not find issues depending on mock behavior
        println!("Found {} issues", findings.len());
    }
}
