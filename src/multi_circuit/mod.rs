//! Multi-Circuit Fuzzing Module
//!
//! Tests circuits that interact with each other, such as:
//! - Recursive proofs
//! - Cross-circuit vulnerabilities
//! - Circuit composition security

pub mod composition;
pub mod recursive;

use std::collections::HashMap;
use std::sync::Arc;
use zk_core::{
    AttackType, CircuitExecutor, ExecutionResult, FieldElement, Finding, ProofOfConcept, Severity,
};

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
            let required_inputs = circuit2.num_private_inputs();
            let inputs2 = if result1.outputs.len() >= required_inputs {
                result1.outputs[..required_inputs].to_vec()
            } else {
                findings.push(Finding {
                    attack_type: AttackType::Boundary,
                    severity: Severity::High,
                    description: format!(
                        "Circuit composition size mismatch: {} produced {} outputs but {} expects {} inputs",
                        circuit_names[idx1],
                        result1.outputs.len(),
                        circuit_names[idx2],
                        required_inputs
                    ),
                    poc: ProofOfConcept {
                        witness_a: inputs1,
                        witness_b: Some(result1.outputs.clone()),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                });
                continue;
            };

            // Execute second circuit
            let result2 = circuit2.execute_sync(&inputs2);

            // Check for composition issues
            if !result2.success {
                // Composition caused failure - might be interesting
                findings.push(Finding {
                    attack_type: AttackType::Boundary,
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

            let inspector = match circuit.constraint_inspector() {
                Some(inspector) => inspector,
                None => continue,
            };

            let constraints = inspector.get_constraints();
            if constraints.is_empty() {
                continue;
            }

            let public_indices = inspector.public_input_indices();
            let private_indices = inspector.private_input_indices();
            if private_indices.is_empty() {
                continue;
            }

            let output_indices = inspector.output_indices();

            let mut analyzer = crate::analysis::taint::TaintAnalyzer::new(
                public_indices.len(),
                private_indices.len(),
            );

            if !public_indices.is_empty() || !private_indices.is_empty() {
                analyzer.initialize_inputs_with_indices(&public_indices, &private_indices);
            } else {
                analyzer.initialize_inputs();
            }

            if !output_indices.is_empty() {
                analyzer.mark_outputs(&output_indices);
            } else {
                analyzer.mark_outputs_from_constraints(&constraints);
            }

            analyzer.propagate_constraints(&constraints);

            for finding in analyzer.to_findings() {
                findings.push(Finding {
                    attack_type: finding.attack_type,
                    severity: finding.severity,
                    description: format!("{}: {}", name, finding.description),
                    poc: ProofOfConcept {
                        witness_a: (0..circuit.num_private_inputs())
                            .map(|_| FieldElement::random(rng))
                            .collect(),
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: finding.location.map(|loc| format!("{}:{}", name, loc)),
                });
            }
        }

        findings
    }

    /// Get all findings
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}

/// Circuit chain for testing chained composition
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

        for (step_idx, (name, executor)) in self.circuits.iter().enumerate() {
            let expected = executor.num_private_inputs();
            if current_inputs.len() != expected {
                let error = format!(
                    "Chain step {} ('{}') input size mismatch: expected {}, got {}",
                    step_idx,
                    name,
                    expected,
                    current_inputs.len()
                );
                tracing::warn!("{}", error);
                results.push(ChainStepResult {
                    circuit_name: name.clone(),
                    inputs: current_inputs.clone(),
                    result: ExecutionResult::failure(error),
                });
                return ChainResult {
                    success: false,
                    steps: results,
                    final_outputs: vec![],
                };
            }

            let step_inputs = current_inputs.clone();
            let result = executor.execute_sync(&step_inputs);

            results.push(ChainStepResult {
                circuit_name: name.clone(),
                inputs: step_inputs,
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
