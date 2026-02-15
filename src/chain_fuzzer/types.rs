//! Mode 3: Core types for multi-step chain fuzzing
//!
//! This module defines the data model for chain specifications, traces, and findings.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity};

/// Specification for a multi-step chain scenario (parsed from YAML)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSpec {
    /// Unique name for this chain
    pub name: String,
    /// Ordered sequence of steps in the chain
    pub steps: Vec<StepSpec>,
    /// Cross-step assertions to check after execution
    pub assertions: Vec<CrossStepAssertion>,
    /// Optional description for documentation
    #[serde(default)]
    pub description: Option<String>,
}

impl ChainSpec {
    /// Create a new chain spec with the given name and steps
    pub fn new(name: impl Into<String>, steps: Vec<StepSpec>) -> Self {
        Self {
            name: name.into(),
            steps,
            assertions: Vec::new(),
            description: None,
        }
    }

    /// Add an assertion to this chain spec
    pub fn with_assertion(mut self, assertion: CrossStepAssertion) -> Self {
        self.assertions.push(assertion);
        self
    }

    /// Add a description to this chain spec
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Get the number of steps in this chain
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Check if this chain has no steps
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Create a truncated version of this chain with only the first n steps
    pub fn truncate(&self, n: usize) -> Self {
        Self {
            name: format!("{}_truncated_{}", self.name, n),
            steps: self.steps.iter().take(n).cloned().collect(),
            assertions: self.assertions.clone(),
            description: self.description.clone(),
        }
    }

    /// Create a version with a step removed at the given index.
    /// Returns `None` if any remaining step wiring becomes invalid.
    pub fn without_step(&self, index: usize) -> Option<Self> {
        if index >= self.steps.len() {
            return None;
        }

        let mut steps: Vec<_> = self
            .steps
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .map(|(_, s)| s.clone())
            .collect();

        // Adjust input wiring references for steps after the removed one
        for (i, step) in steps.iter_mut().enumerate() {
            step.input_wiring = step.input_wiring.adjust_after_removal(index, i)?;
        }

        // Remap assertion step indices - filter out assertions that become invalid
        let assertions: Vec<_> = self
            .assertions
            .iter()
            .filter_map(|a| a.remap_after_removal(index))
            .collect();

        Some(Self {
            name: format!("{}_without_{}", self.name, index),
            steps,
            assertions,
            description: self.description.clone(),
        })
    }

    /// Create a version with steps at positions i and j swapped.
    /// Also updates InputWiring references so that any reference to step i
    /// becomes j and vice versa. Returns None if either index is out of
    /// bounds or i == j.
    pub fn swap_steps(&self, i: usize, j: usize) -> Option<Self> {
        if i >= self.steps.len() || j >= self.steps.len() || i == j {
            return None;
        }

        let mut steps = self.steps.clone();
        steps.swap(i, j);

        for step in steps.iter_mut() {
            step.input_wiring = step.input_wiring.adjust_after_swap(i, j);
        }

        // Remap assertion step indices
        let assertions: Vec<_> = self
            .assertions
            .iter()
            .map(|a| a.remap_after_swap(i, j))
            .collect();

        Some(Self {
            name: format!("{}_swap_{}_{}", self.name, i, j),
            steps,
            assertions,
            description: self.description.clone(),
        })
    }

    /// Insert a copy of the step at `index` immediately after it (for
    /// re-entrancy testing). The duplicate gets Fresh wiring. Wiring
    /// references in subsequent steps that point to indices > index are
    /// incremented by 1. Returns None if index is out of bounds.
    pub fn duplicate_step(&self, index: usize) -> Option<Self> {
        if index >= self.steps.len() {
            return None;
        }

        let mut steps = self.steps.clone();

        let mut dup = steps[index].clone();
        dup.input_wiring = InputWiring::Fresh;
        steps.insert(index + 1, dup);

        for step in steps.iter_mut().skip(index + 2) {
            step.input_wiring = step.input_wiring.adjust_after_insertion(index);
        }

        // Remap assertion step indices (increment indices > index)
        let assertions: Vec<_> = self
            .assertions
            .iter()
            .map(|a| a.remap_after_insertion(index))
            .collect();

        Some(Self {
            name: format!("{}_dup_{}", self.name, index),
            steps,
            assertions,
            description: self.description.clone(),
        })
    }
}

/// Specification for a single step in a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepSpec {
    /// Reference to the circuit (name or path)
    pub circuit_ref: String,
    /// How to derive inputs for this step
    pub input_wiring: InputWiring,
    /// Optional label for debugging/reporting
    #[serde(default)]
    pub label: Option<String>,
    /// Expected number of inputs (for validation)
    #[serde(default)]
    pub expected_inputs: Option<usize>,
    /// Expected number of outputs (for validation)
    #[serde(default)]
    pub expected_outputs: Option<usize>,
}

impl StepSpec {
    /// Create a new step spec with fresh inputs
    pub fn fresh(circuit_ref: impl Into<String>) -> Self {
        Self {
            circuit_ref: circuit_ref.into(),
            input_wiring: InputWiring::Fresh,
            label: None,
            expected_inputs: None,
            expected_outputs: None,
        }
    }

    /// Create a step that uses outputs from a prior step
    pub fn from_prior(
        circuit_ref: impl Into<String>,
        step: usize,
        mapping: Vec<(usize, usize)>,
    ) -> Self {
        Self {
            circuit_ref: circuit_ref.into(),
            input_wiring: InputWiring::FromPriorOutput { step, mapping },
            label: None,
            expected_inputs: None,
            expected_outputs: None,
        }
    }

    /// Add a label to this step
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// How inputs are wired for a step
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InputWiring {
    /// Generate fresh random inputs
    Fresh,
    /// Derive inputs from a prior step's outputs
    FromPriorOutput {
        /// Index of the prior step (0-based)
        step: usize,
        /// Mapping of (output_index, input_index) pairs
        mapping: Vec<(usize, usize)>,
    },
    /// Mix of prior outputs and fresh inputs
    Mixed {
        /// List of (step, output_index, input_index) for prior outputs
        prior: Vec<(usize, usize, usize)>,
        /// Indices that should be filled with fresh random values
        fresh_indices: Vec<usize>,
    },
    /// Use explicit constant values
    Constant {
        /// Map of input_index -> constant value (hex string)
        values: HashMap<usize, String>,
        /// Indices for fresh random values
        #[serde(default)]
        fresh_indices: Vec<usize>,
    },
}

impl InputWiring {
    /// Adjust step references after a step has been removed
    pub fn adjust_after_removal(
        &self,
        removed_index: usize,
        _current_index: usize,
    ) -> Option<Self> {
        match self {
            InputWiring::Fresh => Some(InputWiring::Fresh),
            InputWiring::FromPriorOutput { step, mapping } => {
                if *step == removed_index {
                    // The referenced step was removed; wiring is now invalid.
                    None
                } else if *step > removed_index {
                    // Adjust the step index down
                    Some(InputWiring::FromPriorOutput {
                        step: step - 1,
                        mapping: mapping.clone(),
                    })
                } else {
                    // No adjustment needed
                    Some(InputWiring::FromPriorOutput {
                        step: *step,
                        mapping: mapping.clone(),
                    })
                }
            }
            InputWiring::Mixed {
                prior,
                fresh_indices,
            } => {
                if prior.iter().any(|(s, _, _)| *s == removed_index) {
                    return None;
                }

                let adjusted_prior: Vec<_> = prior
                    .iter()
                    .map(|(s, out_idx, in_idx)| {
                        let new_s = if *s > removed_index { s - 1 } else { *s };
                        (new_s, *out_idx, *in_idx)
                    })
                    .collect();
                Some(InputWiring::Mixed {
                    prior: adjusted_prior,
                    fresh_indices: fresh_indices.clone(),
                })
            }
            InputWiring::Constant {
                values,
                fresh_indices,
            } => Some(InputWiring::Constant {
                values: values.clone(),
                fresh_indices: fresh_indices.clone(),
            }),
        }
    }

    /// Adjust step references after swapping steps at positions i and j
    pub fn adjust_after_swap(&self, i: usize, j: usize) -> Self {
        match self {
            InputWiring::Fresh => InputWiring::Fresh,
            InputWiring::FromPriorOutput { step, mapping } => {
                let new_step = if *step == i {
                    j
                } else if *step == j {
                    i
                } else {
                    *step
                };
                InputWiring::FromPriorOutput {
                    step: new_step,
                    mapping: mapping.clone(),
                }
            }
            InputWiring::Mixed {
                prior,
                fresh_indices,
            } => {
                let adjusted_prior: Vec<_> = prior
                    .iter()
                    .map(|(s, out_idx, in_idx)| {
                        let new_s = if *s == i {
                            j
                        } else if *s == j {
                            i
                        } else {
                            *s
                        };
                        (new_s, *out_idx, *in_idx)
                    })
                    .collect();
                InputWiring::Mixed {
                    prior: adjusted_prior,
                    fresh_indices: fresh_indices.clone(),
                }
            }
            InputWiring::Constant {
                values,
                fresh_indices,
            } => InputWiring::Constant {
                values: values.clone(),
                fresh_indices: fresh_indices.clone(),
            },
        }
    }

    /// Adjust step references after a new step has been inserted at `inserted_at`
    pub fn adjust_after_insertion(&self, inserted_at: usize) -> Self {
        match self {
            InputWiring::Fresh => InputWiring::Fresh,
            InputWiring::FromPriorOutput { step, mapping } => {
                let new_step = if *step > inserted_at { step + 1 } else { *step };
                InputWiring::FromPriorOutput {
                    step: new_step,
                    mapping: mapping.clone(),
                }
            }
            InputWiring::Mixed {
                prior,
                fresh_indices,
            } => {
                let adjusted_prior: Vec<_> = prior
                    .iter()
                    .map(|(s, out_idx, in_idx)| {
                        let new_s = if *s > inserted_at { s + 1 } else { *s };
                        (new_s, *out_idx, *in_idx)
                    })
                    .collect();
                InputWiring::Mixed {
                    prior: adjusted_prior,
                    fresh_indices: fresh_indices.clone(),
                }
            }
            InputWiring::Constant {
                values,
                fresh_indices,
            } => InputWiring::Constant {
                values: values.clone(),
                fresh_indices: fresh_indices.clone(),
            },
        }
    }

    /// Get all step indices that this wiring depends on
    pub fn dependent_steps(&self) -> Vec<usize> {
        match self {
            InputWiring::Fresh => vec![],
            InputWiring::FromPriorOutput { step, .. } => vec![*step],
            InputWiring::Mixed { prior, .. } => {
                let mut steps: Vec<_> = prior.iter().map(|(s, _, _)| *s).collect();
                steps.sort();
                steps.dedup();
                steps
            }
            InputWiring::Constant { .. } => vec![],
        }
    }
}

/// Cross-step assertion to check after chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossStepAssertion {
    /// Unique name for this assertion
    pub name: String,
    /// Relation expression (e.g., "step[0].out[0] == step[1].in[2]")
    pub relation: String,
    /// Severity if violated
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
}

fn default_severity() -> String {
    "high".to_string()
}

impl CrossStepAssertion {
    /// Create a new assertion
    pub fn new(name: impl Into<String>, relation: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            relation: relation.into(),
            severity: default_severity(),
            description: None,
        }
    }

    /// Set the severity
    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = severity.into();
        self
    }

    /// Create a uniqueness assertion
    pub fn unique(name: impl Into<String>, output_index: usize) -> Self {
        Self::new(name, format!("unique(step[*].out[{}])", output_index))
    }

    /// Create an equality assertion between steps
    pub fn equal(
        name: impl Into<String>,
        step_a: usize,
        out_idx: usize,
        step_b: usize,
        in_idx: usize,
    ) -> Self {
        Self::new(
            name,
            format!(
                "step[{}].out[{}] == step[{}].in[{}]",
                step_a, out_idx, step_b, in_idx
            ),
        )
    }

    /// Remap step indices after a step has been removed.
    /// Returns None if the assertion references the removed step and becomes invalid.
    pub fn remap_after_removal(&self, removed_index: usize) -> Option<Self> {
        let new_relation = remap_step_indices_in_relation(&self.relation, |idx| {
            if idx == removed_index {
                None // Step was removed, assertion is invalid
            } else if idx > removed_index {
                Some(idx - 1) // Decrement indices after removed step
            } else {
                Some(idx)
            }
        })?;

        Some(Self {
            name: self.name.clone(),
            relation: new_relation,
            severity: self.severity.clone(),
            description: self.description.clone(),
        })
    }

    /// Remap step indices after steps at positions i and j have been swapped.
    pub fn remap_after_swap(&self, i: usize, j: usize) -> Self {
        let new_relation = remap_step_indices_in_relation(&self.relation, |idx| {
            if idx == i {
                Some(j)
            } else if idx == j {
                Some(i)
            } else {
                Some(idx)
            }
        });
        let new_relation = match new_relation {
            Some(value) => value,
            None => {
                panic!(
                    "Invalid relation during swap remap (relation='{}', i={}, j={})",
                    self.relation, i, j
                )
            }
        };

        Self {
            name: self.name.clone(),
            relation: new_relation,
            severity: self.severity.clone(),
            description: self.description.clone(),
        }
    }

    /// Remap step indices after a step has been inserted (duplicated) at position.
    /// All indices > position are incremented by 1.
    pub fn remap_after_insertion(&self, inserted_at: usize) -> Self {
        let new_relation = remap_step_indices_in_relation(&self.relation, |idx| {
            if idx > inserted_at {
                Some(idx + 1)
            } else {
                Some(idx)
            }
        });
        let new_relation = match new_relation {
            Some(value) => value,
            None => {
                panic!(
                    "Invalid relation during insertion remap (relation='{}', inserted_at={})",
                    self.relation, inserted_at
                )
            }
        };

        Self {
            name: self.name.clone(),
            relation: new_relation,
            severity: self.severity.clone(),
            description: self.description.clone(),
        }
    }
}

/// Helper function to remap step indices in a relation string.
/// The mapper function takes an index and returns the new index, or None if the index is invalid.
fn remap_step_indices_in_relation<F>(relation: &str, mapper: F) -> Option<String>
where
    F: Fn(usize) -> Option<usize>,
{
    use regex::Regex;

    // Match step[N] where N is a number (not *)
    let re = match Regex::new(r"step\s*\[\s*(\d+)\s*\]") {
        Ok(re) => re,
        Err(err) => panic!("Invalid step remap regex pattern: {}", err),
    };

    let mut result = String::new();
    let mut last_end = 0;
    let mut all_valid = true;

    for caps in re.captures_iter(relation) {
        let full_match = caps.get(0)?;
        let idx_str = caps.get(1)?.as_str();
        let idx: usize = match idx_str.parse() {
            Ok(idx) => idx,
            Err(err) => panic!(
                "Invalid step index '{}' in relation '{}': {}",
                idx_str, relation, err
            ),
        };

        // Apply the mapper
        match mapper(idx) {
            Some(new_idx) => {
                result.push_str(&relation[last_end..full_match.start()]);
                result.push_str(&format!("step[{}]", new_idx));
                last_end = full_match.end();
            }
            None => {
                all_valid = false;
                break;
            }
        }
    }

    if !all_valid {
        return None;
    }

    result.push_str(&relation[last_end..]);
    Some(result)
}

/// Runtime trace of a chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTrace {
    /// Name of the chain spec that was executed
    pub spec_name: String,
    /// Traces for each executed step
    pub steps: Vec<StepTrace>,
    /// Whether the entire chain executed successfully
    pub success: bool,
    /// Total execution time in milliseconds
    #[serde(default)]
    pub execution_time_ms: u64,
}

impl ChainTrace {
    /// Create a new empty chain trace
    pub fn new(spec_name: impl Into<String>) -> Self {
        Self {
            spec_name: spec_name.into(),
            steps: Vec::new(),
            success: false,
            execution_time_ms: 0,
        }
    }

    /// Add a step trace
    pub fn add_step(&mut self, trace: StepTrace) {
        self.success = trace.success;
        self.steps.push(trace);
    }

    /// Get the depth (number of steps executed)
    pub fn depth(&self) -> usize {
        self.steps.len()
    }

    /// Get the outputs of a specific step
    pub fn step_outputs(&self, step_index: usize) -> Option<&[FieldElement]> {
        self.steps.get(step_index).map(|s| s.outputs.as_slice())
    }

    /// Get the inputs of a specific step
    pub fn step_inputs(&self, step_index: usize) -> Option<&[FieldElement]> {
        self.steps.get(step_index).map(|s| s.inputs.as_slice())
    }

    /// Collect all outputs at a given index across all steps
    pub fn all_outputs_at(&self, output_index: usize) -> Vec<&FieldElement> {
        self.steps
            .iter()
            .filter_map(|s| s.outputs.get(output_index))
            .collect()
    }
}

/// Trace of a single step execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepTrace {
    /// Index of this step in the chain (0-based)
    pub step_index: usize,
    /// Circuit reference that was executed
    pub circuit_ref: String,
    /// Inputs used for this execution
    pub inputs: Vec<FieldElement>,
    /// Outputs produced by this execution
    pub outputs: Vec<FieldElement>,
    /// Whether this step executed successfully
    pub success: bool,
    /// Constraint indices that were hit during execution
    #[serde(default)]
    pub constraints_hit: HashSet<usize>,
    /// Execution time for this step in milliseconds
    #[serde(default)]
    pub execution_time_ms: u64,
    /// Error message if execution failed
    #[serde(default)]
    pub error: Option<String>,
}

impl StepTrace {
    /// Create a new step trace for a successful execution
    pub fn success(
        step_index: usize,
        circuit_ref: impl Into<String>,
        inputs: Vec<FieldElement>,
        outputs: Vec<FieldElement>,
    ) -> Self {
        Self {
            step_index,
            circuit_ref: circuit_ref.into(),
            inputs,
            outputs,
            success: true,
            constraints_hit: HashSet::new(),
            execution_time_ms: 0,
            error: None,
        }
    }

    /// Create a new step trace for a failed execution
    pub fn failure(
        step_index: usize,
        circuit_ref: impl Into<String>,
        inputs: Vec<FieldElement>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            step_index,
            circuit_ref: circuit_ref.into(),
            inputs,
            outputs: Vec::new(),
            success: false,
            constraints_hit: HashSet::new(),
            execution_time_ms: 0,
            error: Some(error.into()),
        }
    }

    /// Add constraint coverage information
    pub fn with_constraints(mut self, constraints: HashSet<usize>) -> Self {
        self.constraints_hit = constraints;
        self
    }

    /// Set execution time
    pub fn with_time(mut self, ms: u64) -> Self {
        self.execution_time_ms = ms;
        self
    }
}

/// Result of running a chain (success or failure with trace)
#[derive(Debug, Clone)]
pub struct ChainRunResult {
    /// The trace of execution
    pub trace: ChainTrace,
    /// Whether execution completed all steps
    pub completed: bool,
    /// Index of the first failing step (if any)
    pub failed_at: Option<usize>,
}

impl ChainRunResult {
    /// Create a successful result
    pub fn success(trace: ChainTrace) -> Self {
        Self {
            trace,
            completed: true,
            failed_at: None,
        }
    }

    /// Create a failed result
    pub fn failure(trace: ChainTrace, failed_at: usize) -> Self {
        Self {
            trace,
            completed: false,
            failed_at: Some(failed_at),
        }
    }
}

/// A finding with chain depth metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainFinding {
    /// The underlying finding
    pub finding: ChainFindingCore,
    /// Total number of steps in the original chain
    pub chain_length: usize,
    /// Minimum steps required to reproduce (L_min metric)
    pub l_min: usize,
    /// The full execution trace
    pub trace: ChainTrace,
    /// The chain spec that produced this finding
    pub spec_name: String,
    /// Assertion that was violated (if applicable)
    #[serde(default)]
    pub violated_assertion: Option<String>,
}

/// Core finding data (serializable version of Finding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainFindingCore {
    /// Type of attack/vulnerability
    pub attack_type: String,
    /// Severity of the finding
    pub severity: String,
    /// Description of the finding
    pub description: String,
    /// Witness inputs that triggered the finding (hex-encoded)
    pub witness_inputs: Vec<Vec<String>>,
    /// Location in the circuit (if known)
    #[serde(default)]
    pub location: Option<String>,
}

impl ChainFinding {
    /// Create a new chain finding
    pub fn new(
        finding: Finding,
        chain_length: usize,
        l_min: usize,
        trace: ChainTrace,
        spec_name: impl Into<String>,
    ) -> Self {
        // Convert Finding to ChainFindingCore
        let witness_inputs: Vec<Vec<String>> = trace
            .steps
            .iter()
            .map(|s| s.inputs.iter().map(|fe| fe.to_hex()).collect())
            .collect();

        let core = ChainFindingCore {
            attack_type: format!("{:?}", finding.attack_type),
            severity: finding.severity.to_string(),
            description: finding.description,
            witness_inputs,
            location: finding.location,
        };

        Self {
            finding: core,
            chain_length,
            l_min,
            trace,
            spec_name: spec_name.into(),
            violated_assertion: None,
        }
    }

    /// Set the violated assertion
    pub fn with_violated_assertion(mut self, assertion: impl Into<String>) -> Self {
        self.violated_assertion = Some(assertion.into());
        self
    }

    /// Convert to a standard Finding for integration with existing reporting
    pub fn to_finding(&self) -> Finding {
        let severity = match self.finding.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };

        // CRITICAL FIX: Capture all L_min steps, not just first 2
        // This enables reproduction of deep chain bugs (L_min >= 3)
        let witness_a = self.trace.steps.first().map(|s| s.inputs.clone());
        let witness_a = match witness_a {
            Some(value) => value,
            None => {
                panic!(
                    "Cannot convert ChainFinding to Finding without at least one trace step (spec='{}')",
                    self.spec_name
                )
            }
        };

        // For L_min > 2, we need to capture all step inputs
        // Use witness_b for step 2, and embed remaining steps in description
        let witness_b = self.trace.steps.get(1).map(|s| s.inputs.clone());

        // Capture all step inputs as hex strings for complete reproducibility
        let all_step_inputs: Vec<String> = self
            .trace
            .steps
            .iter()
            .enumerate()
            .map(|(i, step)| {
                let inputs_hex: Vec<String> = step.inputs.iter().map(|fe| fe.to_hex()).collect();
                format!("step[{}]: [{}]", i, inputs_hex.join(", "))
            })
            .collect();

        // Build a more complete description with all inputs for reproducibility
        let full_description = if self.l_min > 2 {
            format!(
                "[Chain: {} | L_min: {} | Steps: {}] {}\n\nFull witness (all {} steps):\n{}",
                self.spec_name,
                self.l_min,
                self.chain_length,
                self.finding.description,
                self.trace.steps.len(),
                all_step_inputs.join("\n")
            )
        } else {
            format!(
                "[Chain: {} | L_min: {}] {}",
                self.spec_name, self.l_min, self.finding.description
            )
        };

        // Collect public inputs from all steps for completeness
        let all_public_inputs: Vec<FieldElement> = self
            .trace
            .steps
            .iter()
            .flat_map(|step| step.outputs.iter().cloned())
            .take(10) // Limit to avoid huge PoCs
            .collect();

        Finding {
            attack_type: AttackType::CircuitComposition, // Use composition type for chain findings
            severity,
            description: full_description,
            poc: ProofOfConcept {
                witness_a,
                witness_b,
                public_inputs: all_public_inputs,
                proof: None,
            },
            location: self.finding.location.clone(),
        }
    }

    /// Get all step inputs as a vector for complete PoC reproduction
    pub fn all_step_inputs(&self) -> Vec<Vec<FieldElement>> {
        self.trace
            .steps
            .iter()
            .map(|step| step.inputs.clone())
            .collect()
    }

    /// Check if this is a deep finding (L_min >= 2)
    pub fn is_deep(&self) -> bool {
        self.l_min >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_spec_truncate() {
        let spec = ChainSpec::new(
            "test_chain",
            vec![
                StepSpec::fresh("circuit_a"),
                StepSpec::fresh("circuit_b"),
                StepSpec::fresh("circuit_c"),
            ],
        );

        let truncated = spec.truncate(2);
        assert_eq!(truncated.steps.len(), 2);
        assert_eq!(truncated.name, "test_chain_truncated_2");
    }

    #[test]
    fn test_chain_spec_without_step() {
        let spec = ChainSpec::new(
            "test_chain",
            vec![
                StepSpec::fresh("circuit_a"),
                StepSpec::from_prior("circuit_b", 0, vec![(0, 0)]),
                StepSpec::from_prior("circuit_c", 1, vec![(0, 0)]),
            ],
        );

        // Remove middle step
        let reduced = spec.without_step(1).unwrap();
        assert_eq!(reduced.steps.len(), 2);

        // The third step (now second) should have its wiring adjusted
        // It referenced step 1 which is now gone, so it falls back to Fresh
        assert!(matches!(reduced.steps[1].input_wiring, InputWiring::Fresh));
    }

    #[test]
    fn test_input_wiring_dependent_steps() {
        let empty: Vec<usize> = vec![];
        assert_eq!(InputWiring::Fresh.dependent_steps(), empty);

        let from_prior = InputWiring::FromPriorOutput {
            step: 2,
            mapping: vec![],
        };
        assert_eq!(from_prior.dependent_steps(), vec![2]);

        let mixed = InputWiring::Mixed {
            prior: vec![(0, 0, 0), (2, 1, 1), (0, 2, 2)],
            fresh_indices: vec![3],
        };
        assert_eq!(mixed.dependent_steps(), vec![0, 2]);
    }

    #[test]
    fn test_chain_trace() {
        let mut trace = ChainTrace::new("test_chain");

        trace.add_step(StepTrace::success(
            0,
            "circuit_a",
            vec![FieldElement::one()],
            vec![FieldElement::from_u64(42)],
        ));

        trace.add_step(StepTrace::success(
            1,
            "circuit_b",
            vec![FieldElement::from_u64(42)],
            vec![FieldElement::from_u64(100)],
        ));

        assert_eq!(trace.depth(), 2);
        assert!(trace.success);

        let outputs = trace.step_outputs(0).unwrap();
        assert_eq!(outputs[0], FieldElement::from_u64(42));
    }

    #[test]
    fn test_cross_step_assertion() {
        let unique = CrossStepAssertion::unique("nullifier_unique", 0);
        assert!(unique.relation.contains("unique(step[*].out[0])"));

        let equal = CrossStepAssertion::equal("root_consistent", 0, 1, 1, 0);
        assert!(equal.relation.contains("step[0].out[1] == step[1].in[0]"));
    }

    #[test]
    fn test_chain_spec_swap_steps() {
        let spec = ChainSpec::new(
            "test_chain",
            vec![
                StepSpec::fresh("circuit_a"),
                StepSpec::fresh("circuit_b"),
                StepSpec::from_prior("circuit_c", 0, vec![(0, 0)]),
            ],
        );

        let swapped = spec.swap_steps(0, 1).unwrap();
        assert_eq!(swapped.steps.len(), 3);
        assert_eq!(swapped.steps[0].circuit_ref, "circuit_b");
        assert_eq!(swapped.steps[1].circuit_ref, "circuit_a");

        match &swapped.steps[2].input_wiring {
            InputWiring::FromPriorOutput { step, .. } => assert_eq!(*step, 1),
            other => panic!("expected FromPriorOutput, got {:?}", other),
        }

        assert!(spec.swap_steps(0, 5).is_none());
        assert!(spec.swap_steps(0, 0).is_none());
    }

    #[test]
    fn test_chain_spec_duplicate_step() {
        let spec = ChainSpec::new(
            "test_chain",
            vec![
                StepSpec::fresh("circuit_a"),
                StepSpec::from_prior("circuit_b", 0, vec![(0, 0)]),
            ],
        );

        let duped = spec.duplicate_step(0).unwrap();
        assert_eq!(duped.steps.len(), 3);
        assert_eq!(duped.steps[0].circuit_ref, "circuit_a");
        assert_eq!(duped.steps[1].circuit_ref, "circuit_a");
        assert_eq!(duped.steps[1].input_wiring, InputWiring::Fresh);

        match &duped.steps[2].input_wiring {
            InputWiring::FromPriorOutput { step, .. } => assert_eq!(*step, 0),
            other => panic!("expected FromPriorOutput, got {:?}", other),
        }

        assert!(spec.duplicate_step(5).is_none());
    }

    #[test]
    fn test_assertion_remap_after_removal() {
        // Test remapping assertion when step is removed
        let assertion = CrossStepAssertion::equal("test", 0, 0, 2, 0);

        // Remove step 1 - indices 0 stays 0, index 2 becomes 1
        let remapped = assertion.remap_after_removal(1).unwrap();
        assert!(remapped.relation.contains("step[0]"));
        assert!(remapped.relation.contains("step[1]"));
        assert!(!remapped.relation.contains("step[2]"));

        // Remove step 0 - assertion should become invalid (references removed step)
        let invalid = assertion.remap_after_removal(0);
        assert!(invalid.is_none());
    }

    #[test]
    fn test_assertion_remap_after_swap() {
        // Test remapping assertion when steps are swapped
        let assertion = CrossStepAssertion::equal("test", 0, 0, 2, 0);

        // Swap steps 0 and 2 - indices should swap
        let remapped = assertion.remap_after_swap(0, 2);
        assert!(remapped
            .relation
            .contains("step[2].out[0] == step[0].in[0]"));
    }

    #[test]
    fn test_assertion_remap_after_insertion() {
        // Test remapping assertion when step is inserted
        let assertion = CrossStepAssertion::equal("test", 0, 0, 2, 0);

        // Insert step at 1 - index 0 stays 0, index 2 becomes 3
        let remapped = assertion.remap_after_insertion(1);
        assert!(remapped.relation.contains("step[0]"));
        assert!(remapped.relation.contains("step[3]"));
        assert!(!remapped.relation.contains("step[2]"));
    }

    #[test]
    fn test_chain_with_assertions_without_step() {
        // Test that assertions are properly remapped when removing a step
        let spec = ChainSpec::new(
            "test_chain",
            vec![
                StepSpec::fresh("circuit_a"),
                StepSpec::fresh("circuit_b"),
                StepSpec::fresh("circuit_c"),
            ],
        )
        .with_assertion(CrossStepAssertion::equal("ab_check", 0, 0, 1, 0))
        .with_assertion(CrossStepAssertion::equal("bc_check", 1, 0, 2, 0));

        // Remove step 1 - first assertion should be removed (refs step 1)
        // Second assertion refs both 1 and 2, so should be removed
        let reduced = spec.without_step(1).unwrap();
        assert_eq!(reduced.assertions.len(), 0);
    }

    #[test]
    fn test_chain_with_assertions_swap_steps() {
        let spec = ChainSpec::new(
            "test_chain",
            vec![
                StepSpec::fresh("circuit_a"),
                StepSpec::fresh("circuit_b"),
                StepSpec::fresh("circuit_c"),
            ],
        )
        .with_assertion(CrossStepAssertion::equal("ac_check", 0, 0, 2, 0));

        // Swap 0 and 1 - assertion indices should update: 0->1, 2 stays 2
        let swapped = spec.swap_steps(0, 1).unwrap();
        assert_eq!(swapped.assertions.len(), 1);
        assert!(swapped.assertions[0].relation.contains("step[1]"));
        assert!(swapped.assertions[0].relation.contains("step[2]"));
    }

    #[test]
    fn test_chain_with_assertions_duplicate_step() {
        let spec = ChainSpec::new(
            "test_chain",
            vec![StepSpec::fresh("circuit_a"), StepSpec::fresh("circuit_b")],
        )
        .with_assertion(CrossStepAssertion::equal("ab_check", 0, 0, 1, 0));

        // Duplicate step 0 - assertion indices: 0 stays 0, 1 becomes 2
        let duped = spec.duplicate_step(0).unwrap();
        assert_eq!(duped.assertions.len(), 1);
        assert!(duped.assertions[0].relation.contains("step[0]"));
        assert!(duped.assertions[0].relation.contains("step[2]"));
    }
}
