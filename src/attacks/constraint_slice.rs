//! Constraint Slice Oracle
//!
//! Slices constraints into dependency cones and performs targeted mutation
//! within those cones. This helps find bugs that only manifest when specific
//! subsets of constraints are exercised together.
//!
//! # Concept
//!
//! 1. Build backward slice from each public output
//! 2. Identify the "cone" of constraints affecting that output
//! 3. Mutate only inputs within the cone
//! 4. Detect if output changes unexpectedly (leaked constraints)
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::attacks::constraint_slice::ConstraintSlicer;
//!
//! let slicer = ConstraintSlicer::new();
//! let cone = slicer.slice_to_output(&inspector, output_idx)?;
//! let test_cases = slicer.mutate_in_cone(&cone, base_witness);
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use zk_core::{
    AttackType, CircuitExecutor, ConstraintEquation, ConstraintInspector,
    ExecutionResult, FieldElement, Finding, ProofOfConcept, Severity,
};
use rand::Rng;

/// Unique constraint identifier
pub type ConstraintId = usize;

/// A cone of constraints affecting a specific output
#[derive(Debug, Clone)]
pub struct ConstraintCone {
    /// Root output index this cone affects
    pub output_index: usize,
    /// Constraints in this cone (ordered by distance from output)
    pub constraints: Vec<ConstraintId>,
    /// Input wires that can affect this output
    pub affecting_inputs: HashSet<usize>,
    /// Depth of the cone (max distance from output)
    pub depth: usize,
}

impl ConstraintCone {
    /// Check if an input is in this cone
    pub fn contains_input(&self, input_idx: usize) -> bool {
        self.affecting_inputs.contains(&input_idx)
    }

    /// Get constraint count
    pub fn constraint_count(&self) -> usize {
        self.constraints.len()
    }
}

/// Constraint slicer for building dependency cones
pub struct ConstraintSlicer {
    /// Maximum depth to explore
    max_depth: usize,
    /// Wire-to-constraint mapping
    wire_to_constraints: HashMap<usize, Vec<ConstraintId>>,
    /// Constraint-to-wire mapping
    constraint_to_wires: HashMap<ConstraintId, HashSet<usize>>,
    /// All constraints
    constraints: Vec<ConstraintEquation>,
    /// Number of public inputs
    num_public_inputs: usize,
    /// Total number of wires
    num_wires: usize,
}

impl ConstraintSlicer {
    /// Create a new slicer from constraint inspector
    pub fn from_inspector(
        inspector: &dyn ConstraintInspector,
        num_public_inputs: usize,
        num_wires: usize,
    ) -> Self {
        let constraints = inspector.get_constraints();
        
        let mut wire_to_constraints: HashMap<usize, Vec<ConstraintId>> = HashMap::new();
        let mut constraint_to_wires: HashMap<ConstraintId, HashSet<usize>> = HashMap::new();

        for (idx, constraint) in constraints.iter().enumerate() {
            let wires = Self::extract_wires(constraint);
            constraint_to_wires.insert(idx, wires.clone());
            
            for wire in wires {
                wire_to_constraints.entry(wire).or_default().push(idx);
            }
        }

        Self {
            max_depth: 20,
            wire_to_constraints,
            constraint_to_wires,
            constraints,
            num_public_inputs,
            num_wires,
        }
    }

    /// Extract all wire indices from a constraint
    fn extract_wires(constraint: &ConstraintEquation) -> HashSet<usize> {
        constraint.a_terms.iter()
            .chain(constraint.b_terms.iter())
            .chain(constraint.c_terms.iter())
            .map(|(w, _)| *w)
            .collect()
    }

    /// Set maximum slicing depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Slice to a specific output, building the dependency cone
    pub fn slice_to_output(&self, output_wire: usize) -> ConstraintCone {
        let mut visited_constraints: HashSet<ConstraintId> = HashSet::new();
        let mut visited_wires: HashSet<usize> = HashSet::new();
        let mut affecting_inputs: HashSet<usize> = HashSet::new();
        let mut ordered_constraints: Vec<ConstraintId> = Vec::new();
        
        // BFS from output wire
        let mut queue: VecDeque<(usize, usize)> = VecDeque::new(); // (wire, depth)
        queue.push_back((output_wire, 0));
        visited_wires.insert(output_wire);

        let mut max_depth = 0;

        while let Some((wire, depth)) = queue.pop_front() {
            if depth > self.max_depth {
                continue;
            }
            max_depth = max_depth.max(depth);

            // Check if this wire is an input
            if wire < self.num_public_inputs + self.num_wires / 2 {
                // Heuristic: low-indexed wires are likely inputs
                affecting_inputs.insert(wire);
            }

            // Find constraints that produce this wire
            if let Some(constraints) = self.wire_to_constraints.get(&wire) {
                for &constraint_id in constraints {
                    if visited_constraints.insert(constraint_id) {
                        ordered_constraints.push(constraint_id);

                        // Add input wires of this constraint to queue
                        if let Some(wires) = self.constraint_to_wires.get(&constraint_id) {
                            for &w in wires {
                                if visited_wires.insert(w) {
                                    queue.push_back((w, depth + 1));
                                }
                            }
                        }
                    }
                }
            }
        }

        ConstraintCone {
            output_index: output_wire,
            constraints: ordered_constraints,
            affecting_inputs,
            depth: max_depth,
        }
    }

    /// Slice to all public outputs
    pub fn slice_all_outputs(&self, output_wires: &[usize]) -> Vec<ConstraintCone> {
        output_wires.iter()
            .map(|&w| self.slice_to_output(w))
            .collect()
    }

    /// Generate test cases that mutate only inputs within a cone
    pub fn mutate_in_cone(
        &self,
        cone: &ConstraintCone,
        base_witness: &[FieldElement],
        num_cases: usize,
        rng: &mut impl Rng,
    ) -> Vec<Vec<FieldElement>> {
        let mut test_cases = Vec::new();

        for _ in 0..num_cases {
            let mut case = base_witness.to_vec();

            // Only mutate inputs in the cone
            for &input_idx in &cone.affecting_inputs {
                if input_idx < case.len() && rng.gen_bool(0.3) {
                    case[input_idx] = self.mutate_field_element(&case[input_idx], rng);
                }
            }

            test_cases.push(case);
        }

        test_cases
    }

    /// Simple field element mutation
    fn mutate_field_element(&self, fe: &FieldElement, rng: &mut impl Rng) -> FieldElement {
        let mutation = rng.gen_range(0..5);
        match mutation {
            0 => fe.add(&FieldElement::one()),
            1 => fe.add(&fe.neg().add(&FieldElement::one()).neg()), // subtract 1
            2 => fe.neg(),
            3 => fe.mul(&FieldElement::from_u64(2)),
            _ => FieldElement::random(rng),
        }
    }

    /// Find constraints that "leak" - affect outputs outside their expected cone
    pub fn find_leaking_constraints(&self, cones: &[ConstraintCone]) -> Vec<LeakingConstraint> {
        let mut leaking = Vec::new();

        // Build map of which cones each constraint should be in
        let mut expected_cones: HashMap<ConstraintId, HashSet<usize>> = HashMap::new();
        for (cone_idx, cone) in cones.iter().enumerate() {
            for &constraint_id in &cone.constraints {
                expected_cones.entry(constraint_id).or_default().insert(cone_idx);
            }
        }

        // Find constraints in multiple cones (potential leaks)
        for (constraint_id, cone_indices) in &expected_cones {
            if cone_indices.len() > 1 {
                leaking.push(LeakingConstraint {
                    constraint_id: *constraint_id,
                    affected_outputs: cone_indices.iter().copied().collect(),
                    description: format!(
                        "Constraint {} affects outputs {:?}",
                        constraint_id,
                        cone_indices.iter().collect::<Vec<_>>()
                    ),
                });
            }
        }

        leaking
    }
}

/// A constraint that affects multiple outputs (potential information leak)
#[derive(Debug, Clone)]
pub struct LeakingConstraint {
    pub constraint_id: ConstraintId,
    pub affected_outputs: Vec<usize>,
    pub description: String,
}

/// Constraint slice oracle for testing
pub struct ConstraintSliceOracle {
    /// Number of test cases per cone
    samples_per_cone: usize,
    /// Whether to test for leaks
    test_leaks: bool,
}

impl Default for ConstraintSliceOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintSliceOracle {
    /// Create a new constraint slice oracle
    pub fn new() -> Self {
        Self {
            samples_per_cone: 100,
            test_leaks: true,
        }
    }

    /// Set samples per cone
    pub fn with_samples(mut self, samples: usize) -> Self {
        self.samples_per_cone = samples;
        self
    }

    /// Run the oracle
    pub async fn run(
        &self,
        executor: &dyn CircuitExecutor,
        base_witness: &[FieldElement],
        output_wires: &[usize],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut rng = rand::thread_rng();

        let inspector = match executor.constraint_inspector() {
            Some(i) => i,
            None => {
                tracing::warn!("No constraint inspector for slice oracle");
                return findings;
            }
        };

        let circuit_info = executor.circuit_info();
        let slicer = ConstraintSlicer::from_inspector(
            inspector,
            circuit_info.num_public_inputs,
            base_witness.len(),
        );

        // Build cones for each output
        let cones = slicer.slice_all_outputs(output_wires);

        // Test each cone
        for cone in &cones {
            let cone_findings = self.test_cone(executor, &slicer, cone, base_witness, &mut rng).await;
            findings.extend(cone_findings);
        }

        // Test for leaking constraints
        if self.test_leaks {
            let leaks = slicer.find_leaking_constraints(&cones);
            for leak in leaks {
                findings.push(Finding {
                    attack_type: AttackType::ConstraintSlice,
                    severity: Severity::Medium,
                    description: format!(
                        "Potential information leak: {}",
                        leak.description
                    ),
                    poc: ProofOfConcept::default(),
                    location: Some(format!("constraint_{}", leak.constraint_id)),
                });
            }
        }

        findings
    }

    /// Test a single cone
    async fn test_cone(
        &self,
        executor: &dyn CircuitExecutor,
        slicer: &ConstraintSlicer,
        cone: &ConstraintCone,
        base_witness: &[FieldElement],
        rng: &mut impl Rng,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get base result
        let base_result = executor.execute(base_witness).await;
        if !base_result.success {
            return findings;
        }

        // Generate and test mutated cases
        let test_cases = slicer.mutate_in_cone(cone, base_witness, self.samples_per_cone, rng);

        for case in &test_cases {
            let result = executor.execute(case).await;
            if result.success {
                // Check for unexpected output changes
                let unexpected = self.check_unexpected_change(
                    cone,
                    &base_result,
                    &result,
                    base_witness,
                    case,
                );

                if let Some(finding) = unexpected {
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Check for unexpected output changes
    fn check_unexpected_change(
        &self,
        cone: &ConstraintCone,
        base_result: &ExecutionResult,
        new_result: &ExecutionResult,
        base_witness: &[FieldElement],
        new_witness: &[FieldElement],
    ) -> Option<Finding> {
        // The output in this cone's index should potentially change
        // But OTHER outputs should NOT change

        if cone.output_index >= base_result.outputs.len() {
            return None;
        }

        // Check if outputs outside this cone changed
        for (i, (base_out, new_out)) in base_result.outputs.iter()
            .zip(new_result.outputs.iter())
            .enumerate()
        {
            if i != cone.output_index && base_out != new_out {
                // An output outside this cone changed - this is unexpected
                return Some(Finding {
                    attack_type: AttackType::ConstraintSlice,
                    severity: Severity::High,
                    description: format!(
                        "Mutating inputs for output {} unexpectedly changed output {}. \
                         This suggests constraint coupling or missing isolation.",
                        cone.output_index, i
                    ),
                    poc: ProofOfConcept {
                        witness_a: base_witness.to_vec(),
                        witness_b: Some(new_witness.to_vec()),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: Some(format!("outputs {} and {}", cone.output_index, i)),
                });
            }
        }

        None
    }
}

/// Statistics from slice testing
#[derive(Debug, Clone, Default)]
pub struct ConstraintSliceStats {
    pub cones_analyzed: usize,
    pub total_constraints_in_cones: usize,
    pub leaking_constraints: usize,
    pub unexpected_changes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_cone() {
        let cone = ConstraintCone {
            output_index: 0,
            constraints: vec![1, 2, 3],
            affecting_inputs: [0, 1, 2].into_iter().collect(),
            depth: 3,
        };

        assert!(cone.contains_input(0));
        assert!(cone.contains_input(1));
        assert!(!cone.contains_input(10));
        assert_eq!(cone.constraint_count(), 3);
    }

    #[test]
    fn test_leaking_constraint() {
        let leak = LeakingConstraint {
            constraint_id: 42,
            affected_outputs: vec![0, 1, 2],
            description: "Test leak".to_string(),
        };

        assert_eq!(leak.affected_outputs.len(), 3);
    }
}
