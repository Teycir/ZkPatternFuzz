use super::*;
use zk_core::{CircuitInfo, ConstraintResult, ExecutionCoverage, ExecutionResult, Framework};

struct OverlayRepairExecutor {
    name: String,
    always_fail: bool,
}

impl OverlayRepairExecutor {
    fn new(name: &str, always_fail: bool) -> Self {
        Self {
            name: name.to_string(),
            always_fail,
        }
    }
}

impl CircuitExecutor for OverlayRepairExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo::new(self.name.clone(), 1, 2, 1, 0)
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        if self.always_fail {
            return ExecutionResult::failure("forced failure".to_string());
        }

        // Requires input[1] to mirror input[0] for success.
        if inputs.len() >= 2 && inputs[1] == inputs[0] {
            ExecutionResult::success(
                vec![],
                ExecutionCoverage::with_constraints(vec![0], vec![0]),
            )
        } else {
            ExecutionResult::failure("dependency mismatch".to_string())
        }
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }
}

impl ConstraintInspector for OverlayRepairExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        vec![ConstraintEquation {
            id: 0,
            a_terms: vec![(0, FieldElement::one())],
            b_terms: vec![(1, FieldElement::one())],
            c_terms: vec![(2, FieldElement::one())],
            description: Some("overlay repair dependency".to_string()),
        }]
    }

    fn check_constraints(&self, witness: &[FieldElement]) -> Vec<ConstraintResult> {
        let satisfied = witness.len() >= 2 && witness[1] == witness[0];
        vec![ConstraintResult {
            constraint_id: 0,
            satisfied,
            lhs_value: witness.first().cloned().unwrap_or_else(FieldElement::zero),
            rhs_value: witness.get(1).cloned().unwrap_or_else(FieldElement::zero),
        }]
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        vec![vec![0, 1, 2]]
    }

    fn public_input_indices(&self) -> Vec<usize> {
        vec![0]
    }

    fn private_input_indices(&self) -> Vec<usize> {
        vec![1, 2]
    }
}

#[test]
fn test_constraint_category_all() {
    let categories = ConstraintCategory::all();
    assert!(categories.len() >= 5);
}

#[test]
fn test_engine_creation() {
    let engine = ConstraintInferenceEngine::new()
        .with_confidence_threshold(0.8)
        .with_generate_violations(true);

    assert!(!engine.rules.is_empty());
}

#[test]
fn test_implied_constraint_structure() {
    let implied = ImpliedConstraint {
        category: ConstraintCategory::BitDecompositionRoundTrip,
        description: "Test".to_string(),
        confidence: 0.9,
        involved_wires: vec![1, 2, 3],
        suggested_constraint: "sum(bits) == value".to_string(),
        violation_witness: Some(vec![FieldElement::from_u64(1)]),
        confirmation: ViolationConfirmation::Unchecked,
    };

    assert!(implied.violation_witness.is_some());
    assert_eq!(implied.involved_wires.len(), 3);
}

#[test]
fn confirm_violations_repairs_overlay_before_rejecting() {
    let engine = ConstraintInferenceEngine::new();
    let executor = OverlayRepairExecutor::new("overlay-repair", false);

    let mut implied = vec![ImpliedConstraint {
        category: ConstraintCategory::RangeEnforcement,
        description: "overlay candidate".to_string(),
        confidence: 0.95,
        involved_wires: vec![0],
        suggested_constraint: "wire_0 in range".to_string(),
        violation_witness: Some(vec![FieldElement::from_u64(42)]),
        confirmation: ViolationConfirmation::Unchecked,
    }];

    // Naive overlay would create [42, 7, 9], which fails executor relation
    // (input1 must equal input0). Repair should recover [42, 42, 9].
    let base_inputs = vec![
        FieldElement::from_u64(10),
        FieldElement::from_u64(7),
        FieldElement::from_u64(9),
    ];
    let output_wires = HashSet::new();
    engine.confirm_violations(&executor, &base_inputs, &mut implied, &output_wires);

    assert_eq!(implied[0].confirmation, ViolationConfirmation::Confirmed);
    let repaired = implied[0]
        .violation_witness
        .as_ref()
        .expect("repaired witness stored");
    assert_eq!(repaired[0], FieldElement::from_u64(42));
    assert_eq!(repaired[1], FieldElement::from_u64(42));
}

#[test]
fn confirm_violations_marks_inconclusive_when_repair_fails() {
    let engine = ConstraintInferenceEngine::new();
    let executor = OverlayRepairExecutor::new("overlay-fail", true);

    let mut implied = vec![ImpliedConstraint {
        category: ConstraintCategory::RangeEnforcement,
        description: "overlay candidate fail".to_string(),
        confidence: 0.95,
        involved_wires: vec![0],
        suggested_constraint: "wire_0 in range".to_string(),
        violation_witness: Some(vec![FieldElement::from_u64(42)]),
        confirmation: ViolationConfirmation::Unchecked,
    }];

    let base_inputs = vec![
        FieldElement::from_u64(10),
        FieldElement::from_u64(7),
        FieldElement::from_u64(9),
    ];
    let output_wires = HashSet::new();
    engine.confirm_violations(&executor, &base_inputs, &mut implied, &output_wires);

    assert_eq!(implied[0].confirmation, ViolationConfirmation::Inconclusive);
}
