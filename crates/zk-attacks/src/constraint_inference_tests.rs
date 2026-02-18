
use super::*;

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
