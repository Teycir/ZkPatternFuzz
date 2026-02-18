
use super::*;

#[test]
fn test_lean_exporter_creation() {
    let exporter = LeanExporter::new(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );
    assert_eq!(exporter.system(), ProofSystem::Lean4);
}

#[test]
fn test_value_to_lean() {
    let sym = SymbolicValue::Symbol("x".to_string());
    assert_eq!(LeanExporter::value_to_lean(&sym), "x");

    let add = SymbolicValue::Add(
        Box::new(SymbolicValue::Symbol("x".to_string())),
        Box::new(SymbolicValue::Symbol("y".to_string())),
    );
    assert_eq!(LeanExporter::value_to_lean(&add), "(x + y)");
}

#[test]
fn test_export_obligation_has_no_sorry() {
    let exporter = LeanExporter::new(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );

    let obligation = ProofObligation {
        name: "sample".to_string(),
        description: "Sample obligation".to_string(),
        property: crate::formal::CircuitProperty::ConstraintSatisfied {
            constraint_id: 0,
            description: "c0".to_string(),
        },
        property_type: crate::formal::PropertyType::Soundness,
        constraints: Vec::new(),
        variables: vec!["x".to_string()],
        preconditions: vec![SymbolicConstraint::Eq(
            SymbolicValue::Symbol("x".to_string()),
            SymbolicValue::Symbol("x".to_string()),
        )],
        postconditions: vec![SymbolicConstraint::True],
    };

    let result = exporter.export_obligation(&obligation);
    assert!(result.code.contains("sample_obligation"));
    assert!(!result.code.contains("sorry"));
}
