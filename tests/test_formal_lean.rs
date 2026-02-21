use zk_fuzzer::analysis::symbolic::{SymbolicConstraint, SymbolicValue};
use zk_fuzzer::formal::{
    CircuitProperty, LeanExporter, ProofExporter, ProofObligation, ProofSystem, PropertyType,
};

#[test]
fn test_lean_exporter_creation() {
    let exporter = LeanExporter::new(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );
    assert_eq!(exporter.system(), ProofSystem::Lean4);
}

#[test]
fn test_symbol_names_are_rendered_as_identifiers() {
    let exporter = LeanExporter::new(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );
    let obligation = ProofObligation {
        name: "names".to_string(),
        description: "name rendering".to_string(),
        property: CircuitProperty::ConstraintSatisfied {
            constraint_id: 2,
            description: "names".to_string(),
        },
        property_type: PropertyType::Soundness,
        constraints: Vec::new(),
        variables: vec!["x".to_string()],
        preconditions: vec![SymbolicConstraint::Eq(
            SymbolicValue::Symbol("x".to_string()),
            SymbolicValue::Symbol("x".to_string()),
        )],
        postconditions: vec![SymbolicConstraint::True],
    };

    let result = exporter.export_obligation(&obligation);
    assert!(result.code.contains("x = x"));
}

#[test]
fn test_export_obligation_has_no_sorry() {
    let exporter = LeanExporter::new(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );

    let obligation = ProofObligation {
        name: "sample".to_string(),
        description: "Sample obligation".to_string(),
        property: CircuitProperty::ConstraintSatisfied {
            constraint_id: 0,
            description: "c0".to_string(),
        },
        property_type: PropertyType::Soundness,
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

#[test]
fn test_export_obligation_renders_addition_in_lean_form() {
    let exporter = LeanExporter::new(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );
    let obligation = ProofObligation {
        name: "sum".to_string(),
        description: "sum relation".to_string(),
        property: CircuitProperty::ConstraintSatisfied {
            constraint_id: 1,
            description: "sum".to_string(),
        },
        property_type: PropertyType::Soundness,
        constraints: Vec::new(),
        variables: vec!["x".to_string(), "y".to_string(), "z".to_string()],
        preconditions: vec![SymbolicConstraint::Eq(
            SymbolicValue::Add(
                Box::new(SymbolicValue::Symbol("x".to_string())),
                Box::new(SymbolicValue::Symbol("y".to_string())),
            ),
            SymbolicValue::Symbol("z".to_string()),
        )],
        postconditions: vec![SymbolicConstraint::True],
    };

    let result = exporter.export_obligation(&obligation);
    assert!(result.code.contains("(x + y)"));
}
