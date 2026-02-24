use super::*;

#[test]
fn test_transform_identity() {
    let witness = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];

    let result = Transform::Identity.apply(&witness);
    assert_eq!(witness, result);
}

#[test]
fn test_transform_swap() {
    let witness = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];

    let result = Transform::SwapInputs {
        index_a: 0,
        index_b: 2,
    }
    .apply(&witness);

    assert_eq!(result[0], FieldElement::from_u64(3));
    assert_eq!(result[1], FieldElement::from_u64(2));
    assert_eq!(result[2], FieldElement::from_u64(1));
}

#[test]
fn test_transform_negate() {
    let witness = vec![FieldElement::from_u64(42)];
    let result = Transform::NegateInputs { indices: vec![0] }.apply(&witness);

    assert_ne!(result[0], witness[0]);
}

#[test]
fn test_transform_chain() {
    let witness = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];

    let chain = Transform::Chain(vec![
        Transform::SwapInputs {
            index_a: 0,
            index_b: 1,
        },
        Transform::DoubleInput { index: 0 },
    ]);

    let result = chain.apply(&witness);

    // After swap: [2, 1], after double index 0: [4, 1]
    assert_eq!(result[0], FieldElement::from_u64(4));
    assert_eq!(result[1], FieldElement::from_u64(1));
}

#[test]
fn test_oracle_creation() {
    let oracle = MetamorphicOracle::new()
        .with_circuit_aware_relations()
        .with_tolerance(0.001);

    assert!(!oracle.relations.is_empty());
}

#[test]
fn test_metamorphic_relation() {
    let relation = MetamorphicRelation::new(
        "test_swap",
        Transform::SwapInputs {
            index_a: 0,
            index_b: 1,
        },
        ExpectedBehavior::OutputChanged,
    )
    .with_severity(Severity::Critical)
    .with_description("Test description");

    assert_eq!(relation.name, "test_swap");
    assert_eq!(relation.severity, Severity::Critical);
    assert!(relation.description.is_some());
}

#[test]
fn test_output_unchanged_passes_when_both_fail_same_way() {
    let oracle = MetamorphicOracle::new();
    let base = ExecutionResult::failure("constraint unsatisfied".to_string());
    let transformed = ExecutionResult::failure("constraint unsatisfied".to_string());

    let (passed, reason) =
        oracle.check_expected(&base, &transformed, &ExpectedBehavior::OutputUnchanged);
    assert!(passed);
    assert!(reason.is_none());
}

#[test]
fn test_output_unchanged_fails_when_both_fail_differently() {
    let oracle = MetamorphicOracle::new();
    let base = ExecutionResult::failure("constraint unsatisfied".to_string());
    let transformed = ExecutionResult::failure("index out of bounds".to_string());

    let (passed, reason) =
        oracle.check_expected(&base, &transformed, &ExpectedBehavior::OutputUnchanged);
    assert!(!passed);
    assert_eq!(
        reason.as_deref(),
        Some("Execution failed differently between equivalent inputs")
    );
}
