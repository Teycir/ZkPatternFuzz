use super::*;

#[test]
fn test_underconstrained_oracle() {
    let mut oracle = UnderconstrainedOracle::new();
    let test_case = TestCase {
        inputs: vec![FieldElement::zero()],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let output = vec![FieldElement::one()];

    // First check should not find anything
    assert!(oracle.check(&test_case, &output).is_none());
}

#[test]
fn test_underconstrained_oracle_scopes_public_inputs() {
    let mut oracle = UnderconstrainedOracle::new().with_public_input_count(1);
    let output = vec![FieldElement::one()];

    let tc_a = TestCase {
        inputs: vec![FieldElement::from_u64(1), FieldElement::from_u64(10)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };

    let tc_b = TestCase {
        inputs: vec![FieldElement::from_u64(2), FieldElement::from_u64(20)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };

    let tc_c = TestCase {
        inputs: vec![FieldElement::from_u64(1), FieldElement::from_u64(99)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };

    // Different public inputs: should not collide
    assert!(oracle.check(&tc_a, &output).is_none());
    assert!(oracle.check(&tc_b, &output).is_none());

    // Same public input, different private input: should collide
    let finding = oracle.check(&tc_c, &output);
    assert!(finding.is_some());
    let finding = finding.expect("collision finding expected");
    assert_eq!(finding.attack_type, AttackType::Underconstrained);
    assert_eq!(finding.poc.public_inputs, vec![FieldElement::from_u64(1)]);
}

#[test]
fn test_constraint_count_oracle_emits_variance_once() {
    let mut oracle = ConstraintCountOracle::new(8);
    let test_case = TestCase {
        inputs: vec![FieldElement::from_u64(1), FieldElement::from_u64(2)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };

    assert!(oracle.check_with_count(&test_case, 8).is_none());
    assert!(oracle.check_with_count(&test_case, 7).is_some()); // mismatch

    let variance = oracle.check_with_count(&test_case, 8);
    assert!(variance.is_some());
    let variance = variance.expect("variance finding expected");
    assert_eq!(variance.severity, Severity::Critical);

    // Once emitted, the same min/max variance should not repeatedly fire.
    assert!(oracle.check_with_count(&test_case, 8).is_none());
}

#[test]
fn test_arithmetic_overflow_oracle() {
    let mut oracle = ArithmeticOverflowOracle::new();
    let test_case = TestCase {
        inputs: vec![FieldElement([0xff; 32])], // Definitely overflow
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let output = vec![FieldElement::zero()];

    let finding = oracle.check(&test_case, &output);
    assert!(finding.is_some());
    assert_eq!(finding.unwrap().attack_type, AttackType::ArithmeticOverflow);
}
