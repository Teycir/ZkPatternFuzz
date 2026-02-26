use super::*;

#[test]
fn test_underconstrained_oracle() {
    let mut oracle = UnderconstrainedOracle::new();
    let test_case_a = TestCase {
        inputs: vec![FieldElement::zero()],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let test_case_b = TestCase {
        inputs: vec![FieldElement::from_u64(7)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let output = vec![FieldElement::one()];

    // No public inputs configured: collisions are inapplicable and must not emit.
    assert!(oracle.check(&test_case_a, &output).is_none());
    assert!(oracle.check(&test_case_b, &output).is_none());
    assert_eq!(oracle.collision_count, 0);
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
    let mut oracle = ConstraintCountOracle::new(8).with_public_input_count(1);
    let test_case = TestCase {
        inputs: vec![FieldElement::from_u64(1), FieldElement::from_u64(2)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };

    assert!(oracle.check_with_count(&test_case, 8).is_none());
    let mismatch = oracle
        .check_with_count(&test_case, 7)
        .expect("first mismatch should be reported");
    assert_eq!(mismatch.severity, Severity::High);
    assert_eq!(mismatch.poc.public_inputs, vec![FieldElement::from_u64(1)]);

    // Once counts diverge, variance emits once (critical) and then stops.
    let variance = oracle
        .check_with_count(&test_case, 7)
        .expect("variance finding expected");
    assert_eq!(variance.severity, Severity::Critical);
    assert_eq!(variance.poc.public_inputs, vec![FieldElement::from_u64(1)]);

    // Repeated mismatches are de-duplicated; variance is also single-shot.
    assert!(oracle.check_with_count(&test_case, 7).is_none());
    assert!(oracle.check_with_count(&test_case, 8).is_none());
}

#[test]
fn test_arithmetic_overflow_oracle() {
    let mut oracle = ArithmeticOverflowOracle::new().with_public_input_count(1);
    let test_case = TestCase {
        inputs: vec![FieldElement([0xff; 32]), FieldElement::from_u64(42)], // Definitely overflow
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let output = vec![FieldElement::zero()];

    let finding = oracle.check(&test_case, &output);
    assert!(finding.is_some());
    let finding = finding.expect("overflow finding expected");
    assert_eq!(finding.attack_type, AttackType::ArithmeticOverflow);
    assert_eq!(finding.poc.public_inputs, vec![FieldElement([0xff; 32])]);
}

#[test]
fn test_arithmetic_overflow_boundary_ignored_without_public_inputs() {
    let mut oracle = ArithmeticOverflowOracle::new().with_public_input_count(0);
    let test_case = TestCase {
        inputs: vec![FieldElement::from_u64(1)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    };
    let output = vec![FieldElement::zero()];

    // With no observable public interface, boundary-only output signals are inapplicable.
    assert!(oracle.check(&test_case, &output).is_none());
}
