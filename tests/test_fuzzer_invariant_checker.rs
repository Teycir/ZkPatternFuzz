use zk_core::FieldElement;
use zk_fuzzer::config::v2::{Invariant, InvariantOracle, InvariantType};
use zk_fuzzer::config::{FuzzStrategy, Input};
use zk_fuzzer::fuzzer::invariant_checker::InvariantChecker;

fn make_field_element(val: u64) -> FieldElement {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    FieldElement(bytes)
}

fn field_input(name: &str) -> Input {
    Input {
        name: name.to_string(),
        input_type: "field".to_string(),
        fuzz_strategy: FuzzStrategy::Random,
        constraints: vec![],
        interesting: vec![],
        length: None,
    }
}

#[test]
fn test_range_check() {
    let invariant = Invariant {
        name: "test_range".to_string(),
        invariant_type: InvariantType::Range,
        relation: "0 <= x < 100".to_string(),
        oracle: InvariantOracle::MustHold,
        transform: None,
        expected: None,
        description: None,
        severity: Some("high".to_string()),
    };

    let inputs = vec![field_input("x")];

    let mut checker = InvariantChecker::new(vec![invariant], &inputs);

    // Valid value
    let witness = vec![make_field_element(50)];
    let violations = checker.check(&witness, &[], true);
    assert!(violations.is_empty());

    // Invalid value (>= 100)
    let witness = vec![make_field_element(100)];
    let violations = checker.check(&witness, &[], true);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].invariant_name, "test_range");
}

#[test]
fn test_register_runtime_invariants_from_spec_inference() {
    let inputs = vec![field_input("x")];
    let mut checker = InvariantChecker::new(Vec::new(), &inputs);

    let runtime_invariant = Invariant {
        name: "auto_spec_range_x".to_string(),
        invariant_type: InvariantType::Range,
        relation: "0 <= x <= 9".to_string(),
        oracle: InvariantOracle::MustHold,
        transform: None,
        expected: None,
        description: Some("generated from spec inference".to_string()),
        severity: Some("high".to_string()),
    };

    let added = checker.register_runtime_invariants(vec![runtime_invariant]);
    assert_eq!(added, 1);

    let witness = vec![make_field_element(10)];
    let violations = checker.check(&witness, &[], true);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].invariant_name, "auto_spec_range_x");
}

#[test]
fn test_regression_underconstrained_merkle_detects_root_mismatch() {
    let merkle_invariant = Invariant {
        name: "merkle_root_integrity".to_string(),
        invariant_type: InvariantType::Constraint,
        relation: "claimed_root == output_0".to_string(),
        oracle: InvariantOracle::MustHold,
        transform: None,
        expected: None,
        description: Some("Claimed root must match computed root output".to_string()),
        severity: Some("critical".to_string()),
    };
    let inputs = vec![
        field_input("claimed_root"),
        field_input("leaf"),
        field_input("path_index"),
    ];
    let mut checker = InvariantChecker::new(vec![merkle_invariant], &inputs);

    // Regression fixture: circuit accepted a witness where claimed public root
    // does not match the computed root output (underconstrained Merkle bug class).
    let witness = vec![
        make_field_element(0xAA), // claimed_root
        make_field_element(5),    // leaf
        make_field_element(1),    // path_index
    ];
    let outputs = vec![make_field_element(0xBB)]; // computed root
    let violations = checker.check(&witness, &outputs, true);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].invariant_name, "merkle_root_integrity");
    assert!(violations[0].evidence.contains("Constraint violated"));
}

#[test]
fn test_regression_underconstrained_merkle_no_false_positive_when_bound() {
    let merkle_invariant = Invariant {
        name: "merkle_root_integrity".to_string(),
        invariant_type: InvariantType::Constraint,
        relation: "claimed_root == output_0".to_string(),
        oracle: InvariantOracle::MustHold,
        transform: None,
        expected: None,
        description: Some("Claimed root must match computed root output".to_string()),
        severity: Some("critical".to_string()),
    };
    let inputs = vec![
        field_input("claimed_root"),
        field_input("leaf"),
        field_input("path_index"),
    ];
    let mut checker = InvariantChecker::new(vec![merkle_invariant], &inputs);

    let witness = vec![
        make_field_element(0xAA),
        make_field_element(5),
        make_field_element(1),
    ];
    let outputs = vec![make_field_element(0xAA)];
    let violations = checker.check(&witness, &outputs, true);

    assert!(violations.is_empty());
}

#[test]
fn test_regression_nullifier_replay_detects_cross_scope_reuse() {
    let nullifier_uniqueness = Invariant {
        name: "nullifier_uniqueness".to_string(),
        invariant_type: InvariantType::Uniqueness,
        relation: "unique(nullifier) for each (scope)".to_string(),
        oracle: InvariantOracle::MustHold,
        transform: None,
        expected: None,
        description: Some("Nullifier must be unique across scopes".to_string()),
        severity: Some("critical".to_string()),
    };
    let inputs = vec![field_input("scope"), field_input("nullifier")];
    let mut checker = InvariantChecker::new(vec![nullifier_uniqueness], &inputs);

    let first = vec![make_field_element(1), make_field_element(42)];
    assert!(checker.check(&first, &[], true).is_empty());

    // Replay: same nullifier reused in a different scope.
    let replay = vec![make_field_element(2), make_field_element(42)];
    let violations = checker.check(&replay, &[], true);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].invariant_name, "nullifier_uniqueness");
    assert!(violations[0].evidence.contains("Uniqueness violation"));
}

#[test]
fn test_regression_nullifier_replay_no_false_positive_for_distinct_values() {
    let nullifier_uniqueness = Invariant {
        name: "nullifier_uniqueness".to_string(),
        invariant_type: InvariantType::Uniqueness,
        relation: "unique(nullifier) for each (scope)".to_string(),
        oracle: InvariantOracle::MustHold,
        transform: None,
        expected: None,
        description: Some("Nullifier must be unique across scopes".to_string()),
        severity: Some("critical".to_string()),
    };
    let inputs = vec![field_input("scope"), field_input("nullifier")];
    let mut checker = InvariantChecker::new(vec![nullifier_uniqueness], &inputs);

    let first = vec![make_field_element(1), make_field_element(42)];
    let second = vec![make_field_element(2), make_field_element(43)];

    assert!(checker.check(&first, &[], true).is_empty());
    assert!(checker.check(&second, &[], true).is_empty());
}
