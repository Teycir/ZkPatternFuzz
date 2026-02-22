use zk_core::FieldElement;
use zk_fuzzer::config::v2::{Invariant, InvariantOracle, InvariantType};
use zk_fuzzer::config::{FuzzStrategy, Input};
use zk_fuzzer::fuzzer::invariant_checker::InvariantChecker;

fn make_field_element(val: u64) -> FieldElement {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    FieldElement(bytes)
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

    let inputs = vec![Input {
        name: "x".to_string(),
        input_type: "field".to_string(),
        fuzz_strategy: FuzzStrategy::Random,
        constraints: vec![],
        interesting: vec![],
        length: None,
    }];

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
    let inputs = vec![Input {
        name: "x".to_string(),
        input_type: "field".to_string(),
        fuzz_strategy: FuzzStrategy::Random,
        constraints: vec![],
        interesting: vec![],
        length: None,
    }];
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
