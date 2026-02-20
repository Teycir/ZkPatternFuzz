use super::*;

#[test]
fn test_parse_grammar() {
    let yaml = r#"
name: TestGrammar
description: Test grammar for unit tests
inputs:
  - name: secret
    type: field
    entropy: high
  - name: pathIndices
    type: array
    length: 5
    element_type: bool
"#;
    let grammar = InputGrammar::from_yaml_str(yaml).unwrap();
    assert_eq!(grammar.name, "TestGrammar");
    assert_eq!(grammar.inputs.len(), 2);
    assert_eq!(grammar.inputs[0].input_type, InputType::Field);
    assert_eq!(grammar.inputs[1].length, Some(5));
}

#[test]
fn test_generate_test_case() {
    let grammar = standard::tornado_cash_withdrawal();
    let mut rng = rand::thread_rng();

    let test_case = grammar.generate(&mut rng);

    // Should have: root(1) + nullifierHash(1) + recipient(1) + relayer(1) +
    // fee(1) + refund(1) + nullifier(1) + secret(1) + pathElements(20) + pathIndices(20)
    assert_eq!(test_case.inputs.len(), 48);
}

#[test]
fn test_mutation() {
    let grammar = standard::tornado_cash_withdrawal();
    let mut rng = rand::thread_rng();

    let original = grammar.generate(&mut rng);

    // Try multiple mutations - at least one should differ
    let mut any_different = false;
    for _ in 0..10 {
        let mutated = grammar.mutate(&original, &mut rng);
        // Should have same length
        assert_eq!(original.inputs.len(), mutated.inputs.len());
        if original.inputs != mutated.inputs {
            any_different = true;
            break;
        }
    }

    // At least one mutation should have produced a different result
    assert!(
        any_different,
        "After 10 attempts, mutation should produce different output"
    );
}

#[test]
fn test_standard_grammars() {
    let tornado = standard::tornado_cash_withdrawal();
    assert_eq!(tornado.input_count(), 48);

    let semaphore = standard::semaphore_identity();
    assert!(semaphore.input_count() > 0);

    let range = standard::range_proof(64);
    assert_eq!(range.input_count(), 1);
}
