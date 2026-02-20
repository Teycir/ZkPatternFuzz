use super::*;

#[test]
fn test_chain_spec_truncate() {
    let spec = ChainSpec::new(
        "test_chain",
        vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
            StepSpec::fresh("circuit_c"),
        ],
    );

    let truncated = spec.truncate(2);
    assert_eq!(truncated.steps.len(), 2);
    assert_eq!(truncated.name, "test_chain_truncated_2");
}

#[test]
fn test_chain_spec_without_step() {
    let spec = ChainSpec::new(
        "test_chain",
        vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::from_prior("circuit_b", 0, vec![(0, 0)]),
            StepSpec::from_prior("circuit_c", 1, vec![(0, 0)]),
        ],
    );

    // Remove middle step
    let reduced = spec.without_step(1).unwrap();
    assert_eq!(reduced.steps.len(), 2);

    // The third step (now second) should have its wiring adjusted
    // It referenced step 1 which is now gone, so it falls back to Fresh
    assert!(matches!(reduced.steps[1].input_wiring, InputWiring::Fresh));
}

#[test]
fn test_input_wiring_dependent_steps() {
    let empty: Vec<usize> = vec![];
    assert_eq!(InputWiring::Fresh.dependent_steps(), empty);

    let from_prior = InputWiring::FromPriorOutput {
        step: 2,
        mapping: vec![],
    };
    assert_eq!(from_prior.dependent_steps(), vec![2]);

    let mixed = InputWiring::Mixed {
        prior: vec![(0, 0, 0), (2, 1, 1), (0, 2, 2)],
        fresh_indices: vec![3],
    };
    assert_eq!(mixed.dependent_steps(), vec![0, 2]);
}

#[test]
fn test_chain_trace() {
    let mut trace = ChainTrace::new("test_chain");

    trace.add_step(StepTrace::success(
        0,
        "circuit_a",
        vec![FieldElement::one()],
        vec![FieldElement::from_u64(42)],
    ));

    trace.add_step(StepTrace::success(
        1,
        "circuit_b",
        vec![FieldElement::from_u64(42)],
        vec![FieldElement::from_u64(100)],
    ));

    assert_eq!(trace.depth(), 2);
    assert!(trace.success);

    let outputs = trace.step_outputs(0).unwrap();
    assert_eq!(outputs[0], FieldElement::from_u64(42));
}

#[test]
fn test_cross_step_assertion() {
    let unique = CrossStepAssertion::unique("nullifier_unique", 0);
    assert!(unique.relation.contains("unique(step[*].out[0])"));

    let equal = CrossStepAssertion::equal("root_consistent", 0, 1, 1, 0);
    assert!(equal.relation.contains("step[0].out[1] == step[1].in[0]"));
}

#[test]
fn test_chain_spec_swap_steps() {
    let spec = ChainSpec::new(
        "test_chain",
        vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
            StepSpec::from_prior("circuit_c", 0, vec![(0, 0)]),
        ],
    );

    let swapped = spec.swap_steps(0, 1).unwrap();
    assert_eq!(swapped.steps.len(), 3);
    assert_eq!(swapped.steps[0].circuit_ref, "circuit_b");
    assert_eq!(swapped.steps[1].circuit_ref, "circuit_a");

    match &swapped.steps[2].input_wiring {
        InputWiring::FromPriorOutput { step, .. } => assert_eq!(*step, 1),
        other => panic!("expected FromPriorOutput, got {:?}", other),
    }

    assert!(spec.swap_steps(0, 5).is_none());
    assert!(spec.swap_steps(0, 0).is_none());
}

#[test]
fn test_chain_spec_duplicate_step() {
    let spec = ChainSpec::new(
        "test_chain",
        vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::from_prior("circuit_b", 0, vec![(0, 0)]),
        ],
    );

    let duped = spec.duplicate_step(0).unwrap();
    assert_eq!(duped.steps.len(), 3);
    assert_eq!(duped.steps[0].circuit_ref, "circuit_a");
    assert_eq!(duped.steps[1].circuit_ref, "circuit_a");
    assert_eq!(duped.steps[1].input_wiring, InputWiring::Fresh);

    match &duped.steps[2].input_wiring {
        InputWiring::FromPriorOutput { step, .. } => assert_eq!(*step, 0),
        other => panic!("expected FromPriorOutput, got {:?}", other),
    }

    assert!(spec.duplicate_step(5).is_none());
}

#[test]
fn test_assertion_remap_after_removal() {
    // Test remapping assertion when step is removed
    let assertion = CrossStepAssertion::equal("test", 0, 0, 2, 0);

    // Remove step 1 - indices 0 stays 0, index 2 becomes 1
    let remapped = assertion.remap_after_removal(1).unwrap();
    assert!(remapped.relation.contains("step[0]"));
    assert!(remapped.relation.contains("step[1]"));
    assert!(!remapped.relation.contains("step[2]"));

    // Remove step 0 - assertion should become invalid (references removed step)
    let invalid = assertion.remap_after_removal(0);
    assert!(invalid.is_none());
}

#[test]
fn test_assertion_remap_after_swap() {
    // Test remapping assertion when steps are swapped
    let assertion = CrossStepAssertion::equal("test", 0, 0, 2, 0);

    // Swap steps 0 and 2 - indices should swap
    let remapped = assertion.remap_after_swap(0, 2);
    assert!(remapped
        .relation
        .contains("step[2].out[0] == step[0].in[0]"));
}

#[test]
fn test_assertion_remap_after_insertion() {
    // Test remapping assertion when step is inserted
    let assertion = CrossStepAssertion::equal("test", 0, 0, 2, 0);

    // Insert step at 1 - index 0 stays 0, index 2 becomes 3
    let remapped = assertion.remap_after_insertion(1);
    assert!(remapped.relation.contains("step[0]"));
    assert!(remapped.relation.contains("step[3]"));
    assert!(!remapped.relation.contains("step[2]"));
}

#[test]
fn test_chain_with_assertions_without_step() {
    // Test that assertions are properly remapped when removing a step
    let spec = ChainSpec::new(
        "test_chain",
        vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
            StepSpec::fresh("circuit_c"),
        ],
    )
    .with_assertion(CrossStepAssertion::equal("ab_check", 0, 0, 1, 0))
    .with_assertion(CrossStepAssertion::equal("bc_check", 1, 0, 2, 0));

    // Remove step 1 - first assertion should be removed (refs step 1)
    // Second assertion refs both 1 and 2, so should be removed
    let reduced = spec.without_step(1).unwrap();
    assert_eq!(reduced.assertions.len(), 0);
}

#[test]
fn test_chain_with_assertions_swap_steps() {
    let spec = ChainSpec::new(
        "test_chain",
        vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
            StepSpec::fresh("circuit_c"),
        ],
    )
    .with_assertion(CrossStepAssertion::equal("ac_check", 0, 0, 2, 0));

    // Swap 0 and 1 - assertion indices should update: 0->1, 2 stays 2
    let swapped = spec.swap_steps(0, 1).unwrap();
    assert_eq!(swapped.assertions.len(), 1);
    assert!(swapped.assertions[0].relation.contains("step[1]"));
    assert!(swapped.assertions[0].relation.contains("step[2]"));
}

#[test]
fn test_chain_with_assertions_duplicate_step() {
    let spec = ChainSpec::new(
        "test_chain",
        vec![StepSpec::fresh("circuit_a"), StepSpec::fresh("circuit_b")],
    )
    .with_assertion(CrossStepAssertion::equal("ab_check", 0, 0, 1, 0));

    // Duplicate step 0 - assertion indices: 0 stays 0, 1 becomes 2
    let duped = spec.duplicate_step(0).unwrap();
    assert_eq!(duped.assertions.len(), 1);
    assert!(duped.assertions[0].relation.contains("step[0]"));
    assert!(duped.assertions[0].relation.contains("step[2]"));
}
