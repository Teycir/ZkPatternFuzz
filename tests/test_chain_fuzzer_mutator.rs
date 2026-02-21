use std::collections::HashMap;
use zk_core::FieldElement;
use zk_fuzzer::chain_fuzzer::mutator::{ChainMutator, MutationType, MutationWeights};
use zk_fuzzer::chain_fuzzer::{ChainSpec, StepSpec};

#[test]
fn test_mutate_inputs() {
    let mutator = ChainMutator::new();

    let spec = ChainSpec::new(
        "test_chain",
        vec![StepSpec::fresh("circuit_a"), StepSpec::fresh("circuit_b")],
    );

    let mut initial_inputs = HashMap::new();
    initial_inputs.insert(
        "circuit_a".to_string(),
        vec![FieldElement::one(), FieldElement::from_u64(42)],
    );
    initial_inputs.insert("circuit_b".to_string(), vec![FieldElement::from_u64(100)]);

    let mut rng = rand::thread_rng();
    let (mutated, mutation_type) = mutator.mutate_inputs(&spec, &initial_inputs, &mut rng);

    // Should have mutated something
    assert!(!mutated.is_empty());

    // Mutation type should be recorded
    match mutation_type {
        MutationType::SingleStepTweak { .. }
        | MutationType::CascadeMutation
        | MutationType::BoundaryInjection { .. }
        | MutationType::BitFlip { .. } => {}
        _ => {} // Other types are also valid
    }
}

#[test]
fn test_boundary_injection() {
    let mutator = ChainMutator::new().with_weights(MutationWeights {
        single_step_tweak: 0.0,
        cascade_mutation: 0.0,
        step_reorder: 0.0,
        step_duplication: 0.0,
        boundary_injection: 1.0,
        bit_flip: 0.0,
    });

    let spec = ChainSpec::new("test_chain", vec![StepSpec::fresh("circuit_a")]);

    let mut initial_inputs = HashMap::new();
    initial_inputs.insert("circuit_a".to_string(), vec![FieldElement::from_u64(500)]);

    let mut rng = rand::thread_rng();
    let (mutated, mutation_type) = mutator.mutate_inputs(&spec, &initial_inputs, &mut rng);

    assert!(matches!(
        mutation_type,
        MutationType::BoundaryInjection { .. }
    ));

    // One of the inputs should be a boundary value
    let inputs = mutated.get("circuit_a").unwrap();
    let is_boundary = inputs.iter().any(|fe| {
        *fe == FieldElement::zero()
            || *fe == FieldElement::one()
            || *fe == FieldElement::max_value()
            || *fe == FieldElement::half_modulus()
    });
    assert!(is_boundary);
}

#[test]
fn test_mutate_with_spec() {
    let mutator = ChainMutator::new().with_weights(MutationWeights {
        single_step_tweak: 0.0,
        cascade_mutation: 0.0,
        step_reorder: 0.0,
        step_duplication: 1.0,
        boundary_injection: 0.0,
        bit_flip: 0.0,
    });

    let spec = ChainSpec::new(
        "test_chain",
        vec![StepSpec::fresh("circuit_a"), StepSpec::fresh("circuit_b")],
    );

    let mut initial_inputs = HashMap::new();
    initial_inputs.insert("circuit_a".to_string(), vec![FieldElement::one()]);
    initial_inputs.insert("circuit_b".to_string(), vec![FieldElement::from_u64(42)]);

    let mut rng = rand::thread_rng();
    let result = mutator.mutate(&spec, &initial_inputs, &mut rng);

    assert!(
        result.spec.is_some(),
        "step_duplication should produce a modified spec"
    );
    let new_spec = result.spec.unwrap();
    assert_eq!(new_spec.steps.len(), spec.steps.len() + 1);
    assert!(matches!(
        result.mutation_type,
        MutationType::StepDuplication { .. }
    ));
}
