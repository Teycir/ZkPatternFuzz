use zk_core::FieldElement;
use zk_fuzzer::fuzzer::grammar::{standard, GenerationStrategy, GrammarGenerator};

#[test]
fn test_generator_strategies() {
    let grammar = standard::range_proof(64);
    let mut gen = GrammarGenerator::new(grammar);
    let mut rng = rand::thread_rng();

    let random = gen.generate_with_strategy(GenerationStrategy::Random, &mut rng);
    assert!(!random.inputs.is_empty());

    let boundary = gen.generate_with_strategy(GenerationStrategy::Boundary, &mut rng);
    assert!(
        boundary.inputs[0].is_zero()
            || boundary.inputs[0].is_one()
            || boundary.inputs[0] == FieldElement::max_value()
    );

    let zeros = gen.generate_with_strategy(GenerationStrategy::AllZeros, &mut rng);
    assert!(zeros.inputs.iter().all(|fe| fe.is_zero()));

    let max = gen.generate_with_strategy(GenerationStrategy::AllMax, &mut rng);
    assert!(max
        .inputs
        .iter()
        .all(|fe| fe.0 == FieldElement::max_value().0));
}

#[test]
fn test_generation_count() {
    let grammar = standard::range_proof(64);
    let mut gen = GrammarGenerator::new(grammar);
    let mut rng = rand::thread_rng();

    assert_eq!(gen.generation_count(), 0);
    gen.generate(&mut rng);
    assert_eq!(gen.generation_count(), 1);
    gen.generate(&mut rng);
    assert_eq!(gen.generation_count(), 2);
}
