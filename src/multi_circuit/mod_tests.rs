
use super::*;
use crate::executor::FixtureCircuitExecutor;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_multi_circuit_fuzzer_creation() {
    let config = MultiCircuitConfig::default();
    let fuzzer = MultiCircuitFuzzer::new(config);
    assert!(fuzzer.circuits.is_empty());
}

#[test]
fn test_circuit_chain() {
    let mut chain = CircuitChain::new();
    chain.add(
        "circuit1",
        Arc::new(FixtureCircuitExecutor::new("c1", 2, 1)),
    );
    chain.add(
        "circuit2",
        Arc::new(FixtureCircuitExecutor::new("c2", 1, 1)),
    );

    let inputs = vec![FieldElement::one(), FieldElement::zero()];
    let result = chain.execute(&inputs);

    assert!(result.success);
    assert_eq!(result.steps.len(), 2);
}

#[test]
fn test_multi_circuit_fuzzing() {
    let config = MultiCircuitConfig {
        composition_tests: 10,
        ..Default::default()
    };
    let mut fuzzer = MultiCircuitFuzzer::new(config);

    fuzzer.add_circuit("c1", Arc::new(FixtureCircuitExecutor::new("c1", 2, 1)));
    fuzzer.add_circuit("c2", Arc::new(FixtureCircuitExecutor::new("c2", 2, 1)));

    let mut rng = StdRng::seed_from_u64(42);
    let findings = fuzzer.run(&mut rng);

    // May or may not find issues depending on fixture behavior
    println!("Found {} issues", findings.len());
}

#[test]
fn test_circuit_chain_fails_on_input_size_mismatch() {
    let mut chain = CircuitChain::new();
    chain.add(
        "circuit1",
        Arc::new(FixtureCircuitExecutor::new("c1", 2, 1)),
    );
    chain.add(
        "circuit2",
        Arc::new(FixtureCircuitExecutor::new("c2", 2, 1)),
    );

    let inputs = vec![FieldElement::one(), FieldElement::zero()];
    let result = chain.execute(&inputs);
    assert!(!result.success);
    assert_eq!(result.steps.len(), 2);
    assert!(!result.steps[1].result.success);
}
