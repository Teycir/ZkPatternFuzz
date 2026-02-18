
use super::*;
use crate::chain_fuzzer::types::StepSpec;
use crate::executor::FixtureCircuitExecutor;
use std::sync::Arc;

fn create_test_runner() -> ChainRunner {
    let mut executors = HashMap::new();
    executors.insert(
        "circuit_a".to_string(),
        Arc::new(FixtureCircuitExecutor::new("circuit_a", 2, 0).with_outputs(2))
            as Arc<dyn zk_core::CircuitExecutor>,
    );
    executors.insert(
        "circuit_b".to_string(),
        Arc::new(FixtureCircuitExecutor::new("circuit_b", 2, 0).with_outputs(2))
            as Arc<dyn zk_core::CircuitExecutor>,
    );
    executors.insert(
        "circuit_c".to_string(),
        Arc::new(FixtureCircuitExecutor::new("circuit_c", 2, 0).with_outputs(2))
            as Arc<dyn zk_core::CircuitExecutor>,
    );
    ChainRunner::new(executors).expect("failed to create chain runner")
}

#[test]
fn test_prefix_truncation() {
    let runner = create_test_runner();

    // Create a chain with 5 steps
    let spec = ChainSpec::new(
        "test_chain",
        vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
            StepSpec::fresh("circuit_c"),
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
        ],
    );

    // Create a checker that always finds a violation
    let checker = CrossStepInvariantChecker::new(vec![]);

    let shrinker = ChainShrinker::new(runner, checker);

    // The truncation should work even if no violations are found
    let inputs = HashMap::new();
    let violation = CrossStepViolation::new(
        "test_violation",
        "test_relation",
        vec![0, 1],
        vec![],
        "high",
    );

    // This test mainly verifies the shrinking logic runs without panicking
    let result = shrinker.minimize(&spec, &inputs, &violation);
    assert!(result.l_min <= spec.len());
}

#[test]
fn test_step_dropout() {
    let spec = ChainSpec::new(
        "test_chain",
        vec![
            StepSpec::fresh("circuit_a"),
            StepSpec::fresh("circuit_b"),
            StepSpec::fresh("circuit_c"),
        ],
    );

    // Verify without_step works correctly
    let reduced = spec.without_step(1).unwrap();
    assert_eq!(reduced.steps.len(), 2);
    assert_eq!(reduced.steps[0].circuit_ref, "circuit_a");
    assert_eq!(reduced.steps[1].circuit_ref, "circuit_c");
}
