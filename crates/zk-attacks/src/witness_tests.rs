use super::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use zk_backends::FixtureCircuitExecutor;

#[test]
fn test_witness_fuzzer_creation() {
    let fuzzer = WitnessFuzzer::new()
        .with_determinism_tests(50)
        .with_timing_tests(100);

    assert_eq!(fuzzer.determinism_tests, 50);
    assert_eq!(fuzzer.timing_tests, 100);
}

#[test]
fn test_witness_determinism() {
    let fuzzer = WitnessFuzzer::new().with_determinism_tests(10);
    let executor: Arc<dyn CircuitExecutor> = Arc::new(FixtureCircuitExecutor::new("test", 2, 1));
    let mut rng = StdRng::seed_from_u64(42);

    let findings = fuzzer.test_determinism(&executor, &mut rng);

    // Fixture executor should be deterministic
    assert!(findings.is_empty(), "Expected no non-determinism findings");
}
