
use super::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use zk_backends::FixtureCircuitExecutor;

#[test]
fn test_verification_fuzzer_creation() {
    let fuzzer = VerificationFuzzer::new()
        .with_malleability_tests(100)
        .with_malformed_tests(100);

    assert_eq!(fuzzer.malleability_tests, 100);
    assert_eq!(fuzzer.malformed_tests, 100);
}

#[test]
fn test_verification_fuzzing() {
    let fuzzer = VerificationFuzzer::new()
        .with_malleability_tests(10)
        .with_malformed_tests(10);

    let executor: Arc<dyn CircuitExecutor> = Arc::new(FixtureCircuitExecutor::new("test", 2, 1));
    let mut rng = StdRng::seed_from_u64(42);

    let findings = fuzzer.fuzz(&executor, &mut rng);

    // Fixture executor should reject malformed proofs
    // So we expect no critical findings for properly implemented verifier
    for finding in &findings {
        println!("Finding: {:?} - {}", finding.severity, finding.description);
    }
}
