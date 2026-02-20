use super::*;
use crate::executor::FixtureCircuitExecutor;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_recursive_tester_creation() {
    let tester = RecursiveTester::new(5);
    assert_eq!(tester.max_depth, 5);
    assert!(tester.verifier_circuit.is_none());
}

#[test]
fn test_recursive_verification() {
    let verifier = Arc::new(FixtureCircuitExecutor::new("verifier", 10, 2));
    let tester = RecursiveTester::new(3).with_verifier(verifier);

    let inputs = vec![FieldElement::one(); 10];
    let result = tester.test_recursion(&inputs, 2);

    match result {
        RecursionResult::Success { depth, .. } => {
            assert_eq!(depth, 2);
        }
        other => panic!("Expected success, got {:?}", other),
    }
}

#[test]
fn test_soundness_checking() {
    let verifier = Arc::new(FixtureCircuitExecutor::new("verifier", 5, 2));
    let tester = RecursiveTester::new(3).with_verifier(verifier);

    let mut rng = StdRng::seed_from_u64(42);
    let issues = tester.test_soundness(&mut rng);

    // Fixture executor should reject fake proofs
    assert!(issues.is_empty(), "Expected no soundness issues in fixture");
}
