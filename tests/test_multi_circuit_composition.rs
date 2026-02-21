use std::sync::Arc;
use zk_fuzzer::executor::FixtureCircuitExecutor;
use zk_fuzzer::multi_circuit::composition::{CompositionTester, CompositionType};

#[test]
fn test_composition_tester_creation() {
    let tester = CompositionTester::new(CompositionType::Parallel);
    assert!(tester.check_vulnerabilities().is_empty());
}

#[test]
fn test_vulnerability_detection() {
    let mut tester = CompositionTester::new(CompositionType::Recursive);
    // Mismatched circuits (2 outputs, 5 inputs)
    tester.add_circuit(Arc::new(
        FixtureCircuitExecutor::new("c1", 2, 1).with_outputs(2),
    ));
    tester.add_circuit(Arc::new(FixtureCircuitExecutor::new("c2", 5, 1)));

    let vulnerabilities = tester.check_vulnerabilities();
    assert!(!vulnerabilities.is_empty());
}
