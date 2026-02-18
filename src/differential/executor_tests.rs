
use super::*;
use crate::executor::FixtureCircuitExecutor;

#[test]
fn test_multi_backend_executor() {
    let mut multi = MultiBackendExecutor::new(
        Framework::Circom,
        Arc::new(FixtureCircuitExecutor::new("test", 2, 1)),
    );
    multi.add_backend(
        Framework::Noir,
        Arc::new(FixtureCircuitExecutor::new("test", 2, 1).with_framework(Framework::Noir)),
    );

    let inputs = vec![FieldElement::zero(), FieldElement::one()];
    let results = multi.execute_all(&inputs);

    assert_eq!(results.len(), 2);
    assert!(results.values().all(|r| r.success));
}

#[test]
fn test_primary_backend_registered_at_construction() {
    let multi = MultiBackendExecutor::new(
        Framework::Noir,
        Arc::new(FixtureCircuitExecutor::new("test", 2, 1).with_framework(Framework::Noir)),
    );
    assert_eq!(multi.primary_executor().framework(), Framework::Noir);
}
