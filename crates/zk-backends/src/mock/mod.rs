//! Mock backend implementations.

pub mod executor;

pub use executor::{MockCircuitExecutor, create_collision_mock, create_underconstrained_mock};

/// Mock circuit for testing without actual ZK backend.
///
/// This is an alias of `MockCircuitExecutor`, which now implements both
/// `CircuitExecutor` and `TargetCircuit`.
pub type MockCircuit = MockCircuitExecutor;

#[cfg(test)]
mod tests {
    use super::*;
    use zk_core::FieldElement;

    #[test]
    fn test_mock_circuit() {
        let circuit = MockCircuit::new("test", 5, 2);
        assert_eq!(circuit.name(), "test");
        assert_eq!(circuit.num_private_inputs(), 5);
        assert_eq!(circuit.num_public_inputs(), 2);
    }

    #[test]
    fn test_mock_execute() {
        let circuit = MockCircuit::new("test", 2, 1);
        let inputs = vec![FieldElement::zero(), FieldElement::one()];
        let result = circuit.execute(&inputs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }
}
