//! Mock backend implementations.

use crate::TargetCircuit;
use zk_core::{FieldElement, Framework};

pub mod executor;

pub use executor::{MockCircuitExecutor, create_collision_mock, create_underconstrained_mock};

/// Mock circuit for testing without actual ZK backend.
pub struct MockCircuit {
    name: String,
    num_constraints: usize,
    num_private_inputs: usize,
    num_public_inputs: usize,
}

impl MockCircuit {
    pub fn new(name: &str, num_private_inputs: usize, num_public_inputs: usize) -> Self {
        Self {
            name: name.to_string(),
            num_constraints: num_private_inputs + num_public_inputs,
            num_private_inputs,
            num_public_inputs,
        }
    }

    pub fn with_constraints(mut self, num_constraints: usize) -> Self {
        self.num_constraints = num_constraints;
        self
    }
}

impl TargetCircuit for MockCircuit {
    fn framework(&self) -> Framework {
        Framework::Mock
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    fn num_private_inputs(&self) -> usize {
        self.num_private_inputs
    }

    fn num_public_inputs(&self) -> usize {
        self.num_public_inputs
    }

    fn execute(&self, inputs: &[FieldElement]) -> anyhow::Result<Vec<FieldElement>> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for input in inputs {
            hasher.update(input.0);
        }
        let hash = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&hash);
        Ok(vec![FieldElement(output)])
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for w in witness {
            hasher.update(w.0);
        }
        let hash = hasher.finalize();
        Ok(hash.to_vec())
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(!proof.is_empty() && !public_inputs.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
