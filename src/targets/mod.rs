//! Target ZK framework backends
//!
//! This module provides integrations with various ZK proving systems:
//! - **Circom**: R1CS-based circuits with snarkjs
//! - **Noir**: ACIR-based circuits with Barretenberg
//! - **Halo2**: PLONK-based circuits (PSE fork)
//! - **Cairo**: STARK-based programs with stone-prover

mod circom;
mod noir;
mod halo2;
mod cairo;

pub use circom::CircomTarget;
pub use noir::NoirTarget;
pub use halo2::Halo2Target;
pub use cairo::CairoTarget;

// Re-export analysis modules for use in integration tests
pub use circom::analysis as circom_analysis;
pub use noir::analysis as noir_analysis;
pub use halo2::analysis as halo2_analysis;
pub use cairo::analysis as cairo_analysis;

use crate::config::Framework;
use crate::fuzzer::FieldElement;

/// Common trait for all ZK circuit targets
pub trait TargetCircuit: Send + Sync {
    /// Get the framework type
    fn framework(&self) -> Framework;

    /// Get circuit name
    fn name(&self) -> &str;

    /// Get number of constraints
    fn num_constraints(&self) -> usize;

    /// Get number of private inputs
    fn num_private_inputs(&self) -> usize;

    /// Get number of public inputs
    fn num_public_inputs(&self) -> usize;

    /// Execute the circuit with given inputs
    fn execute(&self, inputs: &[FieldElement]) -> anyhow::Result<Vec<FieldElement>>;

    /// Generate a proof for the given witness
    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>>;

    /// Verify a proof with public inputs
    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool>;
}

/// Mock circuit for testing without actual ZK backend
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
            num_constraints: num_private_inputs + num_public_inputs, // Simple heuristic
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
        // Simple mock: hash inputs to produce output
        use sha2::{Sha256, Digest};
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
        // Mock proof: just hash the witness
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for w in witness {
            hasher.update(w.0);
        }
        let hash = hasher.finalize();
        Ok(hash.to_vec())
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        // Mock verification: always succeeds if proof is non-empty
        Ok(!proof.is_empty() && !public_inputs.is_empty())
    }
}

/// Factory for creating circuit targets
pub struct TargetFactory;

impl TargetFactory {
    pub fn create(
        framework: Framework,
        circuit_path: &str,
        main_component: &str,
    ) -> anyhow::Result<Box<dyn TargetCircuit>> {
        match framework {
            Framework::Circom => Ok(Box::new(CircomTarget::new(circuit_path, main_component)?)),
            Framework::Noir => Ok(Box::new(NoirTarget::new(circuit_path)?)),
            Framework::Halo2 => Ok(Box::new(Halo2Target::new(circuit_path)?)),
            Framework::Cairo => Ok(Box::new(CairoTarget::new(circuit_path)?)),
            Framework::Mock => Ok(Box::new(MockCircuit::new(main_component, 10, 2))),
        }
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
