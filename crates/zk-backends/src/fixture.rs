//! In-process fixture executor for tests and benchmarks.
//!
//! This is intentionally simple and deterministic; it is used to unit-test the
//! fuzzer/oracles without requiring external backends.

use sha2::{Digest, Sha256};
use zk_core::{CircuitExecutor, CircuitInfo, ExecutionCoverage, ExecutionResult, FieldElement, Framework};

/// A deterministic executor with configurable circuit metadata.
#[derive(Debug, Clone)]
pub struct FixtureCircuitExecutor {
    name: String,
    framework: Framework,
    num_private_inputs: usize,
    num_public_inputs: usize,
    num_outputs: usize,
    num_constraints: usize,
    underconstrained: bool,
}

impl FixtureCircuitExecutor {
    pub fn new(name: &str, num_private_inputs: usize, num_public_inputs: usize) -> Self {
        Self {
            name: name.to_string(),
            framework: Framework::Circom,
            num_private_inputs,
            num_public_inputs,
            num_outputs: 1,
            // Default to "well constrained" unless overridden.
            num_constraints: num_private_inputs.saturating_add(num_public_inputs),
            underconstrained: false,
        }
    }

    pub fn with_framework(mut self, framework: Framework) -> Self {
        self.framework = framework;
        self
    }

    pub fn with_outputs(mut self, num_outputs: usize) -> Self {
        self.num_outputs = num_outputs.max(1);
        self
    }

    pub fn with_constraints(mut self, num_constraints: usize) -> Self {
        self.num_constraints = num_constraints;
        self
    }

    /// When enabled, execution intentionally ignores all but the first input
    /// when producing outputs. This makes collisions easy to trigger.
    pub fn with_underconstrained(mut self, enabled: bool) -> Self {
        self.underconstrained = enabled;
        self
    }

    fn derive_output(&self, inputs: &[FieldElement], output_idx: u32) -> FieldElement {
        let mut hasher = Sha256::new();
        hasher.update(self.name.as_bytes());
        hasher.update([output_idx as u8]);

        if self.underconstrained {
            if let Some(first) = inputs.first() {
                hasher.update(first.0);
            }
        } else {
            for fe in inputs {
                hasher.update(fe.0);
            }
        }

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        FieldElement(out)
    }
}

impl CircuitExecutor for FixtureCircuitExecutor {
    fn framework(&self) -> Framework {
        self.framework
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: self.name.clone(),
            num_constraints: self.num_constraints,
            num_private_inputs: self.num_private_inputs,
            num_public_inputs: self.num_public_inputs,
            num_outputs: self.num_outputs,
        }
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        let start = std::time::Instant::now();
        let mut outputs = Vec::with_capacity(self.num_outputs);
        for idx in 0..(self.num_outputs as u32) {
            outputs.push(self.derive_output(inputs, idx));
        }

        ExecutionResult::success(outputs.clone(), ExecutionCoverage::with_output_hash(&outputs))
            .with_time(start.elapsed().as_micros() as u64)
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        for fe in witness {
            hasher.update(fe.0);
        }
        Ok(hasher.finalize().to_vec())
    }

    fn verify(&self, proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        // Model the core soundness property: proofs are bound to the claimed public inputs.
        // For the fixture, we treat the provided `public_inputs` slice as the binding input.
        if proof.is_empty() {
            return Ok(false);
        }

        let mut hasher = Sha256::new();
        for fe in _public_inputs {
            hasher.update(fe.0);
        }
        let expected = hasher.finalize().to_vec();
        Ok(expected == proof)
    }
}

pub fn create_underconstrained_fixture(name: &str, num_private_inputs: usize, num_public_inputs: usize) -> FixtureCircuitExecutor {
    FixtureCircuitExecutor::new(name, num_private_inputs, num_public_inputs)
        .with_constraints(num_private_inputs.saturating_sub(1))
        .with_underconstrained(true)
}

pub fn create_collision_fixture(name: &str, num_private_inputs: usize, num_public_inputs: usize) -> FixtureCircuitExecutor {
    FixtureCircuitExecutor::new(name, num_private_inputs, num_public_inputs)
        .with_underconstrained(true)
}
