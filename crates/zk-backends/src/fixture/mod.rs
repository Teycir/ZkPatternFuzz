//! Deterministic fixture executor for tests and local validation.
//!
//! **IMPORTANT: This is NOT a production backend. It is a testing utility only.**
//!
//! This module provides a lightweight `CircuitExecutor` implementation without external
//! tooling dependencies. It simulates circuit behavior for unit tests and should never
//! be used for actual security audits. All production fuzzing must use real backends:
//! Circom, Noir, Halo2, or Cairo.

use crate::TargetCircuit;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use zk_core::{
    CircuitExecutor, CircuitInfo, ConstraintEquation, ConstraintInspector, ConstraintResult,
    ExecutionCoverage, ExecutionResult, FieldElement, Framework,
};

/// Deterministic executor intended for tests and fixtures.
pub struct FixtureCircuitExecutor {
    name: String,
    framework: Framework,
    num_constraints: usize,
    num_private_inputs: usize,
    num_public_inputs: usize,
    num_outputs: usize,
    execution_count: AtomicUsize,
    simulate_underconstrained: bool,
    collision_probability: f64,
}

impl FixtureCircuitExecutor {
    pub fn new(name: &str, num_private_inputs: usize, num_public_inputs: usize) -> Self {
        Self {
            name: name.to_string(),
            framework: Framework::Circom,
            num_constraints: num_private_inputs + num_public_inputs,
            num_private_inputs,
            num_public_inputs,
            num_outputs: 1,
            execution_count: AtomicUsize::new(0),
            simulate_underconstrained: false,
            collision_probability: 0.0,
        }
    }

    pub fn with_framework(mut self, framework: Framework) -> Self {
        self.framework = framework;
        self
    }

    pub fn with_constraints(mut self, num_constraints: usize) -> Self {
        self.num_constraints = num_constraints;
        self
    }

    pub fn with_outputs(mut self, num_outputs: usize) -> Self {
        self.num_outputs = num_outputs.max(1);
        self
    }

    pub fn with_underconstrained(mut self, enabled: bool) -> Self {
        self.simulate_underconstrained = enabled;
        self
    }

    pub fn with_collision_probability(mut self, probability: f64) -> Self {
        self.collision_probability = probability.clamp(0.0, 1.0);
        self
    }

    pub fn execution_count(&self) -> usize {
        self.execution_count.load(Ordering::Relaxed)
    }

    fn simulate_coverage(&self, inputs: &[FieldElement]) -> ExecutionCoverage {
        let mut satisfied = Vec::new();
        let mut evaluated = Vec::new();

        for i in 0..self.num_constraints {
            evaluated.push(i);

            let mut hasher = Sha256::new();
            hasher.update([i as u8]);
            for input in inputs {
                hasher.update(input.0);
            }
            let hash = hasher.finalize();
            if hash[0] % 2 == 0 {
                satisfied.push(i);
            }
        }

        ExecutionCoverage::with_constraints(satisfied, evaluated)
    }

    fn compute_output(&self, inputs: &[FieldElement]) -> Vec<FieldElement> {
        let mut outputs = Vec::with_capacity(self.num_outputs);

        for output_idx in 0..self.num_outputs {
            let mut hasher = Sha256::new();
            hasher.update([output_idx as u8]);

            if self.simulate_underconstrained && !inputs.is_empty() {
                hasher.update(inputs[0].0);
            } else {
                for input in inputs {
                    hasher.update(input.0);
                }
            }

            let hash = hasher.finalize();
            let mut output_bytes = [0u8; 32];
            output_bytes.copy_from_slice(&hash);

            if self.collision_probability > 0.0 {
                let keep_bytes = ((1.0 - self.collision_probability) * 32.0) as usize;
                let keep_bytes = keep_bytes.clamp(1, 32);
                for byte in output_bytes.iter_mut().skip(keep_bytes) {
                    *byte = 0;
                }
                if self.collision_probability > 0.8 && keep_bytes <= 4 {
                    output_bytes[0] &= 0x0F;
                }
            }

            outputs.push(FieldElement(output_bytes));
        }

        outputs
    }
}

impl ConstraintInspector for FixtureCircuitExecutor {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        let total_inputs = self.num_public_inputs + self.num_private_inputs;
        let output_base = total_inputs;

        if total_inputs == 0 {
            return Vec::new();
        }

        (0..self.num_constraints)
            .map(|i| {
                let a_idx = i % total_inputs;
                let b_idx = (i + 1) % total_inputs;
                let c_idx = output_base + (i % self.num_outputs.max(1));

                ConstraintEquation {
                    id: i,
                    a_terms: vec![(a_idx, FieldElement::one())],
                    b_terms: vec![(b_idx, FieldElement::one())],
                    c_terms: vec![(c_idx, FieldElement::one())],
                    description: Some("fixture constraint".to_string()),
                }
            })
            .collect()
    }

    fn check_constraints(&self, _witness: &[FieldElement]) -> Vec<ConstraintResult> {
        self.get_constraints()
            .iter()
            .map(|c| ConstraintResult {
                constraint_id: c.id,
                satisfied: true,
                lhs_value: FieldElement::one(),
                rhs_value: FieldElement::one(),
            })
            .collect()
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        self.get_constraints()
            .iter()
            .map(|c| {
                let mut deps: Vec<usize> = c
                    .a_terms
                    .iter()
                    .chain(c.b_terms.iter())
                    .chain(c.c_terms.iter())
                    .map(|(idx, _)| *idx)
                    .collect();
                deps.sort_unstable();
                deps.dedup();
                deps
            })
            .collect()
    }
}

#[async_trait]
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
        let start = Instant::now();
        self.execution_count.fetch_add(1, Ordering::Relaxed);
        let outputs = self.compute_output(inputs);
        let coverage = self.simulate_coverage(inputs);
        ExecutionResult::success(outputs, coverage).with_time(start.elapsed().as_micros() as u64)
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        for w in witness {
            hasher.update(w.0);
        }
        let hash = hasher.finalize();

        let mut proof = vec![0u8; 256];
        proof[0..32].copy_from_slice(&hash);
        proof[32] = 0x01;
        proof[33..65].copy_from_slice(&hash);
        Ok(proof)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        if proof.len() < 64 {
            return Ok(false);
        }
        if proof[32] != 0x01 {
            return Ok(false);
        }
        if public_inputs.is_empty() {
            return Ok(false);
        }

        let mut hasher = Sha256::new();
        for input in public_inputs {
            hasher.update(input.0);
        }
        let input_hash = hasher.finalize();
        Ok(&proof[0..32] == input_hash.as_slice())
    }

    fn constraint_inspector(&self) -> Option<&dyn ConstraintInspector> {
        Some(self)
    }
}

impl TargetCircuit for FixtureCircuitExecutor {
    fn framework(&self) -> Framework {
        self.framework
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
        let result = self.execute_sync(inputs);
        if result.success {
            Ok(result.outputs)
        } else {
            let error_message = match result.error {
                Some(error) => error,
                None => panic!("Fixture backend returned success=false without an error message"),
            };
            anyhow::bail!("{}", error_message)
        }
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        <Self as CircuitExecutor>::prove(self, witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        <Self as CircuitExecutor>::verify(self, proof, public_inputs)
    }
}

pub fn create_underconstrained_fixture(name: &str) -> FixtureCircuitExecutor {
    FixtureCircuitExecutor::new(name, 10, 2)
        .with_constraints(5)
        .with_underconstrained(true)
}

pub fn create_collision_fixture(name: &str, collision_rate: f64) -> FixtureCircuitExecutor {
    FixtureCircuitExecutor::new(name, 10, 2).with_collision_probability(collision_rate)
}
