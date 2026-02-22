//! Tests for new scanner implementations from Newscans.md

use std::sync::atomic::{AtomicUsize, Ordering};

use zk_core::{CircuitInfo, ExecutionCoverage, ExecutionResult, Framework};
use zk_fuzzer::executor::{CircuitExecutor, FixtureCircuitExecutor};
use zk_fuzzer::fuzzer::FieldElement;
use zk_fuzzer::oracles::{
    CanonicalizationChecker, CrossBackendDifferential, DeterminismOracle, FrozenWireDetector,
    NullifierReplayScanner, ProofMalleabilityScanner, SetupPoisoningDetector,
};

fn sample_snarkjs_groth16_proof_json() -> Vec<u8> {
    serde_json::json!({
        "pi_a": ["1", "2", "1"],
        "pi_b": [["3", "4"], ["5", "6"], ["1", "0"]],
        "pi_c": ["7", "8", "1"],
        "protocol": "groth16",
        "curve": "bn128"
    })
    .to_string()
    .into_bytes()
}

struct LenientProofExecutor {
    name: String,
    num_private_inputs: usize,
    num_public_inputs: usize,
    num_outputs: usize,
}

impl LenientProofExecutor {
    fn new(name: &str, num_private_inputs: usize, num_public_inputs: usize) -> Self {
        Self {
            name: name.to_string(),
            num_private_inputs,
            num_public_inputs,
            num_outputs: 1,
        }
    }
}

impl CircuitExecutor for LenientProofExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: self.name.clone(),
            num_constraints: 1,
            num_private_inputs: self.num_private_inputs,
            num_public_inputs: self.num_public_inputs,
            num_outputs: self.num_outputs,
        }
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        ExecutionResult::success(vec![FieldElement::one()], ExecutionCoverage::default())
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(sample_snarkjs_groth16_proof_json())
    }

    fn verify(&self, proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(!proof.is_empty())
    }
}

struct FlakyExecutor {
    name: String,
    counter: AtomicUsize,
    num_private_inputs: usize,
    num_public_inputs: usize,
    num_outputs: usize,
}

impl FlakyExecutor {
    fn new(name: &str, num_private_inputs: usize, num_public_inputs: usize) -> Self {
        Self {
            name: name.to_string(),
            counter: AtomicUsize::new(0),
            num_private_inputs,
            num_public_inputs,
            num_outputs: 1,
        }
    }
}

impl CircuitExecutor for FlakyExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: self.name.clone(),
            num_constraints: 1,
            num_private_inputs: self.num_private_inputs,
            num_public_inputs: self.num_public_inputs,
            num_outputs: self.num_outputs,
        }
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        let call = self.counter.fetch_add(1, Ordering::Relaxed);
        let value = if call.is_multiple_of(2) { 1u64 } else { 2u64 };
        ExecutionResult::success(
            vec![FieldElement::from_u64(value)],
            ExecutionCoverage::default(),
        )
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![0x01; 32])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }
}

struct SaltedExecutor {
    name: String,
    salt: u64,
    num_private_inputs: usize,
    num_public_inputs: usize,
    num_outputs: usize,
}

impl SaltedExecutor {
    fn new(name: &str, salt: u64, num_private_inputs: usize, num_public_inputs: usize) -> Self {
        Self {
            name: name.to_string(),
            salt,
            num_private_inputs,
            num_public_inputs,
            num_outputs: 1,
        }
    }
}

impl CircuitExecutor for SaltedExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: self.name.clone(),
            num_constraints: 1,
            num_private_inputs: self.num_private_inputs,
            num_public_inputs: self.num_public_inputs,
            num_outputs: self.num_outputs,
        }
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        ExecutionResult::success(
            vec![FieldElement::from_u64(self.salt)],
            ExecutionCoverage::default(),
        )
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![0x02; 32])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }
}

#[test]
fn test_proof_malleability_scanner_detects_mutation() {
    let executor = LenientProofExecutor::new("lenient", 1, 1);
    let witness = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];

    let scanner = ProofMalleabilityScanner::new()
        .with_proof_samples(1)
        .with_random_mutations(0)
        .with_structured_mutations(true);

    let findings = scanner.run(&executor, &[witness]);
    assert!(!findings.is_empty(), "Expected malleability finding");
    assert!(
        findings
            .iter()
            .any(|finding| finding.description.contains("(algebraic)")),
        "Expected algebraic proof malleability finding"
    );
}

#[test]
fn test_proof_malleability_random_lane_marked_negative_control() {
    let executor = LenientProofExecutor::new("lenient", 1, 1);
    let witness = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];

    let scanner = ProofMalleabilityScanner::new()
        .with_proof_samples(1)
        .with_algebraic_mutations(false)
        .with_negative_control_random_mutations(2);

    let findings = scanner.run(&executor, &[witness]);
    assert!(!findings.is_empty(), "Expected negative-control findings");
    assert!(
        findings
            .iter()
            .all(|finding| finding.description.contains("(negative-control)")),
        "Expected negative-control marker in finding descriptions"
    );
}

#[test]
fn test_determinism_oracle_detects_nondeterminism() {
    let executor = FlakyExecutor::new("flaky", 1, 0);
    let witness = vec![FieldElement::from_u64(1)];

    let oracle = DeterminismOracle::new()
        .with_repetitions(2)
        .with_sample_count(1);

    let findings = oracle.run(&executor, &[witness]);
    assert!(!findings.is_empty(), "Expected determinism finding");
}

#[test]
fn test_frozen_wire_detector_detects_constant_output() {
    let executor = FixtureCircuitExecutor::new("frozen", 1, 1).with_underconstrained(true);

    let mut witnesses = Vec::new();
    for i in 0..3u64 {
        witnesses.push(vec![FieldElement::from_u64(42), FieldElement::from_u64(i)]);
    }

    let detector = FrozenWireDetector::new().with_min_samples(3);
    let findings = detector.run(&executor, &witnesses);
    assert!(!findings.is_empty(), "Expected frozen wire finding");
}

#[test]
fn test_nullifier_replay_scanner_detects_replay() {
    let executor = FixtureCircuitExecutor::new("nullifier", 1, 1).with_underconstrained(true);
    let base = vec![FieldElement::from_u64(7), FieldElement::from_u64(1)];

    let scanner = NullifierReplayScanner::new()
        .with_replay_attempts(5)
        .with_base_samples(1);

    let findings = scanner.run(&executor, &[base]);
    assert!(!findings.is_empty(), "Expected nullifier replay finding");
}

#[test]
fn test_cross_backend_differential_detects_divergence() {
    let exec_a = SaltedExecutor::new("a", 1, 1, 0);
    let exec_b = SaltedExecutor::new("b", 2, 1, 0);
    let witness = vec![FieldElement::from_u64(1)];

    let oracle = CrossBackendDifferential::new()
        .with_sample_count(1)
        .with_tolerance_bits(0);

    let findings = oracle.run(&exec_a, &exec_b, &[witness]);
    assert!(
        !findings.is_empty(),
        "Expected cross-backend divergence finding"
    );
}

#[test]
fn test_canonicalization_checker_detects_non_canonical() {
    let executor = FixtureCircuitExecutor::new("canon", 1, 0);
    let witness = vec![FieldElement::from_u64(1)];

    let checker = CanonicalizationChecker::new()
        .with_sample_count(1)
        .with_field_wrap(true)
        .with_negative_zero(false)
        .with_additive_inverse(false);

    let findings = checker.run(&executor, &[witness]);
    assert!(!findings.is_empty(), "Expected canonicalization finding");
}

#[test]
fn test_setup_poisoning_detector_detects_cross_setup() {
    let exec_a = LenientProofExecutor::new("setup_a", 1, 1);
    let exec_b = LenientProofExecutor::new("setup_b", 1, 1);
    let witness = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];

    let detector = SetupPoisoningDetector::new().with_attempts(1);
    let findings = detector.run(&exec_a, &exec_b, &[witness]);

    assert!(!findings.is_empty(), "Expected setup poisoning finding");
}
