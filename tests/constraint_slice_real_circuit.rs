//! Constraint slice validation on a real circuit.
//!
//! Requires circom + snarkjs (for witness generation).

use std::path::PathBuf;

use zk_core::FieldElement;
use zk_fuzzer::executor::{CircomExecutor, CircuitExecutor};
use zk_fuzzer::oracles::{ConstraintSliceOracle, OutputMapping};
use zk_fuzzer::targets::CircomTarget;

fn require_circom_and_snarkjs() -> bool {
    if let Err(err) = CircomTarget::check_circom_available() {
        eprintln!(
            "Skipping real-circuit slice test: circom unavailable: {}",
            err
        );
        return false;
    }
    if let Err(err) = CircomTarget::check_snarkjs_available() {
        eprintln!(
            "Skipping real-circuit slice test: snarkjs unavailable: {}",
            err
        );
        return false;
    }
    true
}

#[tokio::test]
// Requires circom + snarkjs (real circuit)
async fn test_constraint_slice_withdraw_real_circuit() {
    if !require_circom_and_snarkjs() {
        return;
    }

    let circuit_path = PathBuf::from("tests/bench/known_bugs/range_bypass/circuit.circom");
    assert!(
        circuit_path.exists(),
        "Missing circuit at {:?}",
        circuit_path
    );

    let executor = CircomExecutor::new(circuit_path.to_str().unwrap(), "RangeBypass")
        .expect("Failed to create CircomExecutor");

    let input_count = executor.num_public_inputs() + executor.num_private_inputs();
    let mut rng = rand::thread_rng();
    let base_inputs: Vec<FieldElement> = (0..input_count.max(1))
        .map(|_| FieldElement::random(&mut rng))
        .collect();

    let inspector = executor
        .constraint_inspector()
        .expect("Constraint inspector unavailable for real-circuit slice test");
    let output_wires = {
        let from_inspector = inspector.output_indices();
        if !from_inspector.is_empty() {
            from_inspector
        } else {
            // Some Circom circuits expose only public inputs (no explicit `signal output`),
            // so mirror the engine recovery and use the first post-input wire.
            let num_inputs = executor.num_public_inputs() + executor.num_private_inputs();
            vec![num_inputs]
        }
    };
    let outputs: Vec<OutputMapping> = output_wires
        .into_iter()
        .enumerate()
        .map(|(output_index, output_wire)| OutputMapping {
            output_index,
            output_wire,
        })
        .collect();

    let oracle = ConstraintSliceOracle::new().with_samples(5);
    let findings = oracle.run(&executor, &base_inputs, &outputs).await;

    // Validation: ensure the oracle runs to completion on a real circuit.
    println!(
        "Constraint slice oracle completed with {} finding(s)",
        findings.len()
    );
}
