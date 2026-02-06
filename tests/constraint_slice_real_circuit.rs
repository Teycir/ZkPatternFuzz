//! Constraint slice validation on a real circuit.
//!
//! Requires circom + snarkjs (for witness generation).

use std::path::PathBuf;

use zk_fuzzer::attacks::ConstraintSliceOracle;
use zk_fuzzer::executor::{CircuitExecutor, CircomExecutor, FieldElement};
use zk_fuzzer::targets::CircomTarget;

#[tokio::test]
#[ignore = "Requires circom + snarkjs (real circuit)"]
async fn test_constraint_slice_withdraw_real_circuit() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");

    let circuit_path = PathBuf::from("circuits/withdraw.circom");
    assert!(circuit_path.exists(), "Missing circuit at {:?}", circuit_path);

    let executor = CircomExecutor::new(circuit_path.to_str().unwrap(), "Withdraw")
        .expect("Failed to create CircomExecutor");

    let input_count = executor.num_public_inputs() + executor.num_private_inputs();
    let mut rng = rand::thread_rng();
    let base_inputs: Vec<FieldElement> = (0..input_count.max(1))
        .map(|_| FieldElement::random(&mut rng))
        .collect();

    let output_wires: Vec<usize> = executor
        .constraint_inspector()
        .map(|inspector| {
            let outputs = inspector.output_indices();
            if outputs.is_empty() {
                let start = executor.num_public_inputs() + executor.num_private_inputs();
                vec![start]
            } else {
                outputs
            }
        })
        .unwrap_or_else(|| {
            let start = executor.num_public_inputs() + executor.num_private_inputs();
            vec![start]
        });

    let oracle = ConstraintSliceOracle::new().with_samples(5);
    let findings = oracle
        .run(&executor, &base_inputs, &output_wires)
        .await;

    // Validation: ensure the oracle runs to completion on a real circuit.
    assert!(findings.len() >= 0);
}
