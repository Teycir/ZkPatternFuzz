//! Circom Backend Integration Tests
//!
//! These tests verify that the Circom backend works correctly with real circuits.
//! Run with: cargo test --test circom_backend_test -- --ignored
//!
//! Prerequisites:
//! - circom CLI installed (npm install -g circom)
//! - snarkjs installed (npm install -g snarkjs)

use std::path::PathBuf;
use zk_fuzzer::fuzzer::FieldElement;
use zk_fuzzer::targets::{CircomTarget, TargetCircuit};

/// Get the path to a test circuit
fn test_circuit_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("circuits")
        .join(format!("{}.circom", name))
}

/// Test that circom and snarkjs are available
#[test]
fn test_circom_snarkjs_available() {
    let circom_version = CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    let snarkjs_version = CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");

    println!("✓ Circom available: {}", circom_version);
    println!("✓ snarkjs available: {}", snarkjs_version);
}

/// Test circuit compilation (requires circom)
#[test]
fn test_multiplier_compilation() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    let circuit_path = test_circuit_path("multiplier");

    if !circuit_path.exists() {
        panic!("Test circuit not found at {:?}", circuit_path);
    }

    let mut target = CircomTarget::new(circuit_path.to_str().unwrap(), "Multiplier")
        .expect("Failed to create CircomTarget");

    // Compile the circuit
    target.compile().expect("Circuit compilation failed");

    // Verify metadata was extracted
    assert!(
        target.num_constraints() > 0,
        "Should have at least 1 constraint"
    );
    assert_eq!(
        target.num_private_inputs(),
        2,
        "Multiplier has 2 inputs (a, b)"
    );

    println!("✓ Multiplier circuit compiled successfully");
    println!("  Constraints: {}", target.num_constraints());
    println!("  Private inputs: {}", target.num_private_inputs());
    println!("  Public inputs: {}", target.num_public_inputs());
}

/// Test witness generation (requires circom + snarkjs)
#[test]
fn test_multiplier_witness_generation() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");
    let circuit_path = test_circuit_path("multiplier");

    let mut target = CircomTarget::new(circuit_path.to_str().unwrap(), "Multiplier")
        .expect("Failed to create CircomTarget");

    target.compile().expect("Compilation failed");

    // Test: 3 * 4 = 12
    let a = FieldElement::from_u64(3);
    let b = FieldElement::from_u64(4);

    let outputs = target.execute(&[a, b]).expect("Execution failed");

    assert!(!outputs.is_empty(), "Should have output");

    // Verify output is 12 (3 * 4)
    let expected = FieldElement::from_u64(12);
    assert_eq!(outputs[0], expected, "3 * 4 should equal 12");

    println!("✓ Witness generation verified: 3 * 4 = 12");
}

/// Test proof generation and verification (requires full snarkjs setup)
#[test]
fn test_multiplier_proof_generation() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");
    let circuit_path = test_circuit_path("multiplier");

    let mut target = CircomTarget::new(circuit_path.to_str().unwrap(), "Multiplier")
        .expect("Failed to create CircomTarget");

    target.compile().expect("Compilation failed");
    target.setup_keys().expect("Key setup failed");

    // Generate witness
    let a = FieldElement::from_u64(5);
    let b = FieldElement::from_u64(7);

    // Generate proof
    let proof = target
        .prove(&[a.clone(), b.clone()])
        .expect("Proof generation failed");
    assert!(!proof.is_empty(), "Proof should not be empty");

    // Verify proof
    let public_inputs = vec![FieldElement::from_u64(35)]; // 5 * 7 = 35
    let valid = target
        .verify(&proof, &public_inputs)
        .expect("Verification failed");

    assert!(valid, "Valid proof should verify");
    println!("✓ Proof generated and verified: 5 * 7 = 35");
}

/// Test range check circuit (underconstrained detection test)
#[test]
fn test_range_check_circuit() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");
    let circuit_path = test_circuit_path("range_check");

    let mut target = CircomTarget::new(circuit_path.to_str().unwrap(), "RangeCheck")
        .expect("Failed to create CircomTarget");

    target.compile().expect("Compilation failed");

    println!("✓ RangeCheck circuit compiled");
    println!("  Constraints: {}", target.num_constraints());

    // Test with value = 5 = 0b00000101
    let value = FieldElement::from_u64(5);
    let mut bits = vec![FieldElement::zero(); 8];
    bits[0] = FieldElement::one(); // bit 0 = 1
    bits[2] = FieldElement::one(); // bit 2 = 1 (1 + 4 = 5)

    let mut inputs = vec![value];
    inputs.extend(bits);

    let result = target.execute(&inputs);
    assert!(result.is_ok(), "Valid bit decomposition should pass");

    println!("✓ Valid range check passed for value 5");
}

/// Test boundary conditions
#[test]
fn test_arithmetic_boundaries() {
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");
    let circuit_path = test_circuit_path("multiplier");

    let mut target = CircomTarget::new(circuit_path.to_str().unwrap(), "Multiplier")
        .expect("Failed to create CircomTarget");

    target.compile().expect("Compilation failed");

    // Test with 0
    let zero = FieldElement::zero();
    let one = FieldElement::one();

    let result = target
        .execute(&[zero.clone(), one.clone()])
        .expect("0 * 1 should work");
    assert_eq!(result[0], zero, "0 * 1 = 0");

    // Test with 1
    let result = target
        .execute(&[one.clone(), one.clone()])
        .expect("1 * 1 should work");
    assert_eq!(result[0], one, "1 * 1 = 1");

    // Test with large values (near field boundary)
    let max = FieldElement::max_value();
    let result = target
        .execute(&[one.clone(), max.clone()])
        .expect("1 * max should work");
    assert_eq!(result[0], max, "1 * max = max");

    println!("✓ Boundary condition tests passed");
}

/// Run all backend verification tests
#[test]
fn test_full_backend_verification() {
    println!("\n=== Circom Backend Verification ===\n");

    // 1. Check tools are available
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");

    println!("✓ All required tools available\n");

    // 2. Compile test circuit
    let circuit_path = test_circuit_path("multiplier");
    if !circuit_path.exists() {
        println!("✗ Test circuit not found at {:?}", circuit_path);
        return;
    }

    let mut target = CircomTarget::new(circuit_path.to_str().unwrap(), "Multiplier")
        .expect("Failed to create target");

    target.compile().expect("Compilation failed");
    println!(
        "✓ Circuit compiled: {} constraints",
        target.num_constraints()
    );

    // 3. Test witness generation
    let a = FieldElement::from_u64(6);
    let b = FieldElement::from_u64(7);
    let outputs = target.execute(&[a, b]).expect("Execution failed");
    let expected = FieldElement::from_u64(42);
    assert_eq!(outputs[0], expected);
    println!("✓ Witness generation: 6 * 7 = 42");

    // 4. Test key setup and proving
    target.setup_keys().expect("Key setup failed");
    println!("✓ Proving/verification keys generated");

    let proof = target
        .prove(&[FieldElement::from_u64(6), FieldElement::from_u64(7)])
        .expect("Proving failed");
    println!("✓ Proof generated ({} bytes)", proof.len());

    let valid = target
        .verify(&proof, &[expected])
        .expect("Verification failed");
    assert!(valid);
    println!("✓ Proof verified successfully");

    println!("\n=== Backend Verification Complete ===");
    println!("The Circom backend is fully functional!\n");
}
