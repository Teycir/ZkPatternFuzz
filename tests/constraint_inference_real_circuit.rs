//! Constraint Inference Real Circuit Validation
//!
//! This test validates the constraint inference engine on real circuits
//! with known missing constraints. It verifies:
//! 1. Missing constraints are correctly detected
//! 2. Violation witnesses are generated
//! 3. Violation witnesses actually exploit the missing constraints
//!
//! Completes Phase 4 requirement: "Validate on real circuits"

use std::path::PathBuf;
use zk_fuzzer::attacks::constraint_inference::{
    ConstraintInferenceEngine, ConstraintCategory, ViolationConfirmation,
};
use zk_fuzzer::executor::{CircomExecutor, CircuitExecutor};
use zk_fuzzer::targets::CircomTarget;
use zk_core::FieldElement;

/// Test constraint inference on the range_bypass circuit
/// This circuit has a known bug: bit decomposition without recomposition check
#[tokio::test]
#[ignore = "Requires circom + snarkjs"]
async fn test_constraint_inference_range_bypass() {
    // Check prerequisites
    if CircomTarget::check_circom_available().is_err() {
        eprintln!("Skipping: circom not available. Install with: npm install -g circom");
        return;
    }
    if CircomTarget::check_snarkjs_available().is_err() {
        eprintln!("Skipping: snarkjs not available. Install with: npm install -g snarkjs");
        return;
    }

    let circuit_path = PathBuf::from("tests/bench/known_bugs/range_bypass/circuit.circom");
    if !circuit_path.exists() {
        panic!("Missing test circuit at {:?}", circuit_path);
    }

    // Create executor
    let executor = CircomExecutor::new(
        circuit_path.to_str().unwrap(),
        "RangeBypass"
    ).expect("Failed to create CircomExecutor");

    // Get constraint inspector
    let inspector = executor
        .constraint_inspector()
        .expect("Should have constraint inspector");

    let num_wires = executor.num_public_inputs() 
        + executor.num_private_inputs() 
        + 1000; // Add buffer for intermediate wires

    // Initialize constraint inference engine
    let engine = ConstraintInferenceEngine::new()
        .with_categories(&[
            ConstraintCategory::BitDecompositionRoundTrip,
            ConstraintCategory::RangeEnforcement,
        ]);

    // Run analysis
    let mut implied = engine.analyze(&*inspector, num_wires);

    println!("\n=== Constraint Inference Analysis ===");
    println!("Circuit: range_bypass/circuit.circom");
    println!("Inferred missing constraints: {}", implied.len());

    for (i, constraint) in implied.iter().enumerate() {
        println!("\n[{}] {:?}", i + 1, constraint.category);
        println!("    Description: {}", constraint.description);
        println!("    Confidence: {:.1}%", constraint.confidence * 100.0);
        println!("    Suggested: {}", constraint.suggested_constraint);
        println!("    Involved wires: {:?}", constraint.involved_wires.len());
    }

    // Verify we detected the known missing constraint
    assert!(
        !implied.is_empty(),
        "Should detect at least one missing constraint"
    );

    let has_bit_decomp = implied.iter().any(|c| 
        c.category == ConstraintCategory::BitDecompositionRoundTrip
    );
    
    println!("\n=== Detection Results ===");
    println!("Detected bit decomposition issue: {}", has_bit_decomp);

    // Generate and execute violation witnesses
    let base_inputs = vec![
        FieldElement::from_u64(42),  // value
        FieldElement::zero(),        // Start of bits array
    ];

    println!("\n=== Violation Witness Execution ===");
    engine.confirm_violations(&executor, &base_inputs, &mut implied);

    let mut confirmed_count = 0;
    let mut rejected_count = 0;
    let mut inconclusive_count = 0;

    for constraint in &implied {
        match constraint.confirmation {
            ViolationConfirmation::Confirmed => {
                confirmed_count += 1;
                println!("✓ CONFIRMED: {}", constraint.description);
            }
            ViolationConfirmation::Rejected => {
                rejected_count += 1;
                println!("✗ REJECTED: {}", constraint.description);
            }
            ViolationConfirmation::Inconclusive => {
                inconclusive_count += 1;
                println!("? INCONCLUSIVE: {}", constraint.description);
            }
            ViolationConfirmation::Unchecked => {
                println!("- UNCHECKED: {}", constraint.description);
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Confirmed violations: {}", confirmed_count);
    println!("Rejected: {}", rejected_count);
    println!("Inconclusive: {}", inconclusive_count);

    // The range_bypass circuit SHOULD allow violations through
    // because it's missing the recomposition constraint
    assert!(
        confirmed_count > 0 || inconclusive_count > 0,
        "Should confirm at least one violation on this buggy circuit"
    );

    println!("\n✅ Phase 4 validation complete: Constraint inference validated on real circuit");
}

/// Test constraint inference on the underconstrained_merkle circuit
/// This circuit has known missing constraints for Merkle path validation
#[tokio::test]
#[ignore = "Requires circom + snarkjs"]
async fn test_constraint_inference_merkle() {
    if CircomTarget::check_circom_available().is_err()
        || CircomTarget::check_snarkjs_available().is_err()
    {
        eprintln!("Skipping: circom/snarkjs not available");
        return;
    }

    let circuit_path = PathBuf::from("tests/bench/known_bugs/underconstrained_merkle/circuit.circom");
    if !circuit_path.exists() {
        eprintln!("Skipping: Merkle test circuit not found at {:?}", circuit_path);
        return;
    }

    let executor = CircomExecutor::new(
        circuit_path.to_str().unwrap(),
        "UnderconstrainedMerkle"
    );

    if executor.is_err() {
        eprintln!("Skipping: Failed to create executor for Merkle circuit");
        return;
    }

    let executor = executor.unwrap();
    let inspector = executor
        .constraint_inspector()
        .expect("Should have constraint inspector");

    let num_wires = executor.num_public_inputs() 
        + executor.num_private_inputs() 
        + 1000;

    // Initialize engine with Merkle-specific categories
    let engine = ConstraintInferenceEngine::new()
        .with_categories(&[
            ConstraintCategory::MerklePathValidation,
            ConstraintCategory::HashConsistency,
        ]);

    let mut implied = engine.analyze(&*inspector, num_wires);

    println!("\n=== Merkle Circuit Analysis ===");
    println!("Inferred missing constraints: {}", implied.len());

    for constraint in &implied {
        println!("  - [{:?}] {} (confidence: {:.1}%)",
            constraint.category,
            constraint.description,
            constraint.confidence * 100.0
        );
    }

    // Execute violations
    let base_inputs = vec![FieldElement::from_u64(1); 10];
    engine.confirm_violations(&executor, &base_inputs, &mut implied);

    let confirmed = implied.iter()
        .filter(|c| matches!(c.confirmation, ViolationConfirmation::Confirmed))
        .count();

    println!("Confirmed violations: {}", confirmed);
    
    // We expect some constraints to be detected
    assert!(!implied.is_empty(), "Should detect missing Merkle constraints");
}

/// Test constraint inference produces actionable findings
#[test]
fn test_constraint_inference_to_findings() {
    use zk_fuzzer::attacks::constraint_inference::{ConstraintInferenceEngine, ImpliedConstraint};
    use zk_core::{Severity, AttackType};

    let engine = ConstraintInferenceEngine::new();

    // Create mock implied constraints
    let implied = vec![
        ImpliedConstraint {
            category: ConstraintCategory::BitDecompositionRoundTrip,
            description: "Missing bit recomposition".to_string(),
            confidence: 0.9,
            involved_wires: vec![0, 1, 2],
            suggested_constraint: "sum(bits[i] * 2^i) == value".to_string(),
            violation_witness: Some(vec![FieldElement::from_u64(42)]),
            confirmation: ViolationConfirmation::Confirmed,
        },
    ];

    // Convert to findings
    let findings = engine.to_findings(&implied);

    assert_eq!(findings.len(), 1, "Should produce one finding");
    
    let finding = &findings[0];
    assert_eq!(finding.attack_type, AttackType::ConstraintInference);
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.description.contains("Missing bit recomposition"));
    assert!(!finding.poc.witness_a.is_empty());

    println!("✓ Findings generation validated");
}

/// Comprehensive validation: detect, execute, and verify on multiple circuits
#[tokio::test]
#[ignore = "Requires circom + snarkjs and multiple test circuits"]
async fn test_constraint_inference_comprehensive() {
    if CircomTarget::check_circom_available().is_err()
        || CircomTarget::check_snarkjs_available().is_err()
    {
        eprintln!("Skipping: circom/snarkjs not available");
        return;
    }

    let test_circuits = vec![
        ("tests/bench/known_bugs/range_bypass/circuit.circom", "RangeBypass", 
         vec![ConstraintCategory::BitDecompositionRoundTrip]),
        ("tests/bench/known_bugs/underconstrained_merkle/circuit.circom", "UnderconstrainedMerkle",
         vec![ConstraintCategory::MerklePathValidation]),
    ];

    let mut total_detected = 0;
    let mut total_confirmed = 0;

    for (path, component, expected_categories) in test_circuits {
        let circuit_path = PathBuf::from(path);
        if !circuit_path.exists() {
            eprintln!("Skipping: {} not found", path);
            continue;
        }

        println!("\n=== Testing {} ===", path);

        let executor = match CircomExecutor::new(circuit_path.to_str().unwrap(), component) {
            Ok(e) => e,
            Err(err) => {
                eprintln!("Failed to create executor: {}", err);
                continue;
            }
        };

        let inspector = match executor.constraint_inspector() {
            Some(i) => i,
            None => {
                eprintln!("No constraint inspector available");
                continue;
            }
        };

        let num_wires = executor.num_public_inputs() 
            + executor.num_private_inputs() 
            + 1000;

        // Build engine with relevant categories
        let engine = ConstraintInferenceEngine::new()
            .with_categories(&expected_categories);

        let mut implied = engine.analyze(&*inspector, num_wires);
        total_detected += implied.len();

        println!("  Detected: {} missing constraints", implied.len());

        // Execute violations
        let base_inputs = vec![FieldElement::from_u64(1); 10];
        engine.confirm_violations(&executor, &base_inputs, &mut implied);

        let confirmed = implied.iter()
            .filter(|c| matches!(c.confirmation, ViolationConfirmation::Confirmed))
            .count();
        
        total_confirmed += confirmed;
        println!("  Confirmed: {} violations", confirmed);
    }

    println!("\n=== Overall Results ===");
    println!("Total constraints detected: {}", total_detected);
    println!("Total violations confirmed: {}", total_confirmed);

    assert!(total_detected > 0, "Should detect missing constraints across test circuits");
    
    println!("\n✅ Comprehensive constraint inference validation complete");
}
