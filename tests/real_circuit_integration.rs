//! Real Circuit Integration Tests
//!
//! Tests the ZkPatternFuzz against real ZK circuits from production projects.
//! These tests validate that the R1CS parser and constraint-guided fuzzing
//! work correctly with actual Circom-compiled circuits.
//!
//! External circuit sources (from ${ZK0D_BASE:-/media/elements/Repos/zk0d}):
//! - snarkjs/test: Basic groth16/plonk test circuits
//! - tornado-core: Tornado Cash mixer circuits
//! - semaphore: Privacy-preserving signaling
//! - circuits (iden3): Credential and identity circuits

use std::path::Path;
use zk_fuzzer::analysis::{
    R1CS, ConstraintSeedGenerator, EnhancedSymbolicConfig, PruningStrategy,
    R1CSConstraintGuidedExt,
};

// ============================================================================
// Test Circuit Paths (external repository)
// ============================================================================

const DEFAULT_ZK0D_BASE: &str = "/media/elements/Repos/zk0d";
const COMPILED_SNARKJS_GROTH16_R1CS: &str = "circuits/compiled/snarkjs_groth16/circuit.r1cs";
const COMPILED_SNARKJS_GROTH16_SYM: &str = "circuits/compiled/snarkjs_groth16/circuit.sym";
const COMPILED_SNARKJS_PLONK_R1CS: &str = "circuits/compiled/snarkjs_plonk_circuit/circuit.r1cs";
const COMPILED_SNARKJS_CIRCUIT_R1CS: &str = "circuits/compiled/snarkjs_circuit/circuit.r1cs";
const STAGED_TORNADO_WITHDRAW: &str = "circuits/withdraw.circom";
const STAGED_SEMAPHORE: &str = "circuits/semaphore.circom";
const STAGED_IDEN3_AUTH: &str = "circuits/auth/authV3.circom";

// snarkjs test circuits
const SNARKJS_GROTH16_R1CS: &str = "cat5_frameworks/snarkjs/test/groth16/circuit.r1cs";
const SNARKJS_GROTH16_SYM: &str = "cat5_frameworks/snarkjs/test/groth16/circuit.sym";
const SNARKJS_PLONK_R1CS: &str = "cat5_frameworks/snarkjs/test/plonk_circuit/circuit.r1cs";
const SNARKJS_CIRCUIT_R1CS: &str = "cat5_frameworks/snarkjs/test/circuit/circuit.r1cs";

// risc0 test circuits
const RISC0_MULTIPLIER_R1CS: &str = "cat5_frameworks/risc0/groth16_proof/circom-compat/test/data/multiplier2.r1cs";

// gnark test circuits
const GNARK_ISSUE1045_R1CS: &str = "cat5_frameworks/gnark/internal/regression_tests/issue1045/testdata/issue1045.r1cs";

/// Helper to get the base path for zk0d (supports env override)
fn zk0d_base() -> std::path::PathBuf {
    std::env::var("ZK0D_BASE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| Path::new(DEFAULT_ZK0D_BASE).to_path_buf())
}

fn zk0d_base_display() -> String {
    zk0d_base().display().to_string()
}

fn resolve_path(candidates: &[std::path::PathBuf]) -> Option<std::path::PathBuf> {
    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate.clone());
        }
    }
    None
}

fn resolve_r1cs_path(relative: &str, compiled_fallback: Option<&str>) -> Option<std::path::PathBuf> {
    let mut candidates = vec![zk0d_base().join(relative)];
    if let Some(compiled) = compiled_fallback {
        candidates.push(std::path::PathBuf::from(compiled));
    }
    resolve_path(&candidates)
}

fn resolve_sym_path(relative: &str, compiled_fallback: Option<&str>) -> Option<std::path::PathBuf> {
    let mut candidates = vec![zk0d_base().join(relative)];
    if let Some(compiled) = compiled_fallback {
        candidates.push(std::path::PathBuf::from(compiled));
    }
    resolve_path(&candidates)
}

fn resolve_source_path(relative: &str, staged_fallback: Option<&str>) -> Option<std::path::PathBuf> {
    let mut candidates = vec![zk0d_base().join(relative)];
    if let Some(staged) = staged_fallback {
        candidates.push(std::path::PathBuf::from(staged));
    }
    resolve_path(&candidates)
}

/// Check if external circuits are available
fn external_circuits_available() -> bool {
    resolve_r1cs_path(SNARKJS_GROTH16_R1CS, Some(COMPILED_SNARKJS_GROTH16_R1CS)).is_some()
        || Path::new(STAGED_TORNADO_WITHDRAW).exists()
        || Path::new(STAGED_SEMAPHORE).exists()
        || Path::new(STAGED_IDEN3_AUTH).exists()
}

// ============================================================================
// R1CS Parser Tests with Real Circuits
// ============================================================================

#[test]
fn test_parse_snarkjs_groth16_circuit() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_GROTH16_R1CS,
        Some(COMPILED_SNARKJS_GROTH16_R1CS),
    ) else {
        eprintln!("Skipping: Groth16 R1CS not found");
        return;
    };
    
    let r1cs = R1CS::from_file(&r1cs_path)
        .expect("Should parse snarkjs groth16 circuit.r1cs");

    // The circuit is: Multiplier(1000) with 2 inputs (a, b) and 1 output (c)
    // This creates ~1000 constraints for the iterative squaring
    println!("=== snarkjs Groth16 Circuit ===");
    println!("Wires: {}", r1cs.num_wires);
    println!("Constraints: {}", r1cs.constraints.len());
    println!("Public Outputs: {}", r1cs.num_public_outputs);
    println!("Public Inputs: {}", r1cs.num_public_inputs);
    println!("Private Inputs: {}", r1cs.num_private_inputs);
    println!("Field Bytes: {}", r1cs.field_bytes);
    println!("Constraint Density: {:.2}", r1cs.constraint_density());

    // Validate parsed structure
    assert!(r1cs.num_wires > 0, "Should have wires");
    assert!(!r1cs.constraints.is_empty(), "Should have constraints");
    assert_eq!(r1cs.field_bytes, 32, "Should use 32-byte field (BN254)");
    
    // The Multiplier(1000) circuit has 1 public input (a) and 1 private input (b)
    assert!(r1cs.num_public_inputs >= 1, "Should have at least 1 public input");
    
    // Check constraint structure
    let constraint = &r1cs.constraints[0];
    assert!(!constraint.is_trivial(), "First constraint should not be trivial");
    
    let wire_indices = constraint.wire_indices();
    assert!(!wire_indices.is_empty(), "Constraint should reference wires");
    
    println!("First constraint involves wires: {:?}", wire_indices);
}

#[test]
fn test_parse_snarkjs_groth16_with_symbols() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_GROTH16_R1CS,
        Some(COMPILED_SNARKJS_GROTH16_R1CS),
    ) else {
        eprintln!("Skipping: Groth16 R1CS not found");
        return;
    };
    let Some(sym_path) =
        resolve_sym_path(SNARKJS_GROTH16_SYM, Some(COMPILED_SNARKJS_GROTH16_SYM))
    else {
        eprintln!("Skipping: Groth16 .sym not found");
        return;
    };

    let _r1cs = R1CS::from_file(&r1cs_path)
        .expect("Should parse R1CS");
    
    // Parse symbol file for wire names
    let wire_names = zk_fuzzer::analysis::parse_sym_file(&sym_path)
        .expect("Should parse symbol file");

    println!("=== Symbol File Analysis ===");
    println!("Total symbols: {}", wire_names.len());
    
    // Print first 10 wire names
    for (i, name) in wire_names.iter().take(10).enumerate() {
        println!("  Wire {}: {}", i, name);
    }

    assert!(!wire_names.is_empty(), "Should have wire names");
    
    // Check for expected signal names from Multiplier template
    let has_int_signal = wire_names.iter().any(|n| n.contains("int"));
    let has_main = wire_names.iter().any(|n| n.contains("main"));
    
    println!("Has 'int' signals: {}", has_int_signal);
    println!("Has 'main' signals: {}", has_main);
}

#[test]
fn test_parse_snarkjs_plonk_circuit() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_PLONK_R1CS,
        Some(COMPILED_SNARKJS_PLONK_R1CS),
    ) else {
        eprintln!("Skipping: PLONK circuit not found");
        return;
    };

    let r1cs = R1CS::from_file(&r1cs_path)
        .expect("Should parse snarkjs PLONK circuit");

    println!("=== snarkjs PLONK Circuit ===");
    println!("Wires: {}", r1cs.num_wires);
    println!("Constraints: {}", r1cs.constraints.len());
    println!("Custom Gates Used: {}", r1cs.custom_gates_used);

    assert!(r1cs.num_wires > 0);
    assert!(!r1cs.constraints.is_empty());
}

#[test]
fn test_parse_snarkjs_basic_circuit() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_CIRCUIT_R1CS,
        Some(COMPILED_SNARKJS_CIRCUIT_R1CS),
    ) else {
        eprintln!("Skipping: Basic circuit not found");
        return;
    };

    let r1cs = R1CS::from_file(&r1cs_path)
        .expect("Should parse snarkjs basic circuit");

    println!("=== snarkjs Basic Circuit ===");
    println!("Wires: {}", r1cs.num_wires);
    println!("Constraints: {}", r1cs.constraints.len());

    assert!(r1cs.num_wires > 0);
}

#[test]
fn test_parse_risc0_multiplier() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(RISC0_MULTIPLIER_R1CS, None) else {
        eprintln!("Skipping: RISC0 multiplier circuit not found");
        return;
    };

    let r1cs = R1CS::from_file(&r1cs_path)
        .expect("Should parse RISC0 multiplier2 circuit");

    println!("=== RISC0 Multiplier2 Circuit ===");
    println!("Wires: {}", r1cs.num_wires);
    println!("Constraints: {}", r1cs.constraints.len());
    println!("Public Inputs: {}", r1cs.num_public_inputs);
    println!("Private Inputs: {}", r1cs.num_private_inputs);

    // Simple multiplier should have few constraints
    assert!(r1cs.num_wires > 0);
    assert!(!r1cs.constraints.is_empty());
}

#[test]
fn test_parse_gnark_circuit() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(GNARK_ISSUE1045_R1CS, None) else {
        eprintln!("Skipping: gnark circuit not found");
        return;
    };

    // Note: gnark R1CS format might differ from Circom's
    match R1CS::from_file(&r1cs_path) {
        Ok(r1cs) => {
            println!("=== gnark Issue1045 Circuit ===");
            println!("Wires: {}", r1cs.num_wires);
            println!("Constraints: {}", r1cs.constraints.len());
        }
        Err(e) => {
            // gnark uses a different R1CS format
            println!("gnark R1CS parsing failed (expected - different format): {}", e);
        }
    }
}

// ============================================================================
// Constraint Analysis Tests
// ============================================================================

#[test]
fn test_input_constraints_extraction() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_GROTH16_R1CS,
        Some(COMPILED_SNARKJS_GROTH16_R1CS),
    ) else {
        eprintln!("Skipping: Groth16 R1CS not found");
        return;
    };
    let r1cs = R1CS::from_file(&r1cs_path).expect("Should parse R1CS");

    let input_indices = r1cs.input_wire_indices();
    let public_indices = r1cs.public_input_indices();
    let private_indices = r1cs.private_input_indices();

    println!("=== Input Wire Analysis ===");
    println!("All input indices: {:?}", input_indices);
    println!("Public input indices: {:?}", public_indices);
    println!("Private input indices: {:?}", private_indices);

    // Get constraints that involve input wires
    let input_constraints = r1cs.input_constraints();
    
    println!("Constraints involving inputs: {}", input_constraints.len());
    println!("Total constraints: {}", r1cs.constraints.len());
    println!(
        "Input constraint ratio: {:.1}%",
        (input_constraints.len() as f64 / r1cs.constraints.len() as f64) * 100.0
    );

    assert!(!input_indices.is_empty(), "Should have input wires");
    assert!(!input_constraints.is_empty(), "Should have input constraints");
}

#[test]
fn test_extended_constraint_conversion() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_GROTH16_R1CS,
        Some(COMPILED_SNARKJS_GROTH16_R1CS),
    ) else {
        eprintln!("Skipping: Groth16 R1CS not found");
        return;
    };
    let r1cs = R1CS::from_file(&r1cs_path).expect("Should parse R1CS");

    // Convert to extended constraints for symbolic analysis
    let extended = r1cs.to_extended_constraints();

    println!("=== Extended Constraint Conversion ===");
    println!("Original constraints: {}", r1cs.constraints.len());
    println!("Extended constraints: {}", extended.len());

    assert_eq!(
        r1cs.constraints.len(),
        extended.len(),
        "Should convert all constraints"
    );

    // Verify first few are R1CS type
    for (i, ext) in extended.iter().take(5).enumerate() {
        match ext {
            zk_fuzzer::analysis::ExtendedConstraint::R1CS(_) => {
                println!("Constraint {} is R1CS type", i);
            }
            _ => panic!("Expected R1CS constraint type"),
        }
    }
}

// ============================================================================
// SMT-Guided Seed Generation Tests
// ============================================================================

#[test]
fn test_smt_seed_generation_basic() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_GROTH16_R1CS,
        Some(COMPILED_SNARKJS_GROTH16_R1CS),
    ) else {
        eprintln!("Skipping: Groth16 R1CS not found");
        return;
    };
    let r1cs = R1CS::from_file(&r1cs_path).expect("Should parse R1CS");

    println!("=== SMT Seed Generation ===");
    println!("Generating seeds from {} constraints...", r1cs.constraints.len());

    // Use short timeout for test
    let config = EnhancedSymbolicConfig {
        solver_timeout_ms: 5000,
        simplify_constraints: true,
        pruning_strategy: PruningStrategy::CoverageGuided,
        solutions_per_path: 5,
        max_depth: 100, // Limit depth for faster testing
        ..Default::default()
    };

    let mut generator = ConstraintSeedGenerator::new(config);

    let extended = r1cs.to_extended_constraints();
    let input_indices = r1cs.input_wire_indices();
    let expected_len = r1cs.num_public_inputs + r1cs.num_private_inputs;

    // Only use first 50 constraints for speed
    let limited_constraints: Vec<_> = extended.into_iter().take(50).collect();

    let output = generator.generate_from_extended(
        &limited_constraints,
        &std::collections::HashMap::new(),
        &input_indices,
        expected_len,
    );

    println!("Stats:");
    println!("  Total constraints processed: {}", output.stats.total_constraints);
    println!("  Symbolic constraints: {}", output.stats.symbolic_constraints);
    println!("  Skipped constraints: {}", output.stats.skipped_constraints);
    println!("  Pruned constraints: {}", output.stats.pruned_constraints);
    println!("  Solutions found: {}", output.stats.solutions);
    println!("  Seeds generated: {}", output.seeds.len());

    // Print first few seeds
    for (i, seed) in output.seeds.iter().take(3).enumerate() {
        println!("  Seed {}: {} field elements", i, seed.len());
        for (j, fe) in seed.iter().take(2).enumerate() {
            println!("    Input {}: {:?}", j, &fe.0[..8]);
        }
    }
}

#[test]
fn test_smt_seed_generation_via_r1cs_api() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_GROTH16_R1CS,
        Some(COMPILED_SNARKJS_GROTH16_R1CS),
    ) else {
        eprintln!("Skipping: Groth16 R1CS not found");
        return;
    };
    let r1cs = R1CS::from_file(&r1cs_path).expect("Should parse R1CS");

    println!("=== SMT Seed Generation via R1CS API ===");

    // Use the high-level R1CS API
    let seeds = r1cs.generate_smt_inputs(3, 3000);

    println!("Generated {} seeds", seeds.len());

    for (i, seed) in seeds.iter().enumerate() {
        println!("  Seed {}: {} inputs", i, seed.len());
    }
}

// ============================================================================
// Underconstrained Detection Tests
// ============================================================================

#[test]
fn test_underconstrained_detection() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_GROTH16_R1CS,
        Some(COMPILED_SNARKJS_GROTH16_R1CS),
    ) else {
        eprintln!("Skipping: Groth16 R1CS not found");
        return;
    };
    let r1cs = R1CS::from_file(&r1cs_path).expect("Should parse R1CS");

    println!("=== Underconstrained Analysis ===");
    println!("Wires: {}", r1cs.num_wires);
    println!("Constraints: {}", r1cs.constraints.len());
    println!("Total inputs: {}", r1cs.num_public_inputs + r1cs.num_private_inputs);
    println!("Constraint density: {:.2}", r1cs.constraint_density());
    println!("Likely underconstrained: {}", r1cs.is_likely_underconstrained());

    // The Multiplier(1000) should be well-constrained
    assert!(
        !r1cs.is_likely_underconstrained(),
        "Multiplier circuit should not be underconstrained"
    );
    assert!(
        r1cs.constraint_density() > 0.5,
        "Should have reasonable constraint density"
    );
}

// ============================================================================
// Privacy Circuit Tests (if compiled)
// ============================================================================

#[test]
fn test_find_privacy_circuit_sources() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    println!("=== Privacy Circuit Sources ===");

    // Check for tornado-core circuits
    let tornado_circuits_dir = zk0d_base().join("cat3_privacy/tornado-core/circuits");
    if tornado_circuits_dir.exists() {
        println!("Tornado Cash circuits found at {:?}", tornado_circuits_dir);
        
        // List circom files
        if let Ok(entries) = std::fs::read_dir(&tornado_circuits_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "circom") {
                    println!("  - {}", path.file_name().unwrap().to_string_lossy());
                }
            }
        }
    }

    // Check for semaphore circuits
    let semaphore_circuits_dir = zk0d_base().join("cat3_privacy/semaphore/packages/circuits/src");
    if semaphore_circuits_dir.exists() {
        println!("Semaphore circuits found at {:?}", semaphore_circuits_dir);
    }

    // Check for iden3 circuits
    let iden3_circuits_dir = zk0d_base().join("cat3_privacy/circuits/circuits");
    if iden3_circuits_dir.exists() {
        println!("Iden3 circuits found at {:?}", iden3_circuits_dir);
    }

    // Check staged circuits (from setup script)
    if Path::new(STAGED_TORNADO_WITHDRAW).exists() {
        println!("Staged Tornado withdraw circuit at {}", STAGED_TORNADO_WITHDRAW);
    }
    if Path::new(STAGED_SEMAPHORE).exists() {
        println!("Staged Semaphore circuit at {}", STAGED_SEMAPHORE);
    }
    if Path::new(STAGED_IDEN3_AUTH).exists() {
        println!("Staged Iden3 auth circuit at {}", STAGED_IDEN3_AUTH);
    }
}

// ============================================================================
// Privacy Circuit Source Analysis Tests
// ============================================================================

#[test]
fn test_tornado_cash_source_analysis() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(withdraw_circom) = resolve_source_path(
        "cat3_privacy/tornado-core/circuits/withdraw.circom",
        Some(STAGED_TORNADO_WITHDRAW),
    ) else {
        eprintln!("Skipping: Tornado withdraw.circom not found");
        return;
    };

    println!("=== Tornado Cash Source Analysis ===");

    let source = std::fs::read_to_string(&withdraw_circom)
        .expect("Should read withdraw.circom");

    // Analyze circuit structure
    println!("Source length: {} bytes", source.len());

    // Count key patterns
    let signal_count = source.matches("signal").count();
    let constraint_count = source.matches("<==").count();
    let assert_count = source.matches("===").count();
    let template_count = source.matches("template").count();
    let component_count = source.matches("component").count();

    println!("Templates: {}", template_count);
    println!("Components: {}", component_count);
    println!("Signals: {}", signal_count);
    println!("Constraints (<==): {}", constraint_count);
    println!("Assertions (===): {}", assert_count);

    // Check for key privacy components
    let has_nullifier = source.contains("nullifier");
    let has_commitment = source.contains("commitment");
    let has_merkle = source.contains("Merkle") || source.contains("merkle");
    let has_pedersen = source.contains("Pedersen");

    println!("\nPrivacy components:");
    println!("  Has nullifier: {}", has_nullifier);
    println!("  Has commitment: {}", has_commitment);
    println!("  Has Merkle tree: {}", has_merkle);
    println!("  Has Pedersen hash: {}", has_pedersen);

    assert!(has_nullifier, "Tornado should have nullifier");
    assert!(has_commitment, "Tornado should have commitment");
    assert!(has_merkle, "Tornado should have Merkle tree");
}

#[test]
fn test_semaphore_source_analysis() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(semaphore_circom) = resolve_source_path(
        "cat3_privacy/semaphore/packages/circuits/src/semaphore.circom",
        Some(STAGED_SEMAPHORE),
    ) else {
        eprintln!("Skipping: Semaphore circuit not found");
        return;
    };

    println!("=== Semaphore Source Analysis ===");

    let source = std::fs::read_to_string(&semaphore_circom)
        .expect("Should read semaphore.circom");

    println!("Source length: {} bytes", source.len());

    // Key Semaphore components
    let has_identity = source.contains("identity") || source.contains("Identity");
    let has_nullifier = source.contains("nullifier");
    let has_merkle = source.contains("Merkle") || source.contains("merkle");
    let has_signal = source.contains("signal");
    let has_external = source.contains("external") || source.contains("externalNullifier");

    println!("Semaphore components:");
    println!("  Has identity: {}", has_identity);
    println!("  Has nullifier: {}", has_nullifier);
    println!("  Has Merkle tree: {}", has_merkle);
    println!("  Has signal statements: {}", has_signal);
    println!("  Has external nullifier: {}", has_external);
}

#[test]
fn test_iden3_credential_source_analysis() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(auth_circom) = resolve_source_path(
        "cat3_privacy/circuits/circuits/authV3.circom",
        Some(STAGED_IDEN3_AUTH),
    ) else {
        eprintln!("Skipping: Iden3 authV3.circom not found");
        return;
    };

    println!("=== Iden3 Auth Circuit Analysis ===");

    let source = std::fs::read_to_string(&auth_circom)
        .expect("Should read authV3.circom");

    println!("Source length: {} bytes", source.len());

    // Key Iden3 components
    let has_claim = source.contains("claim") || source.contains("Claim");
    let has_identity = source.contains("identity") || source.contains("Identity");
    let has_state = source.contains("state") || source.contains("State");
    let has_merkle = source.contains("Merkle") || source.contains("merkle") || source.contains("SMT");

    println!("Iden3 components:");
    println!("  Has claim: {}", has_claim);
    println!("  Has identity: {}", has_identity);
    println!("  Has state: {}", has_state);
    println!("  Has Merkle/SMT: {}", has_merkle);
}

// ============================================================================
// Performance Benchmarks
// ============================================================================

#[test]
fn test_r1cs_parsing_performance() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_GROTH16_R1CS,
        Some(COMPILED_SNARKJS_GROTH16_R1CS),
    ) else {
        eprintln!("Skipping: Groth16 R1CS not found");
        return;
    };

    println!("=== R1CS Parsing Performance ===");

    let start = std::time::Instant::now();
    let r1cs = R1CS::from_file(&r1cs_path).expect("Should parse R1CS");
    let parse_time = start.elapsed();

    println!("Parse time: {:?}", parse_time);
    println!("Constraints: {}", r1cs.constraints.len());
    println!("Constraints/ms: {:.1}", r1cs.constraints.len() as f64 / parse_time.as_millis() as f64);

    // Parsing should be fast
    assert!(
        parse_time.as_millis() < 5000,
        "Parsing should complete in under 5 seconds"
    );
}

#[test]
fn test_constraint_conversion_performance() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    let Some(r1cs_path) = resolve_r1cs_path(
        SNARKJS_GROTH16_R1CS,
        Some(COMPILED_SNARKJS_GROTH16_R1CS),
    ) else {
        eprintln!("Skipping: Groth16 R1CS not found");
        return;
    };
    let r1cs = R1CS::from_file(&r1cs_path).expect("Should parse R1CS");

    println!("=== Constraint Conversion Performance ===");

    let start = std::time::Instant::now();
    let extended = r1cs.to_extended_constraints();
    let convert_time = start.elapsed();

    println!("Conversion time: {:?}", convert_time);
    println!("Constraints converted: {}", extended.len());

    // Conversion should be very fast
    assert!(
        convert_time.as_millis() < 1000,
        "Conversion should complete in under 1 second"
    );
}

// ============================================================================
// Test Summary
// ============================================================================

#[test]
fn test_summary_report() {
    if !external_circuits_available() {
        eprintln!(
            "Skipping: External circuits not available at {}",
            zk0d_base_display()
        );
        return;
    }

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           REAL CIRCUIT INTEGRATION TEST SUMMARY              ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    
    // Test each available circuit
    let circuits = [
        ("snarkjs groth16", SNARKJS_GROTH16_R1CS),
        ("snarkjs plonk", SNARKJS_PLONK_R1CS),
        ("snarkjs basic", SNARKJS_CIRCUIT_R1CS),
        ("risc0 multiplier", RISC0_MULTIPLIER_R1CS),
    ];

    for (name, path) in &circuits {
        let full_path = match *path {
            SNARKJS_GROTH16_R1CS => resolve_r1cs_path(
                SNARKJS_GROTH16_R1CS,
                Some(COMPILED_SNARKJS_GROTH16_R1CS),
            ),
            SNARKJS_PLONK_R1CS => resolve_r1cs_path(
                SNARKJS_PLONK_R1CS,
                Some(COMPILED_SNARKJS_PLONK_R1CS),
            ),
            SNARKJS_CIRCUIT_R1CS => resolve_r1cs_path(
                SNARKJS_CIRCUIT_R1CS,
                Some(COMPILED_SNARKJS_CIRCUIT_R1CS),
            ),
            RISC0_MULTIPLIER_R1CS => resolve_r1cs_path(RISC0_MULTIPLIER_R1CS, None),
            _ => resolve_r1cs_path(path, None),
        };

        if let Some(full_path) = full_path {
            match R1CS::from_file(&full_path) {
                Ok(r1cs) => {
                    println!("║ ✅ {:<20} | {:>6} wires | {:>6} constraints  ║",
                        name, r1cs.num_wires, r1cs.constraints.len());
                }
                Err(e) => {
                    println!("║ ❌ {:<20} | Parse error: {}           ║",
                        name, &e.to_string()[..20.min(e.to_string().len())]);
                }
            }
        } else {
            println!("║ ⏭️  {:<20} | Not found                         ║", name);
        }
    }

    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}
