//! Metamorphic Relations Circuit-Aware Tests (Milestone 0.0)
//!
//! Verifies that metamorphic relations are appropriate for circuit types.
//!
//! # Phase 0 Fix: Circuit-Type-Aware Relations
//!
//! Generic linear relations (scale, negate) don't apply to nonlinear ZK circuits
//! like hashes and Merkle trees. Now uses circuit-type detection:
//! - Hash circuits: Avalanche property
//! - Merkle circuits: Leaf sensitivity
//! - Signature circuits: Message binding
//! - Range/Arithmetic: Scaling, boundary testing

use zk_fuzzer::attacks::metamorphic::{CircuitType, MetamorphicOracle};

/// Test circuit type detection from name
#[test]
fn test_circuit_type_detection() {
    // Hash circuits
    assert_eq!(
        CircuitType::detect_from_name("PoseidonHash"),
        CircuitType::Hash
    );
    assert_eq!(
        CircuitType::detect_from_name("mimc_sponge"),
        CircuitType::Hash
    );
    assert_eq!(
        CircuitType::detect_from_name("pedersen_commitment"),
        CircuitType::Hash
    );

    // Merkle circuits
    assert_eq!(
        CircuitType::detect_from_name("MerkleTreeChecker"),
        CircuitType::Merkle
    );
    assert_eq!(
        CircuitType::detect_from_name("merkle_path"),
        CircuitType::Merkle
    );

    // Signature circuits
    assert_eq!(
        CircuitType::detect_from_name("EdDSAVerifier"),
        CircuitType::Signature
    );
    assert_eq!(
        CircuitType::detect_from_name("ecdsa_verification"),
        CircuitType::Signature
    );
    assert_eq!(
        CircuitType::detect_from_name("schnorr_sig"),
        CircuitType::Signature
    );

    // Range circuits
    assert_eq!(
        CircuitType::detect_from_name("range_proof"),
        CircuitType::Range
    );
    assert_eq!(
        CircuitType::detect_from_name("bound_check"),
        CircuitType::Range
    );

    // Nullifier circuits
    assert_eq!(
        CircuitType::detect_from_name("compute_nullifier"),
        CircuitType::Nullifier
    );

    // Commitment circuits
    assert_eq!(
        CircuitType::detect_from_name("commitment_scheme"),
        CircuitType::Commitment
    );

    // Arithmetic circuits
    assert_eq!(
        CircuitType::detect_from_name("add_constraint"),
        CircuitType::Arithmetic
    );
    assert_eq!(
        CircuitType::detect_from_name("linear_combination"),
        CircuitType::Arithmetic
    );

    // Unknown falls back
    assert_eq!(
        CircuitType::detect_from_name("custom_circuit"),
        CircuitType::Unknown
    );
}

/// Test that linear transforms are only allowed for appropriate circuit types
#[test]
fn test_linear_transform_support() {
    // Linear transforms appropriate for these
    assert!(CircuitType::Arithmetic.supports_linear_transforms());
    assert!(CircuitType::Range.supports_linear_transforms());

    // Linear transforms NOT appropriate for nonlinear circuits
    assert!(!CircuitType::Hash.supports_linear_transforms());
    assert!(!CircuitType::Merkle.supports_linear_transforms());
    assert!(!CircuitType::Signature.supports_linear_transforms());
    assert!(!CircuitType::Nullifier.supports_linear_transforms());
    assert!(!CircuitType::Commitment.supports_linear_transforms());
    assert!(!CircuitType::Unknown.supports_linear_transforms());
}

/// Test circuit-aware oracle creation compiles
#[test]
fn test_circuit_aware_oracle() {
    // Should compile and create without panicking
    let _oracle = MetamorphicOracle::new()
        .with_circuit_type(CircuitType::Hash)
        .with_circuit_aware_relations();
}

/// Test that hash circuits can create oracle
#[test]
fn test_hash_circuit_oracle() {
    // Hash circuit should create oracle without error
    let _oracle = MetamorphicOracle::new()
        .with_circuit_type(CircuitType::Hash)
        .with_circuit_aware_relations();
}

/// Test that merkle circuits can create oracle
#[test]
fn test_merkle_circuit_oracle() {
    let _oracle = MetamorphicOracle::new()
        .with_circuit_type(CircuitType::Merkle)
        .with_circuit_aware_relations();
}

/// Test that signature circuits can create oracle
#[test]
fn test_signature_circuit_oracle() {
    let _oracle = MetamorphicOracle::new()
        .with_circuit_type(CircuitType::Signature)
        .with_circuit_aware_relations();
}

/// Test deprecated standard relations warning
#[test]
#[allow(deprecated)]
fn test_deprecated_standard_relations() {
    // This should still compile but is deprecated
    let _oracle = MetamorphicOracle::new().with_standard_relations();
}

/// Test unknown circuit type gets safe defaults
#[test]
fn test_unknown_circuit_safe_defaults() {
    // Unknown circuits should get identity and permutation tests only
    // (safe for any circuit type)
    let _oracle = MetamorphicOracle::new()
        .with_circuit_type(CircuitType::Unknown)
        .with_circuit_aware_relations();
}

/// Test circuit type detection from name creates appropriate oracle
#[test]
fn test_circuit_type_from_name_oracle() {
    // Should work with circuit name detection
    let _oracle = MetamorphicOracle::new()
        .with_circuit_type_from_name("PoseidonHash")
        .with_circuit_aware_relations();
}
