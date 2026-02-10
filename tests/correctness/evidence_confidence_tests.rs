//! Evidence Confidence Threshold Tests (Milestone 0.0)
//!
//! Verifies that evidence mode correctly handles single-oracle findings
//! with validation/reproduction.
//!
//! # Phase 0 Fix: Evidence Confidence Model
//!
//! Previously, `cross_oracle_threshold` defaulted to 2, which would drop valid
//! single-oracle findings. Now:
//! - MEDIUM: 1 oracle + successful validation/reproduction
//! - HIGH: 2+ independent oracle groups agree
//! - CRITICAL: all groups + invariant violation

use zk_fuzzer::fuzzer::oracle_validation::{OracleValidationConfig, ValidationResult};

/// Test that validation config allows single-oracle reproducible findings
#[test]
fn test_single_oracle_reproducible_passes() {
    let config = OracleValidationConfig::default();

    // Single-oracle findings with reproduction should be valid
    assert!(
        config.allow_single_oracle_with_reproduction,
        "Default config should allow single-oracle reproducible findings"
    );
}

/// Test that minimum agreement ratio is reasonable
#[test]
fn test_minimum_agreement_ratio() {
    let config = OracleValidationConfig::default();

    // Lowered from 0.6 to 0.5 in Phase 0 fix
    assert!(
        config.min_agreement_ratio <= 0.5,
        "Agreement ratio should be <= 0.5 to allow single-oracle findings, got {}",
        config.min_agreement_ratio
    );
}

/// Test validation result confidence calculation
#[test]
fn test_validation_result_confidence() {
    // Valid result should have high confidence
    let valid = ValidationResult::valid(vec!["Test reason".to_string()]);
    assert!(valid.is_valid);
    assert_eq!(valid.confidence, 1.0);

    // Invalid result should have low confidence
    let invalid = ValidationResult::invalid(vec!["Test reason".to_string()]);
    assert!(!invalid.is_valid);
    assert_eq!(invalid.confidence, 0.0);

    // Partial result at threshold
    let partial = ValidationResult::partial(0.5, vec!["Test reason".to_string()]);
    assert!(partial.is_valid, "0.5 confidence should be valid");

    // Partial result below threshold
    let partial_low = ValidationResult::partial(0.4, vec!["Test reason".to_string()]);
    assert!(
        !partial_low.is_valid,
        "0.4 confidence should not be valid"
    );
}

/// Test strict config is stricter than default
#[test]
fn test_strict_config() {
    let default = OracleValidationConfig::default();
    let strict = OracleValidationConfig::strict();

    // Strict config should have higher requirements
    assert!(
        strict.min_agreement_ratio > default.min_agreement_ratio,
        "Strict config should have higher agreement ratio"
    );
    assert!(
        !strict.allow_single_oracle_with_reproduction,
        "Strict config should not allow single-oracle findings"
    );
}

/// Test permissive config is more lenient
#[test]
fn test_permissive_config() {
    let default = OracleValidationConfig::default();
    let permissive = OracleValidationConfig::permissive();

    // Permissive config should have lower requirements
    assert!(
        permissive.min_agreement_ratio <= default.min_agreement_ratio,
        "Permissive config should have lower or equal agreement ratio"
    );
    assert!(
        permissive.allow_single_oracle_with_reproduction,
        "Permissive config should allow single-oracle findings"
    );
}
