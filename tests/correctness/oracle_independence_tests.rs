//! Oracle Independence Weighting Tests (Milestone 0.0)
//!
//! Verifies that correlated oracles in the same group don't inflate confidence scores.
//!
//! # Phase 0 Fix: Oracle Independence Weighting
//!
//! Previously, any 2+ oracles would give HIGH confidence. This caused
//! correlated oracles (e.g., UnderconstrainedOracle + NullifierOracle,
//! both in the Structural group) to inflate confidence scores.
//!
//! Now, confidence is based on cross-GROUP agreement:
//! - 1 group: LOW (or MEDIUM with invariant)
//! - 2 groups: HIGH  
//! - 3 groups: CRITICAL (with invariant boost)

use zk_fuzzer::fuzzer::oracle_correlation::{ConfidenceLevel, OracleCorrelator, OracleGroup};
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity};

fn make_finding(attack_type: AttackType, witness: Vec<FieldElement>) -> Finding {
    Finding {
        attack_type,
        severity: Severity::High,
        description: "Test finding".to_string(),
        poc: ProofOfConcept {
            witness_a: witness,
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        },
        location: None,
    }
}

fn make_invariant_finding(attack_type: AttackType, witness: Vec<FieldElement>) -> Finding {
    Finding {
        attack_type,
        severity: Severity::High,
        description: "Invariant violation detected".to_string(),
        poc: ProofOfConcept {
            witness_a: witness,
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        },
        location: None,
    }
}

/// Test that same-group oracles don't inflate confidence
#[test]
fn test_same_group_oracles_low_confidence() {
    let correlator = OracleCorrelator::new();
    let witness = vec![FieldElement::one()];

    // Both Underconstrained and WitnessCollision are in Structural group
    let findings = vec![
        make_finding(AttackType::Underconstrained, witness.clone()),
        make_finding(AttackType::WitnessCollision, witness.clone()),
    ];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    // Same-group oracles should NOT give high confidence
    assert_eq!(
        correlated[0].confidence,
        ConfidenceLevel::Low,
        "Same-group oracles should give LOW confidence, not {:?}",
        correlated[0].confidence
    );
    assert_eq!(correlated[0].independent_group_count, 1);
}

/// Test that cross-group oracles give HIGH confidence
#[test]
fn test_cross_group_oracles_high_confidence() {
    let correlator = OracleCorrelator::new();
    let witness = vec![FieldElement::one()];

    // Soundness (Semantic) + Underconstrained (Structural)
    let findings = vec![
        make_finding(AttackType::Soundness, witness.clone()),
        make_finding(AttackType::Underconstrained, witness.clone()),
    ];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    assert_eq!(
        correlated[0].confidence,
        ConfidenceLevel::High,
        "Cross-group oracles should give HIGH confidence"
    );
    assert_eq!(correlated[0].independent_group_count, 2);
}

/// Test that all three groups + invariant gives CRITICAL
#[test]
fn test_all_groups_critical_confidence() {
    let correlator = OracleCorrelator::new();
    let witness = vec![FieldElement::one()];

    // Structural + Semantic + Behavioral + invariant
    let findings = vec![
        make_finding(AttackType::Underconstrained, witness.clone()),
        make_finding(AttackType::Soundness, witness.clone()),
        make_invariant_finding(AttackType::ArithmeticOverflow, witness.clone()),
    ];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    assert_eq!(
        correlated[0].confidence,
        ConfidenceLevel::Critical,
        "All groups + invariant should give CRITICAL confidence"
    );
    assert_eq!(correlated[0].independent_group_count, 3);
}

/// Test that single group with invariant gives MEDIUM
#[test]
fn test_single_group_with_invariant_medium() {
    let correlator = OracleCorrelator::new();
    let witness = vec![FieldElement::one()];

    let findings = vec![make_invariant_finding(
        AttackType::Underconstrained,
        witness.clone(),
    )];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    assert_eq!(
        correlated[0].confidence,
        ConfidenceLevel::Medium,
        "Single group + invariant should give MEDIUM confidence"
    );
}

/// Test oracle group classification correctness
#[test]
fn test_oracle_group_classification() {
    // Structural group
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Underconstrained),
        OracleGroup::Structural
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::WitnessCollision),
        OracleGroup::Structural
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Collision),
        OracleGroup::Structural
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::ConstraintInference),
        OracleGroup::Structural
    );

    // Semantic group
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Soundness),
        OracleGroup::Semantic
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Metamorphic),
        OracleGroup::Semantic
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Differential),
        OracleGroup::Semantic
    );

    // Behavioral group
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::ArithmeticOverflow),
        OracleGroup::Behavioral
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Boundary),
        OracleGroup::Behavioral
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Malleability),
        OracleGroup::Behavioral
    );
}

/// Test legacy behavior still works for backward compatibility
#[test]
fn test_legacy_confidence_without_independence() {
    let correlator = OracleCorrelator::new().without_independence_weighting();
    let witness = vec![FieldElement::one()];

    // Both in same Structural group
    let findings = vec![
        make_finding(AttackType::Underconstrained, witness.clone()),
        make_finding(AttackType::WitnessCollision, witness.clone()),
    ];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    // Legacy: 2 oracles = HIGH (ignores group independence)
    assert_eq!(
        correlated[0].confidence,
        ConfidenceLevel::High,
        "Legacy mode should give HIGH for 2+ oracles"
    );
}

/// Test that correlated findings are grouped by witness hash
#[test]
fn test_findings_grouped_by_witness() {
    let correlator = OracleCorrelator::new();
    let witness1 = vec![FieldElement::one()];
    let witness2 = vec![FieldElement::from(42u64)];

    // Different witnesses should create different groups
    let findings = vec![
        make_finding(AttackType::Underconstrained, witness1.clone()),
        make_finding(AttackType::Soundness, witness2.clone()),
    ];

    let correlated = correlator.correlate(&findings);
    assert_eq!(
        correlated.len(),
        2,
        "Different witnesses should create separate correlation groups"
    );
}

/// Test that empty findings returns empty correlation
#[test]
fn test_empty_findings() {
    let correlator = OracleCorrelator::new();
    let correlated = correlator.correlate(&[]);
    assert!(correlated.is_empty());
}
