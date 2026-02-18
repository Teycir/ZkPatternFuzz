
use super::*;
use zk_core::{AttackType, ProofOfConcept};

fn make_finding(
    attack_type: AttackType,
    severity: Severity,
    witness: Vec<FieldElement>,
) -> Finding {
    Finding {
        attack_type,
        severity,
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

fn make_invariant_finding(
    attack_type: AttackType,
    severity: Severity,
    witness: Vec<FieldElement>,
) -> Finding {
    Finding {
        attack_type,
        severity,
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

#[test]
fn test_single_oracle_low_confidence() {
    let correlator = OracleCorrelator::new();

    let findings = vec![make_finding(
        AttackType::Soundness,
        Severity::High,
        vec![FieldElement::one()],
    )];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    assert_eq!(correlated[0].confidence, ConfidenceLevel::Low);
}

#[test]
fn test_multiple_oracles_same_group_low_confidence() {
    // Phase 0 Fix: Correlated oracles in same group should NOT inflate confidence
    let correlator = OracleCorrelator::new();

    let witness = vec![FieldElement::one()];
    // Both are in the Structural group
    let findings = vec![
        make_finding(
            AttackType::Underconstrained,
            Severity::Critical,
            witness.clone(),
        ),
        make_finding(
            AttackType::WitnessCollision,
            Severity::High,
            witness.clone(),
        ),
    ];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    // With independence weighting, same-group oracles = LOW confidence
    assert_eq!(correlated[0].confidence, ConfidenceLevel::Low);
    assert_eq!(correlated[0].oracle_count, 2); // 2 oracles...
    assert_eq!(correlated[0].independent_group_count, 1); // ...but only 1 group
}

#[test]
fn test_cross_group_oracles_high_confidence() {
    // Phase 0 Fix: Cross-group agreement = HIGH confidence
    let correlator = OracleCorrelator::new();

    let witness = vec![FieldElement::one()];
    let findings = vec![
        // Semantic group
        make_finding(AttackType::Soundness, Severity::High, witness.clone()),
        // Structural group
        make_finding(
            AttackType::Underconstrained,
            Severity::Critical,
            witness.clone(),
        ),
    ];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    assert_eq!(correlated[0].confidence, ConfidenceLevel::High);
    assert_eq!(correlated[0].independent_group_count, 2);
}

#[test]
fn test_all_groups_with_invariant_critical() {
    // All 3 groups + invariant = CRITICAL
    let correlator = OracleCorrelator::new();

    let witness = vec![FieldElement::one()];
    let findings = vec![
        // Semantic group
        make_finding(AttackType::Soundness, Severity::High, witness.clone()),
        // Structural group
        make_finding(
            AttackType::Underconstrained,
            Severity::Critical,
            witness.clone(),
        ),
        // Behavioral group + invariant
        make_invariant_finding(
            AttackType::ArithmeticOverflow,
            Severity::High,
            witness.clone(),
        ),
    ];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    assert_eq!(correlated[0].confidence, ConfidenceLevel::Critical);
    assert_eq!(correlated[0].independent_group_count, 3);
}

#[test]
fn test_single_group_with_invariant_medium() {
    // Single group + invariant = MEDIUM
    let correlator = OracleCorrelator::new();

    let witness = vec![FieldElement::one()];
    let findings = vec![make_invariant_finding(
        AttackType::Underconstrained,
        Severity::Critical,
        witness.clone(),
    )];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    assert_eq!(correlated[0].confidence, ConfidenceLevel::Medium);
}

#[test]
fn test_oracle_group_classification() {
    // Test that attack types are correctly classified
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Underconstrained),
        OracleGroup::Structural
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::WitnessCollision),
        OracleGroup::Structural
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Soundness),
        OracleGroup::Semantic
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Metamorphic),
        OracleGroup::Semantic
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::ArithmeticOverflow),
        OracleGroup::Behavioral
    );
    assert_eq!(
        OracleGroup::from_attack_type(AttackType::Boundary),
        OracleGroup::Behavioral
    );
}

#[test]
fn test_legacy_behavior_without_independence() {
    // Verify backward compatibility when independence weighting is disabled
    let correlator = OracleCorrelator::new().without_independence_weighting();

    let witness = vec![FieldElement::one()];
    // Both in same Structural group
    let findings = vec![
        make_finding(
            AttackType::Underconstrained,
            Severity::Critical,
            witness.clone(),
        ),
        make_finding(
            AttackType::WitnessCollision,
            Severity::High,
            witness.clone(),
        ),
    ];

    let correlated = correlator.correlate(&findings);
    assert_eq!(correlated.len(), 1);
    // Legacy: 2 oracles = HIGH (ignores group independence)
    assert_eq!(correlated[0].confidence, ConfidenceLevel::High);
}
