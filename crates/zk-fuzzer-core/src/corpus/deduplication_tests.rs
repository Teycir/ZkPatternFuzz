
use super::*;
use zk_core::ProofOfConcept;

fn make_finding(attack_type: AttackType, location: &str) -> Finding {
    Finding {
        attack_type,
        severity: Severity::High,
        description: "Test finding".to_string(),
        poc: ProofOfConcept {
            witness_a: vec![FieldElement::from_u64(42)],
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        },
        location: Some(location.to_string()),
    }
}

#[test]
fn test_semantic_fingerprint() {
    let dedup = SemanticDeduplicator::new();

    let finding = make_finding(AttackType::Collision, "nullifier_collision");
    let fp = dedup.fingerprint(&finding);

    assert_eq!(fp.oracle_type, AttackType::Collision);
    assert_eq!(fp.location_category, "nullifier");
}

#[test]
fn test_deduplication() {
    let mut dedup = SemanticDeduplicator::new();

    let finding1 = make_finding(AttackType::Collision, "nullifier_collision");
    let finding2 = make_finding(AttackType::Collision, "nullifier_collision");
    let finding3 = make_finding(AttackType::Boundary, "merkle_path");

    assert!(dedup.add(finding1));
    assert!(!dedup.add(finding2)); // Duplicate
    assert!(dedup.add(finding3)); // Different

    assert_eq!(dedup.stats().unique_findings, 2);
    assert_eq!(dedup.stats().duplicates_filtered, 1);
}

#[test]
fn test_similarity() {
    let dedup = SemanticDeduplicator::new();

    let finding1 = make_finding(AttackType::Collision, "nullifier_collision");
    let finding2 = make_finding(AttackType::Collision, "nullifier_other");
    let finding3 = make_finding(AttackType::Boundary, "merkle_path");

    // Same oracle, same category
    let sim_1_2 = dedup.similarity(&finding1, &finding2);
    assert!(sim_1_2 > 0.6);

    // Different oracle, different category
    let sim_1_3 = dedup.similarity(&finding1, &finding3);
    assert!(sim_1_3 < 0.4);
}

#[test]
fn test_input_pattern() {
    assert_eq!(
        InputPattern::from_inputs(&[FieldElement::zero()]),
        InputPattern::AllZeros
    );

    assert_eq!(
        InputPattern::from_inputs(&[
            FieldElement::zero(),
            FieldElement::from_u64(42),
            FieldElement::zero()
        ]),
        InputPattern::SingleNonZero(1)
    );
}

#[test]
fn test_confidence_score() {
    let mut finding = make_finding(AttackType::Collision, "test");
    finding.severity = Severity::Critical;
    finding.poc.witness_b = Some(vec![FieldElement::from_u64(1)]);

    let confidence = calculate_confidence(&finding);
    assert!(confidence > 0.9);
}
