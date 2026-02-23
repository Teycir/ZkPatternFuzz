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
        class: None,
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

#[test]
fn test_hash_deduplication_mode_filters_duplicates() {
    let mut dedup = SemanticDeduplicator::with_config(DeduplicationConfig {
        use_semantic: false,
        similarity_threshold: 0.8,
        max_findings: 100,
    });

    let finding1 = make_finding(AttackType::Collision, "nullifier_collision");
    let finding2 = make_finding(AttackType::Collision, "nullifier_collision");

    assert!(dedup.add(finding1));
    assert!(!dedup.add(finding2));
    assert_eq!(dedup.stats().unique_findings, 1);
    assert_eq!(dedup.stats().duplicates_filtered, 1);
}

#[test]
fn test_capacity_eviction_replaces_only_when_incoming_is_stronger() {
    let mut dedup = SemanticDeduplicator::with_config(DeduplicationConfig {
        use_semantic: true,
        similarity_threshold: 0.8,
        max_findings: 1,
    });

    let mut finding1 = make_finding(AttackType::Collision, "nullifier_collision");
    finding1.severity = Severity::Low;
    let mut finding2 = make_finding(AttackType::Boundary, "merkle_path");
    finding2.severity = Severity::Critical;

    assert!(dedup.add(finding1));
    assert!(dedup.add(finding2));
    assert_eq!(dedup.stats().duplicates_filtered, 0);
    assert_eq!(dedup.stats().dropped_capacity, 0);
    assert_eq!(dedup.stats().evicted_capacity, 1);
    let retained = dedup.unique_findings();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].severity, Severity::Critical);
}

#[test]
fn test_duplicate_at_capacity_counts_as_duplicate_not_capacity_drop() {
    let mut dedup = SemanticDeduplicator::with_config(DeduplicationConfig {
        use_semantic: true,
        similarity_threshold: 0.8,
        max_findings: 1,
    });

    let finding1 = make_finding(AttackType::Collision, "nullifier_collision");
    let finding2 = make_finding(AttackType::Collision, "nullifier_collision");

    assert!(dedup.add(finding1));
    assert!(!dedup.add(finding2));
    assert_eq!(dedup.stats().duplicates_filtered, 1);
    assert_eq!(dedup.stats().dropped_capacity, 0);
    assert_eq!(dedup.stats().evicted_capacity, 0);
}

#[test]
fn test_capacity_rejects_weaker_unique_finding_when_full() {
    let mut dedup = SemanticDeduplicator::with_config(DeduplicationConfig {
        use_semantic: true,
        similarity_threshold: 0.8,
        max_findings: 1,
    });

    let mut critical = make_finding(AttackType::Collision, "nullifier_collision");
    critical.severity = Severity::Critical;
    let mut low = make_finding(AttackType::Boundary, "merkle_path");
    low.severity = Severity::Low;

    assert!(dedup.add(critical));
    assert!(!dedup.add(low));
    assert_eq!(dedup.stats().duplicates_filtered, 0);
    assert_eq!(dedup.stats().dropped_capacity, 1);
    assert_eq!(dedup.stats().evicted_capacity, 0);
    let retained = dedup.unique_findings();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].severity, Severity::Critical);
}

#[test]
fn test_capacity_eviction_hash_mode_replaces_only_when_incoming_is_stronger() {
    let mut dedup = SemanticDeduplicator::with_config(DeduplicationConfig {
        use_semantic: false,
        similarity_threshold: 0.8,
        max_findings: 1,
    });

    let mut finding1 = make_finding(AttackType::Collision, "nullifier_collision");
    finding1.severity = Severity::Low;
    let mut finding2 = make_finding(AttackType::Boundary, "merkle_path");
    finding2.severity = Severity::Critical;

    assert!(dedup.add(finding1));
    assert!(dedup.add(finding2));
    assert_eq!(dedup.stats().duplicates_filtered, 0);
    assert_eq!(dedup.stats().dropped_capacity, 0);
    assert_eq!(dedup.stats().evicted_capacity, 1);
    let retained = dedup.unique_findings();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].severity, Severity::Critical);
}

#[test]
fn test_capacity_rejects_weaker_unique_finding_when_full_hash_mode() {
    let mut dedup = SemanticDeduplicator::with_config(DeduplicationConfig {
        use_semantic: false,
        similarity_threshold: 0.8,
        max_findings: 1,
    });

    let mut critical = make_finding(AttackType::Collision, "nullifier_collision");
    critical.severity = Severity::Critical;
    let mut low = make_finding(AttackType::Boundary, "merkle_path");
    low.severity = Severity::Low;

    assert!(dedup.add(critical));
    assert!(!dedup.add(low));
    assert_eq!(dedup.stats().duplicates_filtered, 0);
    assert_eq!(dedup.stats().dropped_capacity, 1);
    assert_eq!(dedup.stats().evicted_capacity, 0);
    let retained = dedup.unique_findings();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].severity, Severity::Critical);
}

#[test]
fn test_cluster_findings_is_deterministic_for_same_dataset() {
    let finding_a = make_finding(AttackType::Collision, "nullifier_collision_a");
    let finding_b = make_finding(AttackType::Collision, "nullifier_collision_b");
    let finding_c = make_finding(AttackType::Boundary, "merkle_path");

    let mut first = SemanticDeduplicator::new();
    assert!(first.add(finding_a.clone()));
    assert!(first.add(finding_b.clone()));
    assert!(first.add(finding_c.clone()));

    let mut second = SemanticDeduplicator::new();
    assert!(second.add(finding_b));
    assert!(second.add(finding_c));
    assert!(second.add(finding_a));

    let summarize = |clusters: Vec<FindingCluster>| -> Vec<(AttackType, usize)> {
        clusters
            .into_iter()
            .map(|cluster| (cluster.representative.attack_type, cluster.members.len()))
            .collect()
    };

    assert_eq!(
        summarize(first.cluster_findings()),
        summarize(second.cluster_findings())
    );
}
