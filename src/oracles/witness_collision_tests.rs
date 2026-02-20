use super::*;

#[test]
fn test_equivalence_differ_only_at() {
    let class = EquivalenceClass {
        name: "test".to_string(),
        predicate: EquivalencePredicate::DifferOnlyAt(vec![1]),
    };

    let a = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];
    let b = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(99), // Different at index 1
        FieldElement::from_u64(3),
    ];
    let c = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(99), // Different at index 2 (not allowed)
    ];

    assert!(class.are_equivalent(&a, &b));
    assert!(!class.are_equivalent(&a, &c));
}

#[test]
fn test_equivalence_permutation() {
    let class = EquivalenceClass {
        name: "permutation".to_string(),
        predicate: EquivalencePredicate::Permutation,
    };

    let a = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];
    let b = vec![
        FieldElement::from_u64(3),
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    ];
    let c = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(4),
    ];

    assert!(class.are_equivalent(&a, &b));
    assert!(!class.are_equivalent(&a, &c));
}

#[test]
fn test_collision_detection() {
    let detector = WitnessCollisionDetector::new().with_samples(1000);

    let collision = WitnessCollision {
        witness_a: vec![FieldElement::from_u64(1)],
        witness_b: vec![FieldElement::from_u64(2)],
        public_inputs: vec![],
        public_input_indices: vec![],
        output_hash: "abc123".to_string(),
        outputs: vec![FieldElement::from_u64(42)],
        is_expected: false,
    };

    let findings = detector.to_findings(&[collision]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].attack_type, AttackType::WitnessCollision);
}

#[test]
fn test_collision_analysis() {
    let detector = WitnessCollisionDetector::new();

    let collisions = vec![
        WitnessCollision {
            witness_a: vec![FieldElement::from_u64(1), FieldElement::from_u64(2)],
            witness_b: vec![FieldElement::from_u64(1), FieldElement::from_u64(3)],
            public_inputs: vec![],
            public_input_indices: vec![],
            output_hash: "hash1".to_string(),
            outputs: vec![],
            is_expected: false,
        },
        WitnessCollision {
            witness_a: vec![FieldElement::from_u64(1), FieldElement::from_u64(4)],
            witness_b: vec![FieldElement::from_u64(1), FieldElement::from_u64(5)],
            public_inputs: vec![],
            public_input_indices: vec![],
            output_hash: "hash2".to_string(),
            outputs: vec![],
            is_expected: false,
        },
    ];

    let analysis = detector.analyze_patterns(&collisions);

    assert_eq!(analysis.total_collisions, 2);
    let differing = match analysis.differing_indices.get(&1) {
        Some(value) => *value,
        None => 0,
    };
    assert_eq!(differing, 2);
}
