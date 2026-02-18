    use super::*;

    #[test]
    fn test_range_near_miss() {
        let detector = NearMissDetector::new().with_range_constraint(RangeConstraint {
            wire_index: 0,
            min_value: None,
            max_value: None,
            bit_length: Some(8),
        });

        // Value close to max (255)
        let witness = vec![FieldElement::from_u64(250)];
        let near_misses = detector.detect(&witness);

        assert!(!near_misses.is_empty());
        assert!(near_misses[0].distance < 0.1);
    }

    #[test]
    fn test_collision_near_miss() {
        let detector = NearMissDetector::new().with_config(NearMissConfig {
            collision_threshold: 0.9,
            ..Default::default()
        });

        // Two hashes that differ by only a few bits
        let hash_a = vec![0xFF; 32];
        let mut hash_b = vec![0xFF; 32];
        hash_b[0] = 0xFE; // One bit different

        let near_miss = detector.check_collision_near_miss(&hash_a, &hash_b);
        assert!(near_miss.is_some());
    }

    #[test]
    fn test_near_miss_suggestion() {
        let nm = NearMiss {
            miss_type: NearMissType::AlmostOutOfRange {
                value: FieldElement::from_u64(250),
                boundary: FieldElement::from_u64(255),
                is_upper: true,
            },
            distance: 0.02,
            location: Some(0),
            value: Some(FieldElement::from_u64(250)),
            suggestion: Some("Try 256 or higher".to_string()),
        };

        assert!(nm.is_close());
        assert!(nm.suggestion.is_some());
    }

    #[test]
    fn test_range_near_miss_detects_min_boundary_proximity() {
        let detector = NearMissDetector::new()
            .with_config(NearMissConfig {
                range_threshold: 0.2,
                ..Default::default()
            })
            .with_range_constraint(RangeConstraint {
                wire_index: 0,
                min_value: Some(FieldElement::from_u64(10)),
                max_value: None,
                bit_length: None,
            });

        let witness = vec![FieldElement::from_u64(11)];
        let near_misses = detector.detect(&witness);
        assert_eq!(near_misses.len(), 1);
        match &near_misses[0].miss_type {
            NearMissType::AlmostOutOfRange { is_upper, .. } => assert!(!is_upper),
            _ => panic!("expected AlmostOutOfRange"),
        }
    }

    #[test]
    fn test_range_near_miss_uses_arithmetic_distance_not_bit_hamming() {
        let detector = NearMissDetector::new().with_range_constraint(RangeConstraint {
            wire_index: 0,
            min_value: Some(FieldElement::from_u64(9)),
            max_value: None,
            bit_length: None,
        });

        // Arithmetic distance is 1/9 ~= 0.111 > default 0.05 threshold, so no near miss.
        // This guards against accidental reintroduction of bit-level Hamming distance.
        let witness = vec![FieldElement::from_u64(8)];
        let near_misses = detector.detect(&witness);
        assert!(near_misses.is_empty());
    }
