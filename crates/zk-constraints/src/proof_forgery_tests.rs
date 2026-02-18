    use super::super::r1cs_parser::R1CSConstraint;
    use super::*;
    use num_bigint::BigUint;

    const BN254_MODULUS: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    #[test]
    fn test_proof_forgery_detector() {
        // Create underconstrained R1CS: a + b = 10
        let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();

        let constraint = R1CSConstraint {
            a: vec![(1, BigUint::from(1u32)), (2, BigUint::from(1u32))],
            b: vec![(0, BigUint::from(1u32))],
            c: vec![(0, BigUint::from(10u32))],
        };

        let r1cs = R1CS {
            field_size: modulus,
            field_bytes: 32,
            num_wires: 3,
            num_public_outputs: 0,
            num_public_inputs: 0,
            num_private_inputs: 2,
            num_labels: 0,
            constraints: vec![constraint],
            wire_names: vec!["one".to_string(), "a".to_string(), "b".to_string()],
            custom_gates_used: false,
        };

        let detector = ProofForgeryDetector::from_r1cs(r1cs, ".");

        // Original: a=4, b=6
        let witness = vec![
            FieldElement::one(),
            FieldElement::from_u64(4),
            FieldElement::from_u64(6),
        ];

        let result = detector.detect_with_witness(&witness);

        assert!(result.is_underconstrained, "Should detect underconstrained");
        assert!(result.alternative_private_inputs.is_some());

        // Verify alternative also sums to 10
        if let Some(alt) = &result.alternative_private_inputs {
            let a: u64 = alt[0].parse().unwrap();
            let b: u64 = alt[1].parse().unwrap();
            assert_eq!(a + b, 10);
        }
    }

    #[test]
    fn test_quick_check() {
        let modulus = BigUint::parse_bytes(BN254_MODULUS.as_bytes(), 10).unwrap();

        // Many signals, few constraints = likely underconstrained
        let r1cs = R1CS {
            field_size: modulus,
            field_bytes: 32,
            num_wires: 100,
            num_public_outputs: 1,
            num_public_inputs: 10,
            num_private_inputs: 88,
            num_labels: 0,
            constraints: vec![], // No constraints!
            wire_names: vec![],
            custom_gates_used: false,
        };

        assert!(quick_underconstrained_check(&r1cs));
    }
