    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_boolean_mutation() {
        let mutator = StructureAwareMutator::new(Framework::Circom)
            .with_structures(vec![InputStructure::Boolean]);

        let mut rng = StdRng::seed_from_u64(42);
        let zero = FieldElement::zero();
        let result = mutator.mutate_structured(&zero, &InputStructure::Boolean, &mut rng);
        assert_eq!(result, FieldElement::one());
    }

    #[test]
    fn test_integer_mutation_stays_in_range() {
        let mutator = StructureAwareMutator::new(Framework::Circom);
        let mut rng = StdRng::seed_from_u64(42);

        for _ in 0..100 {
            let input = FieldElement::from_u64(100);
            let result = mutator.mutate_integer(&input, 8, &mut rng);
            let value = mutator.to_u64(&result);
            assert!(value <= 255, "8-bit value should be <= 255, got {}", value);
        }
    }

    #[test]
    fn test_circom_structure_inference() {
        let source = r#"
            signal input secret;
            signal input bits[8];
            signal input merkle_path[20];
            signal output nullifier;
        "#;

        let structures = StructureAwareMutator::infer_circom_structure(source);
        assert!(!structures.is_empty());
    }

    #[test]
    fn test_splice() {
        let mut rng = StdRng::seed_from_u64(42);
        let a = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
        let b = vec![FieldElement::from_u64(3), FieldElement::from_u64(4)];

        let result = Splicer::splice(&a, &b, &mut rng);
        assert_eq!(result.len(), 2);
    }
