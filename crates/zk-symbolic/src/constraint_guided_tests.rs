    use super::*;

    #[test]
    fn test_assignments_to_inputs_wire_mapping() {
        let mut assignments = HashMap::new();
        assignments.insert("wire_5".to_string(), FieldElement::from_u64(42));

        let inputs = assignments_to_inputs(&assignments, &[5], 1);
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0], FieldElement::from_u64(42));
    }
