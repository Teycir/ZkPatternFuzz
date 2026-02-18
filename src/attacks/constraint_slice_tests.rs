    use super::*;
    use zk_core::ExecutionCoverage;

    #[test]
    fn test_constraint_cone() {
        let cone = ConstraintCone {
            output_index: 0,
            output_wire: 0,
            constraints: vec![1, 2, 3],
            affecting_inputs: [0, 1, 2].into_iter().collect(),
            depth: 3,
        };

        assert!(cone.contains_input(0));
        assert!(cone.contains_input(1));
        assert!(!cone.contains_input(10));
        assert_eq!(cone.constraint_count(), 3);
    }

    #[test]
    fn test_leaking_constraint() {
        let leak = LeakingConstraint {
            constraint_id: 42,
            affected_outputs: vec![0, 1, 2],
            description: "Test leak".to_string(),
        };

        assert_eq!(leak.affected_outputs.len(), 3);
    }

    #[test]
    fn test_output_mapping_uses_output_index_not_wire() {
        let oracle = ConstraintSliceOracle::new();
        let cone = ConstraintCone {
            output_index: 0,
            output_wire: 50,
            constraints: vec![],
            affecting_inputs: HashSet::new(),
            depth: 0,
        };

        let base_result = ExecutionResult::success(
            vec![FieldElement::from_u64(1), FieldElement::from_u64(2)],
            ExecutionCoverage::default(),
        );
        let new_result = ExecutionResult::success(
            vec![FieldElement::from_u64(1), FieldElement::from_u64(3)],
            ExecutionCoverage::default(),
        );

        let base_witness = vec![FieldElement::zero()];
        let new_witness = vec![FieldElement::one()];

        let finding = oracle.check_unexpected_change(
            &cone,
            &base_result,
            &new_result,
            &base_witness,
            &new_witness,
        );

        assert!(
            finding.is_some(),
            "Expected output change detection to use output index, not wire index"
        );
    }
