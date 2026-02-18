    use super::*;

    #[test]
    fn test_dof_analysis_underconstrained() {
        let detector = UnderconstrainedDetector::new(1000);
        let circuit_info = CircuitInfo {
            name: "test".to_string(),
            num_constraints: 5,
            num_private_inputs: 10,
            num_public_inputs: 2,
            num_outputs: 1,
        };

        let finding = detector.dof_analysis(&circuit_info);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().attack_type, AttackType::Underconstrained);
    }

    #[test]
    fn test_dof_analysis_properly_constrained() {
        let detector = UnderconstrainedDetector::new(1000);
        let circuit_info = CircuitInfo {
            name: "test".to_string(),
            num_constraints: 10,
            num_private_inputs: 5,
            num_public_inputs: 2,
            num_outputs: 1,
        };

        let finding = detector.dof_analysis(&circuit_info);
        assert!(finding.is_none());
    }
