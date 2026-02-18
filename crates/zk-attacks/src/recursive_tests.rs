    use super::*;

    fn sample_field_element(val: u64) -> FieldElement {
        FieldElement::from_u64(val)
    }

    #[test]
    fn test_recursive_attack_config_default() {
        let config = RecursiveAttackConfig::default();

        assert_eq!(config.max_recursion_depth, 10);
        assert!(config.detect_base_case_bypass);
        assert!(config.detect_accumulator_overflow);
        assert!(config.detect_vk_substitution);
        assert!(config.detect_folding_attacks);
        assert_eq!(config.recursive_systems.len(), 5);
    }

    #[test]
    fn test_recursive_system_properties() {
        assert!(RecursiveSystem::Nova.uses_folding());
        assert!(RecursiveSystem::Supernova.uses_folding());
        assert!(!RecursiveSystem::Halo2Recursive.uses_folding());
        assert!(RecursiveSystem::Halo2Recursive.uses_accumulation());
        assert!(RecursiveSystem::ProtoStar.uses_accumulation());
    }

    #[test]
    fn test_vulnerability_severities() {
        assert_eq!(
            RecursiveVulnerabilityType::BaseCaseBypass.severity(),
            Severity::Critical
        );
        assert_eq!(
            RecursiveVulnerabilityType::FoldingMismatch.severity(),
            Severity::High
        );
        assert_eq!(
            RecursiveVulnerabilityType::AccumulatorOverflow.severity(),
            Severity::Medium
        );
        assert_eq!(
            RecursiveVulnerabilityType::CrossCircuitRecursion.severity(),
            Severity::Low
        );
    }

    #[test]
    fn test_accumulator_state_folding() {
        let acc = AccumulatorState::new_base_case(3);
        assert_eq!(acc.counter, 0);
        assert_eq!(acc.running_acc.len(), 3);

        let new_instance = vec![
            sample_field_element(1),
            sample_field_element(2),
            sample_field_element(3),
        ];
        let r = sample_field_element(5);

        let folded = acc.fold_with(&new_instance, &r);
        assert_eq!(folded.counter, 1);
    }

    #[test]
    fn test_nova_analyzer_relaxed_r1cs() {
        let config = RecursiveAttackConfig::default();
        let analyzer = NovaAnalyzer::new(config);

        let instance = vec![sample_field_element(1)];
        let witness = vec![sample_field_element(2)];

        // Non-zero error term indicates vulnerability
        let non_zero_error = sample_field_element(1);
        assert!(analyzer.check_relaxed_r1cs_vulnerability(&instance, &witness, &non_zero_error));

        // Zero error term is valid
        let zero_error = FieldElement::zero();
        assert!(!analyzer.check_relaxed_r1cs_vulnerability(&instance, &witness, &zero_error));
    }

    #[test]
    fn test_supernova_analyzer_opcode() {
        let config = RecursiveAttackConfig::default();
        let analyzer = SupernovaAnalyzer::new(config);

        let valid_opcodes = vec![0, 1, 2, 3];

        assert!(!analyzer.check_opcode_selection_vulnerability(0, &valid_opcodes));
        assert!(!analyzer.check_opcode_selection_vulnerability(3, &valid_opcodes));
        assert!(analyzer.check_opcode_selection_vulnerability(4, &valid_opcodes));
        assert!(analyzer.check_opcode_selection_vulnerability(100, &valid_opcodes));
    }

    #[test]
    fn test_halo2_accumulation_analyzer() {
        let config = RecursiveAttackConfig::default();
        let analyzer = Halo2AccumulationAnalyzer::new(config);

        // All-zero commitment is invalid
        let zero_commitment = vec![0u8; 32];
        let expected_opening = vec![sample_field_element(1)];
        assert!(analyzer.check_commitment_binding(&zero_commitment, &expected_opening));

        // Non-zero commitment is valid
        let valid_commitment = vec![1u8; 32];
        assert!(!analyzer.check_commitment_binding(&valid_commitment, &expected_opening));
    }

    #[test]
    fn test_recursive_step_creation() {
        let inputs = vec![sample_field_element(1), sample_field_element(2)];

        let step = RecursiveStep {
            step_index: 0,
            public_inputs: inputs.clone(),
            witness: inputs.clone(),
            accumulator: Some(AccumulatorState::new_base_case(2)),
            is_base_case: true,
            vk_hash: [0u8; 32],
        };

        assert!(step.is_base_case);
        assert_eq!(step.step_index, 0);
        assert_eq!(step.public_inputs.len(), 2);
    }

    #[test]
    fn test_vulnerability_type_strings() {
        assert_eq!(
            RecursiveVulnerabilityType::BaseCaseBypass.as_str(),
            "base_case_bypass"
        );
        assert_eq!(
            RecursiveVulnerabilityType::FoldingMismatch.as_str(),
            "folding_mismatch"
        );
        assert!(!RecursiveVulnerabilityType::BaseCaseBypass
            .description()
            .is_empty());
    }

    #[test]
    fn test_recursive_attack_creation() {
        let config = RecursiveAttackConfig::default();
        let attack = RecursiveAttack::new(config);

        assert!(attack.findings.is_empty());
        assert!(attack.tested_patterns.is_empty());
    }
