    use super::*;

    #[test]
    fn test_zkevm_config_default() {
        let config = ZkEvmConfig::default();
        assert_eq!(config.state_transition_tests, 500);
        assert!(config.detect_state_transition);
        assert!(config.detect_opcode_boundary);
    }

    #[test]
    fn test_vulnerability_types() {
        assert_eq!(
            ZkEvmVulnerabilityType::StateTransitionMismatch.severity(),
            Severity::Critical
        );
        assert_eq!(
            ZkEvmVulnerabilityType::OpcodeBoundaryViolation.severity(),
            Severity::High
        );
        assert_eq!(
            ZkEvmVulnerabilityType::StorageProofBypass.severity(),
            Severity::Critical
        );
    }

    #[test]
    fn test_opcode_list() {
        assert!(EVM_OPCODES.len() >= 30);

        // Check specific opcodes exist
        assert!(EVM_OPCODES.iter().any(|op| op.name == "ADD"));
        assert!(EVM_OPCODES.iter().any(|op| op.name == "CALL"));
        assert!(EVM_OPCODES.iter().any(|op| op.name == "CREATE2"));
    }

    #[test]
    fn test_state_transition_inputs() {
        let test = StateTransitionTest::EmptyTransaction;
        let inputs = test.to_inputs();
        assert_eq!(inputs.len(), 4);
        assert!(inputs.iter().all(|i| i.is_zero()));
    }

    #[test]
    fn test_opcode_boundary_inputs() {
        let case = OpcodeBoundaryCase::MaxU256Values(3);
        let inputs = case.to_inputs();
        assert_eq!(inputs.len(), 3);
        assert!(inputs.iter().all(|i| *i == FieldElement::max_value()));
    }

    #[test]
    fn test_zkevm_attack_creation() {
        let config = ZkEvmConfig::default();
        let attack = ZkEvmAttack::new(config);
        assert!(attack.findings().is_empty());
    }

    #[test]
    fn test_vulnerability_to_finding() {
        let result = ZkEvmTestResult {
            vulnerability_type: ZkEvmVulnerabilityType::OpcodeBoundaryViolation,
            description: "Test finding".to_string(),
            opcode: Some("DIV".to_string()),
            witness: vec![FieldElement::zero()],
            expected_behavior: "Expected".to_string(),
            actual_behavior: "Actual".to_string(),
            context: HashMap::new(),
        };

        let finding = result.to_finding();
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.description.contains("opcode_boundary"));
        assert_eq!(finding.location, Some("opcode:DIV".to_string()));
    }

    #[test]
    fn test_memory_expansion_cases() {
        let test = MemoryExpansionTest::LargeOffset(1 << 24);
        let inputs = test.to_inputs();
        assert_eq!(inputs[0], FieldElement::from_u64(0x52)); // MSTORE
    }

    #[test]
    fn test_price_impact_analyzer() {
        let analyzer = ZkEvmPriceAnalyzer::new(0.05);
        assert_eq!(analyzer.tolerance, 0.05);
    }

    #[test]
    fn test_call_vulnerability_detector() {
        let detector = ZkEvmCallDetector::new(10);
        assert_eq!(detector.max_depth, 10);
    }
