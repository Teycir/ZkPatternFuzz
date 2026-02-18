    use super::*;

    #[test]
    fn test_binding_violation_detected() {
        let config = OracleConfig::default();
        let mut oracle = CommitmentOracle::new(config);

        // Different values
        let tc1 = TestCase {
            inputs: vec![FieldElement::from_u64(100), FieldElement::from_u64(1)],
            expected_output: None,
            metadata: Default::default(),
        };
        let tc2 = TestCase {
            inputs: vec![FieldElement::from_u64(200), FieldElement::from_u64(2)],
            expected_output: None,
            metadata: Default::default(),
        };

        // Same commitment output
        let output = vec![FieldElement::from_u64(999)];

        // First should pass
        assert!(oracle.check(&tc1, &output).is_none());

        // Second with different value but same commitment should fail
        let finding = oracle.check(&tc2, &output);
        assert!(finding.is_some());
        assert!(finding.unwrap().description.contains("BINDING"));
    }

    #[test]
    fn test_no_violation_different_commitments() {
        let config = OracleConfig::default();
        let mut oracle = CommitmentOracle::new(config);

        let tc1 = TestCase {
            inputs: vec![FieldElement::from_u64(100)],
            expected_output: None,
            metadata: Default::default(),
        };
        let tc2 = TestCase {
            inputs: vec![FieldElement::from_u64(200)],
            expected_output: None,
            metadata: Default::default(),
        };

        // Different commitments
        let output1 = vec![FieldElement::from_u64(111)];
        let output2 = vec![FieldElement::from_u64(222)];

        assert!(oracle.check(&tc1, &output1).is_none());
        assert!(oracle.check(&tc2, &output2).is_none());
    }
