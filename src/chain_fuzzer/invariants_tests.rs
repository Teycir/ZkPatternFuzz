    use super::*;
    use crate::chain_fuzzer::types::StepTrace;

    fn create_test_trace() -> ChainTrace {
        let mut trace = ChainTrace::new("test_chain");

        // Step 0: outputs [42, 100]
        trace.add_step(StepTrace::success(
            0,
            "circuit_a",
            vec![FieldElement::one()],
            vec![FieldElement::from_u64(42), FieldElement::from_u64(100)],
        ));

        // Step 1: inputs include 42 (wired from step 0)
        trace.add_step(StepTrace::success(
            1,
            "circuit_b",
            vec![FieldElement::from_u64(42), FieldElement::from_u64(200)],
            vec![FieldElement::from_u64(42)], // Duplicate of step 0 out[0]
        ));

        trace
    }

    #[test]
    fn test_uniqueness_violation() {
        let trace = create_test_trace();

        let assertions = vec![CrossStepAssertion::unique("no_duplicate_outputs", 0)];

        let checker = CrossStepInvariantChecker::new(assertions);
        let violations = checker.check(&trace);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].assertion_name, "no_duplicate_outputs");
    }

    #[test]
    fn test_equality_check() {
        let trace = create_test_trace();

        // This should pass: step[0].out[0] == step[1].in[0] (both are 42)
        let assertions = vec![CrossStepAssertion::equal("wiring_correct", 0, 0, 1, 0)];

        let checker = CrossStepInvariantChecker::new(assertions);
        let violations = checker.check(&trace);

        assert!(violations.is_empty());
    }

    #[test]
    fn test_equality_violation() {
        let trace = create_test_trace();

        // This should fail: step[0].out[1] != step[1].in[0] (100 != 42)
        let assertions = vec![CrossStepAssertion::equal("bad_wiring", 0, 1, 1, 0)];

        let checker = CrossStepInvariantChecker::new(assertions);
        let violations = checker.check(&trace);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].assertion_name, "bad_wiring");
    }
