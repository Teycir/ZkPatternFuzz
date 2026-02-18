    use super::*;
    use crate::executor::FixtureCircuitExecutor;
    use zk_core::ExecutionCoverage;

    #[test]
    fn test_differential_fuzzer_creation() {
        let config = DifferentialConfig::default();
        let fuzzer = DifferentialFuzzer::new(config);
        assert!(fuzzer.executors.is_empty());
    }

    #[test]
    fn test_differential_comparison() {
        let config = DifferentialConfig {
            backends: vec![Framework::Circom, Framework::Circom],
            num_tests: 10,
            ..Default::default()
        };
        let mut fuzzer = DifferentialFuzzer::new(config);

        // Add identical executors - should agree on everything
        let exec1 = Arc::new(FixtureCircuitExecutor::new("test", 2, 1));
        let exec2 = Arc::new(FixtureCircuitExecutor::new("test", 2, 1));

        fuzzer.add_executor(Framework::Circom, exec1);
        fuzzer.add_executor(Framework::Circom, exec2);

        let inputs = vec![FieldElement::zero(), FieldElement::one()];
        let result = fuzzer.compare_backends(&inputs);

        // Same executor configuration should produce same outputs
        assert!(result.is_none() || result.unwrap().disagreeing_backends.is_empty());
    }

    #[test]
    fn test_coverage_stats_overlap() {
        let a = vec![1, 2, 3, 4];
        let b = vec![3, 4, 5, 6];
        let (jaccard, abs_delta, rel_delta) = coverage_stats(&a, &b);
        assert!((jaccard - 0.3333).abs() < 0.01);
        assert_eq!(abs_delta, 0);
        assert!((rel_delta - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_coverage_mismatch_detects_one_empty_side() {
        let config = DifferentialConfig {
            coverage_min_constraints: 1,
            ..Default::default()
        };
        let fuzzer = DifferentialFuzzer::new(config);
        let with_coverage = ExecutionResult {
            outputs: vec![],
            coverage: ExecutionCoverage::with_constraints(vec![1, 2], vec![1, 2]),
            execution_time_us: 0,
            success: true,
            error: None,
        };
        let empty_coverage = ExecutionResult {
            outputs: vec![],
            coverage: ExecutionCoverage::default(),
            execution_time_us: 0,
            success: true,
            error: None,
        };

        assert!(fuzzer.coverage_mismatch(&with_coverage, &empty_coverage));
        assert!(!fuzzer.coverage_mismatch(&empty_coverage, &empty_coverage));
    }

    #[test]
    fn test_timing_variation_uses_fast_side_as_baseline() {
        let config = DifferentialConfig {
            timing_tolerance_percent: 200.0,
            timing_min_us: 0,
            timing_abs_threshold_us: 1,
            ..Default::default()
        };
        let fuzzer = DifferentialFuzzer::new(config);
        let fast = ExecutionResult {
            outputs: vec![],
            coverage: ExecutionCoverage::default(),
            execution_time_us: 100,
            success: true,
            error: None,
        };
        let slow = ExecutionResult {
            outputs: vec![],
            coverage: ExecutionCoverage::default(),
            execution_time_us: 10_000,
            success: true,
            error: None,
        };

        assert!(fuzzer.timing_variation(&fast, &slow));
    }
