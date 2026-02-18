    use super::*;
    use crate::executor::FixtureCircuitExecutor;

    #[test]
    fn test_complexity_analyzer() {
        let analyzer = ComplexityAnalyzer::new();
        let executor: Arc<dyn CircuitExecutor> =
            Arc::new(FixtureCircuitExecutor::new("test", 10, 2));

        let metrics = analyzer.analyze(&executor);

        assert!(metrics.signal_count > 0);
    }

    #[test]
    fn test_complexity_comparison() {
        let analyzer = ComplexityAnalyzer::new();

        let comparison = analyzer.compare_to_optimal("poseidon_per_hash", 350);
        assert!(comparison.is_some());

        let comp = comparison.unwrap();
        assert!(comp.overhead_percent > 0.0);
    }

    #[test]
    fn test_constraint_breakdown() {
        let mut breakdown = ConstraintBreakdown::new();
        breakdown.add_operation("mul", 100);
        breakdown.add_operation("add", 50);
        breakdown.add_operation("range_check", 200);
        breakdown.compute_hotspots(2);

        assert_eq!(breakdown.hotspots.len(), 2);
        assert_eq!(breakdown.hotspots[0].0, "range_check");
    }
