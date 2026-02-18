    use super::*;

    #[test]
    fn test_taint_analyzer_creation() {
        let mut analyzer = TaintAnalyzer::new(2, 3);
        analyzer.initialize_inputs();

        // Check public inputs are labeled
        assert!(analyzer.get_taint(0).unwrap().has_public_taint());
        assert!(analyzer.get_taint(1).unwrap().has_public_taint());

        // Check private inputs are labeled
        assert!(analyzer.get_taint(2).unwrap().has_private_taint());
        assert!(analyzer.get_taint(3).unwrap().has_private_taint());
        assert!(analyzer.get_taint(4).unwrap().has_private_taint());
    }

    #[test]
    fn test_taint_propagation() {
        let mut analyzer = TaintAnalyzer::new(1, 1);
        analyzer.initialize_inputs();

        // Propagate: signal_2 = signal_0 (public) * signal_1 (private)
        analyzer.propagate_constraint(0, &[0, 1], 2);

        let taint = analyzer.get_taint(2).unwrap();
        assert!(taint.has_public_taint());
        assert!(taint.has_private_taint());
    }

    #[test]
    fn test_mixed_flow_detection() {
        let mut analyzer = TaintAnalyzer::new(1, 1);
        analyzer.initialize_inputs();

        // Create mixed flow
        analyzer.propagate_constraint(0, &[0, 1], 2);
        analyzer.mark_as_output(2);

        let findings = analyzer.analyze();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].finding_type, TaintFindingType::MixedFlow);
    }
