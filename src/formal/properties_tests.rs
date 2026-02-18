    use super::*;

    #[test]
    fn test_property_extractor_creation() {
        let extractor = PropertyExtractor::new();
        assert!(extractor.boolean_signals.is_empty());
    }

    #[test]
    fn test_circuit_property_variables() {
        let prop = CircuitProperty::Boolean {
            signal: "x".to_string(),
        };
        let vars = prop.variables();
        assert!(vars.contains("x"));
    }

    #[test]
    fn test_dependency_graph() {
        let mut graph = DependencyGraph::new();
        graph.add_constraint(0, vec![1, 2, 3]);
        graph.add_constraint(1, vec![2, 4]);

        assert_eq!(graph.get_constraint_signals(0), Some(&vec![1, 2, 3]));
        assert!(graph.get_signal_constraints(2).unwrap().contains(&0));
        assert!(graph.get_signal_constraints(2).unwrap().contains(&1));
    }
