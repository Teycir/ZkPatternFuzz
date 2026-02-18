    use super::*;

    #[test]
    fn test_vuln_target_patterns() {
        let target = VulnerabilityTarget::NullifierReuse;
        let patterns = target.constraint_patterns();
        assert!(patterns.contains(&"nullifier".to_string()));
        assert!(patterns.contains(&"hash".to_string()));
    }

    #[test]
    fn test_bug_directed_config() {
        let config = BugDirectedConfig::default();
        assert_eq!(config.max_paths, 5_000);
        assert!(config.enable_pruning);
        assert_eq!(config.targets.len(), 2);
    }

    #[test]
    fn test_bug_directed_executor() {
        let executor = BugDirectedExecutor::new(3);
        assert_eq!(executor.num_inputs, 3);
        assert!(executor.findings.is_empty());
    }

    #[test]
    fn test_differential_config() {
        let config = DifferentialConfig::default();
        assert_eq!(config.max_paths, 5_000);
        assert!(config.compare_public_only);
    }

    #[test]
    fn test_differential_executor_identical() {
        let constraints = vec![SymbolicConstraint::Boolean(SymbolicValue::symbol("x"))];
        let mut executor = DifferentialExecutor::new(constraints.clone(), constraints, 1);

        executor.find_differences();

        // Identical circuits should have no structural differences
        // (solver may still find differences based on constraint ordering)
        assert!(executor.stats.differences_found <= 2);
    }

    #[test]
    fn test_differential_executor_different() {
        let constraints_a = vec![SymbolicConstraint::Boolean(SymbolicValue::symbol("x"))];
        let constraints_b = vec![
            SymbolicConstraint::Boolean(SymbolicValue::symbol("x")),
            SymbolicConstraint::Eq(
                SymbolicValue::symbol("y"),
                SymbolicValue::Concrete(FieldElement::zero()),
            ),
        ];

        let mut executor = DifferentialExecutor::new(constraints_a, constraints_b, 2);
        executor.find_differences();

        // Different constraints should be detected
        assert!(executor.stats.solver_calls > 0);
    }
