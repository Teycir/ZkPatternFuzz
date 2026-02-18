    use super::*;

    #[test]
    fn test_parse_equals_invariant() {
        let ast = parse_invariant_relation("root == merkle(leaf, path)").unwrap();
        match ast {
            InvariantAST::Equals(left, right) => {
                assert!(matches!(*left, InvariantAST::Identifier(_)));
                assert!(matches!(*right, InvariantAST::Call(_, _)));
            }
            _ => panic!("Expected Equals"),
        }
    }

    #[test]
    fn test_parse_less_than_invariant() {
        let ast = parse_invariant_relation("output < 2^64").unwrap();
        match ast {
            InvariantAST::LessThan(left, right) => {
                assert!(matches!(*left, InvariantAST::Identifier(_)));
                assert!(matches!(*right, InvariantAST::Power(_, _)));
            }
            _ => panic!("Expected LessThan"),
        }
    }

    #[test]
    fn test_parse_forall_invariant() {
        let ast = parse_invariant_relation("∀i: path[i] ∈ {0,1}").unwrap();
        match ast {
            InvariantAST::ForAll { expr, .. } => {
                assert!(matches!(*expr, InvariantAST::InSet(_, _)));
            }
            _ => panic!("Expected ForAll"),
        }
    }

    #[test]
    fn test_parse_range_chain() {
        let ast = parse_invariant_relation("0 <= value < 2^64").unwrap();
        match ast {
            InvariantAST::Range { .. } => {}
            _ => panic!("Expected Range"),
        }
    }

    #[test]
    fn test_parse_in_set() {
        let ast = parse_invariant_relation("pathIndices[i] ∈ {0,1}").unwrap();
        match ast {
            InvariantAST::InSet(left, right) => {
                assert!(matches!(*left, InvariantAST::ArrayAccess(_, _)));
                assert!(matches!(*right, InvariantAST::Set(_)));
            }
            _ => panic!("Expected InSet"),
        }
    }

    #[test]
    fn test_invariant_type_serialization() {
        let invariant = Invariant {
            name: "test".to_string(),
            invariant_type: InvariantType::Metamorphic,
            relation: "x == y".to_string(),
            oracle: InvariantOracle::MustHold,
            transform: Some("permute".to_string()),
            expected: Some("unchanged".to_string()),
            description: None,
            severity: Some("critical".to_string()),
        };

        let yaml = serde_yaml::to_string(&invariant).unwrap();
        assert!(yaml.contains("metamorphic"));
    }

    #[test]
    fn test_schedule_phase_serialization() {
        let phase = SchedulePhase {
            phase: "seed".to_string(),
            duration_sec: 60,
            attacks: vec!["underconstrained".to_string()],
            max_iterations: Some(1000),
            early_terminate: Some(EarlyTerminateCondition {
                on_critical_findings: Some(1),
                on_coverage_percent: None,
                on_stale_seconds: None,
            }),
            carry_corpus: true,
            mutation_weights: HashMap::new(),
        };

        let yaml = serde_yaml::to_string(&phase).unwrap();
        let parsed: SchedulePhase = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.phase, "seed");
        assert_eq!(parsed.duration_sec, 60);
    }
