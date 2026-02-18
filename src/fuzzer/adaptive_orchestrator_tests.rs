    use super::*;
    use std::collections::HashMap;
    use zk_core::ProofOfConcept;

    #[test]
    fn test_orchestrator_creation() {
        let orchestrator = AdaptiveOrchestrator::new();
        assert!(orchestrator.start_time.is_none());
    }

    #[test]
    fn test_builder() {
        let orchestrator = AdaptiveOrchestratorBuilder::new()
            .workers(4)
            .max_duration(Duration::from_secs(600))
            .zero_day_hunt_mode(true)
            .build();

        assert_eq!(orchestrator.config.workers, 4);
        assert_eq!(orchestrator.config.max_duration, Duration::from_secs(600));
        assert!(orchestrator.config.zero_day_hunt_mode);
    }

    #[test]
    fn test_config_defaults() {
        let config = AdaptiveOrchestratorConfig::default();
        assert!(config.adaptive_budget);
        assert!(config.zero_day_hunt_mode);
        assert!(config.workers >= 1);
    }

    #[test]
    fn test_build_attack_phase_plan_prefers_higher_budget() {
        let attacks = vec![
            crate::config::Attack {
                attack_type: AttackType::Underconstrained,
                description: "under".to_string(),
                plugin: None,
                config: serde_yaml::Value::Null,
            },
            crate::config::Attack {
                attack_type: AttackType::Soundness,
                description: "sound".to_string(),
                plugin: None,
                config: serde_yaml::Value::Null,
            },
        ];
        let mut allocations = HashMap::new();
        allocations.insert(AttackType::Underconstrained, Duration::from_secs(2));
        allocations.insert(AttackType::Soundness, Duration::from_secs(9));

        let plan = AdaptiveOrchestrator::build_attack_phase_plan(&attacks, &allocations);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].0.attack_type, AttackType::Soundness);
        assert_eq!(plan[1].0.attack_type, AttackType::Underconstrained);
    }

    #[test]
    fn test_with_phase_timeout_sets_budget_key() {
        let base = crate::config::FuzzConfig {
            campaign: crate::config::Campaign {
                name: "test".to_string(),
                version: "1.0".to_string(),
                target: crate::config::Target {
                    framework: zk_core::Framework::Circom,
                    circuit_path: std::path::PathBuf::from("dummy.circom"),
                    main_component: "Main".to_string(),
                },
                parameters: crate::config::Parameters::default(),
            },
            attacks: vec![],
            inputs: vec![],
            mutations: vec![],
            oracles: vec![],
            reporting: crate::config::ReportingConfig::default(),
            chains: vec![],
        };

        let updated = AdaptiveOrchestrator::with_phase_timeout(base, Duration::from_secs(7));
        let timeout = updated
            .campaign
            .parameters
            .additional
            .get("fuzzing_timeout_seconds")
            .and_then(|v| v.as_u64());
        assert_eq!(timeout, Some(7));
    }

    #[test]
    fn test_zero_day_confirmation_requires_content_signal() {
        let orchestrator = AdaptiveOrchestrator::new();
        let hints = vec![ZeroDayHint {
            category: ZeroDayCategory::MissingConstraint,
            confidence: 0.8,
            description: "assignment without constraint on signal balance".to_string(),
            locations: vec![44],
            mutation_focus: Some("assigned_but_unconstrained".to_string()),
        }];
        let findings = vec![Finding {
            attack_type: AttackType::Underconstrained,
            severity: Severity::Low,
            description: "Generic anomaly in witness ordering".to_string(),
            poc: ProofOfConcept::default(),
            location: None,
        }];

        let confirmed = orchestrator.check_confirmed_zero_days(&hints, &findings, "test");
        assert!(confirmed.is_empty());
    }

    #[test]
    fn test_zero_day_confirmation_is_one_to_one_per_finding() {
        let orchestrator = AdaptiveOrchestrator::new();
        let hints = vec![
            ZeroDayHint {
                category: ZeroDayCategory::MissingConstraint,
                confidence: 0.8,
                description: "wire alpha appears unconstrained".to_string(),
                locations: vec![],
                mutation_focus: None,
            },
            ZeroDayHint {
                category: ZeroDayCategory::MissingConstraint,
                confidence: 0.8,
                description: "wire beta appears unconstrained".to_string(),
                locations: vec![],
                mutation_focus: None,
            },
        ];
        let findings = vec![Finding {
            attack_type: AttackType::Underconstrained,
            severity: Severity::High,
            description: "Unused private input wire alpha (index 5) in circuit".to_string(),
            poc: ProofOfConcept::default(),
            location: Some("constraint 11".to_string()),
        }];

        let confirmed = orchestrator.check_confirmed_zero_days(&hints, &findings, "test");
        assert_eq!(confirmed.len(), 1);
        assert!(confirmed[0].hint.description.contains("alpha"));
    }

    #[test]
    fn test_zero_day_confirmation_uses_location_overlap() {
        let orchestrator = AdaptiveOrchestrator::new();
        let hints = vec![ZeroDayHint {
            category: ZeroDayCategory::ArithmeticOverflow,
            confidence: 0.7,
            description: "possible overflow in multiplication path".to_string(),
            locations: vec![128],
            mutation_focus: None,
        }];
        let findings = vec![Finding {
            attack_type: AttackType::ArithmeticOverflow,
            severity: Severity::High,
            description: "Range enforcement bypass with large field value".to_string(),
            poc: ProofOfConcept::default(),
            location: Some("src/circuit.circom:128".to_string()),
        }];

        let confirmed = orchestrator.check_confirmed_zero_days(&hints, &findings, "test");
        assert_eq!(confirmed.len(), 1);
    }
