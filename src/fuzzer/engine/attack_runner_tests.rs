    use super::deterministic_attack_cap;

    #[test]
    fn deterministic_cap_enabled_by_default_in_evidence_mode() {
        let mut additional = crate::config::AdditionalConfig::default();
        additional.insert(
            "fuzzing_iterations".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(20)),
        );

        let (cap, iterations, multiplier) =
            deterministic_attack_cap(&additional, true, 1, "underconstrained_witness_pairs_cap")
                .expect("cap should be enabled");
        assert_eq!(iterations, 20);
        assert_eq!(multiplier, 4);
        assert_eq!(cap, 80);
    }

    #[test]
    fn deterministic_cap_can_be_disabled_explicitly() {
        let mut additional = crate::config::AdditionalConfig::default();
        additional.insert(
            "evidence_deterministic_runtime".to_string(),
            serde_yaml::Value::Bool(false),
        );
        additional.insert(
            "fuzzing_iterations".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(20)),
        );

        let cap =
            deterministic_attack_cap(&additional, true, 1, "underconstrained_witness_pairs_cap");
        assert!(cap.is_none());
    }

    #[test]
    fn per_attack_cap_overrides_global_cap() {
        let mut additional = crate::config::AdditionalConfig::default();
        additional.insert(
            "fuzzing_iterations".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(20)),
        );
        additional.insert(
            "underconstrained_witness_pairs_cap".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(33)),
        );

        let (cap, _, _) =
            deterministic_attack_cap(&additional, true, 1, "underconstrained_witness_pairs_cap")
                .expect("cap should be enabled");
        assert_eq!(cap, 33);
    }
