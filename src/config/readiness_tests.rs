    use super::*;

    #[test]
    fn test_missing_circuit_path_is_critical() {
        let config = FuzzConfig::default_v2();
        let report = check_0day_readiness(&config);

        assert!(!report.ready_for_evidence);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.level == ReadinessLevel::Critical && w.category == "Target"));
    }

    #[test]
    fn test_low_iterations_warning() {
        let mut config = FuzzConfig::default_v2();
        config.campaign.parameters.additional.insert(
            "max_iterations".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(100)),
        );

        let report = check_0day_readiness(&config);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.category == "Fuzzing" && w.message.contains("too low")));
    }

    #[test]
    fn test_evidence_mode_without_validation() {
        let mut config = FuzzConfig::default_v2();
        config
            .campaign
            .parameters
            .additional
            .insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));
        config.campaign.parameters.additional.insert(
            "oracle_validation".to_string(),
            serde_yaml::Value::Bool(false),
        );

        let report = check_0day_readiness(&config);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.category == "Evidence" && w.level == ReadinessLevel::High));
    }
