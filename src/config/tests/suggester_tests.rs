    use super::*;
    use crate::config::test_config::BASIC_CAMPAIGN_YAML;
    use zk_core::{AttackType, Finding, ProofOfConcept, Severity};

    #[test]
    fn test_suggester_creation() {
        let suggester = YamlSuggester::new();
        assert!(suggester.include_comments);
    }

    #[test]
    fn test_suggestions_from_findings() {
        let suggester = YamlSuggester::new();

        let report = FuzzReport {
            campaign_name: "test".to_string(),
            timestamp: chrono::Utc::now(),
            duration_seconds: 100,
            findings: vec![
                Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: "Test 1".to_string(),
                    poc: ProofOfConcept::default(),
                    location: None,
                },
                Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: "Test 2".to_string(),
                    poc: ProofOfConcept::default(),
                    location: None,
                },
                Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: "Test 3".to_string(),
                    poc: ProofOfConcept::default(),
                    location: None,
                },
            ],
            statistics: Default::default(),
            config: Default::default(),
        };

        let suggestions = suggester.generate_suggestions(&report, None);

        // Should suggest increasing budget for Underconstrained
        assert!(suggestions
            .iter()
            .any(|s| s.key.contains("Underconstrained")
                && matches!(s.suggestion_type, SuggestionType::IncreaseBudget)));
    }

    #[test]
    fn test_apply_suggestions() {
        let suggester = YamlSuggester::new();

        let suggestions = vec![YamlSuggestion {
            suggestion_type: SuggestionType::AddInterestingValue,
            key: "interesting".to_string(),
            value: "0xdeadbeef".to_string(),
            reason: "Near-miss detected".to_string(),
        }];

        let result = suggester
            .apply_suggestions(BASIC_CAMPAIGN_YAML, &suggestions)
            .unwrap();

        assert!(result.contains("SUGGESTIONS"));
        assert!(result.contains("Near-miss detected"));
    }
