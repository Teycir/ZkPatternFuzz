use zk_core::{AttackType, Finding, ProofOfConcept, Severity};
use zk_fuzzer::config::suggester::YamlSuggester;
use zk_fuzzer::fuzzer::{SuggestionType, YamlSuggestion};
use zk_fuzzer::reporting::FuzzReport;

const BASIC_CAMPAIGN_YAML: &str = r#"
campaign:
  name: "Test"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "./test.circom"
    main_component: "Main"

inputs:
  - name: "x"
    type: "field"
    interesting: ["0", "1"]

attacks:
  - type: "underconstrained"
    description: "Test"
"#;

#[test]
fn test_suggester_creation() {
    let suggester = YamlSuggester::new();
    let rendered = suggester
        .apply_suggestions(BASIC_CAMPAIGN_YAML, &[])
        .expect("rendering suggestions should succeed");
    assert!(rendered.contains("campaign:"));
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
                class: None,
            },
            Finding {
                attack_type: AttackType::Underconstrained,
                severity: Severity::Critical,
                description: "Test 2".to_string(),
                poc: ProofOfConcept::default(),
                location: None,
                class: None,
            },
            Finding {
                attack_type: AttackType::Underconstrained,
                severity: Severity::Critical,
                description: "Test 3".to_string(),
                poc: ProofOfConcept::default(),
                location: None,
                class: None,
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
