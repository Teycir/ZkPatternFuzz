use std::collections::HashMap;

use zk_core::{FieldElement, Severity};
use zk_fuzzer::oracles::{
    FrontRunningConfig, FrontRunningResult, FrontRunningVulnerability, StateLeakageAnalyzer,
};

#[test]
fn test_front_running_config_default() {
    let config = FrontRunningConfig::default();
    assert_eq!(config.leakage_tests, 100);
    assert!(config.detect_leakage);
    assert!(config.detect_commitment_bypass);
}

#[test]
fn test_vulnerability_types() {
    assert_eq!(
        FrontRunningVulnerability::CommitmentBypass.severity(),
        Severity::Critical
    );
    assert_eq!(
        FrontRunningVulnerability::InformationLeakage.severity(),
        Severity::High
    );
    assert_eq!(
        FrontRunningVulnerability::DelayAttack.severity(),
        Severity::Medium
    );
}

#[test]
fn test_result_to_finding() {
    let result = FrontRunningResult {
        vulnerability_type: FrontRunningVulnerability::InformationLeakage,
        description: "Test leakage".to_string(),
        witness: vec![FieldElement::from_u64(1)],
        context: HashMap::new(),
        measured_entropy: Some(1.5),
    };

    let finding = result.to_finding();
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.description.contains("INFORMATION_LEAKAGE"));
}

#[test]
fn test_state_leakage_analyzer() {
    let mut analyzer = StateLeakageAnalyzer::new(10);

    for i in 0..20 {
        let private = vec![FieldElement::from_u64(i)];
        let output = vec![FieldElement::from_u64(i % 3)];
        analyzer.observe(private, output);
    }

    let finding = analyzer.analyze();
    assert!(finding.is_some());
}
