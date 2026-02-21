use std::collections::HashMap;

use zk_core::{AttackType, FieldElement, Severity};
use zk_fuzzer::executor::FixtureCircuitExecutor;
use zk_fuzzer::oracles::{
    ArbitrageDetector, MevAttack, MevConfig, MevTestResult, MevVulnerabilityType,
    PriceImpactAnalyzer,
};

#[test]
fn test_mev_config_default() {
    let config = MevConfig::default();
    assert_eq!(config.ordering_permutations, 100);
    assert!(config.detect_ordering);
    assert!(config.detect_sandwich);
    assert!(config.detect_leakage);
}

#[test]
fn test_mev_vulnerability_types() {
    assert_eq!(
        MevVulnerabilityType::SandwichAttack.severity(),
        Severity::Critical
    );
    assert_eq!(
        MevVulnerabilityType::OrderingDependency.severity(),
        Severity::High
    );
    assert_eq!(MevVulnerabilityType::Arbitrage.severity(), Severity::Medium);
}

#[test]
fn test_mev_result_to_finding() {
    let result = MevTestResult {
        vulnerability_type: MevVulnerabilityType::SandwichAttack,
        description: "Test sandwich attack".to_string(),
        profit_potential: Some(0.05),
        witness: vec![FieldElement::from_u64(1)],
        context: HashMap::new(),
    };

    let finding = result.to_finding();
    assert_eq!(finding.attack_type, AttackType::Soundness);
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.description.contains("SANDWICH_ATTACK"));
}

#[test]
fn test_mev_run_is_seed_deterministic() {
    let config = MevConfig {
        seed: Some(42),
        ordering_permutations: 12,
        sandwich_attempts: 12,
        ..Default::default()
    };

    let mut attack_a = MevAttack::new(config.clone());
    let mut attack_b = MevAttack::new(config);
    let executor = FixtureCircuitExecutor::new("mev", 3, 1).with_outputs(2);
    let inputs = vec![
        FieldElement::from_u64(10),
        FieldElement::from_u64(20),
        FieldElement::from_u64(30),
        FieldElement::from_u64(40),
    ];

    let findings_a = attack_a
        .run(&executor, &inputs)
        .expect("MEV run should succeed");
    let findings_b = attack_b
        .run(&executor, &inputs)
        .expect("MEV run should succeed");

    assert_eq!(findings_a.len(), findings_b.len());
}

#[test]
fn test_price_impact_analyzer() {
    let mut analyzer = PriceImpactAnalyzer::new(0.05);

    for i in 0..15 {
        analyzer.record(i as f64 * 100.0, 0.005 * (i as f64).powi(2));
    }

    let finding = analyzer.analyze();
    assert!(finding.is_some(), "Should detect price impact exceeding 5%");
}

#[test]
fn test_arbitrage_detector() {
    let mut detector = ArbitrageDetector::new();

    detector.record_price("dex_a", 100.0);
    detector.record_price("dex_a", 101.0);
    detector.record_price("dex_b", 110.0);
    detector.record_price("dex_b", 111.0);

    let findings = detector.detect_arbitrage(0.05);
    assert!(!findings.is_empty());
}
