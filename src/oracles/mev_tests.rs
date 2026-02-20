use super::*;

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
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.description.contains("SANDWICH_ATTACK"));
}

#[test]
fn test_permutation() {
    let config = MevConfig {
        seed: Some(42),
        ..Default::default()
    };
    let mut attack = MevAttack::new(config);

    let inputs = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];

    let permuted = attack.permute_inputs(&inputs);
    assert_eq!(permuted.len(), inputs.len());
}

#[test]
fn test_output_difference() {
    let config = MevConfig::default();
    let attack = MevAttack::new(config);

    let a = vec![FieldElement::from_u64(100), FieldElement::from_u64(200)];
    let b = vec![FieldElement::from_u64(110), FieldElement::from_u64(210)];

    let diff = attack.output_difference(&a, &b);
    assert!(diff > 0.0);
    assert!(diff < 1.0);
}

#[test]
fn test_price_impact_analyzer() {
    let mut analyzer = PriceImpactAnalyzer::new(0.05); // 5% max slippage

    // Record trades with increasing price impact, eventually exceeding 5%
    for i in 0..15 {
        // Price impact grows quadratically: 0, 0.5%, 2%, 4.5%, 8%...
        analyzer.record(i as f64 * 100.0, 0.005 * (i as f64).powi(2));
    }

    let finding = analyzer.analyze();
    assert!(finding.is_some(), "Should detect price impact exceeding 5%");
}

#[test]
fn test_arbitrage_detector() {
    let mut detector = ArbitrageDetector::new();

    // Record prices from two circuits
    detector.record_price("dex_a", 100.0);
    detector.record_price("dex_a", 101.0);
    detector.record_price("dex_b", 110.0);
    detector.record_price("dex_b", 111.0);

    let findings = detector.detect_arbitrage(0.05); // 5% min profit
    assert!(!findings.is_empty());
}
