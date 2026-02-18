use super::*;

#[test]
fn test_batch_vulnerability_types() {
    assert_eq!(
        BatchVulnerabilityType::BatchMixingBypass.as_str(),
        "batch_mixing_bypass"
    );
    assert_eq!(
        BatchVulnerabilityType::AggregationForgery.severity(),
        Severity::Critical
    );
}

#[test]
fn test_aggregation_methods() {
    assert_eq!(AggregationMethod::NaiveBatch.as_str(), "naive_batch");
    assert_eq!(AggregationMethod::SnarkPack.as_str(), "snarkpack");
    assert_eq!(
        AggregationMethod::Groth16Aggregation.as_str(),
        "groth16_aggregation"
    );
}

#[test]
fn test_invalid_position_indices() {
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    assert_eq!(InvalidPosition::First.get_indices(10, &mut rng), vec![0]);
    assert_eq!(InvalidPosition::Last.get_indices(10, &mut rng), vec![9]);
    assert_eq!(InvalidPosition::Middle.get_indices(10, &mut rng), vec![5]);

    let random_indices = InvalidPosition::Random.get_indices(10, &mut rng);
    assert_eq!(random_indices.len(), 1);
    assert!(random_indices[0] < 10);
}

#[test]
fn test_config_defaults() {
    let config = BatchVerificationConfig::default();
    assert_eq!(config.batch_sizes, vec![2, 4, 8, 16, 32]);
    assert!(config.detect_batch_mixing);
    assert!(config.detect_aggregation_forgery);
    assert_eq!(config.correlation_threshold, 0.8);
}

#[test]
fn test_finding_to_generic() {
    let finding = BatchVerificationFinding {
        vulnerability_type: BatchVulnerabilityType::BatchMixingBypass,
        batch_size: 8,
        invalid_positions: vec![0, 4],
        aggregation_method: AggregationMethod::Groth16Aggregation,
        trigger_inputs: vec![vec![FieldElement::one()]],
        severity: Severity::Critical,
        description: "Test finding".to_string(),
        poc: None,
        confidence: 0.95,
    };

    let generic = finding.to_finding();
    assert_eq!(generic.attack_type, AttackType::BatchVerification);
    assert_eq!(generic.severity, Severity::Critical);
}

#[test]
fn test_batch_analyzer_stats() {
    let mut analyzer = BatchVerificationAnalyzer::new();

    let result = BatchVerificationResult {
        passed: true,
        individual_results: vec![true, true, true],
        verification_time_ms: 100,
        metadata: HashMap::new(),
    };

    analyzer.analyze_batch(&result);

    let stats = analyzer.get_stats();
    assert_eq!(stats.total_batches, 1);
    assert_eq!(stats.passed_batches, 1);
    assert_eq!(stats.mixed_results_batches, 0);
    assert_eq!(stats.avg_batch_size, 3.0);
}

#[test]
fn test_batch_analyzer_mixed_results() {
    let mut analyzer = BatchVerificationAnalyzer::new();

    let result = BatchVerificationResult {
        passed: false,
        individual_results: vec![true, false, true, false],
        verification_time_ms: 150,
        metadata: HashMap::new(),
    };

    analyzer.analyze_batch(&result);

    let stats = analyzer.get_stats();
    assert_eq!(stats.mixed_results_batches, 1);
}

#[test]
fn test_vulnerability_recording() {
    let mut analyzer = BatchVerificationAnalyzer::new();

    analyzer.record_vulnerability(BatchVulnerabilityType::BatchMixingBypass);
    analyzer.record_vulnerability(BatchVulnerabilityType::BatchMixingBypass);
    analyzer.record_vulnerability(BatchVulnerabilityType::AggregationForgery);

    let stats = analyzer.get_stats();
    assert_eq!(
        stats.vulnerabilities_by_type.get("batch_mixing_bypass"),
        Some(&2)
    );
    assert_eq!(
        stats.vulnerabilities_by_type.get("aggregation_forgery"),
        Some(&1)
    );
}

#[test]
fn test_correlation_computation() {
    let attack = BatchVerificationAttack::new(BatchVerificationConfig::default());

    // Identical arrays should have correlation 1.0
    let a = vec![FieldElement::one(), FieldElement::zero()];
    let b = a.clone();
    assert_eq!(attack.compute_correlation(&a, &b), Some(1.0));

    // Empty arrays
    let empty: Vec<FieldElement> = vec![];
    assert_eq!(attack.compute_correlation(&empty, &a), None);
}

#[test]
fn test_invalid_input_generation() {
    let mut attack = BatchVerificationAttack::new(BatchVerificationConfig::default());

    let base = vec![vec![FieldElement::one(), FieldElement::from_u64(42)]];
    let invalid = attack.generate_invalid_inputs(&base);

    // Should produce some output
    assert!(!invalid.is_empty());
}
