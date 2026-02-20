use super::*;

#[test]
fn test_validation_result_creation() {
    let valid = ValidationResult::valid(vec!["test".to_string()]);
    assert!(valid.is_valid);
    assert_eq!(valid.confidence, 1.0);

    let invalid = ValidationResult::invalid(vec!["test".to_string()]);
    assert!(!invalid.is_valid);
    assert_eq!(invalid.confidence, 0.0);

    let partial = ValidationResult::partial(0.7, vec!["test".to_string()]);
    assert!(partial.is_valid);
    assert_eq!(partial.confidence, 0.7);
}

#[test]
fn test_ground_truth_result_metrics() {
    let result = GroundTruthValidationResult {
        oracle_name: "test".to_string(),
        true_positives: 8,
        false_positives: 2,
        true_negatives: 85,
        false_negatives: 5,
        total_cases: 100,
    };

    // Precision = 8 / (8 + 2) = 0.8
    assert!((result.precision() - 0.8).abs() < 0.01);

    // Recall = 8 / (8 + 5) = 0.615
    assert!((result.recall() - 0.615).abs() < 0.01);

    // F1 = 2 * (0.8 * 0.615) / (0.8 + 0.615) ≈ 0.696
    assert!((result.f1_score() - 0.696).abs() < 0.01);
}

#[test]
fn test_oracle_validator_stats() {
    let validator = OracleValidator::new();
    let stats = validator.stats();

    assert_eq!(stats.total_validated, 0);
    assert_eq!(stats.estimated_false_positive_rate(), 0.0);
}
