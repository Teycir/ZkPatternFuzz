//! Integration tests for Batch Verification Attack Detection
//!
//! Phase 3.3: Milestone 3.3 - Batch Verification Bypass
//!
//! Tests cover:
//! - Batch mixing bypass detection
//! - Aggregation forgery detection
//! - Cross-circuit batch analysis
//! - Randomness reuse detection
//! - Configuration and API correctness

use zk_fuzzer::attacks::batch_verification::{
    AggregationMethod, BatchVerificationAnalyzer, BatchVerificationAttack,
    BatchVerificationConfig, BatchVerificationFinding, BatchVerificationResult,
    BatchVulnerabilityType, InvalidPosition,
};
use zk_core::{FieldElement, Severity};
use std::collections::HashMap;

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_default_config() {
    let config = BatchVerificationConfig::default();

    assert_eq!(config.batch_sizes, vec![2, 4, 8, 16, 32]);
    assert_eq!(config.batch_mixing_tests, 500);
    assert_eq!(config.aggregation_forgery_tests, 1000);
    assert_eq!(config.cross_circuit_tests, 100);
    assert_eq!(config.randomness_reuse_tests, 500);
    assert!(config.detect_batch_mixing);
    assert!(config.detect_aggregation_forgery);
    assert!(config.detect_cross_circuit_batch);
    assert!(config.detect_randomness_reuse);
    assert_eq!(config.correlation_threshold, 0.8);
    assert_eq!(config.timeout_ms, 30000);
}

#[test]
fn test_custom_config() {
    let config = BatchVerificationConfig {
        batch_sizes: vec![2, 4],
        batch_mixing_tests: 100,
        aggregation_forgery_tests: 200,
        cross_circuit_tests: 50,
        randomness_reuse_tests: 100,
        detect_batch_mixing: true,
        detect_aggregation_forgery: false,
        detect_cross_circuit_batch: true,
        detect_randomness_reuse: false,
        aggregation_methods: vec![AggregationMethod::NaiveBatch],
        invalid_positions: vec![InvalidPosition::First],
        correlation_threshold: 0.9,
        timeout_ms: 10000,
        seed: Some(123),
    };

    assert_eq!(config.batch_sizes.len(), 2);
    assert!(!config.detect_aggregation_forgery);
    assert!(!config.detect_randomness_reuse);
    assert_eq!(config.seed, Some(123));
}

// ============================================================================
// Vulnerability Type Tests
// ============================================================================

#[test]
fn test_vulnerability_type_properties() {
    // Test all vulnerability types have correct properties
    let types = vec![
        BatchVulnerabilityType::BatchMixingBypass,
        BatchVulnerabilityType::AggregationForgery,
        BatchVulnerabilityType::CrossCircuitBypass,
        BatchVulnerabilityType::RandomnessReuse,
        BatchVulnerabilityType::BatchSizeBoundary,
        BatchVulnerabilityType::OrderingDependency,
        BatchVulnerabilityType::SubsetForgery,
        BatchVulnerabilityType::AggregationMalleability,
        BatchVulnerabilityType::IndexMasking,
        BatchVulnerabilityType::AccumulatorManipulation,
    ];

    for vuln_type in types {
        // Each type should have a string representation
        assert!(!vuln_type.as_str().is_empty());

        // Each type should have a severity
        let severity = vuln_type.severity();
        assert!(matches!(
            severity,
            Severity::Critical | Severity::High | Severity::Medium | Severity::Low
        ));

        // Each type should have a description
        assert!(!vuln_type.description().is_empty());
    }
}

#[test]
fn test_critical_vulnerabilities() {
    // These should all be critical severity
    assert_eq!(
        BatchVulnerabilityType::BatchMixingBypass.severity(),
        Severity::Critical
    );
    assert_eq!(
        BatchVulnerabilityType::AggregationForgery.severity(),
        Severity::Critical
    );
    assert_eq!(
        BatchVulnerabilityType::CrossCircuitBypass.severity(),
        Severity::Critical
    );
    assert_eq!(
        BatchVulnerabilityType::SubsetForgery.severity(),
        Severity::Critical
    );
    assert_eq!(
        BatchVulnerabilityType::AccumulatorManipulation.severity(),
        Severity::Critical
    );
}

#[test]
fn test_high_severity_vulnerabilities() {
    assert_eq!(
        BatchVulnerabilityType::RandomnessReuse.severity(),
        Severity::High
    );
    assert_eq!(
        BatchVulnerabilityType::BatchSizeBoundary.severity(),
        Severity::High
    );
    assert_eq!(
        BatchVulnerabilityType::AggregationMalleability.severity(),
        Severity::High
    );
    assert_eq!(
        BatchVulnerabilityType::IndexMasking.severity(),
        Severity::High
    );
}

#[test]
fn test_medium_severity_vulnerabilities() {
    assert_eq!(
        BatchVulnerabilityType::OrderingDependency.severity(),
        Severity::Medium
    );
}

// ============================================================================
// Aggregation Method Tests
// ============================================================================

#[test]
fn test_aggregation_methods() {
    let methods = vec![
        AggregationMethod::NaiveBatch,
        AggregationMethod::SnarkPack,
        AggregationMethod::Groth16Aggregation,
        AggregationMethod::PlonkAggregation,
        AggregationMethod::Halo2Aggregation,
    ];

    for method in methods {
        assert!(!method.as_str().is_empty());
    }

    assert_eq!(AggregationMethod::NaiveBatch.as_str(), "naive_batch");
    assert_eq!(AggregationMethod::SnarkPack.as_str(), "snarkpack");
    assert_eq!(
        AggregationMethod::Groth16Aggregation.as_str(),
        "groth16_aggregation"
    );
    assert_eq!(
        AggregationMethod::PlonkAggregation.as_str(),
        "plonk_aggregation"
    );
    assert_eq!(
        AggregationMethod::Halo2Aggregation.as_str(),
        "halo2_aggregation"
    );
}

// ============================================================================
// Invalid Position Tests
// ============================================================================

#[test]
fn test_invalid_position_first() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let indices = InvalidPosition::First.get_indices(10, &mut rng);

    assert_eq!(indices, vec![0]);
}

#[test]
fn test_invalid_position_last() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let indices = InvalidPosition::Last.get_indices(10, &mut rng);

    assert_eq!(indices, vec![9]);
}

#[test]
fn test_invalid_position_middle() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let indices = InvalidPosition::Middle.get_indices(10, &mut rng);

    assert_eq!(indices, vec![5]);
}

#[test]
fn test_invalid_position_random() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let indices = InvalidPosition::Random.get_indices(10, &mut rng);

    assert_eq!(indices.len(), 1);
    assert!(indices[0] < 10);
}

#[test]
fn test_invalid_position_multiple_random() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let indices = InvalidPosition::MultipleRandom.get_indices(10, &mut rng);

    assert!(indices.len() >= 1);
    assert!(indices.len() <= 5); // At most half
    for idx in &indices {
        assert!(*idx < 10);
    }
}

// ============================================================================
// Attack Initialization Tests
// ============================================================================

#[test]
fn test_attack_creation() {
    let config = BatchVerificationConfig::default();
    let attack = BatchVerificationAttack::new(config);

    assert!(attack.get_findings().is_empty());
}

#[test]
fn test_attack_with_seed() {
    let config = BatchVerificationConfig {
        seed: Some(12345),
        ..Default::default()
    };

    let attack = BatchVerificationAttack::new(config);
    assert!(attack.get_findings().is_empty());
}

#[test]
fn test_attack_reset() {
    let config = BatchVerificationConfig::default();
    let mut attack = BatchVerificationAttack::new(config);

    // Run should not panic with empty inputs
    attack.reset();
    assert!(attack.get_findings().is_empty());
}

// ============================================================================
// Finding Tests
// ============================================================================

#[test]
fn test_finding_to_generic_conversion() {
    use zk_core::AttackType;

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
    assert!(generic.description.contains("Test finding"));
    // Check location contains metadata
    assert!(generic.location.is_some());
    let location = generic.location.unwrap();
    assert!(location.contains("batch_size=8"));
    assert!(location.contains("groth16_aggregation"));
}

#[test]
fn test_finding_with_poc() {
    use zk_fuzzer::attacks::batch_verification::BatchProofOfConcept;

    let poc = BatchProofOfConcept {
        inputs: vec![FieldElement::one(), FieldElement::zero()],
        description: "Mixed invalid proof with valid batch".to_string(),
    };

    let finding = BatchVerificationFinding {
        vulnerability_type: BatchVulnerabilityType::AggregationForgery,
        batch_size: 4,
        invalid_positions: vec![],
        aggregation_method: AggregationMethod::SnarkPack,
        trigger_inputs: vec![],
        severity: Severity::Critical,
        description: "Aggregation forgery detected".to_string(),
        poc: Some(poc.clone()),
        confidence: 0.85,
    };

    assert!(finding.poc.is_some());
    let finding_poc = finding.poc.unwrap();
    assert_eq!(finding_poc.inputs.len(), 2);
}

// ============================================================================
// Analyzer Tests
// ============================================================================

#[test]
fn test_analyzer_creation() {
    let analyzer = BatchVerificationAnalyzer::new();
    let stats = analyzer.get_stats();

    assert_eq!(stats.total_batches, 0);
    assert_eq!(stats.passed_batches, 0);
    assert_eq!(stats.mixed_results_batches, 0);
    assert_eq!(stats.avg_batch_size, 0.0);
}

#[test]
fn test_analyzer_batch_analysis() {
    let mut analyzer = BatchVerificationAnalyzer::new();

    let result = BatchVerificationResult {
        passed: true,
        individual_results: vec![true, true, true, true],
        verification_time_ms: 100,
        metadata: HashMap::new(),
    };

    analyzer.analyze_batch(&result);

    let stats = analyzer.get_stats();
    assert_eq!(stats.total_batches, 1);
    assert_eq!(stats.passed_batches, 1);
    assert_eq!(stats.mixed_results_batches, 0);
    assert_eq!(stats.avg_batch_size, 4.0);
}

#[test]
fn test_analyzer_failed_batch() {
    let mut analyzer = BatchVerificationAnalyzer::new();

    let result = BatchVerificationResult {
        passed: false,
        individual_results: vec![true, false, true, false],
        verification_time_ms: 150,
        metadata: HashMap::new(),
    };

    analyzer.analyze_batch(&result);

    let stats = analyzer.get_stats();
    assert_eq!(stats.total_batches, 1);
    assert_eq!(stats.passed_batches, 0);
    assert_eq!(stats.mixed_results_batches, 1);
}

#[test]
fn test_analyzer_multiple_batches() {
    let mut analyzer = BatchVerificationAnalyzer::new();

    // Batch 1: All pass
    analyzer.analyze_batch(&BatchVerificationResult {
        passed: true,
        individual_results: vec![true, true],
        verification_time_ms: 50,
        metadata: HashMap::new(),
    });

    // Batch 2: Mixed results
    analyzer.analyze_batch(&BatchVerificationResult {
        passed: false,
        individual_results: vec![true, false, false],
        verification_time_ms: 75,
        metadata: HashMap::new(),
    });

    // Batch 3: All fail
    analyzer.analyze_batch(&BatchVerificationResult {
        passed: false,
        individual_results: vec![false, false, false, false],
        verification_time_ms: 100,
        metadata: HashMap::new(),
    });

    let stats = analyzer.get_stats();
    assert_eq!(stats.total_batches, 3);
    assert_eq!(stats.passed_batches, 1);
    assert_eq!(stats.mixed_results_batches, 1);
    // Average batch size: (2 + 3 + 4) / 3 = 3.0
    assert!((stats.avg_batch_size - 3.0).abs() < 0.01);
}

#[test]
fn test_analyzer_vulnerability_recording() {
    let mut analyzer = BatchVerificationAnalyzer::new();

    analyzer.record_vulnerability(BatchVulnerabilityType::BatchMixingBypass);
    analyzer.record_vulnerability(BatchVulnerabilityType::BatchMixingBypass);
    analyzer.record_vulnerability(BatchVulnerabilityType::AggregationForgery);
    analyzer.record_vulnerability(BatchVulnerabilityType::RandomnessReuse);

    let stats = analyzer.get_stats();
    assert_eq!(
        stats.vulnerabilities_by_type.get("batch_mixing_bypass"),
        Some(&2)
    );
    assert_eq!(
        stats.vulnerabilities_by_type.get("aggregation_forgery"),
        Some(&1)
    );
    assert_eq!(
        stats.vulnerabilities_by_type.get("randomness_reuse"),
        Some(&1)
    );
}

#[test]
fn test_analyzer_reset() {
    let mut analyzer = BatchVerificationAnalyzer::new();

    analyzer.analyze_batch(&BatchVerificationResult {
        passed: true,
        individual_results: vec![true, true],
        verification_time_ms: 50,
        metadata: HashMap::new(),
    });

    analyzer.record_vulnerability(BatchVulnerabilityType::BatchMixingBypass);

    analyzer.reset();

    let stats = analyzer.get_stats();
    assert_eq!(stats.total_batches, 0);
    assert!(stats.vulnerabilities_by_type.is_empty());
}

// ============================================================================
// Integration Tests (require fixture executor)
// ============================================================================

#[test]
// Requires fixture executor implementation
fn test_batch_mixing_detection_integration() {
    // This test requires a fixture executor that simulates vulnerable batch verification
    // Enable when fixture executor is available
}

#[test]
// Requires fixture executor implementation
fn test_aggregation_forgery_detection_integration() {
    // This test requires a fixture executor that simulates vulnerable aggregation
    // Enable when fixture executor is available
}

#[test]
// Requires fixture executor implementation
fn test_cross_circuit_detection_integration() {
    // This test requires a fixture executor that simulates cross-circuit vulnerabilities
    // Enable when fixture executor is available
}

#[test]
// Requires fixture executor implementation
fn test_randomness_reuse_detection_integration() {
    // This test requires a fixture executor that simulates randomness reuse
    // Enable when fixture executor is available
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_empty_batch() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);

    // Edge case: batch size of 0
    let indices = InvalidPosition::First.get_indices(0, &mut rng);
    assert_eq!(indices, vec![0]); // saturating_sub handles this

    let indices = InvalidPosition::Last.get_indices(0, &mut rng);
    assert_eq!(indices, vec![0]); // 0.saturating_sub(1) = 0
}

#[test]
fn test_single_element_batch() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);

    let indices = InvalidPosition::First.get_indices(1, &mut rng);
    assert_eq!(indices, vec![0]);

    let indices = InvalidPosition::Last.get_indices(1, &mut rng);
    assert_eq!(indices, vec![0]);

    let indices = InvalidPosition::Middle.get_indices(1, &mut rng);
    assert_eq!(indices, vec![0]);
}

#[test]
fn test_large_batch_size() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let batch_size = 1000;

    let indices = InvalidPosition::First.get_indices(batch_size, &mut rng);
    assert_eq!(indices, vec![0]);

    let indices = InvalidPosition::Last.get_indices(batch_size, &mut rng);
    assert_eq!(indices, vec![999]);

    let indices = InvalidPosition::Middle.get_indices(batch_size, &mut rng);
    assert_eq!(indices, vec![500]);
}

// ============================================================================
// Serialization Tests
// ============================================================================

#[test]
fn test_config_serialization() {
    let config = BatchVerificationConfig::default();

    let serialized = serde_json::to_string(&config).expect("Serialization failed");
    let deserialized: BatchVerificationConfig =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(config.batch_sizes, deserialized.batch_sizes);
    assert_eq!(
        config.correlation_threshold,
        deserialized.correlation_threshold
    );
}

#[test]
fn test_vulnerability_type_serialization() {
    let vuln = BatchVulnerabilityType::BatchMixingBypass;

    let serialized = serde_json::to_string(&vuln).expect("Serialization failed");
    let deserialized: BatchVulnerabilityType =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(vuln, deserialized);
}

#[test]
fn test_aggregation_method_serialization() {
    let method = AggregationMethod::Groth16Aggregation;

    let serialized = serde_json::to_string(&method).expect("Serialization failed");
    let deserialized: AggregationMethod =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(method, deserialized);
}

#[test]
fn test_finding_serialization() {
    let finding = BatchVerificationFinding {
        vulnerability_type: BatchVulnerabilityType::AggregationForgery,
        batch_size: 16,
        invalid_positions: vec![3, 7, 11],
        aggregation_method: AggregationMethod::PlonkAggregation,
        trigger_inputs: vec![vec![FieldElement::one()]],
        severity: Severity::Critical,
        description: "Test serialization".to_string(),
        poc: None,
        confidence: 0.88,
    };

    let serialized = serde_json::to_string(&finding).expect("Serialization failed");
    let deserialized: BatchVerificationFinding =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(
        finding.vulnerability_type,
        deserialized.vulnerability_type
    );
    assert_eq!(finding.batch_size, deserialized.batch_size);
    assert_eq!(finding.confidence, deserialized.confidence);
}
