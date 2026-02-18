
use super::*;
use rand::SeedableRng;

#[test]
fn test_inferred_spec_confidence() {
    let spec = InferredSpec::RangeCheck {
        input_index: 0,
        observed_min: 0,
        observed_max: 255,
        inferred_bits: 8,
        confidence: 0.95,
    };

    assert!((spec.confidence() - 0.95).abs() < 0.001);
}

#[test]
fn test_oracle_creation() {
    let oracle = SpecInferenceOracle::new()
        .with_sample_count(1000)
        .with_confidence_threshold(0.85);

    assert_eq!(oracle.sample_count, 1000);
    assert!((oracle.confidence_threshold - 0.85).abs() < 0.001);
}

#[test]
fn test_nonzero_violations_are_deduplicated() {
    let oracle = SpecInferenceOracle::new().with_violation_attempts(100);
    let spec = InferredSpec::NonZero {
        wire_index: 0,
        confidence: 0.99,
    };
    let base = vec![FieldElement::from_u64(7)];
    let mut rng = rand::rngs::StdRng::seed_from_u64(123);
    let violations = oracle.generate_violations(&spec, &base, &mut rng);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0][0], FieldElement::zero());
}

#[test]
fn test_infer_range_checks() {
    let oracle = SpecInferenceOracle::new();

    let samples: Vec<ExecutionSample> = (0..100)
        .map(|i| ExecutionSample {
            inputs: vec![FieldElement::from_u64(i % 256)],
            outputs: vec![FieldElement::from_u64(i)],
        })
        .collect();

    let specs = oracle.infer_range_checks(&samples, 1);

    assert!(!specs.is_empty());
    if let InferredSpec::RangeCheck { inferred_bits, .. } = &specs[0] {
        assert!(*inferred_bits <= 8);
    }
}

#[test]
fn test_constant_output_violation_is_not_actionable() {
    let oracle = SpecInferenceOracle::new();
    let spec = InferredSpec::ConstantValue {
        wire_index: 5,
        value: FieldElement::one(),
        confidence: 1.0,
    };
    let base = vec![FieldElement::zero(); 2];
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let violations = oracle.generate_violations(&spec, &base, &mut rng);
    assert!(violations.is_empty());
}
