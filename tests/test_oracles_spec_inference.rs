use rand::SeedableRng;
use zk_core::FieldElement;
use zk_fuzzer::executor::FixtureCircuitExecutor;
use zk_fuzzer::oracles::{ExecutionSample, InferredSpec, SpecInferenceOracle};

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

#[tokio::test]
async fn test_collect_samples_respects_sample_count() {
    let oracle = SpecInferenceOracle::new()
        .with_sample_count(5)
        .with_confidence_threshold(0.85);
    let executor = FixtureCircuitExecutor::new("spec", 2, 1).with_outputs(1);

    let samples = oracle
        .collect_samples(&executor, |_rng| {
            vec![
                FieldElement::from_u64(1),
                FieldElement::from_u64(2),
                FieldElement::from_u64(3),
            ]
        })
        .await;

    assert_eq!(samples.len(), 5);
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
fn test_infer_specs_includes_range_checks() {
    let oracle = SpecInferenceOracle::new();

    let samples: Vec<ExecutionSample> = (0..100)
        .map(|i| ExecutionSample {
            inputs: vec![FieldElement::from_u64(i % 256)],
            outputs: vec![FieldElement::from_u64(i)],
        })
        .collect();

    let specs = oracle.infer_specs(&samples);
    let inferred_bits = specs.iter().find_map(|spec| {
        if let InferredSpec::RangeCheck { inferred_bits, .. } = spec {
            Some(*inferred_bits)
        } else {
            None
        }
    });

    assert!(inferred_bits.is_some());
    assert!(inferred_bits.unwrap_or(usize::MAX) <= 8);
}

#[test]
fn test_confidence_threshold_filters_specs() {
    let strict_oracle = SpecInferenceOracle::new().with_confidence_threshold(1.1);

    let samples: Vec<ExecutionSample> = (0..100)
        .map(|i| ExecutionSample {
            inputs: vec![FieldElement::from_u64(i % 256)],
            outputs: vec![FieldElement::from_u64(i)],
        })
        .collect();

    let specs = strict_oracle.infer_specs(&samples);
    assert!(specs.is_empty());
}

#[test]
fn test_infer_specs_keeps_constant_output_specs() {
    let oracle = SpecInferenceOracle::new();
    let samples: Vec<ExecutionSample> = (0..100)
        .map(|i| ExecutionSample {
            inputs: vec![FieldElement::from_u64(i), FieldElement::from_u64(i + 1)],
            outputs: vec![FieldElement::one()],
        })
        .collect();

    let specs = oracle.infer_specs(&samples);
    let has_output_constant = specs.iter().any(|spec| {
        matches!(
            spec,
            InferredSpec::ConstantValue {
                wire_index,
                value,
                ..
            } if *wire_index == 2 && *value == FieldElement::one()
        )
    });

    assert!(has_output_constant);
}

#[test]
fn test_constant_output_violation_generates_input_mutation() {
    let oracle = SpecInferenceOracle::new().with_violation_attempts(32);
    let spec = InferredSpec::ConstantValue {
        wire_index: 5,
        value: FieldElement::one(),
        confidence: 1.0,
    };
    let base = vec![FieldElement::zero(); 2];
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let violations = oracle.generate_violations(&spec, &base, &mut rng);

    assert!(!violations.is_empty());
    assert!(violations
        .iter()
        .all(|candidate| candidate.len() == base.len() && candidate != &base));
}
