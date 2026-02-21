use async_trait::async_trait;
use std::sync::Arc;
use zk_core::{CircuitExecutor, CircuitInfo, ExecutionCoverage, ExecutionResult, FieldElement, Framework};
use zk_fuzzer::differential::{DifferentialConfig, DifferentialFuzzer, DifferentialSeverity};

#[derive(Clone)]
struct FixedExecutor {
    framework: Framework,
    result: ExecutionResult,
}

impl FixedExecutor {
    fn new(framework: Framework, result: ExecutionResult) -> Self {
        Self { framework, result }
    }
}

#[async_trait]
impl CircuitExecutor for FixedExecutor {
    fn framework(&self) -> Framework {
        self.framework
    }

    fn name(&self) -> &str {
        "fixed"
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: "fixed".to_string(),
            num_constraints: self.result.coverage.evaluated_constraints.len(),
            num_private_inputs: 1,
            num_public_inputs: 1,
            num_outputs: self.result.outputs.len(),
        }
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        self.result.clone()
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![1, 2, 3])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }
}

fn success_result(
    outputs: Vec<FieldElement>,
    satisfied: Vec<usize>,
    evaluated: Vec<usize>,
    execution_time_us: u64,
) -> ExecutionResult {
    ExecutionResult::success(outputs, ExecutionCoverage::with_constraints(satisfied, evaluated))
        .with_time(execution_time_us)
}

#[test]
fn test_differential_fuzzer_creation() {
    let fuzzer = DifferentialFuzzer::new(DifferentialConfig::default());
    assert_eq!(fuzzer.stats().total_tests, 0);
    assert!(fuzzer.findings().is_empty());
}

#[test]
fn test_differential_comparison_agrees_for_identical_results() {
    let mut fuzzer = DifferentialFuzzer::new(DifferentialConfig {
        compare_coverage: true,
        compare_timing: false,
        ..Default::default()
    });
    let expected = success_result(
        vec![FieldElement::one()],
        vec![1, 2, 3],
        vec![1, 2, 3],
        10,
    );

    fuzzer.add_executor(
        Framework::Circom,
        Arc::new(FixedExecutor::new(Framework::Circom, expected.clone())),
    );
    fuzzer.add_executor(
        Framework::Noir,
        Arc::new(FixedExecutor::new(Framework::Noir, expected)),
    );

    let inputs = vec![FieldElement::zero(), FieldElement::one()];
    let result = fuzzer.compare_backends(&inputs);
    assert!(result.is_none());
}

#[test]
fn test_coverage_mismatch_detects_one_empty_side() {
    let mut fuzzer = DifferentialFuzzer::new(DifferentialConfig {
        coverage_min_constraints: 1,
        compare_coverage: true,
        compare_timing: false,
        ..Default::default()
    });

    let with_coverage = success_result(vec![FieldElement::one()], vec![1, 2], vec![1, 2], 10);
    let empty_coverage = success_result(vec![FieldElement::one()], vec![], vec![], 10);

    fuzzer.add_executor(
        Framework::Circom,
        Arc::new(FixedExecutor::new(Framework::Circom, with_coverage)),
    );
    fuzzer.add_executor(
        Framework::Noir,
        Arc::new(FixedExecutor::new(Framework::Noir, empty_coverage)),
    );

    let finding = fuzzer
        .compare_backends(&[FieldElement::zero(), FieldElement::one()])
        .expect("coverage mismatch should produce a finding");
    assert_eq!(finding.severity, DifferentialSeverity::CoverageMismatch);
}

#[test]
fn test_coverage_mismatch_detects_low_overlap() {
    let mut fuzzer = DifferentialFuzzer::new(DifferentialConfig {
        coverage_min_constraints: 1,
        coverage_jaccard_threshold: 0.5,
        compare_coverage: true,
        compare_timing: false,
        ..Default::default()
    });

    let a = success_result(vec![FieldElement::one()], vec![1, 2, 3, 4], vec![1, 2, 3, 4], 10);
    let b = success_result(vec![FieldElement::one()], vec![3, 4, 5, 6], vec![3, 4, 5, 6], 10);

    fuzzer.add_executor(Framework::Circom, Arc::new(FixedExecutor::new(Framework::Circom, a)));
    fuzzer.add_executor(Framework::Noir, Arc::new(FixedExecutor::new(Framework::Noir, b)));

    let finding = fuzzer
        .compare_backends(&[FieldElement::zero(), FieldElement::one()])
        .expect("low-overlap coverage should produce a finding");
    assert_eq!(finding.severity, DifferentialSeverity::CoverageMismatch);
}

#[test]
fn test_timing_variation_uses_fast_side_as_baseline() {
    let mut fuzzer = DifferentialFuzzer::new(DifferentialConfig {
        timing_tolerance_percent: 200.0,
        timing_min_us: 0,
        timing_abs_threshold_us: 1,
        compare_coverage: false,
        compare_timing: true,
        ..Default::default()
    });

    let fast = success_result(vec![FieldElement::one()], vec![1, 2], vec![1, 2], 100);
    let slow = success_result(vec![FieldElement::one()], vec![1, 2], vec![1, 2], 10_000);

    fuzzer.add_executor(
        Framework::Circom,
        Arc::new(FixedExecutor::new(Framework::Circom, fast)),
    );
    fuzzer.add_executor(
        Framework::Noir,
        Arc::new(FixedExecutor::new(Framework::Noir, slow)),
    );

    let finding = fuzzer
        .compare_backends(&[FieldElement::zero(), FieldElement::one()])
        .expect("timing variation should produce a finding");
    assert_eq!(finding.severity, DifferentialSeverity::TimingVariation);
}
