use zk_core::{
    AttackType, CircuitExecutor, CircuitInfo, ExecutionCoverage, ExecutionResult, FieldElement,
    Finding, Framework, ProofOfConcept, Severity, TestCase,
};
use zk_fuzzer::fuzzer::oracle_validation::{
    filter_validated_findings, GroundTruthValidationResult, OracleValidationConfig,
    OracleValidator, ValidationResult,
};
use zk_fuzzer::fuzzer::BugOracle;

struct SingleOracleDisagree;

impl BugOracle for SingleOracleDisagree {
    fn check(&mut self, _test_case: &TestCase, _output: &[FieldElement]) -> Option<Finding> {
        None
    }

    fn name(&self) -> &str {
        "single_oracle_disagree"
    }

    fn attack_type(&self) -> Option<AttackType> {
        Some(AttackType::InformationLeakage)
    }
}

struct ValidationExecutor;

impl CircuitExecutor for ValidationExecutor {
    fn framework(&self) -> Framework {
        Framework::Circom
    }

    fn name(&self) -> &str {
        "validation_executor"
    }

    fn circuit_info(&self) -> CircuitInfo {
        CircuitInfo {
            name: "validation_executor".to_string(),
            num_constraints: 1,
            num_private_inputs: 1,
            num_public_inputs: 0,
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        ExecutionResult::success(
            vec![FieldElement::from_u64(7)],
            ExecutionCoverage::default(),
        )
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![0x01; 32])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }
}

fn sample_finding() -> Finding {
    Finding {
        attack_type: AttackType::InformationLeakage,
        severity: Severity::High,
        description: "single-oracle finding".to_string(),
        poc: ProofOfConcept {
            witness_a: vec![FieldElement::from_u64(1)],
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        },
        class: None,
        location: None,
    }
}

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

#[test]
fn test_single_oracle_reproducibility_override_keeps_finding() {
    let executor = ValidationExecutor;
    let mut validator = OracleValidator::with_config(OracleValidationConfig::default());
    let mut oracles: Vec<Box<dyn BugOracle>> = vec![Box::new(SingleOracleDisagree)];

    let filtered = filter_validated_findings(
        vec![sample_finding()],
        &mut validator,
        &mut oracles,
        &executor,
        false,
    );
    assert_eq!(filtered.len(), 1);
}

#[test]
fn test_single_oracle_reproducibility_override_respects_strict_mode() {
    let executor = ValidationExecutor;
    let mut validator = OracleValidator::with_config(OracleValidationConfig::strict());
    let mut oracles: Vec<Box<dyn BugOracle>> = vec![Box::new(SingleOracleDisagree)];

    let filtered = filter_validated_findings(
        vec![sample_finding()],
        &mut validator,
        &mut oracles,
        &executor,
        false,
    );
    assert!(filtered.is_empty());
}
