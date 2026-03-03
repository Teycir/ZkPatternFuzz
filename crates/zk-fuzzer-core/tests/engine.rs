use zk_core::{FieldElement, Finding, Framework, TestCase, TestMetadata};
use zk_fuzzer_core::corpus::create_corpus;
use zk_fuzzer_core::coverage::create_coverage_tracker;
use zk_fuzzer_core::engine::FuzzingEngineCore;
use zk_fuzzer_core::oracle::{BugOracle, UnderconstrainedOracle};
use zk_fuzzer_core::power_schedule::{PowerSchedule, PowerScheduler};
use zk_fuzzer_core::structure_aware::StructureAwareMutator;

#[test]
fn generate_test_case_recovers_from_empty_seed_inputs() {
    let corpus = create_corpus(16);
    let coverage = create_coverage_tracker(8);

    let mut engine = FuzzingEngineCore::builder()
        .seed(Some(7))
        .input_count(3)
        .corpus(corpus.clone())
        .coverage(coverage)
        .power_scheduler(PowerScheduler::new(PowerSchedule::None))
        .structure_mutator(StructureAwareMutator::new(Framework::Circom))
        .oracles(Vec::new())
        .build()
        .expect("engine builder should succeed");

    let empty_case = TestCase {
        inputs: Vec::new(),
        expected_output: None,
        metadata: TestMetadata::default(),
    };
    assert!(corpus.add(zk_fuzzer_core::corpus::CorpusEntry::new(empty_case, 4242)));

    let generated = engine.generate_test_case();
    assert_eq!(generated.inputs.len(), 3);
}

struct ConstraintCountProbeOracle;

impl BugOracle for ConstraintCountProbeOracle {
    fn check(&mut self, _test_case: &TestCase, _output: &[FieldElement]) -> Option<Finding> {
        None
    }

    fn name(&self) -> &str {
        "constraint_count_probe"
    }

    fn check_with_count(&mut self, _test_case: &TestCase, count: usize) -> Option<Finding> {
        Some(Finding {
            attack_type: zk_core::AttackType::Differential,
            severity: zk_core::Severity::Low,
            description: format!("constraint_count={count}"),
            poc: zk_core::ProofOfConcept {
                witness_a: vec![],
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            class: None,
            location: None,
        })
    }

    fn requires_constraint_count(&self) -> bool {
        true
    }
}

struct ConstraintCountSourceExecutor {
    metadata_constraint_count: usize,
    inspector_constraint_count: usize,
}

#[async_trait::async_trait]
impl zk_core::CircuitExecutor for ConstraintCountSourceExecutor {
    fn framework(&self) -> Framework {
        Framework::Cairo
    }

    fn name(&self) -> &str {
        "constraint-count-source-executor"
    }

    fn circuit_info(&self) -> zk_core::CircuitInfo {
        zk_core::CircuitInfo {
            name: self.name().to_string(),
            num_constraints: self.metadata_constraint_count,
            num_private_inputs: 0,
            num_public_inputs: 1,
            num_outputs: 1,
        }
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> zk_core::ExecutionResult {
        let coverage = zk_core::ExecutionCoverage::with_constraints(vec![0], vec![0, 1]);
        zk_core::ExecutionResult::success(vec![FieldElement::one()], coverage)
    }

    fn prove(&self, _witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        Ok(vec![])
    }

    fn verify(&self, _proof: &[u8], _public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        Ok(true)
    }

    fn constraint_inspector(&self) -> Option<&dyn zk_core::ConstraintInspector> {
        Some(self)
    }
}

impl zk_core::ConstraintInspector for ConstraintCountSourceExecutor {
    fn get_constraints(&self) -> Vec<zk_core::ConstraintEquation> {
        (0..self.inspector_constraint_count)
            .map(|id| zk_core::ConstraintEquation {
                id,
                a_terms: vec![(0, FieldElement::one())],
                b_terms: vec![(0, FieldElement::one())],
                c_terms: vec![(0, FieldElement::one())],
                description: None,
            })
            .collect()
    }

    fn check_constraints(&self, _witness: &[FieldElement]) -> Vec<zk_core::ConstraintResult> {
        vec![]
    }

    fn get_constraint_dependencies(&self) -> Vec<Vec<usize>> {
        vec![]
    }
}

#[test]
fn execute_and_track_uses_inspector_constraint_count_for_oracles() {
    let corpus = create_corpus(8);
    let coverage = create_coverage_tracker(64);
    let mut engine = FuzzingEngineCore::builder()
        .seed(Some(11))
        .input_count(1)
        .corpus(corpus)
        .coverage(coverage)
        .power_scheduler(PowerScheduler::new(PowerSchedule::None))
        .structure_mutator(StructureAwareMutator::new(Framework::Cairo))
        .oracles(vec![Box::new(ConstraintCountProbeOracle)])
        .build()
        .expect("engine builder should succeed");

    let executor = ConstraintCountSourceExecutor {
        metadata_constraint_count: 500,
        inspector_constraint_count: 9,
    };
    let test_case = TestCase {
        inputs: vec![FieldElement::one()],
        expected_output: None,
        metadata: TestMetadata::default(),
    };

    let result = engine.execute_and_track(&executor, &test_case);
    assert!(result.success);

    let findings = engine.findings();
    let has_inspector_count = findings
        .read()
        .iter()
        .any(|finding| finding.description == "constraint_count=9");
    assert!(
        has_inspector_count,
        "expected oracle to receive inspector-derived constraint count"
    );
}

#[test]
fn engine_builder_rejects_unconfigured_underconstrained_oracle() {
    let corpus = create_corpus(8);
    let coverage = create_coverage_tracker(64);

    let build = FuzzingEngineCore::builder()
        .seed(Some(13))
        .input_count(1)
        .corpus(corpus)
        .coverage(coverage)
        .power_scheduler(PowerScheduler::new(PowerSchedule::None))
        .structure_mutator(StructureAwareMutator::new(Framework::Circom))
        .oracles(vec![Box::new(UnderconstrainedOracle::new())])
        .build();

    let err = match build {
        Ok(_) => panic!("expected builder to fail on unconfigured oracle"),
        Err(err) => err,
    };
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("underconstrained_oracle")
            && msg.contains("num_public_inputs is not configured"),
        "unexpected error: {}",
        msg
    );
}
