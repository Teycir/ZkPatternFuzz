use std::thread;
use std::time::{Duration, Instant};
use zk_core::{
    AttackType, CircuitExecutor, CircuitInfo, ExecutionCoverage, ExecutionResult, FieldElement,
    Framework,
};
use zk_fuzzer::executor::FixtureCircuitExecutor;
use zk_fuzzer::oracles::{
    EquivalenceClass, EquivalencePredicate, WitnessCollision, WitnessCollisionDetector,
};

struct AsyncDelayExecutor {
    inner: FixtureCircuitExecutor,
    delay: Duration,
}

struct ConstantOutputExecutor {
    inner: FixtureCircuitExecutor,
}

impl ConstantOutputExecutor {
    fn new() -> Self {
        Self {
            inner: FixtureCircuitExecutor::new("witness-collision-constant", 1, 0),
        }
    }
}

impl AsyncDelayExecutor {
    fn new(delay: Duration) -> Self {
        Self {
            inner: FixtureCircuitExecutor::new("witness-collision-delay", 1, 0),
            delay,
        }
    }
}

impl CircuitExecutor for AsyncDelayExecutor {
    fn framework(&self) -> Framework {
        self.inner.framework()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        self.inner.circuit_info()
    }

    fn execute_sync(&self, inputs: &[FieldElement]) -> ExecutionResult {
        thread::sleep(self.delay);
        self.inner.execute_sync(inputs)
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        self.inner.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        self.inner.verify(proof, public_inputs)
    }
}

impl CircuitExecutor for ConstantOutputExecutor {
    fn framework(&self) -> Framework {
        self.inner.framework()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn circuit_info(&self) -> CircuitInfo {
        self.inner.circuit_info()
    }

    fn execute_sync(&self, _inputs: &[FieldElement]) -> ExecutionResult {
        ExecutionResult::success(vec![FieldElement::zero()], ExecutionCoverage::default())
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        self.inner.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        self.inner.verify(proof, public_inputs)
    }
}

#[test]
fn test_equivalence_differ_only_at() {
    let class = EquivalenceClass {
        name: "test".to_string(),
        predicate: EquivalencePredicate::DifferOnlyAt(vec![1]),
    };

    let a = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];
    let b = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(99),
        FieldElement::from_u64(3),
    ];
    let c = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(99),
    ];

    assert!(class.are_equivalent(&a, &b));
    assert!(!class.are_equivalent(&a, &c));
}

#[test]
fn test_equivalence_permutation() {
    let class = EquivalenceClass {
        name: "permutation".to_string(),
        predicate: EquivalencePredicate::Permutation,
    };

    let a = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];
    let b = vec![
        FieldElement::from_u64(3),
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    ];
    let c = vec![
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
        FieldElement::from_u64(4),
    ];

    assert!(class.are_equivalent(&a, &b));
    assert!(!class.are_equivalent(&a, &c));
}

#[test]
fn test_collision_detection() {
    let detector = WitnessCollisionDetector::new().with_samples(1000);

    let collision = WitnessCollision {
        witness_a: vec![FieldElement::from_u64(1)],
        witness_b: vec![FieldElement::from_u64(2)],
        public_inputs: vec![FieldElement::from_u64(7)],
        public_input_indices: vec![0],
        output_hash: "abc123".to_string(),
        outputs: vec![FieldElement::from_u64(42)],
        is_expected: false,
    };

    let findings = detector.to_findings(&[collision]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].attack_type, AttackType::WitnessCollision);
}

#[test]
fn test_collision_detection_skips_empty_public_interface() {
    let detector = WitnessCollisionDetector::new();

    let collision = WitnessCollision {
        witness_a: vec![FieldElement::from_u64(1)],
        witness_b: vec![FieldElement::from_u64(2)],
        public_inputs: vec![],
        public_input_indices: vec![],
        output_hash: "deadbeef".to_string(),
        outputs: vec![FieldElement::one()],
        is_expected: false,
    };

    let findings = detector.to_findings(&[collision]);
    assert!(findings.is_empty());
}

#[test]
fn test_collision_analysis() {
    let detector = WitnessCollisionDetector::new();

    let collisions = vec![
        WitnessCollision {
            witness_a: vec![FieldElement::from_u64(1), FieldElement::from_u64(2)],
            witness_b: vec![FieldElement::from_u64(1), FieldElement::from_u64(3)],
            public_inputs: vec![],
            public_input_indices: vec![],
            output_hash: "hash1".to_string(),
            outputs: vec![],
            is_expected: false,
        },
        WitnessCollision {
            witness_a: vec![FieldElement::from_u64(1), FieldElement::from_u64(4)],
            witness_b: vec![FieldElement::from_u64(1), FieldElement::from_u64(5)],
            public_inputs: vec![],
            public_input_indices: vec![],
            output_hash: "hash2".to_string(),
            outputs: vec![],
            is_expected: false,
        },
    ];

    let analysis = detector.analyze_patterns(&collisions);

    assert_eq!(analysis.total_collisions, 2);
    let differing = analysis.differing_indices.get(&1).copied().unwrap_or(0);
    assert_eq!(differing, 2);
}

#[tokio::test]
async fn test_collision_detector_respects_time_budget() {
    let detector = WitnessCollisionDetector::new().with_samples(100);
    let executor = AsyncDelayExecutor::new(Duration::from_millis(30));
    let witnesses: Vec<Vec<FieldElement>> = (0..100u64)
        .map(|value| vec![FieldElement::from_u64(value)])
        .collect();

    let start = Instant::now();
    let _collisions = detector
        .run_with_budget(&executor, &witnesses, Some(Duration::from_millis(20)))
        .await;

    // Budget enforcement should stop this attack quickly instead of iterating over all samples.
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "budgeted witness collision run exceeded expected upper bound: {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn test_collision_detector_caps_collision_volume() {
    let detector = WitnessCollisionDetector::new()
        .with_samples(200)
        .with_max_collisions(7);
    let executor = ConstantOutputExecutor::new();
    let witnesses: Vec<Vec<FieldElement>> = (0..200u64)
        .map(|value| vec![FieldElement::from_u64(value)])
        .collect();

    let collisions = detector.run(&executor, &witnesses).await;
    assert_eq!(collisions.len(), 7);
}
