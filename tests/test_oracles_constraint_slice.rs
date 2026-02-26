use std::collections::HashSet;
use std::thread;
use std::time::{Duration, Instant};

use rand::SeedableRng;
use zk_core::{CircuitInfo, FieldElement, Framework};
use zk_fuzzer::executor::{CircuitExecutor, FixtureCircuitExecutor};
use zk_fuzzer::oracles::{
    ConstraintCone, ConstraintSliceOracle, ConstraintSlicer, LeakingConstraint, OutputMapping,
};

struct AsyncDelayExecutor {
    inner: FixtureCircuitExecutor,
    delay: Duration,
}

impl AsyncDelayExecutor {
    fn new(delay: Duration) -> Self {
        Self {
            inner: FixtureCircuitExecutor::new("constraint-slice-delay", 1, 1).with_constraints(8),
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

    fn execute_sync(&self, inputs: &[FieldElement]) -> zk_core::ExecutionResult {
        thread::sleep(self.delay);
        self.inner.execute_sync(inputs)
    }

    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>> {
        self.inner.prove(witness)
    }

    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool> {
        self.inner.verify(proof, public_inputs)
    }

    fn constraint_inspector(&self) -> Option<&dyn zk_core::ConstraintInspector> {
        self.inner.constraint_inspector()
    }
}

#[test]
fn test_constraint_cone() {
    let cone = ConstraintCone {
        output_index: 0,
        output_wire: 0,
        constraints: vec![1, 2, 3],
        affecting_inputs: [0, 1, 2].into_iter().collect(),
        depth: 3,
    };

    assert!(cone.contains_input(0));
    assert!(cone.contains_input(1));
    assert!(!cone.contains_input(10));
    assert_eq!(cone.constraint_count(), 3);
}

#[test]
fn test_leaking_constraint() {
    let leak = LeakingConstraint {
        constraint_id: 42,
        affected_outputs: vec![0, 1, 2],
        description: "Test leak".to_string(),
    };

    assert_eq!(leak.affected_outputs.len(), 3);
}

#[test]
fn test_slice_all_outputs_preserves_mapping_indices() {
    let executor = FixtureCircuitExecutor::new("slice", 3, 1)
        .with_outputs(2)
        .with_constraints(8);
    let slicer = ConstraintSlicer::from_inspector(&executor, executor.num_public_inputs(), 8);

    let outputs = vec![
        OutputMapping {
            output_index: 0,
            output_wire: 4,
        },
        OutputMapping {
            output_index: 1,
            output_wire: 5,
        },
    ];

    let cones = slicer.slice_all_outputs(&outputs);
    assert_eq!(cones.len(), 2);
    assert_eq!(cones[0].output_index, 0);
    assert_eq!(cones[0].output_wire, 4);
    assert_eq!(cones[1].output_index, 1);
    assert_eq!(cones[1].output_wire, 5);
}

#[test]
fn test_mutate_in_cone_touches_only_affecting_inputs() {
    let executor = FixtureCircuitExecutor::new("slice_mut", 3, 1).with_constraints(6);
    let slicer = ConstraintSlicer::from_inspector(&executor, executor.num_public_inputs(), 8);

    let cone = ConstraintCone {
        output_index: 0,
        output_wire: 4,
        constraints: vec![0, 1],
        affecting_inputs: [1usize].into_iter().collect::<HashSet<_>>(),
        depth: 2,
    };

    let base = vec![
        FieldElement::from_u64(11),
        FieldElement::from_u64(22),
        FieldElement::from_u64(33),
    ];
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);

    let mutated = slicer.mutate_in_cone(&cone, &base, 32, &mut rng);
    assert!(!mutated.is_empty());
    assert!(mutated
        .iter()
        .all(|case| case[0] == base[0] && case[2] == base[2]));
}

#[tokio::test]
async fn test_constraint_slice_oracle_respects_time_budget() {
    let executor = AsyncDelayExecutor::new(Duration::from_millis(30));
    let oracle = ConstraintSliceOracle::new().with_samples(128);
    let base_witness = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
    let outputs = vec![OutputMapping {
        output_index: 0,
        output_wire: 2,
    }];

    let start = Instant::now();
    let _findings = oracle
        .run_with_budget(
            &executor,
            &base_witness,
            &outputs,
            Some(Duration::from_millis(20)),
        )
        .await;

    assert!(
        start.elapsed() < Duration::from_millis(250),
        "constraint slice oracle exceeded budget upper bound: {:?}",
        start.elapsed()
    );
}
