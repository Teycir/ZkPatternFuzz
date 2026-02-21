use std::collections::HashSet;

use rand::SeedableRng;
use zk_core::FieldElement;
use zk_fuzzer::executor::{CircuitExecutor, FixtureCircuitExecutor};
use zk_fuzzer::oracles::{ConstraintCone, ConstraintSlicer, LeakingConstraint, OutputMapping};

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
