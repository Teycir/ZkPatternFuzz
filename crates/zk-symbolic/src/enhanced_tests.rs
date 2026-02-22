use super::*;
use std::collections::{HashMap, HashSet};

#[test]
fn test_constraint_simplifier_constant_folding() {
    let mut simplifier = ConstraintSimplifier::new();

    // Test x + 0 = x
    let constraint = SymbolicConstraint::Eq(
        SymbolicValue::Add(
            Box::new(SymbolicValue::Symbol("x".to_string())),
            Box::new(SymbolicValue::Concrete(FieldElement::zero())),
        ),
        SymbolicValue::Symbol("x".to_string()),
    );

    let simplified = simplifier.simplify_constraint(&constraint);
    assert!(matches!(simplified, Some(SymbolicConstraint::True)));
}

#[test]
fn test_path_pruner_depth_bounded() {
    let mut pruner = PathPruner::new(PruningStrategy::DepthBounded).with_max_depth(5);

    let mut state = SymbolicState::new(3);
    state.depth = 3;
    assert!(!pruner.should_prune(&state, 0));

    state.depth = 10;
    assert!(pruner.should_prune(&state, 0));
}

#[test]
fn test_enhanced_executor_creation() {
    let executor = EnhancedSymbolicExecutor::new(5);
    assert_eq!(executor.num_inputs, 5);
    assert!(!executor.worklist.is_empty());
}

#[test]
fn test_path_pruner_subsumption_based() {
    let mut pruner = PathPruner::new(PruningStrategy::SubsumptionBased);

    let mut base_state = SymbolicState::new(1);
    base_state
        .path_condition
        .add_constraint(SymbolicConstraint::Eq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::one()),
        ));
    assert!(!pruner.should_prune(&base_state, 0));

    let mut stricter_state = SymbolicState::new(1);
    stricter_state
        .path_condition
        .add_constraint(SymbolicConstraint::Eq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::one()),
        ));
    stricter_state
        .path_condition
        .add_constraint(SymbolicConstraint::Neq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::zero()),
        ));
    assert!(pruner.should_prune(&stricter_state, 1));
}

#[test]
fn test_incremental_solver_cache_hits() {
    let mut solver = IncrementalSolver::new();
    let base_path = PathCondition::new();
    let constraints = vec![SymbolicConstraint::Eq(
        SymbolicValue::symbol("input_0"),
        SymbolicValue::concrete(FieldElement::zero()),
    )];

    let first = solver.solve_incremental(&base_path, &constraints);
    assert!(
        !matches!(first, SolverResult::Unknown),
        "first incremental solve returned unknown"
    );
    assert_eq!(solver.cache_hits(), 0);

    let second = solver.solve_incremental(&base_path, &constraints);
    assert!(
        !matches!(second, SolverResult::Unknown),
        "second incremental solve returned unknown"
    );
    assert_eq!(solver.cache_hits(), 1);
}

#[test]
fn test_constraint_subset_selector_single_constraint_strategy() {
    let constraints = vec![
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("a"),
            SymbolicValue::concrete(FieldElement::one()),
        ),
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("b"),
            SymbolicValue::concrete(FieldElement::one()),
        ),
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("c"),
            SymbolicValue::concrete(FieldElement::one()),
        ),
    ];

    let selector = ConstraintSubsetSelector::new(ConstraintSubsetStrategy::RemoveSingleConstraint)
        .with_max_subsets(8);
    let plans = selector.select(&constraints);
    assert_eq!(plans.len(), 3);
    assert_eq!(plans[0].removed_indices, vec![0]);
    assert_eq!(plans[1].removed_indices, vec![1]);
    assert_eq!(plans[2].removed_indices, vec![2]);
}

#[test]
fn test_constraint_subset_selector_dependency_cluster_strategy() {
    let constraints = vec![
        SymbolicConstraint::Eq(SymbolicValue::symbol("x"), SymbolicValue::symbol("y")),
        SymbolicConstraint::Eq(SymbolicValue::symbol("y"), SymbolicValue::symbol("z")),
        SymbolicConstraint::Eq(SymbolicValue::symbol("p"), SymbolicValue::symbol("q")),
    ];

    let selector = ConstraintSubsetSelector::new(ConstraintSubsetStrategy::RemoveDependencyCluster)
        .with_max_removed_constraints(4)
        .with_max_subsets(8);
    let plans = selector.select(&constraints);

    assert_eq!(plans.len(), 2);
    assert_eq!(plans[0].removed_indices, vec![0, 1]);
    assert_eq!(plans[1].removed_indices, vec![2]);
}

#[test]
fn test_constraint_subset_selector_by_type_strategy() {
    let constraints = vec![
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::one()),
        ),
        SymbolicConstraint::Neq(
            SymbolicValue::symbol("y"),
            SymbolicValue::concrete(FieldElement::zero()),
        ),
        SymbolicConstraint::Boolean(SymbolicValue::symbol("flag")),
        SymbolicConstraint::Range(
            SymbolicValue::symbol("limb"),
            SymbolicValue::concrete(FieldElement::from_u64(16)),
        ),
    ];

    let selector = ConstraintSubsetSelector::new(ConstraintSubsetStrategy::RemoveByType)
        .with_max_removed_constraints(4)
        .with_max_subsets(8);
    let plans = selector.select(&constraints);

    assert!(
        plans.iter().any(|plan| plan.removed_indices == vec![0, 1]),
        "comparison constraints should be grouped together"
    );
    assert!(
        plans.iter().any(|plan| plan.removed_indices == vec![2]),
        "boolean constraint should form its own group"
    );
    assert!(
        plans.iter().any(|plan| plan.removed_indices == vec![3]),
        "range constraint should form its own group"
    );
}

#[test]
fn test_incremental_solver_witness_extension_reports_invariant_violations() {
    let constraints = vec![
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("input_0"),
            SymbolicValue::concrete(FieldElement::from_u64(1)),
        ),
        SymbolicConstraint::Eq(SymbolicValue::symbol("z"), SymbolicValue::symbol("w")),
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("w"),
            SymbolicValue::concrete(FieldElement::from_u64(3)),
        ),
    ];
    let removed_indices = vec![2usize];

    let base_witness = HashMap::from([
        ("input_0".to_string(), FieldElement::from_u64(1)),
        ("z".to_string(), FieldElement::from_u64(3)),
        ("w".to_string(), FieldElement::from_u64(3)),
    ]);
    let fixed_symbols = HashSet::from(["input_0".to_string()]);
    let semantic_invariants = vec![SymbolicConstraint::Eq(
        SymbolicValue::symbol("input_0"),
        SymbolicValue::concrete(FieldElement::from_u64(2)),
    )];

    let mut solver = IncrementalSolver::new();
    let result = solver.solve_witness_extension(
        &constraints,
        &removed_indices,
        &base_witness,
        &fixed_symbols,
        &semantic_invariants,
    );

    assert!(result.sat, "expected SAT extension on kept constraints");
    assert_eq!(result.removed_constraints_total, 1);
    assert_eq!(result.removed_indices, removed_indices);
    assert_eq!(result.violated_invariants, vec![0]);
}

#[test]
fn test_enhanced_executor_witness_extension_mode_filters_non_violations() {
    let constraints = vec![
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("input_0"),
            SymbolicValue::concrete(FieldElement::from_u64(1)),
        ),
        SymbolicConstraint::Eq(SymbolicValue::symbol("z"), SymbolicValue::symbol("w")),
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("w"),
            SymbolicValue::concrete(FieldElement::from_u64(3)),
        ),
    ];
    let base_witness = HashMap::from([
        ("input_0".to_string(), FieldElement::from_u64(1)),
        ("z".to_string(), FieldElement::from_u64(3)),
        ("w".to_string(), FieldElement::from_u64(3)),
    ]);
    let fixed_symbols = HashSet::from(["input_0".to_string()]);
    let semantic_invariants = vec![SymbolicConstraint::Eq(
        SymbolicValue::symbol("input_0"),
        SymbolicValue::concrete(FieldElement::from_u64(2)),
    )];

    let config = EnhancedSymbolicConfig {
        execution_mode: ExecutionMode::WitnessExtension,
        witness_extension: WitnessExtensionConfig {
            enabled: true,
            subset_strategy: ConstraintSubsetStrategy::RemoveSingleConstraint,
            max_removed_constraints: 1,
            max_subsets: 4,
            require_invariant_violation: true,
            max_analysis_time_ms: 60_000,
        },
        ..Default::default()
    };
    let mut executor = EnhancedSymbolicExecutor::with_config(1, config);

    let results = executor.run_witness_extension(
        &constraints,
        &base_witness,
        &fixed_symbols,
        &semantic_invariants,
    );

    assert!(!results.is_empty(), "expected witness-extension findings");
    assert!(results
        .iter()
        .all(WitnessExtensionResult::violates_invariants));
}

#[test]
fn test_witness_extension_analysis_budget_zero_stops_immediately() {
    let constraints = vec![
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("input_0"),
            SymbolicValue::concrete(FieldElement::from_u64(1)),
        ),
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::from_u64(5)),
        ),
    ];
    let base_witness = HashMap::from([
        ("input_0".to_string(), FieldElement::from_u64(1)),
        ("x".to_string(), FieldElement::from_u64(5)),
    ]);
    let fixed_symbols = HashSet::from(["input_0".to_string(), "x".to_string()]);

    let config = EnhancedSymbolicConfig {
        execution_mode: ExecutionMode::WitnessExtension,
        witness_extension: WitnessExtensionConfig {
            enabled: true,
            subset_strategy: ConstraintSubsetStrategy::RemoveSingleConstraint,
            max_removed_constraints: 1,
            max_subsets: 8,
            require_invariant_violation: false,
            max_analysis_time_ms: 0,
        },
        ..Default::default()
    };
    let mut executor = EnhancedSymbolicExecutor::with_config(1, config);

    let results = executor.run_witness_extension(&constraints, &base_witness, &fixed_symbols, &[]);
    assert!(
        results.is_empty(),
        "analysis with zero budget should stop before processing plans"
    );
}
