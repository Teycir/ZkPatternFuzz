use super::*;

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
