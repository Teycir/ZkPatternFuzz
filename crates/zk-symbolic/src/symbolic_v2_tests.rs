use super::*;

#[test]
fn test_constraint_cache() {
    let cache = ConstraintCache::new();
    let mut pc = PathCondition::new();
    pc.add_constraint(SymbolicConstraint::Boolean(SymbolicValue::symbol("x")));

    // Initially empty
    assert!(cache.get(&pc).is_none());

    // Insert and retrieve
    let mut assignments = HashMap::new();
    assignments.insert("x".to_string(), FieldElement::from_u64(1));
    cache.insert(&pc, SolverResult::Sat(assignments.clone()));

    assert!(cache.get(&pc).is_some());
    let (hits, misses, rate) = cache.stats();
    assert_eq!(hits, 1);
    assert_eq!(misses, 1); // First get was a miss
    assert!(rate > 0.0);
}

#[test]
fn test_constraint_cache_unsat_cache_respects_size_cap() {
    let cache = ConstraintCache::new()
        .with_max_size(100)
        .with_max_unsat_cache_size(2);

    let mut pc_a = PathCondition::new();
    pc_a.add_constraint(SymbolicConstraint::Boolean(SymbolicValue::symbol("a")));
    cache.insert(&pc_a, SolverResult::Unsat);

    let mut pc_b = PathCondition::new();
    pc_b.add_constraint(SymbolicConstraint::Boolean(SymbolicValue::symbol("b")));
    cache.insert(&pc_b, SolverResult::Unsat);

    let mut pc_c = PathCondition::new();
    pc_c.add_constraint(SymbolicConstraint::Boolean(SymbolicValue::symbol("c")));
    cache.insert(&pc_c, SolverResult::Unsat);

    assert!(cache.get(&pc_a).is_none());
    assert!(matches!(cache.get(&pc_b), Some(SolverResult::Unsat)));
    assert!(matches!(cache.get(&pc_c), Some(SolverResult::Unsat)));
}

#[test]
fn test_path_merger() {
    let mut merger = PathMerger::new(MergeStrategy::ProgramPoint).with_threshold(2);

    let mut state1 = SymbolicState::new(3);
    state1.current_constraint = 5;
    state1
        .path_condition
        .add_constraint(SymbolicConstraint::Boolean(SymbolicValue::symbol("a")));

    let mut state2 = SymbolicState::new(3);
    state2.current_constraint = 5;
    state2
        .path_condition
        .add_constraint(SymbolicConstraint::Boolean(SymbolicValue::symbol("b")));

    // First state should return None (waiting for more)
    assert!(merger.submit(state1).is_none());

    // Second state should trigger merge
    let merged = merger.submit(state2);
    assert!(merged.is_some());

    let (merges, eliminated) = merger.stats();
    assert_eq!(merges, 1);
    assert_eq!(eliminated, 1);
}

#[test]
fn test_path_priority() {
    let mut state = SymbolicState::new(3);
    state
        .path_condition
        .add_constraint(SymbolicConstraint::Boolean(SymbolicValue::symbol("x")));
    state.set_signal_by_name("output", SymbolicValue::symbol("output"));
    let coverage: Vec<bool> = vec![false; 100];
    let patterns = vec![VulnerabilityTargetPattern::underconstrained()];

    let priority = PathPriority::compute(&state, &coverage, &patterns);
    assert!(priority.score > 0.0);
    assert!(priority.depth_penalty >= 0.0);
}

#[test]
fn test_symbolic_v2_config_defaults() {
    let config = SymbolicV2Config::default();

    // Verify 10x path increase
    assert_eq!(config.max_paths, 10_000);
    // Verify 20x depth increase
    assert_eq!(config.max_depth, 1_000);
    // Verify 6x timeout increase
    assert_eq!(config.solver_timeout_ms, 30_000);
    // Verify features enabled
    assert!(config.enable_caching);
    assert!(config.simplify_constraints);
    assert!(config.adaptive_timeout);
}

#[test]
fn test_symbolic_v2_executor_creation() {
    let executor = SymbolicV2Executor::new(5);
    assert_eq!(executor.num_inputs, 5);
    assert!(executor.generated_tests.is_empty());
    assert!(executor.completed_paths.is_empty());
}

#[test]
fn test_vuln_patterns() {
    let state = SymbolicState::new(3);

    let pattern = VulnerabilityTargetPattern::nullifier_reuse();
    let score = pattern.match_score(&state);
    assert!(score >= 0.0);
}

#[test]
fn test_merged_value() {
    let single = MergedValue::Single(SymbolicValue::Concrete(FieldElement::from_u64(42)));
    let sym = single.to_symbolic_value();
    assert!(matches!(sym, SymbolicValue::Concrete(_)));
}
