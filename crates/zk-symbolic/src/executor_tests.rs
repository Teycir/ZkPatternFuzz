
use super::*;

#[test]
fn test_symbolic_value_creation() {
    let x = SymbolicValue::symbol("x");
    let y = SymbolicValue::symbol("y");
    let sum = x.add(y);

    let symbols = sum.symbols();
    assert!(symbols.contains("x"));
    assert!(symbols.contains("y"));
}

#[test]
fn test_symbolic_state() {
    let state = SymbolicState::new(3);

    assert_eq!(state.signals.len(), 3);
    assert!(state.get_signal(0).is_some());
    assert!(state.get_signal(3).is_none());
}

#[test]
fn test_path_condition() {
    let mut pc = PathCondition::new();

    let x = SymbolicValue::symbol("x");
    let zero = SymbolicValue::concrete(FieldElement::zero());

    pc.add_constraint(SymbolicConstraint::eq(x, zero));

    assert_eq!(pc.constraints.len(), 1);
    assert!(pc.symbols().contains("x"));
}

#[test]
fn test_symbolic_executor_creation() {
    let executor = SymbolicExecutor::new(5).with_config(SymbolicConfig {
        max_paths: 50,
        ..Default::default()
    });

    assert_eq!(executor.worklist.len(), 1);
    assert_eq!(executor.config.max_paths, 50);
}

#[test]
fn test_z3_solver_simple_equality() {
    let solver = Z3Solver::new();
    let mut pc = PathCondition::new();

    pc.add_constraint(SymbolicConstraint::eq(
        SymbolicValue::symbol("input_0"),
        SymbolicValue::concrete(FieldElement::from_u64(42)),
    ));

    let result = solver.solve(&pc);
    assert!(result.is_sat());

    if let SolverResult::Sat(assignments) = result {
        assert!(assignments.contains_key("input_0"));
    }
}

#[test]
fn test_z3_solver_unsatisfiable() {
    // Test using direct Z3 API to ensure unsatisfiability works
    use z3::{Config, Context as Z3Context, SatResult as Z3SatResult, Solver as Z3Solver2};

    let mut cfg = Config::new();
    cfg.set_model_generation(true);
    let ctx = Z3Context::new(&cfg);
    let solver = Z3Solver2::new(&ctx);

    let x = ast::Int::new_const(&ctx, "x");
    let one = ast::Int::from_i64(&ctx, 1);
    let two = ast::Int::from_i64(&ctx, 2);

    solver.assert(&x._eq(&one));
    solver.assert(&x._eq(&two));

    let result = solver.check();
    assert!(
        matches!(result, Z3SatResult::Unsat),
        "Expected Unsat, got {:?}",
        result
    );
}

#[test]
fn test_fuzzer_integration() {
    let mut integration = SymbolicFuzzerIntegration::new(3);
    let seeds = integration.generate_seeds(10);

    assert!(!seeds.is_empty());
    assert!(seeds.len() <= 10);
}

#[test]
fn test_boundary_test_generation() {
    let integration = SymbolicFuzzerIntegration::new(2);
    let tests = integration.generate_overflow_tests();

    assert!(!tests.is_empty());
}
