use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use zk_core::FieldElement;
use zk_fuzzer::{
    ConstraintSubsetStrategy, EnhancedSymbolicConfig, EnhancedSymbolicExecutor, ExecutionMode,
    PruningStrategy, SymbolicConstraint, SymbolicValue, WitnessExtensionConfig,
};

#[test]
fn test_witness_extension_completes_under_sixty_seconds_for_sub_10k_constraints() {
    let mut constraints = Vec::with_capacity(9_000);
    for _ in 0..9_000 {
        constraints.push(SymbolicConstraint::Eq(
            SymbolicValue::symbol("x"),
            SymbolicValue::concrete(FieldElement::from_u64(1)),
        ));
    }

    let config = EnhancedSymbolicConfig {
        max_paths: 64,
        max_depth: 64,
        solver_timeout_ms: 1_000,
        random_seed: Some(11),
        pruning_strategy: PruningStrategy::DepthBounded,
        simplify_constraints: true,
        incremental_solving: true,
        solutions_per_path: 1,
        loop_bound: 1,
        execution_mode: ExecutionMode::WitnessExtension,
        witness_extension: WitnessExtensionConfig {
            enabled: true,
            subset_strategy: ConstraintSubsetStrategy::RemoveByType,
            max_removed_constraints: 1,
            max_subsets: 1,
            require_invariant_violation: false,
            max_analysis_time_ms: 60_000,
        },
    };

    let mut executor = EnhancedSymbolicExecutor::with_config(1, config);
    let base_witness = HashMap::from([("x".to_string(), FieldElement::from_u64(1))]);
    let fixed_symbols = HashSet::from(["x".to_string()]);

    let start = Instant::now();
    let _ = executor.run_witness_extension(&constraints, &base_witness, &fixed_symbols, &[]);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(60),
        "expected witness-extension run <60s for <10K constraints, got {:?}",
        elapsed
    );
}
