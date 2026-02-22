use std::collections::{HashMap, HashSet};

use zk_core::FieldElement;
use zk_fuzzer::{
    ConstraintSubsetStrategy, EnhancedSymbolicConfig, EnhancedSymbolicExecutor, ExecutionMode,
    PruningStrategy, SymbolicConstraint, SymbolicValue, WitnessExtensionConfig,
    WitnessExtensionResult,
};

fn run_single_removal_case(
    constraints: Vec<SymbolicConstraint>,
    invariants: Vec<SymbolicConstraint>,
    base_witness: HashMap<String, FieldElement>,
    fixed_symbols: HashSet<String>,
) -> Vec<WitnessExtensionResult> {
    let config = EnhancedSymbolicConfig {
        max_paths: 64,
        max_depth: 64,
        solver_timeout_ms: 3_000,
        random_seed: Some(7),
        pruning_strategy: PruningStrategy::DepthBounded,
        simplify_constraints: true,
        incremental_solving: true,
        solutions_per_path: 1,
        loop_bound: 1,
        execution_mode: ExecutionMode::WitnessExtension,
        witness_extension: WitnessExtensionConfig {
            enabled: true,
            subset_strategy: ConstraintSubsetStrategy::RemoveSingleConstraint,
            max_removed_constraints: 3,
            max_subsets: 32,
            require_invariant_violation: true,
            max_analysis_time_ms: 60_000,
        },
    };
    let mut executor = EnhancedSymbolicExecutor::with_config(2, config);
    executor.run_witness_extension(&constraints, &base_witness, &fixed_symbols, &invariants)
}

#[test]
fn test_witness_extension_detects_range_check_removal_bug() {
    let constraints = vec![
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("input_0"),
            SymbolicValue::concrete(FieldElement::from_u64(1)),
        ),
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("amount"),
            SymbolicValue::concrete(FieldElement::from_u64(300)),
        ),
        SymbolicConstraint::Range(
            SymbolicValue::symbol("amount"),
            SymbolicValue::concrete(FieldElement::from_u64(16)),
        ),
    ];
    let invariants = vec![SymbolicConstraint::Lt(
        SymbolicValue::symbol("amount"),
        SymbolicValue::concrete(FieldElement::from_u64(16)),
    )];
    let base_witness = HashMap::from([
        ("input_0".to_string(), FieldElement::from_u64(1)),
        ("amount".to_string(), FieldElement::from_u64(300)),
    ]);
    let fixed_symbols = HashSet::from(["input_0".to_string(), "amount".to_string()]);

    let results = run_single_removal_case(constraints, invariants, base_witness, fixed_symbols);
    assert!(!results.is_empty(), "expected range-check removal finding");
    assert!(results.iter().all(|r| r.removed_indices.len() <= 3));
    assert!(results.iter().any(|r| r.violates_invariants()));
}

#[test]
fn test_witness_extension_detects_nullifier_uniqueness_removal_bug() {
    let constraints = vec![
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("input_0"),
            SymbolicValue::concrete(FieldElement::from_u64(1)),
        ),
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("nullifier"),
            SymbolicValue::concrete(FieldElement::from_u64(42)),
        ),
        SymbolicConstraint::Neq(
            SymbolicValue::symbol("nullifier"),
            SymbolicValue::concrete(FieldElement::from_u64(42)),
        ),
    ];
    let invariants = vec![SymbolicConstraint::Neq(
        SymbolicValue::symbol("nullifier"),
        SymbolicValue::concrete(FieldElement::from_u64(42)),
    )];
    let base_witness = HashMap::from([
        ("input_0".to_string(), FieldElement::from_u64(1)),
        ("nullifier".to_string(), FieldElement::from_u64(42)),
    ]);
    let fixed_symbols = HashSet::from(["input_0".to_string(), "nullifier".to_string()]);

    let results = run_single_removal_case(constraints, invariants, base_witness, fixed_symbols);
    assert!(
        !results.is_empty(),
        "expected nullifier-uniqueness removal finding"
    );
    assert!(results.iter().all(|r| r.removed_indices.len() <= 3));
    assert!(results.iter().any(|r| r.violates_invariants()));
}

#[test]
fn test_witness_extension_detects_booleanity_removal_bug() {
    let constraints = vec![
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("input_0"),
            SymbolicValue::concrete(FieldElement::from_u64(1)),
        ),
        SymbolicConstraint::Eq(
            SymbolicValue::symbol("flag"),
            SymbolicValue::concrete(FieldElement::from_u64(2)),
        ),
        SymbolicConstraint::Boolean(SymbolicValue::symbol("flag")),
    ];
    let invariants = vec![SymbolicConstraint::Boolean(SymbolicValue::symbol("flag"))];
    let base_witness = HashMap::from([
        ("input_0".to_string(), FieldElement::from_u64(1)),
        ("flag".to_string(), FieldElement::from_u64(2)),
    ]);
    let fixed_symbols = HashSet::from(["input_0".to_string(), "flag".to_string()]);

    let results = run_single_removal_case(constraints, invariants, base_witness, fixed_symbols);
    assert!(!results.is_empty(), "expected booleanity-removal finding");
    assert!(results.iter().all(|r| r.removed_indices.len() <= 3));
    assert!(results.iter().any(|r| r.violates_invariants()));
}
