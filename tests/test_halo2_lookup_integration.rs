use std::path::Path;

use zk_core::{CircuitExecutor, FieldElement};
use zk_fuzzer::executor::Halo2Executor;

fn write_temp_halo2_spec(json: &str) -> tempfile::NamedTempFile {
    let file = tempfile::Builder::new()
        .prefix("halo2_lookup_")
        .suffix(".json")
        .tempfile()
        .expect("create temporary halo2 lookup spec");
    std::fs::write(file.path(), json).expect("write temporary halo2 lookup spec");
    file
}

#[test]
fn halo2_lookup_fixture_reports_lookup_constraints_and_executes() {
    let spec_path = Path::new("tests/halo2_specs/lookup.json");
    assert!(
        spec_path.exists(),
        "missing Halo2 lookup fixture at {:?}",
        spec_path
    );

    let executor = Halo2Executor::new(spec_path.to_str().unwrap(), "main")
        .expect("create halo2 executor from lookup fixture");
    let inspector = executor.constraint_inspector().expect("lookup fixture inspector");

    let lookup_constraints = inspector
        .get_constraints()
        .iter()
        .filter(|eq| eq.description.as_deref() == Some("lookup"))
        .count();
    assert!(
        lookup_constraints >= 1,
        "expected at least one lookup constraint in Halo2 lookup fixture"
    );

    let witness = vec![
        FieldElement::one(),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];
    let result = executor.execute_sync(&witness);
    assert!(
        result.success,
        "lookup fixture execution should succeed: {:?}",
        result.error
    );

    let checks = inspector.check_constraints(&witness);
    assert!(!checks.is_empty(), "expected non-empty lookup checks");
    assert!(
        checks.iter().all(|check| check.satisfied),
        "lookup fixture checks should all pass"
    );
}

#[test]
fn halo2_lookup_vector_selector_semantics_end_to_end() {
    let json = r#"
        {
          "name": "lookup_vector_selector",
          "k": 5,
          "advice_columns": 4,
          "fixed_columns": 1,
          "instance_columns": 1,
          "constraints": 1,
          "private_inputs": 3,
          "public_inputs": 1,
          "tables": {
            "7": { "name": "pair_table", "num_columns": 2, "entries": [["2", "4"], ["7", "9"]] }
          },
          "lookups": [
            { "table_id": 7, "inputs": [1, 2], "table_columns": [0, 1], "enable": 3 }
          ]
        }
        "#;
    let temp = write_temp_halo2_spec(json);

    let executor = Halo2Executor::new(temp.path().to_str().unwrap(), "main")
        .expect("create halo2 executor for vector lookup");
    let inspector = executor.constraint_inspector().expect("vector lookup inspector");

    let enabled_passing = vec![
        FieldElement::one(),
        FieldElement::from_u64(2),
        FieldElement::from_u64(4),
        FieldElement::one(),
    ];
    let enabled_pass = executor.execute_sync(&enabled_passing);
    assert!(
        enabled_pass.success,
        "enabled vector lookup should pass: {:?}",
        enabled_pass.error
    );
    let enabled_checks = inspector.check_constraints(&enabled_passing);
    assert_eq!(enabled_checks.len(), 1);
    assert!(enabled_checks[0].satisfied);

    let disabled_non_member = vec![
        FieldElement::one(),
        FieldElement::from_u64(99),
        FieldElement::from_u64(98),
        FieldElement::zero(),
    ];
    let disabled_pass = executor.execute_sync(&disabled_non_member);
    assert!(
        disabled_pass.success,
        "selector-disabled lookup should be skipped: {:?}",
        disabled_pass.error
    );
    let disabled_checks = inspector.check_constraints(&disabled_non_member);
    assert_eq!(disabled_checks.len(), 1);
    assert!(disabled_checks[0].satisfied);

    let enabled_non_member = vec![
        FieldElement::one(),
        FieldElement::from_u64(99),
        FieldElement::from_u64(98),
        FieldElement::one(),
    ];
    let enabled_fail = executor.execute_sync(&enabled_non_member);
    assert!(
        !enabled_fail.success,
        "enabled vector lookup should fail for non-member values"
    );
    let enabled_fail_error = enabled_fail.error.unwrap_or_default();
    assert!(
        enabled_fail_error.contains("unsatisfied"),
        "expected lookup failure message, got '{}'",
        enabled_fail_error
    );

    let enabled_fail_checks = inspector.check_constraints(&enabled_non_member);
    assert_eq!(enabled_fail_checks.len(), 1);
    assert!(!enabled_fail_checks[0].satisfied);
}

#[test]
fn halo2_lookup_missing_table_fails_closed_end_to_end() {
    let json = r#"
        {
          "name": "lookup_missing_table",
          "k": 4,
          "advice_columns": 2,
          "fixed_columns": 0,
          "instance_columns": 1,
          "constraints": 1,
          "private_inputs": 1,
          "public_inputs": 1,
          "lookups": [
            { "table_id": 99, "input": 1 }
          ]
        }
        "#;
    let temp = write_temp_halo2_spec(json);

    let executor = Halo2Executor::new(temp.path().to_str().unwrap(), "main")
        .expect("create halo2 executor with missing table lookup");
    let inspector = executor
        .constraint_inspector()
        .expect("missing table lookup inspector");

    let witness = vec![FieldElement::one(), FieldElement::from_u64(7)];
    let result = executor.execute_sync(&witness);
    assert!(
        !result.success,
        "lookup with unresolved table must fail in fail-closed mode"
    );
    let error = result.error.unwrap_or_default();
    assert!(
        error.contains("unsatisfied"),
        "expected unresolved-table lookup failure, got '{}'",
        error
    );

    let checks = inspector.check_constraints(&witness);
    assert_eq!(checks.len(), 1);
    assert!(!checks[0].satisfied);
}
