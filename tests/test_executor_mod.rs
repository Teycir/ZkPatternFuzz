use zk_core::{CircuitExecutor, ExecutionCoverage, ExecutionResult, FieldElement};
use zk_fuzzer::executor::{CairoExecutor, Halo2Executor};
use zk_fuzzer::targets::CairoTarget;

#[test]
fn execution_result_helpers_behave_as_expected() {
    let result = ExecutionResult::success(vec![FieldElement::one()], ExecutionCoverage::default());
    assert!(result.success);
    assert!(result.error.is_none());

    let failure = ExecutionResult::failure("test error".to_string());
    assert!(!failure.success);
    assert_eq!(failure.error, Some("test error".to_string()));
}

#[test]
fn halo2_plonk_constraint_checking() {
    let json = r#"
        {
          "name": "test",
          "k": 4,
          "advice_columns": 3,
          "fixed_columns": 0,
          "instance_columns": 0,
          "constraints": 2,
          "private_inputs": 3,
          "public_inputs": 0,
          "lookups": 1,
          "tables": {
            "0": { "name": "tiny", "num_columns": 1, "entries": [[2], [3]] }
          },
          "gates": [
            { "a": 1, "b": 2, "c": 3, "q_l": "1", "q_r": "1", "q_o": "-1", "q_m": "0", "q_c": "0" }
          ],
          "lookups": [
            { "table_id": 0, "input": 1 }
          ]
        }
        "#;

    let temp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    std::fs::write(temp.path(), json).unwrap();

    let executor = Halo2Executor::new(temp.path().to_str().unwrap(), "main").unwrap();
    let inspector = executor.constraint_inspector().unwrap();

    let witness = vec![
        FieldElement::one(),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
        FieldElement::from_u64(5),
    ];

    let results = inspector.check_constraints(&witness);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.satisfied));
}

#[test]
fn halo2_constraint_checks_with_json_spec() {
    let json = r#"
        {
          "name": "test",
          "k": 4,
          "advice_columns": 3,
          "fixed_columns": 0,
          "instance_columns": 0,
          "constraints": 2,
          "private_inputs": 3,
          "public_inputs": 0,
          "lookups": 1,
          "tables": {
            "0": { "name": "tiny", "num_columns": 1, "entries": [[2], [3]] }
          },
          "gates": [
            { "a": 1, "b": 2, "c": 3, "q_l": "1", "q_r": "1", "q_o": "-1", "q_m": "0", "q_c": "0" }
          ],
          "lookups": [
            { "table_id": 0, "input": 1 }
          ]
        }
        "#;

    let temp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    std::fs::write(temp.path(), json).unwrap();

    let executor = Halo2Executor::new(temp.path().to_str().unwrap(), "main").unwrap();
    let inputs = vec![
        FieldElement::one(),
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
        FieldElement::from_u64(5),
    ];

    let result = executor.execute_sync(&inputs);
    assert!(result.success);

    let inspector = executor.constraint_inspector().unwrap();
    let checks = inspector.check_constraints(&inputs);
    assert_eq!(checks.len(), 2);
    assert!(checks.iter().all(|c| c.satisfied));
}

#[test]
fn halo2_wire_label_fallback_for_metadata_only_json_spec() {
    let json = r#"
        {
          "name": "minimal_halo2",
          "k": 4,
          "advice_columns": 2,
          "fixed_columns": 1,
          "instance_columns": 1,
          "constraints": 8,
          "private_inputs": 2,
          "public_inputs": 1,
          "lookups": 0
        }
        "#;

    let temp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    std::fs::write(temp.path(), json).unwrap();

    let executor = Halo2Executor::new(temp.path().to_str().unwrap(), "main").unwrap();
    let inspector = executor.constraint_inspector().unwrap();
    let labels = inspector.wire_labels();

    assert_eq!(labels.get(&0).map(String::as_str), Some("public_input_0"));
    assert_eq!(labels.get(&1).map(String::as_str), Some("private_input_0"));
    assert_eq!(labels.get(&2).map(String::as_str), Some("private_input_1"));
}

#[test]
fn cairo_wire_label_fallback_covers_all_input_indices() {
    if CairoTarget::check_cairo_available().is_err() {
        return;
    }

    let cairo_program = "tests/cairo_programs/multiplier.cairo";
    if !std::path::Path::new(cairo_program).exists() {
        return;
    }

    let executor = CairoExecutor::new(cairo_program).expect("create Cairo executor");
    let inspector = executor.constraint_inspector().unwrap();
    let labels = inspector.wire_labels();

    for idx in inspector
        .public_input_indices()
        .into_iter()
        .chain(inspector.private_input_indices().into_iter())
    {
        assert!(
            labels.contains_key(&idx),
            "expected Cairo wire labels to include input index {}",
            idx
        );
    }
}
