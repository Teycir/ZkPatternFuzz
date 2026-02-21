use super::*;

#[test]
fn test_execution_result() {
    let result = ExecutionResult::success(vec![FieldElement::one()], ExecutionCoverage::default());
    assert!(result.success);
    assert!(result.error.is_none());

    let failure = ExecutionResult::failure("test error".to_string());
    assert!(!failure.success);
    assert_eq!(failure.error, Some("test error".to_string()));
}

#[test]
fn test_coverage_from_results_returns_none_when_constraints_missing() {
    assert!(coverage_from_results(vec![]).is_none());
}

#[test]
fn test_halo2_plonk_constraint_checking() {
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
fn test_halo2_constraint_checks_with_json_spec() {
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
fn test_halo2_wire_label_fallback_for_metadata_only_json_spec() {
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
fn test_cairo_wire_label_fallback_covers_all_input_indices() {
    if crate::targets::CairoTarget::check_cairo_available().is_err() {
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

#[cfg(unix)]
#[test]
fn test_circom_include_paths_invalid_utf8_does_not_panic() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    struct EnvRestore {
        previous: Option<OsString>,
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var("CIRCOM_INCLUDE_PATHS", value),
                None => std::env::remove_var("CIRCOM_INCLUDE_PATHS"),
            }
        }
    }

    let mut restore = EnvRestore {
        previous: std::env::var_os("CIRCOM_INCLUDE_PATHS"),
    };

    let invalid = OsString::from_vec(vec![0xff, b'x', b':', b'y']);
    std::env::set_var("CIRCOM_INCLUDE_PATHS", invalid);

    let result =
        std::panic::catch_unwind(|| CircomExecutor::default_include_paths_for("dummy.circom"));
    assert!(
        result.is_ok(),
        "default_include_paths_for should gracefully handle invalid UTF-8 env values"
    );

    // Explicitly restore before assertion exits to keep global env clean in this process.
    match restore.previous.take() {
        Some(value) => std::env::set_var("CIRCOM_INCLUDE_PATHS", value),
        None => std::env::remove_var("CIRCOM_INCLUDE_PATHS"),
    }
}

#[test]
fn test_circom_include_paths_include_vendor_from_circuit_ancestors() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let root = temp_dir.path();
    let circuits_dir = root.join("circuits");
    let vendor_dir = root.join("vendor").join("circomlib").join("circuits");

    std::fs::create_dir_all(&circuits_dir).expect("mkdir circuits");
    std::fs::create_dir_all(&vendor_dir).expect("mkdir vendor/circomlib/circuits");

    let circuit_path = circuits_dir.join("example.circom");
    std::fs::write(&circuit_path, "pragma circom 2.0.0;").expect("write circuit");
    std::fs::write(vendor_dir.join("poseidon.circom"), "// fixture").expect("write include");

    let include_paths =
        CircomExecutor::default_include_paths_for(circuit_path.to_str().expect("utf8 path"));
    let expected_vendor_root = root.join("vendor");
    assert!(
        include_paths.iter().any(|p| p == &expected_vendor_root),
        "expected include paths to contain '{}', got {:?}",
        expected_vendor_root.display(),
        include_paths
    );
}
