    use super::*;

    #[test]
    fn test_execution_result() {
        let result =
            ExecutionResult::success(vec![FieldElement::one()], ExecutionCoverage::default());
        assert!(result.success);
        assert!(result.error.is_none());

        let failure = ExecutionResult::failure("test error".to_string());
        assert!(!failure.success);
        assert_eq!(failure.error, Some("test error".to_string()));
    }

    #[test]
    fn test_coverage_fallback_uses_output_hash_when_constraints_missing() {
        let outputs = vec![FieldElement::from_u64(7), FieldElement::from_u64(11)];
        let coverage = coverage_from_results_or_output_hash(vec![], &outputs, "test");
        assert!(coverage.evaluated_constraints.is_empty());
        assert_eq!(
            coverage.coverage_hash,
            ExecutionCoverage::with_output_hash(&outputs).coverage_hash
        );
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
    fn test_circom_ptau_autodetect_prefers_env_override() {
        let temp = tempfile::tempdir().expect("tempdir");
        let ptau = temp.path().join("custom.ptau");
        std::fs::write(&ptau, b"ptau-test").expect("write");

        let previous = std::env::var("ZKF_PTAU_PATH").ok();
        std::env::set_var("ZKF_PTAU_PATH", &ptau);
        let detected = CircomExecutor::autodetect_ptau_path("circuits/example.circom");

        match previous {
            Some(value) => std::env::set_var("ZKF_PTAU_PATH", value),
            None => std::env::remove_var("ZKF_PTAU_PATH"),
        }

        assert_eq!(detected.as_deref(), Some(ptau.as_path()));
    }

    #[test]
    fn test_circom_ptau_autodetect_finds_bins_ptau_fixture() {
        let temp = tempfile::tempdir().expect("tempdir");
        let circuit_dir = temp.path().join("project").join("circuits");
        std::fs::create_dir_all(&circuit_dir).expect("mkdir circuits");
        let circuit_path = circuit_dir.join("sample.circom");
        std::fs::write(&circuit_path, "pragma circom 2.0.0;").expect("write circuit");

        let bins_ptau_dir = temp.path().join("project").join("bins").join("ptau");
        std::fs::create_dir_all(&bins_ptau_dir).expect("mkdir ptau");
        let ptau_path = bins_ptau_dir.join("pot12_final.ptau");
        std::fs::write(&ptau_path, b"ptau-test").expect("write ptau");

        let previous = std::env::var("ZKF_PTAU_PATH").ok();
        std::env::remove_var("ZKF_PTAU_PATH");
        let detected =
            CircomExecutor::autodetect_ptau_path(circuit_path.to_str().expect("utf8 circuit path"));
        match previous {
            Some(value) => std::env::set_var("ZKF_PTAU_PATH", value),
            None => std::env::remove_var("ZKF_PTAU_PATH"),
        }

        assert_eq!(detected.as_deref(), Some(ptau_path.as_path()));
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
