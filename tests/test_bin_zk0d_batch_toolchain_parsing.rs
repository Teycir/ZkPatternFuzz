#[allow(dead_code, unused_imports, clippy::all)]
mod zk0d_batch_impl {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bin/zk0d_batch.rs"
    ));

    #[test]
    fn parse_rustup_toolchain_names_extracts_first_token_and_filters_noise() {
        let raw = "\
nightly-x86_64-unknown-linux-gnu (default)\n\
stable-x86_64-unknown-linux-gnu\n\
info: syncing channel updates\n\
error: network unavailable\n";
        let parsed = parse_rustup_toolchain_names(raw);
        assert_eq!(
            parsed,
            vec![
                "nightly-x86_64-unknown-linux-gnu".to_string(),
                "stable-x86_64-unknown-linux-gnu".to_string()
            ]
        );
    }

    #[test]
    fn push_unique_nonempty_dedupes_and_ignores_empty_values() {
        let mut values = Vec::new();
        push_unique_nonempty(&mut values, "");
        push_unique_nonempty(&mut values, "nightly");
        push_unique_nonempty(&mut values, "nightly");
        push_unique_nonempty(&mut values, " stable ");
        assert_eq!(values, vec!["nightly".to_string(), "stable".to_string()]);
    }

    #[test]
    fn resolve_target_run_overrides_matches_target_and_loads_env_overrides() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target_path = temp.path().join("account_creation.circom");
        std::fs::write(&target_path, "template Main() {}").expect("write target");

        let overrides_dir = temp.path().join("external").join("target_run_overrides");
        std::fs::create_dir_all(&overrides_dir).expect("mkdir overrides");
        let override_path = overrides_dir.join("ext999_example.json");
        std::fs::write(
            &override_path,
            r#"{
  "run_overrides": {
    "batch_jobs": 1,
    "workers": 2,
    "iterations": 123,
    "timeout": 777,
    "env": {
      "ZKF_PTAU_PATH": "/tmp/pot23.ptau",
      "ENABLE_FLAG": true,
      "MAX_RETRIES": 5
    }
  }
}"#,
        )
        .expect("write override");

        let matrix_path = temp.path().join("matrix.yaml");
        let matrix_yaml = format!(
            "version: 1\ntargets:\n  - name: ext999_example\n    target_circuit: \"{}\"\n    framework: circom\n    run_overrides_file: external/target_run_overrides/ext999_example.json\n",
            target_path.display()
        );
        std::fs::write(&matrix_path, matrix_yaml).expect("write matrix");

        let resolved = resolve_target_run_overrides(&matrix_path, &target_path, "circom")
            .expect("resolve overrides")
            .expect("matching override");
        assert_eq!(resolved.target_name, "ext999_example");
        assert_eq!(resolved.overrides.batch_jobs, Some(1));
        assert_eq!(resolved.overrides.workers, Some(2));
        assert_eq!(resolved.overrides.iterations, Some(123));
        assert_eq!(resolved.overrides.timeout, Some(777));

        let env = collect_target_override_env(&resolved.overrides).expect("env overrides");
        assert_eq!(
            env.get("ZKF_PTAU_PATH"),
            Some(&"/tmp/pot23.ptau".to_string())
        );
        assert_eq!(env.get("ENABLE_FLAG"), Some(&"1".to_string()));
        assert_eq!(env.get("MAX_RETRIES"), Some(&"5".to_string()));

        let no_match = resolve_target_run_overrides(&matrix_path, &target_path, "halo2")
            .expect("resolve no match");
        assert!(no_match.is_none());
    }

    #[test]
    fn collect_target_override_env_rejects_non_scalar_values() {
        let mut overrides = TargetRunOverrides::default();
        let invalid: serde_yaml::Value = serde_yaml::from_str("[1, 2, 3]").expect("yaml");
        overrides.env.insert("BAD".to_string(), invalid);
        let err =
            collect_target_override_env(&overrides).expect_err("expected non-scalar rejection");
        assert!(err
            .to_string()
            .contains("Unsupported target override env value type"));
    }
}
