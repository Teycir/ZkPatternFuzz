use super::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_halo2_target_from_json_spec() {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("test_circuit.json");
    fs::write(
        &spec_path,
        r#"{
                "name": "test_circuit",
                "k": 12,
                "advice_columns": 3,
                "fixed_columns": 1,
                "instance_columns": 1,
                "constraints": 42,
                "private_inputs": 4,
                "public_inputs": 1,
                "lookups": 2
            }"#,
    )
    .unwrap();

    let mut target = Halo2Target::new(spec_path.to_str().unwrap()).unwrap();
    target.setup().unwrap();

    assert_eq!(target.name(), "test_circuit");
    assert_eq!(target.num_constraints(), 42);
    assert_eq!(target.num_private_inputs(), 4);
    assert_eq!(target.num_public_inputs(), 1);
}

#[test]
fn test_halo2_execute_metadata_only_spec_returns_public_projection() {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("test.json");
    fs::write(
        &spec_path,
        r#"{
                "name":"test",
                "k":12,
                "advice_columns":2,
                "fixed_columns":1,
                "instance_columns":1,
                "constraints":1,
                "private_inputs":0,
                "public_inputs":2,
                "lookups":0
            }"#,
    )
    .unwrap();

    let mut target = Halo2Target::new(spec_path.to_str().unwrap()).unwrap();
    target.setup().unwrap();

    let inputs = vec![FieldElement::zero(), FieldElement::one()];
    let result = target.execute(&inputs);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), inputs);
}

#[test]
fn test_halo2_key_setup_reports_not_implemented() {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("test.json");
    fs::write(
        &spec_path,
        r#"{
                "name":"test",
                "k":12,
                "advice_columns":2,
                "fixed_columns":1,
                "instance_columns":1,
                "constraints":1,
                "private_inputs":0,
                "public_inputs":1,
                "lookups":0
            }"#,
    )
    .unwrap();

    let mut target = Halo2Target::new(spec_path.to_str().unwrap()).unwrap();
    target.setup().unwrap();
    let result = target.setup_keys();
    assert!(result.is_err());
}

#[test]
fn test_analysis_unused_columns() {
    let source = r#"
            let a1 = meta.advice_column();
            let a2 = meta.advice_column();
            let a3 = meta.advice_column();
            
            region.query_advice(a1, Rotation::cur())
        "#;

    let issues = analysis::check_unused_columns(source);
    assert!(!issues.is_empty());
}

#[test]
fn test_halo2_cargo_command_uses_configured_toolchain() {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("test.json");
    fs::write(
        &spec_path,
        r#"{
                "name":"test",
                "k":12,
                "advice_columns":2,
                "fixed_columns":1,
                "instance_columns":1,
                "constraints":1,
                "private_inputs":0,
                "public_inputs":1,
                "lookups":0
            }"#,
    )
    .unwrap();

    let mut target = Halo2Target::new(spec_path.to_str().unwrap()).unwrap();
    target.cargo_toolchain = Some("nightly".to_string());
    let command = target.cargo_command();
    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect();
    assert!(args.iter().any(|arg| arg == "+nightly"));
}
