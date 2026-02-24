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
fn test_halo2_key_setup_writes_canonical_artifacts_for_json_spec() {
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

    target.setup_keys().expect("Halo2 key setup should succeed");

    let keys_dir = spec_path
        .parent()
        .unwrap()
        .join("target")
        .join("halo2_build")
        .join("keys");
    let proving_key_path = keys_dir.join("halo2_proving.key");
    let verification_key_path = keys_dir.join("halo2_verification.key");

    let proving_key = fs::read(&proving_key_path).expect("read proving key");
    let verification_key = fs::read(&verification_key_path).expect("read verification key");
    assert!(!proving_key.is_empty());
    assert!(!verification_key.is_empty());

    let manifest_path = spec_path
        .parent()
        .unwrap()
        .join("target")
        .join("halo2_build")
        .join("halo2_key_setup_manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read key setup manifest"))
            .expect("parse key setup manifest");
    assert_eq!(manifest["framework"], "halo2");
    assert_eq!(manifest["setup_mode"], "canonical_adapter");
    assert_eq!(manifest["contract_version"], 1);
    assert_eq!(manifest["commitment"], "kzg");
}

#[test]
fn test_halo2_key_setup_is_deterministic_for_identical_json_spec() {
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
    target.setup_keys().expect("first key setup");

    let build_dir = spec_path
        .parent()
        .unwrap()
        .join("target")
        .join("halo2_build");
    let proving_key_path = build_dir.join("keys").join("halo2_proving.key");
    let verification_key_path = build_dir.join("keys").join("halo2_verification.key");
    let manifest_path = build_dir.join("halo2_key_setup_manifest.json");

    let first_proving = fs::read(&proving_key_path).expect("read first proving key");
    let first_verification = fs::read(&verification_key_path).expect("read first verification key");
    let first_manifest = fs::read(&manifest_path).expect("read first manifest");

    target.setup_keys().expect("second key setup");

    let second_proving = fs::read(&proving_key_path).expect("read second proving key");
    let second_verification =
        fs::read(&verification_key_path).expect("read second verification key");
    let second_manifest = fs::read(&manifest_path).expect("read second manifest");

    assert_eq!(first_proving, second_proving);
    assert_eq!(first_verification, second_verification);
    assert_eq!(first_manifest, second_manifest);
}

#[test]
fn test_halo2_canonical_prove_verify_for_json_spec() {
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
                "private_inputs":1,
                "public_inputs":2,
                "lookups":0
            }"#,
    )
    .unwrap();

    let mut target = Halo2Target::new(spec_path.to_str().unwrap()).unwrap();
    target.setup().unwrap();

    let witness = vec![
        FieldElement::from_u64(7),
        FieldElement::from_u64(11),
        FieldElement::from_u64(13),
    ];
    let proof = target
        .prove(&witness)
        .expect("canonical prove should succeed");

    let public_inputs = vec![FieldElement::from_u64(7), FieldElement::from_u64(11)];
    assert!(target
        .verify(&proof, &public_inputs)
        .expect("canonical verify should parse"));

    let mismatched_public_inputs = vec![FieldElement::from_u64(7), FieldElement::from_u64(12)];
    assert!(!target
        .verify(&proof, &mismatched_public_inputs)
        .expect("canonical verify should parse"));
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
    let command = target
        .cargo_command_with_binary_and_toolchain("cargo", target.cargo_toolchain.as_deref())
        .expect("cargo command should be constructed");
    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect();
    assert!(args.iter().any(|arg| arg == "+nightly"));
}
