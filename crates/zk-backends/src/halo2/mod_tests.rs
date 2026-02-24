use super::*;
use std::fs;
use std::os::unix::process::ExitStatusExt;
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
        .cargo_command_with_binary_and_toolchain("cargo", target.cargo_toolchain.as_deref(), false)
        .expect("cargo command should be constructed");
    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect();
    assert!(args.iter().any(|arg| arg == "+nightly"));
}

#[test]
fn test_parse_git_db_repo_paths_from_text_extracts_repo_paths() {
    let text = "failed to create directory `/tmp/run/_cargo_home/git/db/bls12_381-f1081d7d6f0a3320`\nfailed to fetch into: /tmp/run/_cargo_home/git/db/halo2-af1b752da3db31e1";
    let repos = parse_git_db_repo_paths_from_text(text);
    assert_eq!(repos.len(), 2);
    assert!(repos
        .iter()
        .any(|path| path.ends_with("bls12_381-f1081d7d6f0a3320")));
    assert!(repos
        .iter()
        .any(|path| path.ends_with("halo2-af1b752da3db31e1")));
}

#[test]
fn test_warm_git_db_aliases_repairs_missing_repo_alias() {
    let temp = tempdir().expect("tempdir");
    let db = temp.path().join("git").join("db");
    let seeded = db.join("bls12_381-a041ea989373b087");
    let missing = db.join("bls12_381-f1081d7d6f0a3320");
    let seeded_pack = seeded.join("objects").join("pack");
    fs::create_dir_all(&seeded_pack).expect("create seeded pack dir");
    fs::write(seeded_pack.join("pack-seeded.pack"), b"seed").expect("write seeded pack");
    fs::create_dir_all(missing.join("objects").join("pack")).expect("create missing pack dir");

    let stderr = format!(
        "failed to create directory `{}`\ncan't checkout from 'https://github.com/scroll-tech/bls12_381': you are in the offline mode (--offline)",
        missing.display()
    );
    let output = std::process::Output {
        status: std::process::ExitStatus::from_raw(1),
        stdout: Vec::new(),
        stderr: stderr.into_bytes(),
    };

    let repaired = warm_git_db_aliases_from_output(&output);
    assert!(repaired, "expected alias repair to copy seeded repo");
    assert!(
        git_db_repo_has_content(&missing),
        "missing alias should become non-empty after repair"
    );
}

#[test]
fn test_parse_channel_from_rust_toolchain_file_toml_format() {
    let temp = tempdir().expect("tempdir");
    let toolchain_path = temp.path().join("rust-toolchain");
    fs::write(
        &toolchain_path,
        "[toolchain]\nchannel = \"nightly-2025-12-01\"\ncomponents = [\"rustfmt\"]\n",
    )
    .expect("write rust-toolchain");

    let parsed = parse_channel_from_rust_toolchain_file(&toolchain_path);
    assert_eq!(parsed.as_deref(), Some("nightly-2025-12-01"));
}

#[test]
fn test_parse_channel_from_rust_toolchain_file_plain_format() {
    let temp = tempdir().expect("tempdir");
    let toolchain_path = temp.path().join("rust-toolchain");
    fs::write(&toolchain_path, "stable\n").expect("write rust-toolchain");

    let parsed = parse_channel_from_rust_toolchain_file(&toolchain_path);
    assert_eq!(parsed.as_deref(), Some("stable"));
}

#[test]
fn test_inferred_manifest_toolchain_hints_prioritize_rust_toolchain() {
    let temp = tempdir().expect("tempdir");
    let manifest_path = temp.path().join("Cargo.toml");
    fs::write(
        &manifest_path,
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nrust-version = \"1.82\"\n",
    )
    .expect("write manifest");
    fs::write(
        temp.path().join("rust-toolchain"),
        "[toolchain]\nchannel = \"nightly-2025-12-01\"\n",
    )
    .expect("write rust-toolchain");

    let target = Halo2Target::new(manifest_path.to_str().expect("manifest path")).expect("target");
    let hints = target.inferred_manifest_toolchain_hints();
    assert_eq!(
        hints.first().map(String::as_str),
        Some("nightly-2025-12-01"),
        "rust-toolchain channel should be the first hint"
    );
    assert!(
        hints.iter().any(|hint| hint == "1.82"),
        "manifest rust-version hints should still be included"
    );
}
