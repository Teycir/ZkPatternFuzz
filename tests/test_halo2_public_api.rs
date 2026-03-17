use std::fs;

use tempfile::tempdir;
use zk_fuzzer::fuzzer::FieldElement;
use zk_fuzzer::targets::{halo2_analysis, Halo2Target, TargetCircuit};

fn write_halo2_json_spec(path: &std::path::Path, private_inputs: usize, public_inputs: usize) {
    fs::write(
        path,
        format!(
            r#"{{
                "name":"test",
                "k":12,
                "advice_columns":2,
                "fixed_columns":1,
                "instance_columns":1,
                "constraints":1,
                "private_inputs":{private_inputs},
                "public_inputs":{public_inputs},
                "lookups":0
            }}"#
        ),
    )
    .expect("write halo2 json spec");
}

#[test]
fn test_halo2_target_from_json_spec_uses_public_api() {
    let dir = tempdir().expect("tempdir");
    let spec_path = dir.path().join("test_circuit.json");
    write_halo2_json_spec(&spec_path, 4, 1);

    let mut target = Halo2Target::new(spec_path.to_str().expect("utf8 path")).expect("target");
    target.setup().expect("setup");

    assert_eq!(target.name(), "test_circuit");
    assert_eq!(target.num_constraints(), 1);
    assert_eq!(target.num_private_inputs(), 4);
    assert_eq!(target.num_public_inputs(), 1);
}

#[test]
fn test_halo2_key_setup_writes_canonical_artifacts_for_json_spec() {
    let dir = tempdir().expect("tempdir");
    let spec_path = dir.path().join("test.json");
    write_halo2_json_spec(&spec_path, 0, 1);

    let mut target = Halo2Target::new(spec_path.to_str().expect("utf8 path")).expect("target");
    target.setup().expect("setup");
    target.setup_keys().expect("key setup");

    let build_dir = spec_path
        .parent()
        .expect("parent")
        .join("target/halo2_build");
    let proving_key_path = build_dir.join("keys/halo2_proving.key");
    let verification_key_path = build_dir.join("keys/halo2_verification.key");
    let manifest_path = build_dir.join("halo2_key_setup_manifest.json");

    assert!(!fs::read(&proving_key_path)
        .expect("read proving key")
        .is_empty());
    assert!(!fs::read(&verification_key_path)
        .expect("read verification key")
        .is_empty());

    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    assert_eq!(manifest["framework"], "halo2");
    assert_eq!(manifest["setup_mode"], "canonical_adapter");
    assert_eq!(manifest["contract_version"], 1);
}

#[test]
fn test_halo2_unused_columns_analysis_uses_public_api() {
    let source = r#"
let a1 = meta.advice_column();
let a2 = meta.advice_column();
let a3 = meta.advice_column();

region.query_advice(a1, Rotation::cur())
"#;

    let issues = halo2_analysis::check_unused_columns(source);
    assert!(!issues.is_empty());
}

#[test]
fn test_halo2_execute_metadata_only_spec_returns_public_projection() {
    let dir = tempdir().expect("tempdir");
    let spec_path = dir.path().join("test.json");
    write_halo2_json_spec(&spec_path, 0, 2);

    let mut target = Halo2Target::new(spec_path.to_str().expect("utf8 path")).expect("target");
    target.setup().expect("setup");

    let inputs = vec![FieldElement::zero(), FieldElement::one()];
    let result = target.execute(&inputs).expect("execute");
    assert_eq!(result, inputs);
}
