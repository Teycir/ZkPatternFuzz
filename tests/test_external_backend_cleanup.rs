use std::fs;

use tempfile::TempDir;
use zk_fuzzer::targets::{CircomTarget, NoirTarget, TargetCircuit};

fn require_circom() -> bool {
    match CircomTarget::check_circom_available() {
        Ok(version) => {
            println!("circom available: {version}");
            true
        }
        Err(err) => {
            eprintln!("Skipping Circom external cleanup test: {err}");
            false
        }
    }
}

fn require_nargo() -> bool {
    match NoirTarget::check_nargo_available() {
        Ok(version) => {
            println!("nargo available: {version}");
            true
        }
        Err(err) => {
            eprintln!("Skipping Noir external cleanup test: {err}");
            false
        }
    }
}

fn write_circom_external_fixture() -> TempDir {
    let dir = tempfile::tempdir().expect("temp circom fixture");
    let circuits_dir = dir.path().join("circuits");
    fs::create_dir_all(&circuits_dir).expect("create circuits dir");

    fs::write(
        circuits_dir.join("child.circom"),
        r#"include "../node_modules/circomlib/circuits/comparators.circom";

template Child() {
    signal input x;
    signal output y;

    component lt = LessThan(8);
    lt.in[0] <== x;
    lt.in[1] <== 10;
    y <== lt.out;
}
"#,
    )
    .expect("write child");

    fs::write(
        circuits_dir.join("main.circom"),
        r#"include "child.circom";

template Main() {
    signal input x;
    signal output y;

    component child = Child();
    child.x <== x;
    y <== child.y;
}

component main = Main();
"#,
    )
    .expect("write main");

    dir
}

#[test]
fn test_circom_compile_falls_back_to_vendored_circomlib_for_missing_external_include() {
    if !require_circom() {
        return;
    }

    let fixture = write_circom_external_fixture();
    let build_dir = tempfile::tempdir().expect("temp build dir");
    let main = fixture.path().join("circuits").join("main.circom");

    let mut target = CircomTarget::new(main.to_str().expect("utf8 path"), "Main")
        .expect("create circom target")
        .with_build_dir(build_dir.path().to_path_buf());

    target
        .compile()
        .expect("vendored circomlib fallback should make compile succeed");
    assert!(
        target.num_constraints() > 0,
        "compiled circuit should have constraints"
    );
}

fn write_noir_external_fixture() -> TempDir {
    let dir = tempfile::tempdir().expect("temp noir fixture");
    let src_dir = dir.path().join("src");
    fs::create_dir_all(&src_dir).expect("create src dir");

    fs::write(
        dir.path().join("Nargo.toml"),
        r#"[package]
name = "external_cleanup"
type = "bin"
authors = ["zk-fuzzer"]
"#,
    )
    .expect("write manifest");

    fs::write(
        src_dir.join("main.nr"),
        r#"fn main(loop_length: u32, flag: bool) {
    assert(loop_length < 32);
    if flag {
        assert(loop_length >= 0);
    }
}
"#,
    )
    .expect("write main.nr");

    dir
}

#[test]
fn test_noir_compile_falls_back_to_source_abi_when_artifact_json_is_missing() {
    if !require_nargo() {
        return;
    }

    let fixture = write_noir_external_fixture();
    let mut target =
        NoirTarget::new(fixture.path().to_str().expect("utf8 path")).expect("create noir target");

    target.compile().expect("compile noir target");
    assert_eq!(
        target.num_private_inputs(),
        2,
        "source-derived ABI should find both private inputs"
    );
    assert_eq!(
        target.num_public_inputs(),
        0,
        "source-derived ABI should not invent public inputs"
    );
}
