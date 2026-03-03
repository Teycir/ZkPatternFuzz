use std::fs;
use std::path::Path;

use tempfile::tempdir;
use zk_fuzzer::target_overrides::{collect_target_override_env, resolve_target_run_overrides};

fn write(path: &Path, contents: &str) {
    fs::write(path, contents).expect("failed writing test fixture");
}

#[test]
fn resolves_matching_target_override_and_env_values() {
    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("circuit.circom");
    write(&target, "template main() {}");

    let overrides = dir.path().join("ext017.json");
    write(
        &overrides,
        r#"{
  "run_overrides": {
    "workers": 3,
    "iterations": 40,
    "timeout": 900,
    "env": {
      "NODE_OPTIONS": "--max_old_space_size=8192",
      "ZKF_PTAU_PATH": "/tmp/pot23_final.ptau",
      "ENABLE_X": true,
      "RETRY_COUNT": 7
    }
  }
}"#,
    );

    let index = dir.path().join("targets.yaml");
    write(
        &index,
        &format!(
            "targets:\n  - name: ext017\n    target_circuit: {}\n    framework: circom\n    run_overrides_file: {}\n",
            target.display(),
            overrides.display()
        ),
    );

    let resolved = resolve_target_run_overrides(&index, &target, "circom")
        .expect("resolve should succeed")
        .expect("target should match");

    assert_eq!(resolved.target_name, "ext017");
    assert_eq!(resolved.overrides.workers, Some(3));
    assert_eq!(resolved.overrides.iterations, Some(40));
    assert_eq!(resolved.overrides.timeout, Some(900));

    let env = collect_target_override_env(&resolved.overrides).expect("env conversion should pass");
    assert_eq!(
        env.get("NODE_OPTIONS").map(String::as_str),
        Some("--max_old_space_size=8192")
    );
    assert_eq!(
        env.get("ZKF_PTAU_PATH").map(String::as_str),
        Some("/tmp/pot23_final.ptau")
    );
    assert_eq!(env.get("ENABLE_X").map(String::as_str), Some("1"));
    assert_eq!(env.get("RETRY_COUNT").map(String::as_str), Some("7"));
}

#[test]
fn returns_none_for_framework_mismatch() {
    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("circuit.circom");
    write(&target, "template main() {}");

    let overrides = dir.path().join("override.json");
    write(&overrides, r#"{"run_overrides":{"workers":2}}"#);

    let index = dir.path().join("targets.yaml");
    write(
        &index,
        &format!(
            "targets:\n  - name: t\n    target_circuit: {}\n    framework: noir\n    run_overrides_file: {}\n",
            target.display(),
            overrides.display()
        ),
    );

    let resolved = resolve_target_run_overrides(&index, &target, "circom").expect("resolve");
    assert!(resolved.is_none());
}

#[test]
fn errors_when_multiple_entries_match_same_target() {
    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("circuit.circom");
    write(&target, "template main() {}");

    let override_a = dir.path().join("a.json");
    let override_b = dir.path().join("b.json");
    write(&override_a, r#"{"run_overrides":{"workers":1}}"#);
    write(&override_b, r#"{"run_overrides":{"workers":2}}"#);

    let index = dir.path().join("targets.yaml");
    write(
        &index,
        &format!(
            "targets:\n  - name: a\n    target_circuit: {}\n    framework: circom\n    run_overrides_file: {}\n  - name: b\n    target_circuit: {}\n    framework: circom\n    run_overrides_file: {}\n",
            target.display(),
            override_a.display(),
            target.display(),
            override_b.display()
        ),
    );

    let err = resolve_target_run_overrides(&index, &target, "circom").expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("Multiple target overrides matched"));
}
