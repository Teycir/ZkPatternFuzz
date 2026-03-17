use std::path::PathBuf;

use tempfile::TempDir;
use zk_fuzzer::targets::{circom_analysis, CircomTarget};

fn test_circuit_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("circuits")
        .join(format!("{}.circom", name))
}

fn isolated_target(name: &str, component: &str) -> (TempDir, CircomTarget) {
    let circuit_path = test_circuit_path(name);
    let build_dir = tempfile::tempdir().expect("temp circom build dir");
    let target = CircomTarget::new(circuit_path.to_str().expect("utf8 path"), component)
        .expect("create CircomTarget")
        .with_build_dir(build_dir.path().to_path_buf());
    (build_dir, target)
}

#[test]
fn test_circom_signal_extraction_uses_public_analysis_api() {
    let source = r#"
signal input a;
signal input b;
signal output c;
signal private input d;
"#;

    let signals = circom_analysis::extract_signals(source);
    assert_eq!(signals.len(), 4);
    assert_eq!(signals[0].name, "a");
    assert_eq!(
        signals[0].direction,
        circom_analysis::SignalDirection::Input
    );
}

#[test]
fn test_circom_constraint_loading_works_from_public_target_api() {
    let (_build_dir, mut target) = isolated_target("multiplier", "Multiplier");
    if CircomTarget::check_circom_available().is_err() {
        return;
    }

    target.compile().expect("compile multiplier");
    let constraints = target.load_constraints().expect("load constraints");
    assert!(!constraints.is_empty(), "expected at least one constraint");
}
