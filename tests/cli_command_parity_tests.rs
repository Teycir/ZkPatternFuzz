use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zk-fuzzer"))
}

fn assert_successful_help(subcommand: &str) {
    let output = Command::new(binary_path())
        .arg(subcommand)
        .arg("--help")
        .output()
        .unwrap_or_else(|err| panic!("Failed to run '{} --help': {}", subcommand, err));
    assert!(
        output.status.success(),
        "{} --help failed: {}",
        subcommand,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(subcommand),
        "Expected help output to mention '{}', got: {}",
        subcommand,
        stdout
    );
}

#[test]
fn root_help_lists_legacy_and_scan_commands() {
    let output = Command::new(binary_path())
        .arg("--help")
        .output()
        .expect("Failed to run --help");
    assert!(
        output.status.success(),
        "--help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in ["scan", "run", "evidence", "chains"] {
        assert!(
            stdout.contains(command),
            "Root help is missing command '{}': {}",
            command,
            stdout
        );
    }
}

#[test]
fn legacy_subcommand_help_smoke() {
    for subcommand in ["run", "evidence", "chains"] {
        assert_successful_help(subcommand);
    }
}

#[test]
fn config_without_subcommand_defaults_to_run_mode() {
    let temp = tempfile::tempdir().expect("tempdir");
    let signal_dir = temp.path().join("run_signals");
    let cache_dir = temp.path().join("build_cache");
    let output_root = temp.path().join("scan_output");

    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("campaigns")
        .join("examples")
        .join("trusted_setup_audit.yaml");
    assert!(
        config_path.exists(),
        "Missing test campaign config '{}'",
        config_path.display()
    );

    let output = Command::new(binary_path())
        .arg("--config")
        .arg(config_path)
        .arg("--dry-run")
        .arg("--simple-progress")
        .env("ZKF_RUN_SIGNAL_DIR", &signal_dir)
        .env("ZKF_BUILD_CACHE_DIR", &cache_dir)
        .env("ZKF_SCAN_OUTPUT_ROOT", &output_root)
        .output()
        .expect("Failed to run legacy default mode");

    assert!(
        output.status.success(),
        "Expected --config without subcommand to succeed in dry-run mode. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
