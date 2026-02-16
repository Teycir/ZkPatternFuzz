//! Unified scan minimal CLI smoke regression.
//!
//! This executes `scan` in mono and multi families against a tiny real Circom target
//! with very small budgets so we can catch flow-level regressions quickly.

use std::path::{Path, PathBuf};
use std::process::Command;

const SKIP_ENV: &str = "ZKFUZZ_SKIP_MODE123_SMOKE";
const MONO_PATTERN_ENV: &str = "ZKFUZZ_SCAN_MONO_PATTERN";
const MULTI_PATTERN_ENV: &str = "ZKFUZZ_SCAN_MULTI_PATTERN";
const TARGET_CIRCUIT_ENV: &str = "ZKFUZZ_SCAN_TARGET_CIRCUIT";
const MAIN_COMPONENT_ENV: &str = "ZKFUZZ_SCAN_MAIN_COMPONENT";
const DEFAULT_MONO_PATTERN: &str = "tests/patterns/scan_smoke_mono.yaml";
const DEFAULT_MULTI_PATTERN: &str = "tests/patterns/scan_smoke_multi.yaml";
const DEFAULT_TARGET_CIRCUIT: &str = "tests/ground_truth/chains/mode123_smoke/mode123_main.circom";
const DEFAULT_MAIN_COMPONENT: &str = "Mode123Main";

fn should_skip_mode123_smoke() -> bool {
    std::env::var(SKIP_ENV)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn maybe_skip(test_name: &str) -> bool {
    if should_skip_mode123_smoke() {
        eprintln!(
            "Skipping {} (unset {} to run standard scan smoke regression)",
            test_name, SKIP_ENV
        );
        return true;
    }

    // This smoke executes real Circom backend paths and requires both tools.
    if !command_available("circom") || !command_available("snarkjs") {
        eprintln!(
            "Skipping {} (requires both 'circom' and 'snarkjs' on PATH)",
            test_name
        );
        return true;
    }

    if !output_root_writable() {
        eprintln!(
            "Skipping {} (cannot write to ~/ZkFuzz output root in this environment)",
            test_name
        );
        return true;
    }
    false
}

fn output_root_writable() -> bool {
    let home = match std::env::var("HOME") {
        Ok(value) => PathBuf::from(value),
        Err(_) => return false,
    };
    let output_root = home.join("ZkFuzz");
    if std::fs::create_dir_all(&output_root).is_err() {
        return false;
    }

    let probe = output_root.join(".mode123_smoke_write_probe");
    if std::fs::write(&probe, b"probe").is_err() {
        return false;
    }

    let _ = std::fs::remove_file(probe);
    true
}

fn command_available(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--help")
        .output()
        .is_ok()
}

fn campaign_path_for(env_name: &str, default_path: &str, repo_root: &Path) -> PathBuf {
    match std::env::var(env_name) {
        Ok(value) => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                repo_root.join(path)
            }
        }
        Err(std::env::VarError::NotPresent) => repo_root.join(default_path),
        Err(err) => panic!("Invalid {} value: {}", env_name, err),
    }
}

struct ScanRun<'a> {
    label: &'a str,
    family: &'a str,
    pattern: &'a Path,
    target_circuit: &'a Path,
    main_component: &'a str,
    iterations: u64,
    timeout_sec: u64,
}

fn run_scan(bin: &Path, repo_root: &Path, temp_root: &Path, run: ScanRun<'_>) {
    assert!(
        run.pattern.exists(),
        "Pattern for scan '{}' not found: {}",
        run.label,
        run.pattern.display()
    );
    assert!(
        run.target_circuit.exists(),
        "Target circuit for scan '{}' not found: {}",
        run.label,
        run.target_circuit.display()
    );

    let build_cache_dir = temp_root.join("build_cache");
    let signal_dir = temp_root.join("signals");
    let engagement_dir = temp_root.join(format!("engagement_{}", run.label));

    let output = Command::new(bin)
        .current_dir(repo_root)
        .arg("scan")
        .arg(run.pattern)
        .arg("--family")
        .arg(run.family)
        .arg("--target-circuit")
        .arg(run.target_circuit)
        .arg("--main-component")
        .arg(run.main_component)
        .arg("--framework")
        .arg("circom")
        .arg("--seed")
        .arg("42")
        .arg("--workers")
        .arg("1")
        .arg("--iterations")
        .arg(run.iterations.to_string())
        .arg("--timeout")
        .arg(run.timeout_sec.to_string())
        .arg("--simple-progress")
        .env("ZKF_BUILD_CACHE_DIR", &build_cache_dir)
        .env("ZKF_RUN_SIGNAL_DIR", &signal_dir)
        .env("ZKF_ENGAGEMENT_DIR", &engagement_dir)
        .output()
        .unwrap_or_else(|err| panic!("Failed to launch scan '{}': {}", run.label, err));

    if !output.status.success() {
        panic!(
            "Scan '{}' failed (status: {:?})\nstdout:\n{}\nstderr:\n{}",
            run.label,
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let report_path = engagement_dir.join("latest.json");
    let run_outcome_path = engagement_dir.join("summary.json");
    assert!(
        report_path.exists() || run_outcome_path.exists(),
        "Scan '{}' completed but no engagement artifacts were found in {}",
        run.label,
        engagement_dir.display()
    );
}

#[test]
fn mode123_cli_smoke_non_regression() {
    if maybe_skip("mode123_cli_smoke_non_regression") {
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_zk-fuzzer"));
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let temp_root = temp_dir.path();

    let mono_pattern = campaign_path_for(MONO_PATTERN_ENV, DEFAULT_MONO_PATTERN, &repo_root);
    let multi_pattern = campaign_path_for(MULTI_PATTERN_ENV, DEFAULT_MULTI_PATTERN, &repo_root);
    let target_circuit = campaign_path_for(TARGET_CIRCUIT_ENV, DEFAULT_TARGET_CIRCUIT, &repo_root);
    let main_component =
        std::env::var(MAIN_COMPONENT_ENV).unwrap_or_else(|_| DEFAULT_MAIN_COMPONENT.to_string());

    // `scan` runs a single YAML-selected mono/multi pass.
    run_scan(
        &bin,
        &repo_root,
        temp_root,
        ScanRun {
            label: "mono",
            family: "mono",
            pattern: &mono_pattern,
            target_circuit: &target_circuit,
            main_component: &main_component,
            iterations: 8,
            timeout_sec: 25,
        },
    );
    run_scan(
        &bin,
        &repo_root,
        temp_root,
        ScanRun {
            label: "multi",
            family: "multi",
            pattern: &multi_pattern,
            target_circuit: &target_circuit,
            main_component: &main_component,
            iterations: 6,
            timeout_sec: 25,
        },
    );
}
