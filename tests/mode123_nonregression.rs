//! Mode 1/2/3 minimal CLI smoke regression.
//!
//! This executes `run`, `evidence`, and `chains` against a tiny real Circom target
//! with very small budgets so we can catch mode-level regressions quickly.

use std::path::{Path, PathBuf};
use std::process::Command;

const SKIP_ENV: &str = "ZKFUZZ_SKIP_MODE123_SMOKE";
const MODE1_CAMPAIGN_ENV: &str = "ZKFUZZ_MODE1_CAMPAIGN";
const MODE2_CAMPAIGN_ENV: &str = "ZKFUZZ_MODE2_CAMPAIGN";
const MODE3_CAMPAIGN_ENV: &str = "ZKFUZZ_MODE3_CAMPAIGN";
const DEFAULT_MODE1_CAMPAIGN: &str = "tests/campaigns/mode1_smoke.yaml";
const DEFAULT_MODE23_CAMPAIGN: &str = "tests/campaigns/mode123_smoke.yaml";

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
            "Skipping {} (unset {} to run standard Mode 1/2/3 smoke regression)",
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
    false
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

fn run_mode(
    bin: &Path,
    repo_root: &Path,
    temp_root: &Path,
    mode: &str,
    campaign: &Path,
    iterations: u64,
    timeout_sec: u64,
) {
    assert!(
        campaign.exists(),
        "Campaign for mode '{}' not found: {}",
        mode,
        campaign.display()
    );

    let output_dir = temp_root.join(format!("output_{}", mode));
    let build_cache_dir = temp_root.join("build_cache");
    let signal_dir = temp_root.join("signals");

    let output = Command::new(bin)
        .current_dir(repo_root)
        .arg(mode)
        .arg(campaign)
        .arg("--seed")
        .arg("42")
        .arg("--workers")
        .arg("1")
        .arg("--iterations")
        .arg(iterations.to_string())
        .arg("--timeout")
        .arg(timeout_sec.to_string())
        .arg("--simple-progress")
        .env("ZKF_OUTPUT_DIR", &output_dir)
        .env("ZKF_BUILD_CACHE_DIR", &build_cache_dir)
        .env("ZKF_RUN_SIGNAL_DIR", &signal_dir)
        .output()
        .unwrap_or_else(|err| panic!("Failed to launch '{}': {}", mode, err));

    if !output.status.success() {
        panic!(
            "Mode '{}' failed (status: {:?})\nstdout:\n{}\nstderr:\n{}",
            mode,
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let report_path = output_dir.join("report.json");
    let run_outcome_path = output_dir.join("run_outcome.json");
    assert!(
        report_path.exists() || run_outcome_path.exists(),
        "Mode '{}' completed but no report artifacts were found in {}",
        mode,
        output_dir.display()
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

    let mode1_campaign = campaign_path_for(MODE1_CAMPAIGN_ENV, DEFAULT_MODE1_CAMPAIGN, &repo_root);
    let mode2_campaign = campaign_path_for(MODE2_CAMPAIGN_ENV, DEFAULT_MODE23_CAMPAIGN, &repo_root);
    let mode3_campaign = campaign_path_for(MODE3_CAMPAIGN_ENV, DEFAULT_MODE23_CAMPAIGN, &repo_root);

    // Keep budgets tiny for non-regression speed while still executing each mode.
    run_mode(&bin, &repo_root, temp_root, "run", &mode1_campaign, 8, 20);
    run_mode(
        &bin,
        &repo_root,
        temp_root,
        "evidence",
        &mode2_campaign,
        8,
        25,
    );
    run_mode(
        &bin,
        &repo_root,
        temp_root,
        "chains",
        &mode3_campaign,
        6,
        25,
    );
}
