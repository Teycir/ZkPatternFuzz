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

fn read_json(path: &Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("Failed to read JSON '{}': {}", path.display(), err));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("Invalid JSON in '{}': {}", path.display(), err))
}

fn assert_exists(path: &Path, label: &str, run_label: &str) {
    assert!(
        path.exists(),
        "Scan '{}' missing {} at {}",
        run_label,
        label,
        path.display()
    );
}

fn assert_engagement_contract(
    engagement_dir: &Path,
    mode_folder: &str,
    expected_command: &str,
    run_label: &str,
) {
    // Public contract files for scan-mode engagement output.
    let required = [
        (
            "engagement latest pointer",
            engagement_dir.join("latest.json"),
        ),
        (
            "engagement summary json",
            engagement_dir.join("summary.json"),
        ),
        (
            "engagement summary markdown",
            engagement_dir.join("summary.md"),
        ),
        (
            "engagement event stream",
            engagement_dir.join("log/events.jsonl"),
        ),
        (
            "engagement incremental results stream",
            engagement_dir.join("incremental_results.jsonl"),
        ),
        (
            "mode latest pointer",
            engagement_dir.join(mode_folder).join("latest.json"),
        ),
        (
            "mode event stream",
            engagement_dir.join(mode_folder).join("events.jsonl"),
        ),
        (
            "mode incremental results stream",
            engagement_dir
                .join(mode_folder)
                .join("incremental_results.jsonl"),
        ),
        (
            "mode run outcome",
            engagement_dir.join(mode_folder).join("run_outcome.json"),
        ),
    ];
    for (label, path) in required {
        assert_exists(&path, label, run_label);
    }

    let summary_path = engagement_dir.join("summary.json");
    let summary = read_json(&summary_path);
    let modes = summary
        .get("modes")
        .and_then(|v| v.as_object())
        .unwrap_or_else(|| panic!("summary.json missing object field 'modes'"));
    let scan = modes
        .get(mode_folder)
        .and_then(|v| v.as_object())
        .unwrap_or_else(|| panic!("summary.json missing object field 'modes.{}'", mode_folder));

    for key in [
        "status",
        "command",
        "run_id",
        "stage",
        "started_utc",
        "output_dir",
    ] {
        assert!(
            scan.contains_key(key),
            "Scan '{}' summary contract missing 'modes.{}.{}'",
            run_label,
            mode_folder,
            key
        );
    }
    assert_eq!(
        scan.get("command").and_then(|v| v.as_str()),
        Some(expected_command),
        "Scan '{}' expected modes.{}.command={}",
        run_label,
        mode_folder,
        expected_command
    );

    let latest_path = engagement_dir.join("latest.json");
    let latest = read_json(&latest_path);
    let latest_run_id = latest
        .get("run_id")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("latest.json missing run_id"));
    let summary_run_id = scan
        .get("run_id")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("summary.json modes.{} missing run_id", mode_folder));
    assert_eq!(
        latest_run_id, summary_run_id,
        "Scan '{}' run_id mismatch between latest.json and summary.json",
        run_label
    );

    let run_outcome_path = engagement_dir.join(mode_folder).join("run_outcome.json");
    let run_outcome = read_json(&run_outcome_path);
    let run_outcome_run_id = run_outcome
        .get("run_id")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("{}/run_outcome.json missing run_id", mode_folder));
    assert_eq!(
        run_outcome_run_id, summary_run_id,
        "Scan '{}' run_id mismatch between {}/run_outcome.json and summary.json",
        run_label, mode_folder
    );
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
    let scan_output_root = temp_root.join(format!("scan_output_{}", run.label));

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
        .env("ZKF_SCAN_OUTPUT_ROOT", &scan_output_root)
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

    let (mode_folder, expected_command) = match run.family {
        "mono" => ("scan", "scan"),
        "multi" => ("chains", "chains"),
        other => panic!("Unsupported scan family '{}'", other),
    };
    assert_engagement_contract(&engagement_dir, mode_folder, expected_command, run.label);
}

#[test]
fn scan_engagement_contract_fixture_passes() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let engagement_dir = temp_dir.path();
    std::fs::create_dir_all(engagement_dir.join("log")).expect("mkdir log");
    std::fs::create_dir_all(engagement_dir.join("scan")).expect("mkdir scan");

    std::fs::write(engagement_dir.join("summary.md"), "# Summary\n").expect("write summary.md");
    std::fs::write(engagement_dir.join("log/events.jsonl"), "{}\n").expect("write log events");
    std::fs::write(engagement_dir.join("incremental_results.jsonl"), "{}\n")
        .expect("write incremental events");
    std::fs::write(engagement_dir.join("scan/events.jsonl"), "{}\n").expect("write scan events");
    std::fs::write(
        engagement_dir.join("scan/incremental_results.jsonl"),
        "{}\n",
    )
    .expect("write scan incremental events");

    let run_doc = serde_json::json!({
        "status": "completed",
        "command": "scan",
        "run_id": "scan_123",
        "stage": "completed",
        "started_utc": "2026-02-18T12:00:00Z",
        "output_dir": "/tmp/out"
    });
    std::fs::write(
        engagement_dir.join("scan/run_outcome.json"),
        serde_json::to_vec_pretty(&run_doc).expect("serialize run outcome"),
    )
    .expect("write scan/run_outcome.json");
    std::fs::write(
        engagement_dir.join("scan/latest.json"),
        serde_json::to_vec_pretty(&run_doc).expect("serialize scan latest"),
    )
    .expect("write scan/latest.json");
    std::fs::write(
        engagement_dir.join("latest.json"),
        serde_json::to_vec_pretty(&run_doc).expect("serialize latest"),
    )
    .expect("write latest.json");
    std::fs::write(
        engagement_dir.join("summary.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "updated_utc": "2026-02-18T12:00:01Z",
            "report_dir": engagement_dir.display().to_string(),
            "modes": {
                "scan": run_doc
            }
        }))
        .expect("serialize summary"),
    )
    .expect("write summary.json");

    assert_engagement_contract(engagement_dir, "scan", "scan", "fixture");
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
