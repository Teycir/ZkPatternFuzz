#[allow(dead_code)]
#[path = "../src/run_outcome_docs.rs"]
mod run_outcome_docs;

use run_outcome_docs::{classify_run_reason_code, standardize_run_outcome_doc};
use tempfile::tempdir;

fn write_required_proof_pack(dir: &std::path::Path, note_file: &str) {
    std::fs::write(dir.join("replay_command.txt"), "cargo run -- replay\n").expect("write replay command");
    std::fs::write(dir.join(note_file), "# Notes\n").expect("write proof notes");
    std::fs::write(dir.join("impact.md"), "# Impact\n").expect("write impact");
    std::fs::write(dir.join("proof_replay.log"), "ok\n").expect("write replay log");
}

#[test]
fn standardize_running_outcome_sets_analysis_defaults() {
    let input = serde_json::json!({
        "status": "running",
        "stage": "engine_run",
        "command": "scan",
        "run_id": "scan_1",
    });

    let normalized = standardize_run_outcome_doc(&input);
    assert_eq!(
        normalized.get("reason_code").and_then(|v| v.as_str()),
        Some("running")
    );
    assert_eq!(
        normalized.get("status_family").and_then(|v| v.as_str()),
        Some("running")
    );
    assert_eq!(
        normalized.get("terminal").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("discovery_state"))
            .and_then(|v| v.as_str()),
        Some("in_progress")
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("proof_status"))
            .and_then(|v| v.as_str()),
        Some("not_ready")
    );
}

#[test]
fn standardize_completed_critical_without_bundles_marks_proof_failed() {
    let input = serde_json::json!({
        "status": "completed_with_critical_findings",
        "stage": "completed",
        "output_dir": "/tmp/zkfuzz/out",
        "metrics": {
            "findings_total": 3,
            "critical_findings": true
        }
    });

    let normalized = standardize_run_outcome_doc(&input);
    assert_eq!(
        normalized.get("reason_code").and_then(|v| v.as_str()),
        Some("critical_findings_detected")
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("discovery_state"))
            .and_then(|v| v.as_str()),
        Some("candidate_vulnerability")
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("proof_status"))
            .and_then(|v| v.as_str()),
        Some("proof_failed")
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("analysis_inputs"))
            .and_then(|v| v.get("report_json"))
            .and_then(|v| v.as_str()),
        Some("/tmp/zkfuzz/out/report.json")
    );
}

#[test]
fn standardize_completed_without_findings_marks_proof_skipped() {
    let input = serde_json::json!({
        "status": "completed",
        "stage": "completed",
        "metrics": {
            "findings_total": 0,
            "critical_findings": false
        }
    });

    let normalized = standardize_run_outcome_doc(&input);
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("discovery_state"))
            .and_then(|v| v.as_str()),
        Some("no_vulnerability_observed")
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("proof_status"))
            .and_then(|v| v.as_str()),
        Some("proof_skipped_by_policy")
    );
}

#[test]
fn standardize_completed_with_passed_bundle_marks_exploitable() {
    let dir = tempdir().expect("tempdir");
    let finding_dir = dir.path().join("evidence").join("finding_abc");
    std::fs::create_dir_all(&finding_dir).expect("create evidence dir");
    std::fs::write(
        finding_dir.join("bundle.json"),
        r#"{"verification_result":"Passed"}"#,
    )
    .expect("write bundle");
    write_required_proof_pack(&finding_dir, "exploit_notes.md");

    let input = serde_json::json!({
        "status": "completed_with_critical_findings",
        "stage": "completed",
        "output_dir": dir.path().display().to_string(),
        "metrics": {
            "findings_total": 1,
            "critical_findings": true
        }
    });

    let normalized = standardize_run_outcome_doc(&input);
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("proof_status"))
            .and_then(|v| v.as_str()),
        Some("exploitable")
    );
}

#[test]
fn standardize_completed_with_failed_bundle_marks_not_exploitable_within_bounds() {
    let dir = tempdir().expect("tempdir");
    let finding_dir = dir.path().join("evidence").join("finding_abc");
    std::fs::create_dir_all(&finding_dir).expect("create evidence dir");
    std::fs::write(
        finding_dir.join("bundle.json"),
        r#"{"verification_result":{"Failed":"invalid proof"}}"#,
    )
    .expect("write bundle");
    write_required_proof_pack(&finding_dir, "no_exploit_proof.md");

    let input = serde_json::json!({
        "status": "completed",
        "stage": "completed",
        "output_dir": dir.path().display().to_string(),
        "metrics": {
            "findings_total": 1,
            "critical_findings": false
        }
    });

    let normalized = standardize_run_outcome_doc(&input);
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("proof_status"))
            .and_then(|v| v.as_str()),
        Some("not_exploitable_within_bounds")
    );
}

#[test]
fn standardize_passed_bundle_without_required_proof_pack_stays_proof_failed() {
    let dir = tempdir().expect("tempdir");
    let finding_dir = dir.path().join("evidence").join("finding_abc");
    std::fs::create_dir_all(&finding_dir).expect("create evidence dir");
    std::fs::write(
        finding_dir.join("bundle.json"),
        r#"{"verification_result":"Passed"}"#,
    )
    .expect("write bundle");

    let input = serde_json::json!({
        "status": "completed_with_critical_findings",
        "stage": "completed",
        "output_dir": dir.path().display().to_string(),
        "metrics": {
            "findings_total": 1,
            "critical_findings": true
        }
    });

    let normalized = standardize_run_outcome_doc(&input);
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("proof_status"))
            .and_then(|v| v.as_str()),
        Some("proof_failed")
    );
}

#[test]
fn classify_and_standardize_selector_mismatch() {
    let input = serde_json::json!({
        "status": "failed",
        "stage": "preflight_selector",
        "error": "Pattern selectors did not match target circuit",
    });

    assert_eq!(classify_run_reason_code(&input), Some("selector_mismatch"));

    let normalized = standardize_run_outcome_doc(&input);
    assert_eq!(
        normalized.get("reason_code").and_then(|v| v.as_str()),
        Some("selector_mismatch")
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("discovery_state"))
            .and_then(|v| v.as_str()),
        Some("run_failed")
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("proof_status"))
            .and_then(|v| v.as_str()),
        Some("not_ready")
    );
}

#[test]
fn classify_and_standardize_wall_clock_timeout_marks_proof_failed() {
    let input = serde_json::json!({
        "status": "failed",
        "stage": "engine_run",
        "error": "Global wall-clock timeout reached while proving",
    });

    assert_eq!(classify_run_reason_code(&input), Some("wall_clock_timeout"));

    let normalized = standardize_run_outcome_doc(&input);
    assert_eq!(
        normalized.get("reason_code").and_then(|v| v.as_str()),
        Some("wall_clock_timeout")
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("discovery_state"))
            .and_then(|v| v.as_str()),
        Some("run_failed")
    );
    assert_eq!(
        normalized
            .get("discovery_qualification")
            .and_then(|v| v.get("proof_status"))
            .and_then(|v| v.as_str()),
        Some("proof_failed")
    );
}
