#[allow(dead_code)]
#[path = "../src/run_outcome_docs.rs"]
mod run_outcome_docs;

use run_outcome_docs::{classify_run_reason_code, standardize_run_outcome_doc};

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
fn standardize_completed_critical_marks_candidate_pending_proof() {
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
        Some("pending_proof")
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
fn standardize_completed_without_findings_stays_pending_proof() {
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
        Some("pending_proof")
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
}
