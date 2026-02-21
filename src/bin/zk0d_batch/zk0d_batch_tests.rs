use super::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_temp_report(contents: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("zk0d_batch_report_{}.json", stamp));
    fs::write(&path, contents).expect("write temp report");
    path
}

#[test]
fn parse_correlation_metadata_extracts_confidence_and_oracles() {
    let description = "abc\nCorrelation: HIGH (groups=2, oracles=3, corroborating=9)";
    assert_eq!(
        parse_correlation_confidence(description).as_deref(),
        Some("high")
    );
    assert_eq!(parse_correlation_oracle_count(description), Some(3));
}

#[test]
fn high_confidence_high_requires_min_oracles() {
    let report = r#"{
  "findings": [
    {
      "description": "x\nCorrelation: HIGH (groups=2, oracles=2, corroborating=1)"
    }
  ]
}"#;
    let path = write_temp_report(report);
    assert!(report_has_high_confidence_finding_with_min_oracles(
        &path, 2
    ));
    assert!(!report_has_high_confidence_finding_with_min_oracles(
        &path, 3
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn high_confidence_critical_ignores_oracle_threshold() {
    let report = r#"{
  "findings": [
    {
      "description": "x\nCorrelation: CRITICAL (groups=3, oracles=2, corroborating=7)"
    }
  ]
}"#;
    let path = write_temp_report(report);
    assert!(report_has_high_confidence_finding_with_min_oracles(
        &path, 4
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn selector_mismatch_validation_detection_matches_expected_message() {
    let stderr = "Error: Pattern 'x.yaml' selectors did not match target circuit '/tmp/test.nr'";
    assert!(is_selector_mismatch_validation("", stderr));
    assert!(!is_selector_mismatch_validation(
        "",
        "some other validation error"
    ));
}

#[test]
fn classify_reason_code_marks_preflight_selector_as_selector_mismatch() {
    let doc = serde_json::json!({
        "status": "failed",
        "stage": "preflight_selector",
        "reason": "selector_mismatch"
    });
    assert_eq!(classify_run_reason_code(&doc), "selector_mismatch");
}

#[test]
fn selector_mismatch_outcome_writer_creates_run_outcome_json() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    let artifacts_root = std::env::temp_dir().join(format!("zk0d_batch_artifacts_{}", stamp));
    let run_root = "scan_run_test";
    let suffix = "auto__selector_case";

    write_selector_mismatch_outcome(&artifacts_root, Some(run_root), suffix)
        .expect("write selector mismatch outcome");

    let outcome_path = artifacts_root
        .join(run_root)
        .join(suffix)
        .join("run_outcome.json");
    assert!(outcome_path.exists());
    let raw = fs::read_to_string(&outcome_path).expect("read run outcome");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse run outcome");
    assert_eq!(
        parsed.get("stage").and_then(|v| v.as_str()),
        Some("preflight_selector")
    );
    assert_eq!(
        parsed.get("reason").and_then(|v| v.as_str()),
        Some("selector_mismatch")
    );

    let _ = fs::remove_dir_all(artifacts_root);
}
