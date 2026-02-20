use super::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn transient_setup_reason_classifier() {
    assert!(is_transient_setup_reason("key_generation_failed"));
    assert!(is_transient_setup_reason("output_dir_locked"));
    assert!(is_transient_setup_reason("backend_preflight_failed"));
    assert!(!is_transient_setup_reason("backend_tooling_missing"));
    assert!(!is_transient_setup_reason("circom_compilation_failed"));
    assert!(!is_transient_setup_reason("completed"));
}

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
