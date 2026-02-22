use std::fs;

#[allow(dead_code)]
#[path = "../src/run_identity.rs"]
mod run_identity;
#[allow(dead_code)]
#[path = "../src/run_outcome_docs.rs"]
mod run_outcome_docs;
#[allow(dead_code)]
#[path = "../src/run_paths.rs"]
mod run_paths;
#[allow(dead_code)]
#[path = "../src/scan_selector.rs"]
mod scan_selector;
#[allow(dead_code)]
#[path = "../src/scan_selector_context.rs"]
mod scan_selector_context;
pub(crate) use run_paths::{engagement_root_dir, run_signal_dir};
#[allow(dead_code)]
#[path = "../src/engagement_artifacts.rs"]
mod engagement_artifacts;

use engagement_artifacts::get_command_from_doc;
use run_paths::{engagement_dir_name, run_id_epoch_dir};
use scan_selector::{
    evaluate_loaded_scan_regex_patterns, load_scan_regex_selector_config,
    validate_scan_regex_pattern_safety, ScanRegexPatternSummary,
};

fn evaluate_selector_summary(pattern_yaml: &str, target_source: &str) -> ScanRegexPatternSummary {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let pattern_path = temp_dir.path().join("pattern.yaml");
    let target_path = temp_dir.path().join("target.circom");

    fs::write(&pattern_path, pattern_yaml).expect("write pattern");
    fs::write(&target_path, target_source).expect("write target");

    let selector_config =
        load_scan_regex_selector_config(pattern_path.to_str().expect("utf8 path"))
            .expect("load selector config")
            .expect("selector config should exist");
    evaluate_loaded_scan_regex_patterns(&selector_config, &target_path)
        .expect("evaluate selector config")
}

fn evaluate_selector_summary_with_target_file(
    pattern_yaml: &str,
    target_path: &std::path::Path,
) -> ScanRegexPatternSummary {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let pattern_path = temp_dir.path().join("pattern.yaml");
    fs::write(&pattern_path, pattern_yaml).expect("write pattern");
    let selector_config =
        load_scan_regex_selector_config(pattern_path.to_str().expect("utf8 path"))
            .expect("load selector config")
            .expect("selector config should exist");
    evaluate_loaded_scan_regex_patterns(&selector_config, target_path)
        .expect("evaluate selector config")
}

#[test]
fn scan_selector_default_policy_matches_any_single_pattern() {
    let pattern_yaml = r#"
patterns:
  - id: contains_alpha
    kind: regex
    pattern: "\\balpha\\b"
  - id: contains_beta
    kind: regex
    pattern: "\\bbeta\\b"
"#;
    let summary = evaluate_selector_summary(pattern_yaml, "signal input alpha;");

    assert_eq!(summary.required_k_of_n, 1);
    assert_eq!(summary.matched_patterns, 1);
    assert!(summary.selector_passed);
}

#[test]
fn scan_selector_policy_supports_k_of_n_and_min_score() {
    let pattern_yaml = r#"
patterns:
  - id: alpha_context
    kind: regex
    pattern: "\\balpha\\b"
    group: "core"
    weight: 1.0
  - id: beta_context
    kind: regex
    pattern: "\\bbeta\\b"
    group: "core"
    weight: 1.0
  - id: gamma_hint
    kind: regex
    pattern: "\\bgamma\\b"
    group: "aux"
    weight: 0.5
selector_policy:
  k_of_n: 2
  min_score: 1.5
  groups:
    - name: core
      k_of_n: 1
"#;
    let summary = evaluate_selector_summary(pattern_yaml, "alpha gamma");

    assert_eq!(summary.matched_patterns, 2);
    assert!((summary.matched_score - 1.5).abs() < 1e-9);
    assert!(summary.selector_passed);
}

#[test]
fn scan_selector_policy_fails_when_group_requirement_is_not_met() {
    let pattern_yaml = r#"
patterns:
  - id: alpha_context
    kind: regex
    pattern: "\\balpha\\b"
    group: "core"
    weight: 1.0
  - id: beta_context
    kind: regex
    pattern: "\\bbeta\\b"
    group: "core"
    weight: 1.0
  - id: gamma_hint
    kind: regex
    pattern: "\\bgamma\\b"
    group: "aux"
    weight: 0.5
selector_policy:
  k_of_n: 2
  min_score: 1.5
  groups:
    - name: core
      k_of_n: 2
"#;
    let summary = evaluate_selector_summary(pattern_yaml, "alpha gamma");

    assert!(!summary.selector_passed);
    assert_eq!(summary.group_matches.len(), 1);
    assert!(!summary.group_matches[0].passed);
}

#[test]
fn scan_selector_policy_rejects_invalid_global_k_of_n() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let pattern_path = temp_dir.path().join("pattern.yaml");
    fs::write(
        &pattern_path,
        r#"
patterns:
  - id: one
    kind: regex
    pattern: "one"
  - id: two
    kind: regex
    pattern: "two"
selector_policy:
  k_of_n: 3
"#,
    )
    .expect("write pattern");

    let err = load_scan_regex_selector_config(pattern_path.to_str().expect("utf8 path"))
        .expect_err("invalid k_of_n should fail");
    assert!(format!("{err:#}").contains("selector_policy.k_of_n"));
}

#[test]
fn scan_selector_synonym_bundle_matches_separator_and_case_variants() {
    let pattern_yaml = r#"
selector_synonyms:
  zkevm:
    - "zkEVM"
patterns:
  - id: zkevm_context
    kind: regex
    pattern: "{{zkevm}}"
"#;
    let summary = evaluate_selector_summary(pattern_yaml, "component zk_evm_main {}");
    assert!(summary.selector_passed);
    assert_eq!(summary.matched_patterns, 1);
}

#[test]
fn scan_selector_synonym_bundle_can_disable_flexible_separator_normalization() {
    let pattern_yaml = r#"
selector_synonyms:
  zkevm:
    - "zkEVM"
selector_normalization:
  synonym_flexible_separators: false
patterns:
  - id: zkevm_context
    kind: regex
    pattern: "{{zkevm}}"
"#;
    let summary = evaluate_selector_summary(pattern_yaml, "component zk_evm_main {}");
    assert!(!summary.selector_passed);
    assert_eq!(summary.matched_patterns, 0);
}

#[test]
fn scan_selector_synonym_bundle_rejects_unknown_placeholder_bundle() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let pattern_path = temp_dir.path().join("pattern.yaml");
    fs::write(
        &pattern_path,
        r#"
selector_synonyms:
  known:
    - "abc"
patterns:
  - id: bad_ref
    kind: regex
    pattern: "{{missing_bundle}}"
"#,
    )
    .expect("write pattern");

    let err = load_scan_regex_selector_config(pattern_path.to_str().expect("utf8 path"))
        .expect_err("unknown synonym bundle must fail");
    assert!(format!("{err:#}").contains("Unknown synonym bundle"));
}

#[test]
fn scan_selector_regex_safety_allows_optional_group_quantifier() {
    validate_scan_regex_pattern_safety(r"(zk[-_ ]?evm)?")
        .expect("optional group quantifier should be allowed");
}

#[test]
fn scan_selector_regex_safety_rejects_nested_dangerous_quantifier() {
    let err = validate_scan_regex_pattern_safety(r"(a+)+")
        .expect_err("nested quantifier must be rejected");
    assert!(format!("{err:#}").contains("nested quantifier"));
}

#[test]
fn scan_selector_manifest_context_reads_nargo_src_tree() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let project_dir = temp_dir.path().join("noir_project");
    let src_dir = project_dir.join("src");
    fs::create_dir_all(&src_dir).expect("create src dir");
    fs::write(
        project_dir.join("Nargo.toml"),
        r#"[package]
name = "demo"
type = "bin"
authors = ["tests"]
"#,
    )
    .expect("write nargo manifest");
    fs::write(
        src_dir.join("main.nr"),
        r#"fn main(noteIndex: Field) { let nullifier = noteIndex; }"#,
    )
    .expect("write noir source");

    let pattern_yaml = r#"
patterns:
  - id: noir_nullifier
    kind: regex
    pattern: "\\bnullifier\\b"
  - id: noir_note_index
    kind: regex
    pattern: "\\bnoteIndex\\b"
selector_policy:
  k_of_n: 2
"#;
    let summary =
        evaluate_selector_summary_with_target_file(pattern_yaml, &project_dir.join("Nargo.toml"));
    assert!(summary.selector_passed);
    assert_eq!(summary.matched_patterns, 2);
}

#[test]
fn scan_selector_manifest_context_reads_cargo_src_tree() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let project_dir = temp_dir.path().join("halo2_project");
    let src_dir = project_dir.join("src");
    fs::create_dir_all(&src_dir).expect("create src dir");
    fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "halo2_demo"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("write cargo manifest");
    fs::write(
        src_dir.join("main.rs"),
        r#"fn main() { let flow_constraint = "execution flow constraint"; println!("{}", flow_constraint); }"#,
    )
    .expect("write rust source");

    let pattern_yaml = r#"
patterns:
  - id: execution_flow
    kind: regex
    pattern: "execution\\s*flow"
  - id: constraint_term
    kind: regex
    pattern: "\\bconstraint\\b"
selector_policy:
  k_of_n: 2
"#;
    let summary =
        evaluate_selector_summary_with_target_file(pattern_yaml, &project_dir.join("Cargo.toml"));
    assert!(summary.selector_passed);
    assert_eq!(summary.matched_patterns, 2);
}

#[test]
fn run_doc_command_extraction_uses_context_fallback() {
    let doc = serde_json::json!({
        "status": "panic",
        "context": {
            "command": "scan"
        }
    });
    assert_eq!(get_command_from_doc(&doc), "scan");
}

#[test]
fn run_doc_command_extraction_defaults_to_unknown_when_missing() {
    let doc = serde_json::json!({
        "status": "panic"
    });
    assert_eq!(get_command_from_doc(&doc), "unknown");
}

#[test]
fn engagement_dir_name_invalid_run_id_never_panics() {
    assert!(run_id_epoch_dir("invalid").is_none());
    let result = std::panic::catch_unwind(|| engagement_dir_name("invalid"));
    assert!(result.is_ok(), "engagement_dir_name should not panic");
    let dir = result.expect("string");
    assert!(!dir.trim().is_empty());
}
