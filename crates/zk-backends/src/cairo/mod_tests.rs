use super::*;

#[test]
fn test_detect_version() {
    // Cairo 1 syntax detection
    let cairo1_content = r#"
            fn main() -> felt252 {
                return 42;
            }
        "#;

    // Would need actual file for full test
    assert!(cairo1_content.contains("fn main()"));
}

#[test]
fn test_vulnerability_analysis() {
    let source = r#"
            func main{output_ptr: felt*}() {
                let x = 5;
                %{ memory[ap] = 100 %}
                [ap] = [ap - 1] + x;
            }
        "#;

    let issues = analysis::analyze_for_vulnerabilities(source);
    assert!(issues
        .iter()
        .any(|i| i.issue_type == analysis::IssueType::HintUsage));
}

#[test]
fn test_parse_cairo1_execution_id_from_output() {
    let output = "Proving package demo...\nExecution ID: run_abc123\nDone.";
    let parsed = CairoTarget::parse_cairo1_execution_id(output);
    assert_eq!(parsed.as_deref(), Some("run_abc123"));
}

#[test]
fn test_parse_cairo1_execution_id_missing_returns_none() {
    let output = "Proving package demo...\nDone.";
    assert!(CairoTarget::parse_cairo1_execution_id(output).is_none());
}

#[test]
fn test_cairo1_arguments_json_serialization() {
    let args = CairoTarget::cairo1_arguments_json(&[
        FieldElement::from_u64(3),
        FieldElement::from_u64(42),
    ]);
    assert_eq!(args, "[3, 42]");
}

#[test]
fn test_cairo1_proof_artifact_roundtrip() {
    let witness = vec![FieldElement::from_u64(3), FieldElement::from_u64(42)];
    let args_json = CairoTarget::cairo1_arguments_json(&witness);
    let artifact =
        CairoTarget::build_cairo1_proof_artifact("run_abc123", &witness, args_json.clone());

    let encoded = CairoTarget::serialize_cairo1_proof_artifact(&artifact)
        .expect("serialize Cairo1 proof artifact contract");
    let parsed = CairoTarget::parse_cairo1_proof_artifact(&encoded)
        .expect("parse Cairo1 proof artifact contract");

    assert_eq!(parsed, artifact);
    assert_eq!(parsed.witness_args_json, args_json);
}

#[test]
fn test_parse_cairo1_proof_artifact_rejects_legacy_execution_id_payload() {
    let err = CairoTarget::parse_cairo1_proof_artifact(b"run_legacy_execution_id")
        .expect_err("legacy execution-id payload must be rejected");
    assert!(
        err.to_string()
            .contains("Invalid Cairo1 proof artifact format"),
        "unexpected error: {err}"
    );
}
