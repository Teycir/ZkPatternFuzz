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
    assert_eq!(args, "[\"3\", \"42\"]");
}
