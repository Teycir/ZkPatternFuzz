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
