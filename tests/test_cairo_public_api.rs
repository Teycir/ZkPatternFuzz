use zk_fuzzer::targets::cairo_analysis;

#[test]
fn test_cairo_vulnerability_analysis_uses_public_analysis_api() {
    let source = r#"
func main{output_ptr: felt*}() {
    let x = 5;
    %{ memory[ap] = 100 %}
    [ap] = [ap - 1] + x;
}
"#;

    let issues = cairo_analysis::analyze_for_vulnerabilities(source);
    assert!(issues
        .iter()
        .any(|issue| issue.issue_type == cairo_analysis::IssueType::HintUsage));
}
