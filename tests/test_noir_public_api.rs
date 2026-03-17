use zk_fuzzer::targets::noir_analysis;

#[test]
fn test_noir_function_extraction_uses_public_analysis_api() {
    let source = r#"
fn main(x: Field, y: pub Field) -> Field {
    x + y
}

fn helper(a: u64) {
    let _ = a;
}
"#;

    let functions = noir_analysis::extract_functions(source);
    assert_eq!(functions.len(), 2);
    assert!(functions[0].is_main);
    assert_eq!(functions[0].params.len(), 2);
}
