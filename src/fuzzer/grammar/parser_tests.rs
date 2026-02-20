use super::*;

#[test]
fn test_parse_valid_grammar() {
    let yaml = r#"
name: Test
inputs:
  - name: x
    type: field
"#;
    let grammar = GrammarParser::parse_str(yaml).unwrap();
    assert!(GrammarParser::validate(&grammar).is_ok());
}

#[test]
fn test_invalid_grammar_no_name() {
    let yaml = r#"
name: ""
inputs:
  - name: x
    type: field
"#;
    let grammar = GrammarParser::parse_str(yaml).unwrap();
    assert!(GrammarParser::validate(&grammar).is_err());
}

#[test]
fn test_invalid_grammar_array_no_length() {
    let yaml = r#"
name: Test
inputs:
  - name: arr
    type: array
"#;
    let grammar = GrammarParser::parse_str(yaml).unwrap();
    assert!(GrammarParser::validate(&grammar).is_err());
}
