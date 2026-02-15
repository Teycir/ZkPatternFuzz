//! Grammar parser for YAML DSL

use super::InputGrammar;
use std::path::Path;

/// Parser for input grammar files
pub struct GrammarParser;

impl GrammarParser {
    /// Parse grammar from file
    pub fn parse_file<P: AsRef<Path>>(path: P) -> anyhow::Result<InputGrammar> {
        let path_ref = path.as_ref();
        let path_str = path_ref.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "Grammar path is not valid UTF-8: {}",
                path_ref.display()
            )
        })?;
        InputGrammar::from_yaml(path_str)
    }

    /// Parse grammar from string
    pub fn parse_str(yaml: &str) -> anyhow::Result<InputGrammar> {
        InputGrammar::from_yaml_str(yaml)
    }

    /// Validate grammar structure
    pub fn validate(grammar: &InputGrammar) -> anyhow::Result<()> {
        if grammar.name.is_empty() {
            anyhow::bail!("Grammar name cannot be empty");
        }

        if grammar.inputs.is_empty() {
            anyhow::bail!("Grammar must have at least one input");
        }

        for input in &grammar.inputs {
            if input.name.is_empty() {
                anyhow::bail!("Input name cannot be empty");
            }

            // Validate array types have length
            if input.input_type == super::InputType::Array && input.length.is_none() {
                anyhow::bail!("Array input '{}' must specify length", input.name);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
}
