use super::*;
use std::path::Path;

#[test]
fn test_merkle_pattern_detection() {
    let source = r#"
            template MerkleProof(levels) {
                signal input leaf;
                signal input pathElements[levels];
                signal input pathIndices[levels];
                signal output root;
            }
        "#;

    let generator = ConfigGenerator::new();
    let patterns = generator.detect_patterns(source, Framework::Circom);

    assert!(!patterns.is_empty());
    assert!(patterns
        .iter()
        .any(|p| p.pattern_type == PatternType::MerkleTree));
}

#[test]
fn test_hash_pattern_detection() {
    let source = r#"
            include "circomlib/poseidon.circom";
            
            template HashCheck() {
                signal input x;
                component hasher = Poseidon(1);
            }
        "#;

    let generator = ConfigGenerator::new();
    let patterns = generator.detect_patterns(source, Framework::Circom);

    assert!(patterns
        .iter()
        .any(|p| matches!(&p.pattern_type, PatternType::HashFunction(name) if name == "poseidon")));
}

#[test]
fn test_detect_main_component() {
    let source = r#"
            template MerkleProof() {
                // ...
            }
            component main = MerkleProof();
        "#;

    let main = detect_main_component(source, Framework::Circom).unwrap();
    assert_eq!(main, "MerkleProof");
}

#[test]
fn test_detect_main_component_requires_explicit_circom_main() {
    let source = r#"
            template MerkleProof() {
                // ...
            }
        "#;

    let err = detect_main_component(source, Framework::Circom)
        .expect_err("missing explicit Circom main should return an error");
    assert!(format!("{err:#}").contains("component main"));
}

#[test]
fn test_detect_main_component_requires_noir_main() {
    let source = r#"
            fn helper(x: Field) -> Field {
                x
            }
        "#;

    let err = detect_main_component(source, Framework::Noir)
        .expect_err("missing Noir main should return an error");
    assert!(format!("{err:#}").contains("fn main"));
}

#[test]
fn test_generate_from_source_fails_when_main_component_missing() {
    let source = r#"
            template MerkleProof() {
                signal input leaf;
                signal output root;
            }
        "#;

    let generator = ConfigGenerator::new();
    let err = generator
        .generate_from_source(source, Framework::Circom, Path::new("missing-main.circom"))
        .expect_err("missing explicit main component should fail config generation");
    assert!(format!("{err:#}").contains("component main"));
}

#[test]
fn test_parse_circom_input() {
    let line = "    signal input leaf;";
    let input = parse_circom_input(line).unwrap();
    assert_eq!(input.name, "leaf");
    assert_eq!(input.input_type, "field");
}

#[test]
fn test_parse_circom_array_input() {
    let line = "    signal input pathElements[20];";
    let input = parse_circom_input(line).unwrap();
    assert_eq!(input.name, "pathElements");
    assert_eq!(input.input_type, "array<field>");
    assert_eq!(input.length, Some(20));
}

#[test]
fn test_generate_from_source_includes_static_first_pass_template() {
    let source = r#"
            template Main() {
                signal input a;
                signal output out;
                out <== a;
            }
            component main = Main();
        "#;

    let generator = ConfigGenerator::new();
    let config = generator
        .generate_from_source(source, Framework::Circom, Path::new("main.circom"))
        .expect("config generation should succeed");

    assert_eq!(
        config.includes.first().map(String::as_str),
        Some("templates/traits/static_first_pass.yaml")
    );
    assert!(config
        .includes
        .iter()
        .any(|include| include == "templates/traits/base.yaml"));
}
