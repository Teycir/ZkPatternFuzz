use std::path::Path;
use zk_core::{AttackType, Framework, Severity};
use zk_fuzzer::config::generator::{ConfigGenerator, PatternType};

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
fn test_quantum_vulnerable_pattern_detection() {
    let source = r#"
            include "circomlib/ecdsa.circom";
            template Verify() {
                signal input msg;
                // uses secp256 curve logic
            }
            component main = Verify();
        "#;

    let generator = ConfigGenerator::new();
    let patterns = generator.detect_patterns(source, Framework::Circom);

    assert!(patterns
        .iter()
        .any(|p| p.pattern_type == PatternType::QuantumVulnerablePrimitive));
}

#[test]
fn test_quantum_pattern_detection_uses_word_tokens() {
    let source = r#"
            template Main() {
                signal input parse_value;
                signal output out;
                out <== parse_value;
            }
            component main = Main();
        "#;

    let generator = ConfigGenerator::new();
    let patterns = generator.detect_patterns(source, Framework::Circom);

    assert!(!patterns
        .iter()
        .any(|p| p.pattern_type == PatternType::QuantumVulnerablePrimitive));
}

#[test]
fn test_trusted_setup_pattern_detection() {
    let source = r#"
            // powersOfTau ceremony transcript reference
            // ptau: ./setup/pot12_final.ptau
            template Main() {
                signal input a;
                signal output out;
                out <== a;
            }
            component main = Main();
        "#;

    let generator = ConfigGenerator::new();
    let patterns = generator.detect_patterns(source, Framework::Circom);

    assert!(patterns
        .iter()
        .any(|p| p.pattern_type == PatternType::TrustedSetupArtifact));
}

#[test]
fn test_detect_main_component() {
    let source = r#"
            template MerkleProof() {
                // ...
            }
            component main = MerkleProof();
        "#;

    let generator = ConfigGenerator::new();
    let config = generator
        .generate_from_source(source, Framework::Circom, Path::new("main.circom"))
        .expect("config generation should succeed");

    let main = config
        .base
        .as_ref()
        .expect("base config should be present")
        .campaign
        .target
        .main_component
        .clone();
    assert_eq!(main, "MerkleProof");
}

#[test]
fn test_detect_main_component_requires_explicit_circom_main() {
    let source = r#"
            template MerkleProof() {
                // ...
            }
        "#;

    let generator = ConfigGenerator::new();
    let err = generator
        .generate_from_source(source, Framework::Circom, Path::new("missing-main.circom"))
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

    let generator = ConfigGenerator::new();
    let err = generator
        .generate_from_source(source, Framework::Noir, Path::new("main.nr"))
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
    let source = r#"
            template Main() {
                signal input leaf;
                signal output out;
                out <== leaf;
            }
            component main = Main();
        "#;

    let generator = ConfigGenerator::new();
    let config = generator
        .generate_from_source(source, Framework::Circom, Path::new("main.circom"))
        .expect("config generation should succeed");
    let base = config.base.as_ref().expect("base config should be present");
    let input = base
        .inputs
        .iter()
        .find(|input| input.name == "leaf")
        .expect("input should be detected");
    assert_eq!(input.input_type, "field");
}

#[test]
fn test_parse_circom_array_input() {
    let source = r#"
            template Main() {
                signal input pathElements[20];
                signal output out;
                out <== pathElements[0];
            }
            component main = Main();
        "#;

    let generator = ConfigGenerator::new();
    let config = generator
        .generate_from_source(source, Framework::Circom, Path::new("main.circom"))
        .expect("config generation should succeed");
    let base = config.base.as_ref().expect("base config should be present");
    let input = base
        .inputs
        .iter()
        .find(|input| input.name == "pathElements")
        .expect("array input should be detected");
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

#[test]
fn test_generate_from_source_adds_quantum_and_trusted_setup_attacks() {
    let source = r#"
            // setup uses powersOfTau and ptau artifacts
            include "circomlib/ecdsa.circom";
            template Main() {
                signal input msg;
                signal output out;
                // secp256 verify placeholder
                out <== msg;
            }
            component main = Main();
        "#;

    let generator = ConfigGenerator::new();
    let config = generator
        .generate_from_source(source, Framework::Circom, Path::new("main.circom"))
        .expect("config generation should succeed");

    let attacks = config
        .base
        .as_ref()
        .expect("base config should be present")
        .attacks
        .iter()
        .map(|attack| attack.attack_type.clone())
        .collect::<Vec<_>>();

    assert!(attacks.contains(&AttackType::QuantumResistance));
    assert!(attacks.contains(&AttackType::TrustedSetup));
}

#[test]
fn test_generate_from_source_includes_strict_required_attacks() {
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

    let attacks = config
        .base
        .as_ref()
        .expect("base config should be present")
        .attacks
        .iter()
        .map(|attack| attack.attack_type.clone())
        .collect::<Vec<_>>();

    assert!(attacks.contains(&AttackType::Underconstrained));
    assert!(attacks.contains(&AttackType::Soundness));
    assert!(attacks.contains(&AttackType::QuantumResistance));
    assert!(attacks.contains(&AttackType::CircomStaticLint));
    assert!(attacks.contains(&AttackType::ConstraintInference));
    assert!(attacks.contains(&AttackType::Metamorphic));
    assert!(attacks.contains(&AttackType::ConstraintSlice));
    assert!(attacks.contains(&AttackType::SpecInference));
    assert!(attacks.contains(&AttackType::WitnessCollision));
}

#[test]
fn test_generate_schedule_includes_novel_oracle_phase() {
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

    let schedule = config.schedule;
    let static_phase = schedule
        .iter()
        .find(|phase| phase.phase == "static_prepass")
        .expect("static_prepass phase should exist");
    assert_eq!(static_phase.max_iterations, Some(1));
    assert!(static_phase.fail_on_findings.contains(&Severity::Critical));
    assert!(static_phase.fail_on_findings.contains(&Severity::High));
    assert!(static_phase
        .attacks
        .iter()
        .any(|name| name == "quantum_resistance"));
    assert!(static_phase
        .attacks
        .iter()
        .any(|name| name == "circom_static_lint"));

    let novel_phase = schedule
        .iter()
        .find(|phase| phase.phase == "novel_oracles")
        .expect("novel_oracles phase should exist");
    assert!(novel_phase
        .attacks
        .iter()
        .any(|name| name == "constraint_inference"));
    assert!(novel_phase
        .attacks
        .iter()
        .any(|name| name == "witness_collision"));
}
