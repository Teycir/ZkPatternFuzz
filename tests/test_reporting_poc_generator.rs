use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity};
use zk_fuzzer::reporting::{PoCFormat, PoCGenerator};

fn sample_finding() -> Finding {
    Finding {
        attack_type: AttackType::Underconstrained,
        severity: Severity::Critical,
        description: "Path indices not constrained to binary values".to_string(),
        poc: ProofOfConcept {
            witness_a: vec![
                FieldElement::from_u64(1),
                FieldElement::from_u64(0),
                FieldElement::from_u64(1),
            ],
            witness_b: Some(vec![
                FieldElement::from_u64(1),
                FieldElement::from_u64(2), // Invalid: not 0 or 1
                FieldElement::from_u64(1),
            ]),
            public_inputs: vec![FieldElement::from_u64(12345)],
            proof: None,
        },
        location: Some("merkle.circom:42".to_string()),
        class: None,
    }
}

#[test]
fn test_generate_shell() {
    let generator = PoCGenerator::new();
    let finding = sample_finding();

    let script = generator.generate(&finding, PoCFormat::Shell).unwrap();

    assert!(script.contains("#!/bin/bash"));
    assert!(script.contains("Underconstrained"));
    assert!(script.contains("input_a.json"));
    assert!(script.contains("input_b.json"));
}

#[test]
fn test_generate_javascript() {
    let generator = PoCGenerator::new();
    let finding = sample_finding();

    let script = generator.generate(&finding, PoCFormat::JavaScript).unwrap();

    assert!(script.contains("snarkjs"));
    assert!(script.contains("witnessA"));
    assert!(script.contains("witnessB"));
    assert!(script.contains("VULNERABILITY CONFIRMED"));
}

#[test]
fn test_generate_rust() {
    let generator = PoCGenerator::new();
    let finding = sample_finding();

    let script = generator.generate(&finding, PoCFormat::Rust).unwrap();

    assert!(script.contains("#[test]"));
    assert!(script.contains("witness_a"));
    assert!(script.contains("witness_b"));
}

#[test]
fn test_generate_json() {
    let generator = PoCGenerator::new();
    let finding = sample_finding();

    let json = generator.generate(&finding, PoCFormat::Json).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["attack_type"], "Underconstrained");
    assert_eq!(parsed["severity"], "Critical");
}
