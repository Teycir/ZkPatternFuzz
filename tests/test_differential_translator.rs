use std::collections::HashMap;
use zk_fuzzer::differential::translator::{CircuitPattern, CircuitTranslator, TargetFramework, TranslatorConfig};

#[test]
fn test_pattern_from_circom_template() {
    assert_eq!(
        CircuitPattern::from_circom_template("Add"),
        CircuitPattern::Add
    );
    assert_eq!(
        CircuitPattern::from_circom_template("Poseidon"),
        CircuitPattern::Poseidon { inputs: 2 }
    );
    assert_eq!(
        CircuitPattern::from_circom_template("Num2Bits32"),
        CircuitPattern::Num2Bits { num_bits: 32 }
    );
}

#[test]
fn test_translator_basic() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    let patterns = vec![
        CircuitPattern::Add,
        CircuitPattern::Mul,
        CircuitPattern::Equal,
    ];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);
    assert_eq!(result.translated_patterns.len(), 3);
}

#[test]
fn test_translator_parameterized() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    let patterns = vec![
        CircuitPattern::Num2Bits { num_bits: 64 },
        CircuitPattern::RangeCheck { num_bits: 32 },
    ];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    // Check that parameters are captured
    assert!(result.translated_patterns[0]
        .parameter_map
        .contains_key("num_bits"));
}

#[test]
fn test_translator_halo2() {
    let translator = CircuitTranslator::new(TargetFramework::Halo2);

    let patterns = vec![CircuitPattern::Add, CircuitPattern::Poseidon { inputs: 2 }];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);
    assert!(result.translated_patterns[0]
        .target_code
        .contains("assign_advice"));
}

#[test]
fn test_translator_strict_mode() {
    let config = TranslatorConfig {
        strict_mode: true,
        ..TranslatorConfig::default()
    };

    let translator = CircuitTranslator::with_config(config);

    let patterns = vec![CircuitPattern::Unsupported("unknown".to_string())];

    let result = translator.translate(&patterns);
    assert!(result.is_err());
}

#[test]
fn test_complexity_limit() {
    let config = TranslatorConfig {
        max_complexity: 10,
        strict_mode: false,
        ..TranslatorConfig::default()
    };

    let translator = CircuitTranslator::with_config(config);

    let patterns = vec![
        CircuitPattern::MerkleProof { levels: 20 }, // Complexity: 1000
    ];

    let result = translator.translate(&patterns).unwrap();
    assert!(!result.warnings.is_empty());
}

#[test]
fn test_can_translate() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    assert!(translator.can_translate(&[CircuitPattern::Add, CircuitPattern::Mul]));
    assert!(!translator.can_translate(&[CircuitPattern::Unsupported("x".to_string())]));
}

#[test]
fn test_custom_mapping() {
    let mut custom_mappings = HashMap::new();
    custom_mappings.insert("MyCustomGadget".to_string(), "my_custom_impl()".to_string());
    let config = TranslatorConfig {
        custom_mappings,
        ..TranslatorConfig::default()
    };

    let translator = CircuitTranslator::with_config(config);

    let patterns = vec![CircuitPattern::Custom("MyCustomGadget".to_string())];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);
    assert_eq!(
        result.translated_patterns[0].target_code,
        "my_custom_impl()"
    );
}
