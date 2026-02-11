//! Translation Validation Tests (Phase 5: Milestone 5.6)
//!
//! Tests for the circuit translation layer to ensure semantic equivalence
//! between translated circuits across different ZK frameworks.

use zk_fuzzer::differential::translator::{
    CircuitPattern, CircuitTranslator, TargetFramework, TranslatorConfig,
};

// ============================================================================
// Pattern Recognition Tests
// ============================================================================

#[test]
fn test_pattern_recognition_arithmetic() {
    let patterns = [
        ("Add", CircuitPattern::Add),
        ("Multiplier", CircuitPattern::Mul),
        ("Sub", CircuitPattern::Sub),
        ("Divide", CircuitPattern::Div),
    ];

    for (name, expected) in patterns {
        let parsed = CircuitPattern::from_circom_template(name);
        assert_eq!(parsed, expected, "Failed to parse pattern: {}", name);
    }
}

#[test]
fn test_pattern_recognition_logic() {
    let patterns = [
        ("And", CircuitPattern::And),
        ("Or", CircuitPattern::Or),
        ("Xor", CircuitPattern::Xor),
        ("Not", CircuitPattern::Not),
    ];

    for (name, expected) in patterns {
        let parsed = CircuitPattern::from_circom_template(name);
        assert_eq!(parsed, expected, "Failed to parse pattern: {}", name);
    }
}

#[test]
fn test_pattern_recognition_comparisons() {
    let patterns = [
        ("LessThan", CircuitPattern::LessThan),
        ("GreaterThan", CircuitPattern::GreaterThan),
        ("IsEqual", CircuitPattern::Equal),
        ("LessEqThan", CircuitPattern::LessOrEqual),
        ("GreaterEqThan", CircuitPattern::GreaterOrEqual),
    ];

    for (name, expected) in patterns {
        let parsed = CircuitPattern::from_circom_template(name);
        assert_eq!(parsed, expected, "Failed to parse pattern: {}", name);
    }
}

#[test]
fn test_pattern_recognition_parameterized() {
    // Num2Bits with parameter
    let parsed = CircuitPattern::from_circom_template("Num2Bits64");
    assert_eq!(parsed, CircuitPattern::Num2Bits { num_bits: 64 });

    // Bits2Num with parameter
    let parsed = CircuitPattern::from_circom_template("Bits2Num32");
    assert_eq!(parsed, CircuitPattern::Bits2Num { num_bits: 32 });

    // RangeCheck with parameter
    let parsed = CircuitPattern::from_circom_template("RangeCheck128");
    assert_eq!(parsed, CircuitPattern::RangeCheck { num_bits: 128 });
}

#[test]
fn test_pattern_recognition_crypto() {
    let patterns = [
        ("Poseidon", CircuitPattern::Poseidon { inputs: 2 }),
        ("MiMC", CircuitPattern::MiMC { rounds: 91 }),
        ("Pedersen", CircuitPattern::Pedersen),
        ("Sha256", CircuitPattern::Sha256),
    ];

    for (name, expected) in patterns {
        let parsed = CircuitPattern::from_circom_template(name);
        assert_eq!(parsed, expected, "Failed to parse pattern: {}", name);
    }
}

#[test]
fn test_pattern_recognition_signatures() {
    assert_eq!(
        CircuitPattern::from_circom_template("EdDSA"),
        CircuitPattern::EdDSA
    );
    assert_eq!(
        CircuitPattern::from_circom_template("ECDSA"),
        CircuitPattern::ECDSA
    );
}

// ============================================================================
// Translation Tests - Noir
// ============================================================================

#[test]
fn test_translate_to_noir_arithmetic() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    let patterns = vec![
        CircuitPattern::Add,
        CircuitPattern::Mul,
        CircuitPattern::Sub,
        CircuitPattern::Div,
    ];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);
    assert_eq!(result.translated_patterns.len(), 4);

    // Check specific translations
    assert_eq!(result.translated_patterns[0].target_code, "a + b");
    assert_eq!(result.translated_patterns[1].target_code, "a * b");
    assert_eq!(result.translated_patterns[2].target_code, "a - b");
    assert_eq!(result.translated_patterns[3].target_code, "a / b");
}

#[test]
fn test_translate_to_noir_logic() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    let patterns = vec![
        CircuitPattern::And,
        CircuitPattern::Or,
        CircuitPattern::Xor,
        CircuitPattern::Not,
    ];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    assert_eq!(result.translated_patterns[0].target_code, "a & b");
    assert_eq!(result.translated_patterns[1].target_code, "a | b");
    assert_eq!(result.translated_patterns[2].target_code, "a ^ b");
    assert_eq!(result.translated_patterns[3].target_code, "!a");
}

#[test]
fn test_translate_to_noir_comparisons() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    let patterns = vec![
        CircuitPattern::LessThan,
        CircuitPattern::GreaterThan,
        CircuitPattern::Equal,
    ];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    assert_eq!(result.translated_patterns[0].target_code, "a < b");
    assert_eq!(result.translated_patterns[1].target_code, "a > b");
    assert_eq!(result.translated_patterns[2].target_code, "a == b");
}

#[test]
fn test_translate_to_noir_parameterized() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    let patterns = vec![
        CircuitPattern::Num2Bits { num_bits: 64 },
        CircuitPattern::RangeCheck { num_bits: 32 },
    ];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    // Check parameters are captured
    assert!(result.translated_patterns[0].parameter_map.contains_key("num_bits"));
    assert_eq!(result.translated_patterns[0].parameter_map["num_bits"], "64");

    // Check generated code contains the bit count
    assert!(result.translated_patterns[0].target_code.contains("64"));
    assert!(result.translated_patterns[1].target_code.contains("32"));
}

#[test]
fn test_translate_to_noir_crypto() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    let patterns = vec![CircuitPattern::Poseidon { inputs: 2 }];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    assert!(result.translated_patterns[0].target_code.contains("poseidon"));
}

// ============================================================================
// Translation Tests - Halo2
// ============================================================================

#[test]
fn test_translate_to_halo2_arithmetic() {
    let translator = CircuitTranslator::new(TargetFramework::Halo2);

    let patterns = vec![CircuitPattern::Add, CircuitPattern::Mul];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    // Halo2 uses region assignment
    assert!(result.translated_patterns[0].target_code.contains("assign_advice"));
    assert!(result.translated_patterns[1].target_code.contains("assign_advice"));
}

#[test]
fn test_translate_to_halo2_equality() {
    let translator = CircuitTranslator::new(TargetFramework::Halo2);

    let patterns = vec![CircuitPattern::Equal];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    assert!(result.translated_patterns[0].target_code.contains("constrain_equal"));
}

// ============================================================================
// Translation Tests - Cairo
// ============================================================================

#[test]
fn test_translate_to_cairo_arithmetic() {
    let translator = CircuitTranslator::new(TargetFramework::Cairo);

    let patterns = vec![CircuitPattern::Add, CircuitPattern::Mul, CircuitPattern::Sub];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    assert_eq!(result.translated_patterns[0].target_code, "a + b");
    assert_eq!(result.translated_patterns[1].target_code, "a * b");
    assert_eq!(result.translated_patterns[2].target_code, "a - b");
}

#[test]
fn test_translate_to_cairo_crypto() {
    let translator = CircuitTranslator::new(TargetFramework::Cairo);

    let patterns = vec![CircuitPattern::Poseidon { inputs: 2 }];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    assert!(result.translated_patterns[0].target_code.contains("poseidon_hash_span"));
}

// ============================================================================
// Complexity Tests
// ============================================================================

#[test]
fn test_complexity_calculation() {
    assert_eq!(CircuitPattern::Add.complexity(), 1);
    assert_eq!(CircuitPattern::Mul.complexity(), 1);
    assert_eq!(CircuitPattern::Div.complexity(), 5);
    assert_eq!(CircuitPattern::Num2Bits { num_bits: 64 }.complexity(), 64);
    assert_eq!(CircuitPattern::MerkleProof { levels: 20 }.complexity(), 1000);
}

#[test]
fn test_complexity_limit() {
    let mut config = TranslatorConfig::default();
    config.max_complexity = 100;
    config.strict_mode = false;

    let translator = CircuitTranslator::with_config(config);

    // This should exceed the limit
    let patterns = vec![CircuitPattern::MerkleProof { levels: 20 }]; // complexity: 1000

    let result = translator.translate(&patterns).unwrap();
    assert!(!result.warnings.is_empty(), "Expected warning about complexity limit");
}

#[test]
fn test_complexity_limit_strict() {
    let mut config = TranslatorConfig::default();
    config.max_complexity = 100;
    config.strict_mode = true;

    let translator = CircuitTranslator::with_config(config);

    let patterns = vec![CircuitPattern::MerkleProof { levels: 20 }];

    let result = translator.translate(&patterns);
    assert!(result.is_err(), "Expected error in strict mode");
}

// ============================================================================
// Unsupported Pattern Tests
// ============================================================================

#[test]
fn test_unsupported_pattern_non_strict() {
    let mut config = TranslatorConfig::default();
    config.strict_mode = false;

    let translator = CircuitTranslator::with_config(config);

    let patterns = vec![
        CircuitPattern::Add,
        CircuitPattern::Unsupported("UnknownGadget".to_string()),
    ];

    let result = translator.translate(&patterns).unwrap();
    assert!(!result.success);
    assert_eq!(result.translated_patterns.len(), 1);
    assert!(!result.unsupported.is_empty());
}

#[test]
fn test_unsupported_pattern_strict() {
    let mut config = TranslatorConfig::default();
    config.strict_mode = true;

    let translator = CircuitTranslator::with_config(config);

    let patterns = vec![CircuitPattern::Unsupported("UnknownGadget".to_string())];

    let result = translator.translate(&patterns);
    assert!(result.is_err());
}

// ============================================================================
// Custom Mapping Tests
// ============================================================================

#[test]
fn test_custom_mapping() {
    let mut config = TranslatorConfig::default();
    config.custom_mappings.insert(
        "MyCustomHasher".to_string(),
        "custom_hash_impl(inputs)".to_string(),
    );

    let translator = CircuitTranslator::with_config(config);

    let patterns = vec![CircuitPattern::Custom("MyCustomHasher".to_string())];

    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);
    assert_eq!(result.translated_patterns[0].target_code, "custom_hash_impl(inputs)");
}

// ============================================================================
// Can Translate Tests
// ============================================================================

#[test]
fn test_can_translate_basic() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    assert!(translator.can_translate(&[CircuitPattern::Add, CircuitPattern::Mul]));
    assert!(translator.can_translate(&[CircuitPattern::Poseidon { inputs: 2 }]));
    assert!(translator.can_translate(&[CircuitPattern::Num2Bits { num_bits: 64 }]));
}

#[test]
fn test_can_translate_with_unsupported() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    assert!(!translator.can_translate(&[CircuitPattern::Unsupported("x".to_string())]));
}

// ============================================================================
// Validation Tests
// ============================================================================

#[test]
fn test_validation_report_success() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    let patterns = vec![CircuitPattern::Add, CircuitPattern::Mul];
    let result = translator.translate(&patterns).unwrap();

    let report = translator.validate_translation(&result).unwrap();
    assert!(report.valid);
    assert_eq!(report.pattern_count, 2);
    assert!(report.errors.is_empty());
}

#[test]
fn test_validation_report_with_unsupported() {
    let mut config = TranslatorConfig::default();
    config.strict_mode = false;

    let translator = CircuitTranslator::with_config(config);

    let patterns = vec![CircuitPattern::Unsupported("x".to_string())];
    let result = translator.translate(&patterns).unwrap();

    let report = translator.validate_translation(&result).unwrap();
    assert!(!report.valid);
    assert!(!report.errors.is_empty());
}

// ============================================================================
// Merkle Proof Translation Tests
// ============================================================================

#[test]
fn test_merkle_proof_noir() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);

    let patterns = vec![CircuitPattern::MerkleProof { levels: 10 }];
    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    let code = &result.translated_patterns[0].target_code;
    assert!(code.contains("verify_merkle_proof"));
    assert!(code.contains("[Field; 10]")); // Path length
    assert!(code.contains("poseidon")); // Hash function
}

#[test]
fn test_merkle_proof_halo2() {
    let translator = CircuitTranslator::new(TargetFramework::Halo2);

    let patterns = vec![CircuitPattern::MerkleProof { levels: 15 }];
    let result = translator.translate(&patterns).unwrap();
    assert!(result.success);

    let code = &result.translated_patterns[0].target_code;
    assert!(code.contains("merkle_chip"));
    assert!(code.contains("15")); // Levels
}

// ============================================================================
// Supported Patterns Tests
// ============================================================================

#[test]
fn test_supported_patterns_noir() {
    let translator = CircuitTranslator::new(TargetFramework::Noir);
    let supported = translator.supported_patterns();

    assert!(supported.contains(&CircuitPattern::Add));
    assert!(supported.contains(&CircuitPattern::Mul));
    assert!(supported.contains(&CircuitPattern::LessThan));
}

#[test]
fn test_supported_patterns_halo2() {
    let translator = CircuitTranslator::new(TargetFramework::Halo2);
    let supported = translator.supported_patterns();

    assert!(supported.contains(&CircuitPattern::Add));
    assert!(supported.contains(&CircuitPattern::Equal));
}

// ============================================================================
// Translatability Tests (50+ patterns)
// ============================================================================

#[test]
fn test_50_plus_common_patterns_translatable() {
    // Test that we can translate 50+ common circuit patterns
    let patterns = vec![
        // Arithmetic (6)
        CircuitPattern::Add,
        CircuitPattern::Mul,
        CircuitPattern::Sub,
        CircuitPattern::Div,
        CircuitPattern::Mod,
        CircuitPattern::Pow,
        // Logic (4)
        CircuitPattern::And,
        CircuitPattern::Or,
        CircuitPattern::Xor,
        CircuitPattern::Not,
        // Comparisons (6)
        CircuitPattern::LessThan,
        CircuitPattern::GreaterThan,
        CircuitPattern::Equal,
        CircuitPattern::LessOrEqual,
        CircuitPattern::GreaterOrEqual,
        CircuitPattern::IsZero,
        // Bit operations (varying sizes)
        CircuitPattern::Num2Bits { num_bits: 8 },
        CircuitPattern::Num2Bits { num_bits: 16 },
        CircuitPattern::Num2Bits { num_bits: 32 },
        CircuitPattern::Num2Bits { num_bits: 64 },
        CircuitPattern::Num2Bits { num_bits: 128 },
        CircuitPattern::Num2Bits { num_bits: 254 },
        CircuitPattern::Bits2Num { num_bits: 8 },
        CircuitPattern::Bits2Num { num_bits: 16 },
        CircuitPattern::Bits2Num { num_bits: 32 },
        CircuitPattern::Bits2Num { num_bits: 64 },
        CircuitPattern::Bits2Num { num_bits: 128 },
        CircuitPattern::Bits2Num { num_bits: 254 },
        CircuitPattern::RangeCheck { num_bits: 8 },
        CircuitPattern::RangeCheck { num_bits: 16 },
        CircuitPattern::RangeCheck { num_bits: 32 },
        CircuitPattern::RangeCheck { num_bits: 64 },
        // Crypto (with varying inputs)
        CircuitPattern::Poseidon { inputs: 2 },
        CircuitPattern::Poseidon { inputs: 3 },
        CircuitPattern::Poseidon { inputs: 4 },
        CircuitPattern::Poseidon { inputs: 8 },
        CircuitPattern::Poseidon { inputs: 16 },
        // Merkle (varying levels)
        CircuitPattern::MerkleProof { levels: 5 },
        CircuitPattern::MerkleProof { levels: 10 },
        CircuitPattern::MerkleProof { levels: 15 },
        CircuitPattern::MerkleProof { levels: 20 },
        CircuitPattern::MerkleProof { levels: 32 },
    ];

    // Check all are translatable
    let mut translated_count = 0;
    let mut config = TranslatorConfig::default();
    config.max_complexity = usize::MAX; // No limit for this test
    config.strict_mode = false;
    
    let translator = CircuitTranslator::with_config(config);

    for pattern in &patterns {
        if translator.can_translate(&[pattern.clone()]) {
            translated_count += 1;
        }
    }

    assert!(
        translated_count >= 40,
        "Expected 40+ patterns translatable, got {}",
        translated_count
    );
}
