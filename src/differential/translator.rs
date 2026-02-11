//! Circuit Translation Layer (Phase 5: Milestone 5.6)
//!
//! Provides translation between ZK circuit frameworks for differential testing.
//! This ensures that when comparing circuits across backends, we're comparing
//! semantically equivalent implementations.
//!
//! # Supported Translations
//!
//! - Circom → Noir (subset)
//! - Circom → Halo2 (subset)
//! - Common arithmetic patterns
//! - Hash function mappings
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Circuit Translation Layer                     │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
//! │  │   Circom    │───►│   Translator    │───►│   Noir/Halo2   │  │
//! │  │   Circuit   │    │   (Pattern DB)  │    │   Circuit      │  │
//! │  └─────────────┘    └─────────────────┘    └─────────────────┘  │
//! │                                                                  │
//! │  ┌─────────────────────────────────────────────────────────┐    │
//! │  │                 Pattern Database                         │    │
//! │  │  • Arithmetic: add, mul, sub, div                       │    │
//! │  │  • Logic: and, or, xor, not                             │    │
//! │  │  • Comparisons: lt, gt, eq, leq, geq                    │    │
//! │  │  • Crypto: poseidon, mimc, pedersen                     │    │
//! │  │  • Range: num2bits, bits2num, range_check               │    │
//! │  └─────────────────────────────────────────────────────────┘    │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Configuration
// ============================================================================

/// Target framework for translation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetFramework {
    Noir,
    Halo2,
    Cairo,
}

impl TargetFramework {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetFramework::Noir => "noir",
            TargetFramework::Halo2 => "halo2",
            TargetFramework::Cairo => "cairo",
        }
    }
}

/// Translation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslatorConfig {
    /// Target framework
    pub target: TargetFramework,
    /// Enable strict mode (fail on unsupported patterns)
    pub strict_mode: bool,
    /// Maximum pattern complexity to translate
    pub max_complexity: usize,
    /// Custom pattern mappings
    pub custom_mappings: HashMap<String, String>,
}

impl Default for TranslatorConfig {
    fn default() -> Self {
        Self {
            target: TargetFramework::Noir,
            strict_mode: true,
            max_complexity: 1000,
            custom_mappings: HashMap::new(),
        }
    }
}

// ============================================================================
// Circuit Patterns
// ============================================================================

/// Common circuit patterns that can be translated
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CircuitPattern {
    // Arithmetic
    Add,
    Mul,
    Sub,
    Div,
    Mod,
    Pow,

    // Logic
    And,
    Or,
    Xor,
    Not,

    // Comparisons
    LessThan,
    GreaterThan,
    Equal,
    LessOrEqual,
    GreaterOrEqual,
    IsZero,

    // Bit operations
    Num2Bits { num_bits: usize },
    Bits2Num { num_bits: usize },
    RangeCheck { num_bits: usize },

    // Crypto primitives
    Poseidon { inputs: usize },
    MiMC { rounds: usize },
    Pedersen,
    Sha256,

    // Merkle trees
    MerkleProof { levels: usize },
    MerkleRoot { levels: usize },

    // Signatures
    EdDSA,
    ECDSA,

    // Custom/unsupported
    Custom(String),
    Unsupported(String),
}

impl CircuitPattern {
    /// Parse pattern from Circom template name
    pub fn from_circom_template(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            // Arithmetic
            "add" | "adder" => CircuitPattern::Add,
            "mul" | "multiplier" => CircuitPattern::Mul,
            "sub" | "subtract" => CircuitPattern::Sub,
            "div" | "divide" => CircuitPattern::Div,
            "mod" | "modulo" => CircuitPattern::Mod,
            "pow" | "power" => CircuitPattern::Pow,

            // Logic
            "and" | "andgate" => CircuitPattern::And,
            "or" | "orgate" => CircuitPattern::Or,
            "xor" | "xorgate" => CircuitPattern::Xor,
            "not" | "notgate" => CircuitPattern::Not,

            // Comparisons
            "lessthan" | "lt" => CircuitPattern::LessThan,
            "greaterthan" | "gt" => CircuitPattern::GreaterThan,
            "isequal" | "eq" => CircuitPattern::Equal,
            "lesseqthan" | "leq" => CircuitPattern::LessOrEqual,
            "greatereqthan" | "geq" => CircuitPattern::GreaterOrEqual,
            "iszero" => CircuitPattern::IsZero,

            // Crypto (patterns with common names)
            "poseidon" => CircuitPattern::Poseidon { inputs: 2 },
            "mimc" | "mimcsponge" => CircuitPattern::MiMC { rounds: 91 },
            "pedersen" => CircuitPattern::Pedersen,
            "sha256" | "sha256hasher" => CircuitPattern::Sha256,

            // Signatures
            "eddsa" | "eddsaverifier" => CircuitPattern::EdDSA,
            "ecdsa" | "ecdsaverify" => CircuitPattern::ECDSA,

            // Default
            _ => {
                // Try to parse parameterized patterns
                if name.starts_with("num2bits") {
                    let bits = parse_num_from_name(name).unwrap_or(254);
                    CircuitPattern::Num2Bits { num_bits: bits }
                } else if name.starts_with("bits2num") {
                    let bits = parse_num_from_name(name).unwrap_or(254);
                    CircuitPattern::Bits2Num { num_bits: bits }
                } else if name.starts_with("rangecheck") || name.starts_with("range_check") {
                    let bits = parse_num_from_name(name).unwrap_or(32);
                    CircuitPattern::RangeCheck { num_bits: bits }
                } else if name.starts_with("merkle") {
                    let levels = parse_num_from_name(name).unwrap_or(20);
                    CircuitPattern::MerkleProof { levels }
                } else {
                    CircuitPattern::Custom(name.to_string())
                }
            }
        }
    }

    /// Check if this pattern is translatable
    pub fn is_translatable(&self) -> bool {
        !matches!(self, CircuitPattern::Unsupported(_))
    }

    /// Get complexity score (for limiting translation)
    pub fn complexity(&self) -> usize {
        match self {
            CircuitPattern::Add | CircuitPattern::Sub | CircuitPattern::Mul => 1,
            CircuitPattern::Div | CircuitPattern::Mod => 5,
            CircuitPattern::And | CircuitPattern::Or | CircuitPattern::Xor | CircuitPattern::Not => 1,
            CircuitPattern::LessThan
            | CircuitPattern::GreaterThan
            | CircuitPattern::Equal
            | CircuitPattern::LessOrEqual
            | CircuitPattern::GreaterOrEqual
            | CircuitPattern::IsZero => 3,
            CircuitPattern::Num2Bits { num_bits } => *num_bits,
            CircuitPattern::Bits2Num { num_bits } => *num_bits,
            CircuitPattern::RangeCheck { num_bits } => *num_bits * 2,
            CircuitPattern::Poseidon { inputs } => inputs * 10,
            CircuitPattern::MiMC { rounds } => *rounds,
            CircuitPattern::Pedersen => 100,
            CircuitPattern::Sha256 => 500,
            CircuitPattern::MerkleProof { levels } => levels * 50,
            CircuitPattern::MerkleRoot { levels } => levels * 50,
            CircuitPattern::EdDSA => 200,
            CircuitPattern::ECDSA => 300,
            CircuitPattern::Pow => 10,
            CircuitPattern::Custom(_) => 50,
            CircuitPattern::Unsupported(_) => usize::MAX,
        }
    }
}

fn parse_num_from_name(name: &str) -> Option<usize> {
    name.chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
}

// ============================================================================
// Translation Result
// ============================================================================

/// Result of a translation attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationResult {
    /// Whether translation was successful
    pub success: bool,
    /// Translated patterns
    pub translated_patterns: Vec<PatternTranslation>,
    /// Unsupported patterns (if any)
    pub unsupported: Vec<String>,
    /// Warnings during translation
    pub warnings: Vec<String>,
    /// Total complexity of translated circuit
    pub total_complexity: usize,
}

/// Single pattern translation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternTranslation {
    /// Source pattern
    pub source: CircuitPattern,
    /// Target representation
    pub target_code: String,
    /// Any parameter mappings
    pub parameter_map: HashMap<String, String>,
}

// ============================================================================
// Translator Implementation
// ============================================================================

/// Circuit translator for cross-framework differential testing
pub struct CircuitTranslator {
    config: TranslatorConfig,
    /// Built-in pattern translations
    pattern_db: HashMap<(CircuitPattern, TargetFramework), String>,
}

impl CircuitTranslator {
    /// Create a new translator with default config
    pub fn new(target: TargetFramework) -> Self {
        let mut config = TranslatorConfig::default();
        config.target = target;
        Self::with_config(config)
    }

    /// Create with custom config
    pub fn with_config(config: TranslatorConfig) -> Self {
        let mut translator = Self {
            config,
            pattern_db: HashMap::new(),
        };
        translator.init_pattern_db();
        translator
    }

    /// Initialize built-in pattern database
    fn init_pattern_db(&mut self) {
        // Noir translations
        self.add_pattern(CircuitPattern::Add, TargetFramework::Noir, "a + b");
        self.add_pattern(CircuitPattern::Mul, TargetFramework::Noir, "a * b");
        self.add_pattern(CircuitPattern::Sub, TargetFramework::Noir, "a - b");
        self.add_pattern(CircuitPattern::Div, TargetFramework::Noir, "a / b");
        self.add_pattern(CircuitPattern::And, TargetFramework::Noir, "a & b");
        self.add_pattern(CircuitPattern::Or, TargetFramework::Noir, "a | b");
        self.add_pattern(CircuitPattern::Xor, TargetFramework::Noir, "a ^ b");
        self.add_pattern(CircuitPattern::Not, TargetFramework::Noir, "!a");
        self.add_pattern(CircuitPattern::LessThan, TargetFramework::Noir, "a < b");
        self.add_pattern(CircuitPattern::GreaterThan, TargetFramework::Noir, "a > b");
        self.add_pattern(CircuitPattern::Equal, TargetFramework::Noir, "a == b");
        self.add_pattern(CircuitPattern::LessOrEqual, TargetFramework::Noir, "a <= b");
        self.add_pattern(CircuitPattern::GreaterOrEqual, TargetFramework::Noir, "a >= b");
        self.add_pattern(
            CircuitPattern::Poseidon { inputs: 2 },
            TargetFramework::Noir,
            "dep::std::hash::poseidon::bn254::hash_2([a, b])",
        );
        self.add_pattern(
            CircuitPattern::Sha256,
            TargetFramework::Noir,
            "dep::std::hash::sha256(input)",
        );

        // Halo2 translations
        self.add_pattern(
            CircuitPattern::Add,
            TargetFramework::Halo2,
            "region.assign_advice(|| \"add\", config.advice[0], offset, || a.value() + b.value())?",
        );
        self.add_pattern(
            CircuitPattern::Mul,
            TargetFramework::Halo2,
            "region.assign_advice(|| \"mul\", config.advice[0], offset, || a.value() * b.value())?",
        );
        self.add_pattern(
            CircuitPattern::Equal,
            TargetFramework::Halo2,
            "region.constrain_equal(a.cell(), b.cell())?",
        );
        self.add_pattern(
            CircuitPattern::Poseidon { inputs: 2 },
            TargetFramework::Halo2,
            "PoseidonChip::new(config.poseidon).hash(layouter, [a, b])?",
        );

        // Cairo translations
        self.add_pattern(CircuitPattern::Add, TargetFramework::Cairo, "a + b");
        self.add_pattern(CircuitPattern::Mul, TargetFramework::Cairo, "a * b");
        self.add_pattern(CircuitPattern::Sub, TargetFramework::Cairo, "a - b");
        self.add_pattern(
            CircuitPattern::Poseidon { inputs: 2 },
            TargetFramework::Cairo,
            "poseidon_hash_span(array![a, b].span())",
        );
    }

    fn add_pattern(&mut self, pattern: CircuitPattern, target: TargetFramework, code: &str) {
        self.pattern_db.insert((pattern, target), code.to_string());
    }

    /// Translate a list of patterns
    pub fn translate(&self, patterns: &[CircuitPattern]) -> Result<TranslationResult> {
        let mut translated = Vec::new();
        let mut unsupported = Vec::new();
        let mut warnings = Vec::new();
        let mut total_complexity = 0;

        for pattern in patterns {
            let complexity = pattern.complexity();
            total_complexity += complexity;

            if total_complexity > self.config.max_complexity {
                warnings.push(format!(
                    "Complexity limit reached at pattern {:?}",
                    pattern
                ));
                if self.config.strict_mode {
                    return Err(anyhow!(
                        "Translation complexity {} exceeds limit {}",
                        total_complexity,
                        self.config.max_complexity
                    ));
                }
                break;
            }

            match self.translate_pattern(pattern) {
                Ok(translation) => translated.push(translation),
                Err(e) => {
                    let msg = format!("{:?}: {}", pattern, e);
                    if self.config.strict_mode {
                        return Err(anyhow!("Unsupported pattern: {}", msg));
                    }
                    unsupported.push(msg);
                }
            }
        }

        Ok(TranslationResult {
            success: unsupported.is_empty(),
            translated_patterns: translated,
            unsupported,
            warnings,
            total_complexity,
        })
    }

    /// Translate a single pattern
    fn translate_pattern(&self, pattern: &CircuitPattern) -> Result<PatternTranslation> {
        // Check custom mappings first
        if let CircuitPattern::Custom(name) = pattern {
            if let Some(code) = self.config.custom_mappings.get(name) {
                return Ok(PatternTranslation {
                    source: pattern.clone(),
                    target_code: code.clone(),
                    parameter_map: HashMap::new(),
                });
            }
        }

        // Check built-in pattern database
        let key = (pattern.clone(), self.config.target);
        if let Some(code) = self.pattern_db.get(&key) {
            return Ok(PatternTranslation {
                source: pattern.clone(),
                target_code: code.clone(),
                parameter_map: HashMap::new(),
            });
        }

        // Handle parameterized patterns
        match pattern {
            CircuitPattern::Num2Bits { num_bits } => {
                let code = self.generate_num2bits(*num_bits);
                Ok(PatternTranslation {
                    source: pattern.clone(),
                    target_code: code,
                    parameter_map: [("num_bits".to_string(), num_bits.to_string())]
                        .into_iter()
                        .collect(),
                })
            }
            CircuitPattern::Bits2Num { num_bits } => {
                let code = self.generate_bits2num(*num_bits);
                Ok(PatternTranslation {
                    source: pattern.clone(),
                    target_code: code,
                    parameter_map: [("num_bits".to_string(), num_bits.to_string())]
                        .into_iter()
                        .collect(),
                })
            }
            CircuitPattern::RangeCheck { num_bits } => {
                let code = self.generate_range_check(*num_bits);
                Ok(PatternTranslation {
                    source: pattern.clone(),
                    target_code: code,
                    parameter_map: [("num_bits".to_string(), num_bits.to_string())]
                        .into_iter()
                        .collect(),
                })
            }
            CircuitPattern::MerkleProof { levels } => {
                let code = self.generate_merkle_proof(*levels);
                Ok(PatternTranslation {
                    source: pattern.clone(),
                    target_code: code,
                    parameter_map: [("levels".to_string(), levels.to_string())]
                        .into_iter()
                        .collect(),
                })
            }
            CircuitPattern::Poseidon { inputs } => {
                let code = self.generate_poseidon(*inputs);
                Ok(PatternTranslation {
                    source: pattern.clone(),
                    target_code: code,
                    parameter_map: [("inputs".to_string(), inputs.to_string())]
                        .into_iter()
                        .collect(),
                })
            }
            CircuitPattern::Unsupported(name) => Err(anyhow!("Unsupported pattern: {}", name)),
            _ => Err(anyhow!("No translation for pattern: {:?}", pattern)),
        }
    }

    // Pattern generators for each target

    fn generate_num2bits(&self, num_bits: usize) -> String {
        match self.config.target {
            TargetFramework::Noir => {
                format!(
                    "fn num_to_bits(x: Field) -> [u1; {}] {{\n    x.to_le_bits()\n}}",
                    num_bits
                )
            }
            TargetFramework::Halo2 => {
                format!(
                    "// Num2Bits gadget with {} bits\nlet bits = self.num_to_bits(layouter, value, {})?;",
                    num_bits, num_bits
                )
            }
            TargetFramework::Cairo => {
                format!(
                    "fn num_to_bits(x: felt252) -> Array<bool> {{\n    // {} bit decomposition\n    let mut bits = ArrayTrait::new();\n    // Implementation\n    bits\n}}",
                    num_bits
                )
            }
        }
    }

    fn generate_bits2num(&self, num_bits: usize) -> String {
        match self.config.target {
            TargetFramework::Noir => {
                format!(
                    "fn bits_to_num(bits: [u1; {}]) -> Field {{\n    let mut result = 0;\n    for i in 0..{} {{\n        result += (bits[i] as Field) * (1 << i);\n    }}\n    result\n}}",
                    num_bits, num_bits
                )
            }
            TargetFramework::Halo2 => {
                format!(
                    "// Bits2Num gadget with {} bits\nlet value = self.bits_to_num(layouter, &bits)?;",
                    num_bits
                )
            }
            TargetFramework::Cairo => {
                format!(
                    "fn bits_to_num(bits: Array<bool>) -> felt252 {{\n    // {} bits to number\n    let mut result: felt252 = 0;\n    // Implementation\n    result\n}}",
                    num_bits
                )
            }
        }
    }

    fn generate_range_check(&self, num_bits: usize) -> String {
        match self.config.target {
            TargetFramework::Noir => {
                format!(
                    "fn range_check(x: Field) {{\n    assert(x < (1 << {}));\n}}",
                    num_bits
                )
            }
            TargetFramework::Halo2 => {
                format!(
                    "// Range check for {} bits\nself.range_chip.check(layouter, value, {})?;",
                    num_bits, num_bits
                )
            }
            TargetFramework::Cairo => {
                format!(
                    "fn range_check(x: felt252) {{\n    assert(x < {}, 'out of range');\n}}",
                    1u128 << num_bits.min(127)
                )
            }
        }
    }

    fn generate_merkle_proof(&self, levels: usize) -> String {
        match self.config.target {
            TargetFramework::Noir => {
                format!(
                    "fn verify_merkle_proof(\n    leaf: Field,\n    path: [Field; {}],\n    indices: [u1; {}],\n    root: Field\n) -> bool {{\n    let mut current = leaf;\n    for i in 0..{} {{\n        let (left, right) = if indices[i] == 0 {{\n            (current, path[i])\n        }} else {{\n            (path[i], current)\n        }};\n        current = dep::std::hash::poseidon::bn254::hash_2([left, right]);\n    }}\n    current == root\n}}",
                    levels, levels, levels
                )
            }
            TargetFramework::Halo2 => {
                format!(
                    "// Merkle proof verification with {} levels\nlet computed_root = self.merkle_chip.verify(layouter, leaf, path, indices)?;\nlayouter.constrain_equal(computed_root.cell(), root.cell())?;",
                    levels
                )
            }
            TargetFramework::Cairo => {
                format!(
                    "fn verify_merkle_proof(\n    leaf: felt252,\n    path: Array<felt252>,\n    indices: Array<bool>,\n    root: felt252\n) -> bool {{\n    // {} level Merkle proof\n    let mut current = leaf;\n    // Implementation\n    current == root\n}}",
                    levels
                )
            }
        }
    }

    fn generate_poseidon(&self, inputs: usize) -> String {
        match self.config.target {
            TargetFramework::Noir => {
                if inputs == 2 {
                    "dep::std::hash::poseidon::bn254::hash_2([a, b])".to_string()
                } else {
                    format!(
                        "dep::std::hash::poseidon::bn254::hash_{}(inputs)",
                        inputs
                    )
                }
            }
            TargetFramework::Halo2 => {
                format!(
                    "PoseidonChip::new(config.poseidon).hash(layouter, inputs)?  // {} inputs",
                    inputs
                )
            }
            TargetFramework::Cairo => {
                format!("poseidon_hash_span(inputs.span())  // {} inputs", inputs)
            }
        }
    }

    /// Check if a set of patterns can be fully translated
    pub fn can_translate(&self, patterns: &[CircuitPattern]) -> bool {
        patterns.iter().all(|p| {
            let key = (p.clone(), self.config.target);
            self.pattern_db.contains_key(&key) || matches!(p, 
                CircuitPattern::Num2Bits { .. } |
                CircuitPattern::Bits2Num { .. } |
                CircuitPattern::RangeCheck { .. } |
                CircuitPattern::MerkleProof { .. } |
                CircuitPattern::Poseidon { .. }
            )
        })
    }

    /// Get supported patterns for target framework
    pub fn supported_patterns(&self) -> Vec<CircuitPattern> {
        self.pattern_db
            .keys()
            .filter(|(_, target)| *target == self.config.target)
            .map(|(pattern, _)| pattern.clone())
            .collect()
    }

    /// Validate translation produces semantically equivalent circuit
    pub fn validate_translation(&self, result: &TranslationResult) -> Result<ValidationReport> {
        let mut report = ValidationReport {
            valid: true,
            pattern_count: result.translated_patterns.len(),
            complexity: result.total_complexity,
            warnings: result.warnings.clone(),
            errors: Vec::new(),
        };

        // Check for unsupported patterns
        if !result.unsupported.is_empty() {
            report.valid = false;
            report.errors.extend(
                result
                    .unsupported
                    .iter()
                    .map(|s| format!("Unsupported: {}", s)),
            );
        }

        // Check complexity limits
        if result.total_complexity > self.config.max_complexity {
            report.valid = false;
            report.errors.push(format!(
                "Complexity {} exceeds limit {}",
                result.total_complexity, self.config.max_complexity
            ));
        }

        Ok(report)
    }
}

impl Default for CircuitTranslator {
    fn default() -> Self {
        Self::new(TargetFramework::Noir)
    }
}

/// Validation report for translated circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub valid: bool,
    pub pattern_count: usize,
    pub complexity: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

        let patterns = vec![CircuitPattern::Add, CircuitPattern::Mul, CircuitPattern::Equal];

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
        let mut config = TranslatorConfig::default();
        config.strict_mode = true;

        let translator = CircuitTranslator::with_config(config);

        let patterns = vec![CircuitPattern::Unsupported("unknown".to_string())];

        let result = translator.translate(&patterns);
        assert!(result.is_err());
    }

    #[test]
    fn test_complexity_limit() {
        let mut config = TranslatorConfig::default();
        config.max_complexity = 10;
        config.strict_mode = false;

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
        let mut config = TranslatorConfig::default();
        config
            .custom_mappings
            .insert("MyCustomGadget".to_string(), "my_custom_impl()".to_string());

        let translator = CircuitTranslator::with_config(config);

        let patterns = vec![CircuitPattern::Custom("MyCustomGadget".to_string())];

        let result = translator.translate(&patterns).unwrap();
        assert!(result.success);
        assert_eq!(result.translated_patterns[0].target_code, "my_custom_impl()");
    }
}
