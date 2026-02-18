//! Configuration Generator for ZkPatternFuzz
//!
//! Automatically generates campaign configurations by analyzing circuit source code
//! and detecting common patterns like Merkle trees, range checks, hash functions, etc.
//!
//! # Usage
//!
//! ```rust,ignore
//! use zk_fuzzer::config::generator::ConfigGenerator;
//!
//! let generator = ConfigGenerator::new();
//! let config = generator.generate_from_source("circuit.circom")?;
//! ```

use super::v2::{
    FuzzConfigV2, Invariant, InvariantOracle, InvariantType, Profile, SchedulePhase, TargetTraits,
};
use super::{Attack, Campaign, FuzzConfig, Input, Parameters, ReportingConfig, Target};
use std::collections::HashMap;
use std::path::Path;
use zk_core::{AttackType, Framework};

/// Pattern detection result
#[derive(Debug, Clone)]
pub struct DetectedPattern {
    /// Pattern type identifier
    pub pattern_type: PatternType,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Source location (line numbers)
    pub locations: Vec<usize>,
    /// Suggested trait template
    pub suggested_trait: Option<String>,
}

/// Types of patterns that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PatternType {
    MerkleTree,
    RangeCheck,
    HashFunction(String), // poseidon, mimc, pedersen, sha256
    Nullifier,
    Signature,
    Commitment,
    BitDecomposition,
    ArrayAccess,
    Conditional,
    Loop,
}

/// Configuration generator for automated campaign creation
pub struct ConfigGenerator {
    /// Known pattern matchers
    pattern_matchers: Vec<Box<dyn PatternMatcher>>,
}

impl Default for ConfigGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigGenerator {
    /// Create a new configuration generator with default pattern matchers
    pub fn new() -> Self {
        Self {
            pattern_matchers: vec![
                Box::new(MerklePatternMatcher),
                Box::new(RangePatternMatcher),
                Box::new(HashPatternMatcher),
                Box::new(NullifierPatternMatcher),
                Box::new(SignaturePatternMatcher),
                Box::new(BitDecompPatternMatcher),
            ],
        }
    }

    /// Add a custom pattern matcher
    pub fn with_matcher(mut self, matcher: Box<dyn PatternMatcher>) -> Self {
        self.pattern_matchers.push(matcher);
        self
    }

    /// Generate configuration from circuit source file
    pub fn generate_from_file(&self, path: impl AsRef<Path>) -> anyhow::Result<FuzzConfigV2> {
        let source = std::fs::read_to_string(path.as_ref())?;
        let framework = detect_framework(path.as_ref())?;
        self.generate_from_source(&source, framework, path.as_ref())
    }

    /// Generate configuration from circuit source code
    pub fn generate_from_source(
        &self,
        source: &str,
        framework: Framework,
        circuit_path: &Path,
    ) -> anyhow::Result<FuzzConfigV2> {
        // Detect patterns in source
        let patterns = self.detect_patterns(source, framework);

        // Build target traits from detected patterns
        let target_traits = self.build_target_traits(&patterns);

        // Generate invariants from patterns
        let invariants = self.generate_invariants(&patterns);

        // Generate attack schedule based on detected patterns
        let schedule = self.generate_schedule(&patterns);

        // Detect inputs from source
        let inputs = self.detect_inputs(source, framework);

        // Build includes list
        let includes = self.suggest_includes(&patterns);

        // Build profiles
        let profiles = self.suggest_profiles(&patterns);

        // Detect main component
        let main_component = detect_main_component(source, framework)?;

        // Build attacks based on patterns
        let attacks = self.generate_attacks(&patterns);

        let config = FuzzConfigV2 {
            includes,
            profiles,
            active_profile: None,
            target_traits,
            invariants,
            schedule,
            chains: Vec::new(), // Mode 3: No auto-generated chains
            base: Some(FuzzConfig {
                campaign: Campaign {
                    name: format!("Auto-generated: {}", circuit_path.display()),
                    version: "2.0".to_string(),
                    target: Target {
                        framework,
                        circuit_path: circuit_path.to_path_buf(),
                        main_component,
                    },
                    parameters: Parameters::default(),
                },
                attacks,
                inputs,
                mutations: vec![],
                oracles: vec![],
                reporting: ReportingConfig::default(),
                chains: vec![],
            }),
        };

        Ok(config)
    }

    /// Detect patterns in source code
    pub fn detect_patterns(&self, source: &str, framework: Framework) -> Vec<DetectedPattern> {
        let mut patterns = Vec::new();

        for matcher in &self.pattern_matchers {
            if let Some(pattern) = matcher.detect(source, framework) {
                patterns.push(pattern);
            }
        }

        // Sort by confidence descending
        patterns.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));

        patterns
    }

    /// Build target traits from detected patterns
    fn build_target_traits(&self, patterns: &[DetectedPattern]) -> TargetTraits {
        let mut traits = TargetTraits::default();

        for pattern in patterns {
            match &pattern.pattern_type {
                PatternType::MerkleTree => traits.uses_merkle = true,
                PatternType::Nullifier => traits.uses_nullifier = true,
                PatternType::Commitment => traits.uses_commitment = true,
                PatternType::Signature => traits.uses_signature = true,
                PatternType::HashFunction(name) => {
                    traits.hash_function = Some(name.clone());
                }
                PatternType::RangeCheck => {
                    if !traits.range_checks.contains(&"detected".to_string()) {
                        traits.range_checks.push("detected".to_string());
                    }
                }
                _ => {}
            }
        }

        traits
    }

    /// Generate invariants from detected patterns
    fn generate_invariants(&self, patterns: &[DetectedPattern]) -> Vec<Invariant> {
        let mut invariants = Vec::new();

        for pattern in patterns {
            match &pattern.pattern_type {
                PatternType::MerkleTree => {
                    invariants.push(Invariant {
                        name: "merkle_path_binary".to_string(),
                        invariant_type: InvariantType::Constraint,
                        relation: "∀i: pathIndices[i] ∈ {0,1}".to_string(),
                        oracle: InvariantOracle::MustHold,
                        transform: None,
                        expected: None,
                        description: Some("Merkle path indices must be binary".to_string()),
                        severity: Some("critical".to_string()),
                    });
                }
                PatternType::RangeCheck => {
                    invariants.push(Invariant {
                        name: "range_bound".to_string(),
                        invariant_type: InvariantType::Range,
                        relation: "0 <= value < 2^n".to_string(),
                        oracle: InvariantOracle::MustHold,
                        transform: None,
                        expected: None,
                        description: Some("Value must be within range".to_string()),
                        severity: Some("critical".to_string()),
                    });
                }
                PatternType::Nullifier => {
                    invariants.push(Invariant {
                        name: "nullifier_uniqueness".to_string(),
                        invariant_type: InvariantType::Uniqueness,
                        relation: "unique(nullifier)".to_string(),
                        oracle: InvariantOracle::MustHold,
                        transform: None,
                        expected: None,
                        description: Some("Nullifier must be unique".to_string()),
                        severity: Some("critical".to_string()),
                    });
                }
                PatternType::HashFunction(_) => {
                    invariants.push(Invariant {
                        name: "hash_collision_resistance".to_string(),
                        invariant_type: InvariantType::Constraint,
                        relation: "x != y => hash(x) != hash(y)".to_string(),
                        oracle: InvariantOracle::MustHold,
                        transform: None,
                        expected: None,
                        description: Some("Hash must be collision resistant".to_string()),
                        severity: Some("critical".to_string()),
                    });
                }
                _ => {}
            }
        }

        invariants
    }

    /// Generate attack schedule based on detected patterns
    fn generate_schedule(&self, patterns: &[DetectedPattern]) -> Vec<SchedulePhase> {
        let mut phases = vec![
            // Always start with exploration
            SchedulePhase {
                phase: "exploration".to_string(),
                duration_sec: 60,
                attacks: vec!["underconstrained".to_string(), "boundary".to_string()],
                max_iterations: None,
                early_terminate: None,
                carry_corpus: true,
                mutation_weights: HashMap::new(),
            },
        ];

        // Add pattern-specific phases
        let mut deep_attacks = vec!["soundness".to_string()];

        for pattern in patterns {
            match &pattern.pattern_type {
                PatternType::MerkleTree | PatternType::HashFunction(_) => {
                    if !deep_attacks.contains(&"collision".to_string()) {
                        deep_attacks.push("collision".to_string());
                    }
                }
                PatternType::RangeCheck => {
                    if !deep_attacks.contains(&"arithmetic_overflow".to_string()) {
                        deep_attacks.push("arithmetic_overflow".to_string());
                    }
                }
                _ => {}
            }
        }

        phases.push(SchedulePhase {
            phase: "deep_testing".to_string(),
            duration_sec: 300,
            attacks: deep_attacks,
            max_iterations: None,
            early_terminate: None,
            carry_corpus: true,
            mutation_weights: HashMap::new(),
        });

        phases
    }

    /// Suggest include files based on detected patterns
    fn suggest_includes(&self, patterns: &[DetectedPattern]) -> Vec<String> {
        let mut includes = vec!["templates/traits/base.yaml".to_string()];

        for pattern in patterns {
            if let Some(ref trait_name) = pattern.suggested_trait {
                let include = format!("templates/traits/{}.yaml", trait_name);
                if !includes.contains(&include) {
                    includes.push(include);
                }
            }
        }

        includes
    }

    /// Suggest profiles based on detected patterns
    fn suggest_profiles(&self, patterns: &[DetectedPattern]) -> HashMap<String, Profile> {
        let mut profiles = HashMap::new();

        for pattern in patterns {
            match &pattern.pattern_type {
                PatternType::MerkleTree => {
                    profiles.insert(
                        "merkle_detected".to_string(),
                        Profile {
                            description: Some("Auto-detected Merkle tree pattern".to_string()),
                            max_depth: Some(20),
                            hash_function: Some("poseidon".to_string()),
                            ..Default::default()
                        },
                    );
                }
                PatternType::RangeCheck => {
                    profiles.insert(
                        "range_detected".to_string(),
                        Profile {
                            description: Some("Auto-detected range check pattern".to_string()),
                            bit_length: Some(64),
                            ..Default::default()
                        },
                    );
                }
                _ => {}
            }
        }

        profiles
    }

    /// Detect inputs from source code
    fn detect_inputs(&self, source: &str, framework: Framework) -> Vec<Input> {
        let mut inputs = Vec::new();

        match framework {
            Framework::Circom => {
                // Parse Circom signal declarations
                for line in source.lines() {
                    if let Some(input) = parse_circom_input(line) {
                        inputs.push(input);
                    }
                }
            }
            Framework::Noir => {
                // Parse Noir function parameters
                for line in source.lines() {
                    if let Some(input) = parse_noir_input(line) {
                        inputs.push(input);
                    }
                }
            }
            _ => {}
        }

        inputs
    }

    /// Generate attacks based on detected patterns
    fn generate_attacks(&self, patterns: &[DetectedPattern]) -> Vec<Attack> {
        let mut attacks = vec![
            Attack {
                attack_type: AttackType::Underconstrained,
                description: "Auto-detected: Check for missing constraints".to_string(),
                plugin: None,
                config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            },
            Attack {
                attack_type: AttackType::Boundary,
                description: "Auto-detected: Boundary value testing".to_string(),
                plugin: None,
                config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            },
        ];

        for pattern in patterns {
            match &pattern.pattern_type {
                PatternType::MerkleTree | PatternType::HashFunction(_) => {
                    if !attacks
                        .iter()
                        .any(|a| a.attack_type == AttackType::Collision)
                    {
                        attacks.push(Attack {
                            attack_type: AttackType::Collision,
                            description: "Auto-detected: Hash/Merkle collision testing".to_string(),
                            plugin: None,
                            config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
                        });
                    }
                }
                PatternType::RangeCheck | PatternType::BitDecomposition => {
                    if !attacks
                        .iter()
                        .any(|a| a.attack_type == AttackType::ArithmeticOverflow)
                    {
                        attacks.push(Attack {
                            attack_type: AttackType::ArithmeticOverflow,
                            description: "Auto-detected: Arithmetic overflow testing".to_string(),
                            plugin: None,
                            config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
                        });
                    }
                }
                PatternType::Signature => {
                    attacks.push(Attack {
                        attack_type: AttackType::Soundness,
                        description: "Auto-detected: Signature forgery testing".to_string(),
                        plugin: None,
                        config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
                    });
                }
                _ => {}
            }
        }

        attacks
    }
}

/// Trait for pattern matching implementations
pub trait PatternMatcher: Send + Sync {
    fn detect(&self, source: &str, framework: Framework) -> Option<DetectedPattern>;
}

/// Merkle tree pattern matcher
struct MerklePatternMatcher;

impl PatternMatcher for MerklePatternMatcher {
    fn detect(&self, source: &str, _framework: Framework) -> Option<DetectedPattern> {
        let keywords = [
            "merkle",
            "MerkleProof",
            "merkleRoot",
            "pathElements",
            "pathIndices",
        ];
        let mut matches = 0;
        let mut locations = Vec::new();

        for (i, line) in source.lines().enumerate() {
            let line_lower = line.to_lowercase();
            for keyword in &keywords {
                if line_lower.contains(&keyword.to_lowercase()) {
                    matches += 1;
                    locations.push(i + 1);
                    break;
                }
            }
        }

        if matches >= 2 {
            Some(DetectedPattern {
                pattern_type: PatternType::MerkleTree,
                confidence: (matches as f64 / 5.0).min(1.0),
                locations,
                suggested_trait: Some("merkle".to_string()),
            })
        } else {
            None
        }
    }
}

/// Range check pattern matcher
struct RangePatternMatcher;

impl PatternMatcher for RangePatternMatcher {
    fn detect(&self, source: &str, _framework: Framework) -> Option<DetectedPattern> {
        let keywords = [
            "Num2Bits",
            "range_check",
            "LessThan",
            "GreaterThan",
            "InRange",
            "bits",
        ];
        let mut matches = 0;
        let mut locations = Vec::new();

        for (i, line) in source.lines().enumerate() {
            for keyword in &keywords {
                if line.contains(keyword) {
                    matches += 1;
                    locations.push(i + 1);
                    break;
                }
            }
        }

        if matches >= 1 {
            Some(DetectedPattern {
                pattern_type: PatternType::RangeCheck,
                confidence: (matches as f64 / 3.0).min(1.0),
                locations,
                suggested_trait: Some("range".to_string()),
            })
        } else {
            None
        }
    }
}

/// Hash function pattern matcher
struct HashPatternMatcher;

impl PatternMatcher for HashPatternMatcher {
    fn detect(&self, source: &str, _framework: Framework) -> Option<DetectedPattern> {
        let hash_patterns = [
            ("Poseidon", "poseidon"),
            ("MiMC", "mimc"),
            ("Pedersen", "pedersen"),
            ("SHA256", "sha256"),
            ("Keccak", "keccak"),
        ];

        for (i, line) in source.lines().enumerate() {
            for (pattern, name) in &hash_patterns {
                if line.contains(pattern) {
                    return Some(DetectedPattern {
                        pattern_type: PatternType::HashFunction(name.to_string()),
                        confidence: 0.9,
                        locations: vec![i + 1],
                        suggested_trait: Some("hash".to_string()),
                    });
                }
            }
        }

        None
    }
}

/// Nullifier pattern matcher
struct NullifierPatternMatcher;

impl PatternMatcher for NullifierPatternMatcher {
    fn detect(&self, source: &str, _framework: Framework) -> Option<DetectedPattern> {
        let keywords = ["nullifier", "nullifierHash", "commitment"];
        let mut matches = 0;
        let mut locations = Vec::new();

        for (i, line) in source.lines().enumerate() {
            let line_lower = line.to_lowercase();
            for keyword in &keywords {
                if line_lower.contains(keyword) {
                    matches += 1;
                    locations.push(i + 1);
                    break;
                }
            }
        }

        if matches >= 2 {
            Some(DetectedPattern {
                pattern_type: PatternType::Nullifier,
                confidence: (matches as f64 / 3.0).min(1.0),
                locations,
                suggested_trait: Some("nullifier".to_string()),
            })
        } else {
            None
        }
    }
}

/// Signature pattern matcher
struct SignaturePatternMatcher;

impl PatternMatcher for SignaturePatternMatcher {
    fn detect(&self, source: &str, _framework: Framework) -> Option<DetectedPattern> {
        let keywords = [
            "EdDSA",
            "ECDSA",
            "Schnorr",
            "signature",
            "verify_signature",
            "pubkey",
        ];
        let mut matches = 0;
        let mut locations = Vec::new();

        for (i, line) in source.lines().enumerate() {
            for keyword in &keywords {
                if line.contains(keyword) {
                    matches += 1;
                    locations.push(i + 1);
                    break;
                }
            }
        }

        if matches >= 2 {
            Some(DetectedPattern {
                pattern_type: PatternType::Signature,
                confidence: (matches as f64 / 4.0).min(1.0),
                locations,
                suggested_trait: Some("signature".to_string()),
            })
        } else {
            None
        }
    }
}

/// Bit decomposition pattern matcher
struct BitDecompPatternMatcher;

impl PatternMatcher for BitDecompPatternMatcher {
    fn detect(&self, source: &str, _framework: Framework) -> Option<DetectedPattern> {
        let keywords = ["Bits2Num", "Num2Bits", "bit_decomposition", "bits["];
        let mut matches = 0;
        let mut locations = Vec::new();

        for (i, line) in source.lines().enumerate() {
            for keyword in &keywords {
                if line.contains(keyword) {
                    matches += 1;
                    locations.push(i + 1);
                    break;
                }
            }
        }

        if matches >= 1 {
            Some(DetectedPattern {
                pattern_type: PatternType::BitDecomposition,
                confidence: (matches as f64 / 2.0).min(1.0),
                locations,
                suggested_trait: Some("range".to_string()),
            })
        } else {
            None
        }
    }
}

/// Detect framework from file extension
fn detect_framework(path: &Path) -> anyhow::Result<Framework> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("circom") => Ok(Framework::Circom),
        Some("nr") => Ok(Framework::Noir),
        Some("cairo") => Ok(Framework::Cairo),
        Some("rs") => Ok(Framework::Halo2), // Halo2 uses Rust
        _ => anyhow::bail!(
            "Unsupported circuit file extension for backend detection: {}",
            path.display()
        ),
    }
}

/// Detect main component name from source
fn detect_main_component(source: &str, framework: Framework) -> anyhow::Result<String> {
    match framework {
        Framework::Circom => {
            // Look for "template X" or "component main = X"
            for line in source.lines() {
                if line.contains("component main") {
                    if let Some(start) = line.find('=') {
                        let rest = &line[start + 1..];
                        if let Some(end) = rest.find('(') {
                            return Ok(rest[..end].trim().to_string());
                        }
                    }
                }
            }
            anyhow::bail!("Circom source missing explicit `component main = ...`; implicit template selection removed");
        }
        Framework::Noir => {
            // Look for "fn main"
            for line in source.lines() {
                if line.contains("fn main") {
                    return Ok("main".to_string());
                }
            }
            anyhow::bail!("Noir source missing `fn main`; implicit defaults removed");
        }
        _ => {}
    }
    anyhow::bail!(
        "Unsupported framework for main component detection: {:?}",
        framework
    )
}

/// Parse Circom input declaration
fn parse_circom_input(line: &str) -> Option<Input> {
    let line = line.trim();
    if line.starts_with("signal input") || line.starts_with("signal private input") {
        // Extract signal name
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let name_part = parts.last()?;
            let name = name_part.trim_end_matches(';').trim_end_matches(']');

            // Check for array
            let (name, length) = if let Some(bracket) = name.find('[') {
                let base_name = &name[..bracket];
                let len_str = &name[bracket + 1..];
                let len: usize = match len_str.trim_end_matches(']').parse() {
                    Ok(len) => len,
                    Err(err) => {
                        tracing::debug!(
                            "Skipping non-literal Circom input length '{}' in '{}': {}",
                            len_str,
                            line,
                            err
                        );
                        return None;
                    }
                };
                (base_name.to_string(), Some(len))
            } else {
                (name.to_string(), None)
            };

            return Some(Input {
                name,
                input_type: if length.is_some() {
                    "array<field>".to_string()
                } else {
                    "field".to_string()
                },
                fuzz_strategy: super::FuzzStrategy::Random,
                constraints: vec![],
                interesting: vec![],
                length,
            });
        }
    }
    None
}

/// Parse Noir input declaration
fn parse_noir_input(line: &str) -> Option<Input> {
    let line = line.trim();
    // Look for function parameters
    if line.contains("fn main") || line.contains("fn ") {
        if let Some(start) = line.find('(') {
            if let Some(end) = line.find(')') {
                let params = &line[start + 1..end];
                for param in params.split(',') {
                    let param = param.trim();
                    if param.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = param.split(':').collect();
                    if parts.len() == 2 {
                        return Some(Input {
                            name: parts[0].trim().to_string(),
                            input_type: "field".to_string(),
                            fuzz_strategy: super::FuzzStrategy::Random,
                            constraints: vec![],
                            interesting: vec![],
                            length: None,
                        });
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "tests/generator_tests.rs"]
mod tests;
