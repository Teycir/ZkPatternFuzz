//! YAML v2 Schema Extensions for ZkPatternFuzz
//!
//! This module extends the base configuration with:
//! - YAML includes/overlays for composition
//! - Profile system for reusable configurations
//! - Target traits for circuit-specific patterns
//! - Explicit invariants for metamorphic testing
//! - Phased attack scheduling
//!
//! # Example YAML v2
//!
//! ```yaml
//! includes:
//!   - "templates/base.yaml"
//!   - "templates/traits/merkle.yaml"
//!
//! profiles:
//!   merkle_default:
//!     max_depth: 32
//!     hash_function: "poseidon"
//!
//! target_traits:
//!   uses_merkle: true
//!   range_checks: ["u64", "bitlen:252"]
//!
//! invariants:
//!   - name: "root_consistency"
//!     relation: "root == merkle(leaf, path)"
//!     oracle: "must_hold"
//!
//! schedule:
//!   - phase: "seed"
//!     duration_sec: 60
//!     attacks: ["underconstrained"]
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use serde_yaml::Value;

use super::{FuzzConfig, ReportingConfig};

/// Errors that can occur during v2 config processing
#[derive(Debug, Error)]
pub enum ConfigV2Error {
    #[error("Circular include detected: {0}")]
    CircularInclude(String),

    #[error("Include file not found: {0}")]
    IncludeNotFound(PathBuf),

    #[error("Failed to parse include file: {0}")]
    ParseError(String),

    #[error("Invalid invariant expression: {0}")]
    InvalidInvariant(String),

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("Maximum include depth exceeded")]
    MaxIncludeDepth,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    YamlError(#[from] serde_yaml::Error),
}

/// Extended configuration with v2 features
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct FuzzConfigV2 {
    /// List of YAML files to include (processed in order)
    #[serde(default)]
    pub includes: Vec<String>,

    /// Named profiles with reusable parameter sets
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,

    /// Active profile name (if using a predefined profile)
    #[serde(default)]
    pub active_profile: Option<String>,

    /// Target traits describing circuit characteristics
    #[serde(default)]
    pub target_traits: TargetTraits,

    /// Explicit invariants for oracle testing
    #[serde(default)]
    pub invariants: Vec<Invariant>,

    /// Phased attack schedule
    #[serde(default)]
    pub schedule: Vec<SchedulePhase>,

    /// Base v1 configuration (merged after includes)
    #[serde(flatten)]
    pub base: Option<FuzzConfig>,
}

/// Reusable configuration profile
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Profile {
    /// Profile description
    #[serde(default)]
    pub description: Option<String>,

    /// Maximum tree depth (for Merkle circuits)
    #[serde(default)]
    pub max_depth: Option<u32>,

    /// Hash function used
    #[serde(default)]
    pub hash_function: Option<String>,

    /// Bit length for range checks
    #[serde(default)]
    pub bit_length: Option<u32>,

    /// Field prime name (bn254, bls12-381, etc.)
    #[serde(default)]
    pub field: Option<String>,

    /// Custom parameters
    #[serde(default, flatten)]
    pub custom: HashMap<String, serde_yaml::Value>,
}

/// Target traits describing circuit characteristics
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TargetTraits {
    /// Circuit uses Merkle tree structures
    #[serde(default)]
    pub uses_merkle: bool,

    /// Circuit uses nullifier patterns
    #[serde(default)]
    pub uses_nullifier: bool,

    /// Circuit uses commitment schemes
    #[serde(default)]
    pub uses_commitment: bool,

    /// Circuit uses signature verification
    #[serde(default)]
    pub uses_signature: bool,

    /// Range check specifications (e.g., ["u64", "bitlen:252"])
    #[serde(default)]
    pub range_checks: Vec<String>,

    /// Hash function used in circuit
    #[serde(default)]
    pub hash_function: Option<String>,

    /// Curve used (bn254, bls12-381, etc.)
    #[serde(default)]
    pub curve: Option<String>,

    /// Custom traits
    #[serde(default, flatten)]
    pub custom: HashMap<String, serde_yaml::Value>,
}

/// Invariant definition for metamorphic testing
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Invariant {
    /// Unique invariant name
    pub name: String,

    /// Invariant type
    #[serde(default)]
    pub invariant_type: InvariantType,

    /// Relation expression (DSL or S-expression)
    /// Examples:
    /// - "root == merkle(leaf, path)"
    /// - "∀i: path[i] ∈ {0,1}"
    /// - "output < 2^64"
    pub relation: String,

    /// Oracle to use for checking
    #[serde(default)]
    pub oracle: InvariantOracle,

    /// Metamorphic transform (for metamorphic invariants)
    #[serde(default)]
    pub transform: Option<String>,

    /// Expected behavior after transform
    #[serde(default)]
    pub expected: Option<String>,

    /// Description for documentation
    #[serde(default)]
    pub description: Option<String>,

    /// Severity if violated
    #[serde(default)]
    pub severity: Option<String>,
}

/// Type of invariant
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvariantType {
    /// Standard constraint-based invariant
    #[default]
    Constraint,
    /// Metamorphic relation (input transformation)
    Metamorphic,
    /// Range bound invariant
    Range,
    /// Uniqueness invariant
    Uniqueness,
    /// Custom oracle-based
    Custom,
}

/// Oracle types for invariant checking
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvariantOracle {
    /// Invariant must always hold
    #[default]
    MustHold,
    /// Check via constraint satisfaction
    ConstraintCheck,
    /// Check via symbolic execution
    Symbolic,
    /// Check via differential testing
    Differential,
    /// Custom oracle implementation
    Custom,
}

/// A phase in the attack schedule
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SchedulePhase {
    /// Phase name/identifier
    pub phase: String,

    /// Duration in seconds for this phase
    pub duration_sec: u64,

    /// Attacks to run in this phase
    pub attacks: Vec<String>,

    /// Optional iteration limit (overrides duration if set)
    #[serde(default)]
    pub max_iterations: Option<u64>,

    /// Early termination conditions
    #[serde(default)]
    pub early_terminate: Option<EarlyTerminateCondition>,

    /// Carry corpus to next phase
    #[serde(default = "default_true")]
    pub carry_corpus: bool,

    /// Phase-specific mutation weights
    #[serde(default)]
    pub mutation_weights: HashMap<String, f64>,
}

fn default_true() -> bool {
    true
}

/// Conditions for early phase termination
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EarlyTerminateCondition {
    /// Terminate if this many critical findings found
    #[serde(default)]
    pub on_critical_findings: Option<u32>,

    /// Terminate if coverage reaches this percentage
    #[serde(default)]
    pub on_coverage_percent: Option<f64>,

    /// Terminate if no new coverage for this many seconds
    #[serde(default)]
    pub on_stale_seconds: Option<u64>,
}

/// Configuration resolver for v2 includes and overlays
pub struct ConfigResolver {
    /// Base path for resolving relative includes
    base_path: PathBuf,
    /// Maximum include depth to prevent infinite recursion
    max_depth: usize,
    /// Track visited files for cycle detection
    visited: Vec<PathBuf>,
}

impl ConfigResolver {
    /// Create a new resolver with the given base path
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            max_depth: 10,
            visited: Vec::new(),
        }
    }

    /// Set maximum include depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Resolve a v2 configuration, processing all includes
    pub fn resolve(&mut self, config_path: impl AsRef<Path>) -> Result<FuzzConfig, ConfigV2Error> {
        self.resolve_recursive(config_path.as_ref(), 0)
    }

    fn resolve_recursive(
        &mut self,
        config_path: &Path,
        depth: usize,
    ) -> Result<FuzzConfig, ConfigV2Error> {
        if depth > self.max_depth {
            return Err(ConfigV2Error::MaxIncludeDepth);
        }

        let canonical = config_path
            .canonicalize()
            .unwrap_or_else(|_| config_path.to_path_buf());

        // Check for circular includes
        if self.visited.contains(&canonical) {
            return Err(ConfigV2Error::CircularInclude(
                canonical.display().to_string(),
            ));
        }
        self.visited.push(canonical.clone());

        // Read and parse the file
        let content = std::fs::read_to_string(config_path)?;

        // Try parsing as v2 first
        if let Ok(v2_config) = serde_yaml::from_str::<FuzzConfigV2>(&content) {
            // Process includes first
            let mut merged = FuzzConfig::default_v2();

            for include_path in &v2_config.includes {
                let resolved_path = self.resolve_include_path(include_path, config_path)?;
                let included = self.resolve_recursive(&resolved_path, depth + 1)?;
                merged = Self::merge_configs(merged, included);
            }

            // Apply base config
            if let Some(base) = v2_config.base {
                merged = Self::merge_configs(merged, base);
            }

            // Apply profile if specified
            if let Some(profile_name) = &v2_config.active_profile {
                if let Some(profile) = v2_config.profiles.get(profile_name) {
                    merged = Self::apply_profile(merged, profile);
                } else {
                    return Err(ConfigV2Error::ProfileNotFound(profile_name.clone()));
                }
            }

            // Store v2-specific extensions in additional parameters
            merged
                .campaign
                .parameters
                .additional
                .insert("v2_invariants".to_string(), serde_yaml::to_value(&v2_config.invariants)?);
            merged
                .campaign
                .parameters
                .additional
                .insert("v2_schedule".to_string(), serde_yaml::to_value(&v2_config.schedule)?);
            merged
                .campaign
                .parameters
                .additional
                .insert("v2_traits".to_string(), serde_yaml::to_value(&v2_config.target_traits)?);

            Ok(merged)
        } else {
            // Fall back to v1 parsing
            let config: FuzzConfig = serde_yaml::from_str(&content)?;
            Ok(config)
        }
    }

    fn resolve_include_path(
        &self,
        include: &str,
        current_file: &Path,
    ) -> Result<PathBuf, ConfigV2Error> {
        let include_path = Path::new(include);

        // Try relative to current file first
        if let Some(parent) = current_file.parent() {
            let relative_path = parent.join(include_path);
            if relative_path.exists() {
                return Ok(relative_path);
            }
        }

        // Try relative to base path
        let base_relative = self.base_path.join(include_path);
        if base_relative.exists() {
            return Ok(base_relative);
        }

        // Try absolute path
        if include_path.exists() {
            return Ok(include_path.to_path_buf());
        }

        Err(ConfigV2Error::IncludeNotFound(include_path.to_path_buf()))
    }

    fn merge_configs(base: FuzzConfig, overlay: FuzzConfig) -> FuzzConfig {
        let base_campaign = base.campaign.clone();
        let overlay_campaign = overlay.campaign.clone();

        let mut campaign = if overlay_campaign.name.is_empty() {
            base_campaign.clone()
        } else {
            overlay_campaign.clone()
        };

        // Merge campaign parameters.additional (preserve v2 metadata from templates).
        campaign.parameters.additional = Self::merge_additional(
            base_campaign.parameters.additional,
            overlay_campaign.parameters.additional,
        );

        if !overlay_campaign.name.is_empty() {
            // Overlay explicitly set campaign details; treat as authoritative.
            campaign.name = overlay_campaign.name;
            campaign.version = overlay_campaign.version;
            campaign.target = overlay_campaign.target;
            campaign.parameters.field = overlay_campaign.parameters.field;
            campaign.parameters.max_constraints = overlay_campaign.parameters.max_constraints;
            campaign.parameters.timeout_seconds = overlay_campaign.parameters.timeout_seconds;
        }

        FuzzConfig {
            campaign,
            attacks: if overlay.attacks.is_empty() {
                base.attacks
            } else {
                let mut merged = base.attacks;
                merged.extend(overlay.attacks);
                merged
            },
            inputs: Self::merge_inputs(base.inputs, overlay.inputs),
            mutations: if overlay.mutations.is_empty() {
                base.mutations
            } else {
                let mut merged = base.mutations;
                merged.extend(overlay.mutations);
                merged
            },
            oracles: if overlay.oracles.is_empty() {
                base.oracles
            } else {
                let mut merged = base.oracles;
                merged.extend(overlay.oracles);
                merged
            },
            reporting: if overlay.reporting == ReportingConfig::default() {
                base.reporting
            } else {
                overlay.reporting
            },
        }
    }

    fn merge_inputs(base: Vec<super::Input>, overlay: Vec<super::Input>) -> Vec<super::Input> {
        if base.is_empty() {
            return overlay;
        }
        if overlay.is_empty() {
            return base;
        }

        let mut merged = Vec::with_capacity(base.len() + overlay.len());
        let mut index_by_name: HashMap<String, usize> = HashMap::new();

        for input in base {
            index_by_name.insert(input.name.clone(), merged.len());
            merged.push(input);
        }

        for input in overlay {
            if let Some(idx) = index_by_name.get(&input.name).copied() {
                merged[idx] = input;
            } else {
                index_by_name.insert(input.name.clone(), merged.len());
                merged.push(input);
            }
        }

        merged
    }

    fn merge_additional(
        mut base: HashMap<String, Value>,
        overlay: HashMap<String, Value>,
    ) -> HashMap<String, Value> {
        for (key, value) in overlay {
            let merged_value = match (base.get(&key), value) {
                (Some(Value::Sequence(base_seq)), Value::Sequence(mut overlay_seq))
                    if key == "v2_invariants" || key == "v2_schedule" =>
                {
                    let mut merged = base_seq.clone();
                    merged.append(&mut overlay_seq);
                    Value::Sequence(merged)
                }
                (Some(Value::Mapping(base_map)), Value::Mapping(overlay_map))
                    if key == "v2_traits" =>
                {
                    let mut merged = base_map.clone();
                    for (k, v) in overlay_map {
                        merged.insert(k, v);
                    }
                    Value::Mapping(merged)
                }
                (_, other) => other,
            };
            base.insert(key, merged_value);
        }
        base
    }

    fn apply_profile(mut config: FuzzConfig, profile: &Profile) -> FuzzConfig {
        if let Some(ref field) = profile.field {
            config.campaign.parameters.field = field.clone();
        }

        // Add profile parameters to additional config
        if let Some(depth) = profile.max_depth {
            config
                .campaign
                .parameters
                .additional
                .insert("max_depth".to_string(), serde_yaml::Value::Number(depth.into()));
        }

        if let Some(ref hash) = profile.hash_function {
            config
                .campaign
                .parameters
                .additional
                .insert("hash_function".to_string(), serde_yaml::Value::String(hash.clone()));
        }

        if let Some(bits) = profile.bit_length {
            config
                .campaign
                .parameters
                .additional
                .insert("bit_length".to_string(), serde_yaml::Value::Number(bits.into()));
        }

        // Merge custom parameters
        for (key, value) in &profile.custom {
            config
                .campaign
                .parameters
                .additional
                .insert(key.clone(), value.clone());
        }

        config
    }
}

impl FuzzConfig {
    /// Create a default v2-compatible config
    pub fn default_v2() -> Self {
        Self {
            campaign: super::Campaign {
                name: String::new(),
                version: "2.0".to_string(),
                target: super::Target {
                    framework: zk_core::Framework::Mock,
                    circuit_path: PathBuf::new(),
                    main_component: String::new(),
                },
                parameters: super::Parameters::default(),
            },
            attacks: Vec::new(),
            inputs: Vec::new(),
            mutations: Vec::new(),
            oracles: Vec::new(),
            reporting: ReportingConfig::default(),
        }
    }

    /// Load configuration from a YAML file with v2 support
    pub fn from_yaml_v2(path: &str) -> Result<Self, ConfigV2Error> {
        let base_path = Path::new(path)
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        let mut resolver = ConfigResolver::new(base_path);
        resolver.resolve(path)
    }

    /// Extract v2 invariants from config
    pub fn get_invariants(&self) -> Vec<Invariant> {
        self.campaign
            .parameters
            .additional
            .get("v2_invariants")
            .and_then(|v| serde_yaml::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    /// Extract v2 schedule from config
    pub fn get_schedule(&self) -> Vec<SchedulePhase> {
        self.campaign
            .parameters
            .additional
            .get("v2_schedule")
            .and_then(|v| serde_yaml::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    /// Extract v2 target traits from config
    pub fn get_target_traits(&self) -> TargetTraits {
        self.campaign
            .parameters
            .additional
            .get("v2_traits")
            .and_then(|v| serde_yaml::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    /// Check if config uses v2 features
    pub fn is_v2(&self) -> bool {
        self.campaign.version.starts_with("2.")
            || self.campaign.parameters.additional.contains_key("v2_invariants")
            || self.campaign.parameters.additional.contains_key("v2_schedule")
    }
}

/// Parse an invariant relation expression
pub fn parse_invariant_relation(relation: &str) -> Result<InvariantAST, ConfigV2Error> {
    // Simple parser for invariant expressions
    // Supports: ==, <, >, <=, >=, ∈, ∀
    let relation = relation.trim();

    if relation.contains("==") {
        let parts: Vec<&str> = relation.splitn(2, "==").collect();
        if parts.len() == 2 {
            return Ok(InvariantAST::Equals(
                Box::new(parse_expr(parts[0].trim())?),
                Box::new(parse_expr(parts[1].trim())?),
            ));
        }
    }

    if relation.contains('<') && !relation.contains("<=") {
        let parts: Vec<&str> = relation.splitn(2, '<').collect();
        if parts.len() == 2 {
            return Ok(InvariantAST::LessThan(
                Box::new(parse_expr(parts[0].trim())?),
                Box::new(parse_expr(parts[1].trim())?),
            ));
        }
    }

    if relation.starts_with("∀") || relation.starts_with("forall") {
        return Ok(InvariantAST::ForAll(relation.to_string()));
    }

    // Default to raw expression
    Ok(InvariantAST::Raw(relation.to_string()))
}

fn parse_expr(expr: &str) -> Result<InvariantAST, ConfigV2Error> {
    let expr = expr.trim();

    // Function call: name(args)
    if let Some(paren_idx) = expr.find('(') {
        if expr.ends_with(')') {
            let name = &expr[..paren_idx];
            let args = &expr[paren_idx + 1..expr.len() - 1];
            return Ok(InvariantAST::Call(
                name.to_string(),
                args.split(',').map(|s| s.trim().to_string()).collect(),
            ));
        }
    }

    // Array access: name[index]
    if let Some(bracket_idx) = expr.find('[') {
        if expr.ends_with(']') {
            let name = &expr[..bracket_idx];
            let index = &expr[bracket_idx + 1..expr.len() - 1];
            return Ok(InvariantAST::ArrayAccess(
                name.to_string(),
                index.to_string(),
            ));
        }
    }

    // Power expression: 2^64
    if expr.contains('^') {
        let parts: Vec<&str> = expr.splitn(2, '^').collect();
        if parts.len() == 2 {
            return Ok(InvariantAST::Power(
                parts[0].trim().to_string(),
                parts[1].trim().to_string(),
            ));
        }
    }

    // Simple identifier or literal
    Ok(InvariantAST::Identifier(expr.to_string()))
}

/// AST for invariant expressions
#[derive(Debug, Clone)]
pub enum InvariantAST {
    Identifier(String),
    Call(String, Vec<String>),
    ArrayAccess(String, String),
    Power(String, String),
    Equals(Box<InvariantAST>, Box<InvariantAST>),
    LessThan(Box<InvariantAST>, Box<InvariantAST>),
    ForAll(String),
    Raw(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_equals_invariant() {
        let ast = parse_invariant_relation("root == merkle(leaf, path)").unwrap();
        match ast {
            InvariantAST::Equals(left, right) => {
                assert!(matches!(*left, InvariantAST::Identifier(_)));
                assert!(matches!(*right, InvariantAST::Call(_, _)));
            }
            _ => panic!("Expected Equals"),
        }
    }

    #[test]
    fn test_parse_less_than_invariant() {
        let ast = parse_invariant_relation("output < 2^64").unwrap();
        match ast {
            InvariantAST::LessThan(left, right) => {
                assert!(matches!(*left, InvariantAST::Identifier(_)));
                assert!(matches!(*right, InvariantAST::Power(_, _)));
            }
            _ => panic!("Expected LessThan"),
        }
    }

    #[test]
    fn test_parse_forall_invariant() {
        let ast = parse_invariant_relation("∀i: path[i] ∈ {0,1}").unwrap();
        assert!(matches!(ast, InvariantAST::ForAll(_)));
    }

    #[test]
    fn test_invariant_type_serialization() {
        let invariant = Invariant {
            name: "test".to_string(),
            invariant_type: InvariantType::Metamorphic,
            relation: "x == y".to_string(),
            oracle: InvariantOracle::MustHold,
            transform: Some("permute".to_string()),
            expected: Some("unchanged".to_string()),
            description: None,
            severity: Some("critical".to_string()),
        };

        let yaml = serde_yaml::to_string(&invariant).unwrap();
        assert!(yaml.contains("metamorphic"));
    }

    #[test]
    fn test_schedule_phase_serialization() {
        let phase = SchedulePhase {
            phase: "seed".to_string(),
            duration_sec: 60,
            attacks: vec!["underconstrained".to_string()],
            max_iterations: Some(1000),
            early_terminate: Some(EarlyTerminateCondition {
                on_critical_findings: Some(1),
                on_coverage_percent: None,
                on_stale_seconds: None,
            }),
            carry_corpus: true,
            mutation_weights: HashMap::new(),
        };

        let yaml = serde_yaml::to_string(&phase).unwrap();
        let parsed: SchedulePhase = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.phase, "seed");
        assert_eq!(parsed.duration_sec, 60);
    }
}
