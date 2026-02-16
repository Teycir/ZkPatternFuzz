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
use serde_yaml::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

use super::{AdditionalConfig, FuzzConfig, ReportingConfig};

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

    /// Mode 3: Multi-step chain specifications
    #[serde(default)]
    pub chains: Vec<ChainConfig>,

    /// Base v1 configuration (merged after includes)
    #[serde(flatten)]
    pub base: Option<FuzzConfig>,
}

// ============================================================================
// Mode 3: Chain Configuration Types
// ============================================================================

/// Configuration for a multi-step chain scenario
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ChainConfig {
    /// Unique name for this chain
    pub name: String,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
    /// Ordered sequence of steps
    pub steps: Vec<StepConfig>,
    /// Cross-step assertions to check
    #[serde(default)]
    pub assertions: Vec<AssertionConfig>,
    /// Circuit path mappings: circuit_ref -> circuit_path
    /// Required for multi-circuit chains. Each unique circuit_ref in steps
    /// must have a corresponding entry here with the actual file path.
    #[serde(default)]
    pub circuits: HashMap<String, CircuitPathConfig>,
}

/// Configuration for a circuit path in multi-circuit chains
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CircuitPathConfig {
    /// Path to the circuit file
    pub path: std::path::PathBuf,
    /// Main component name (defaults to circuit_ref if not specified)
    #[serde(default)]
    pub main_component: Option<String>,
    /// Framework override (defaults to campaign framework)
    #[serde(default)]
    pub framework: Option<zk_core::Framework>,
}

/// Configuration for a single step in a chain
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StepConfig {
    /// Reference to the circuit (name or path)
    pub circuit_ref: String,
    /// How to wire inputs for this step
    #[serde(default)]
    pub input_wiring: InputWiringConfig,
    /// Optional label for debugging
    #[serde(default)]
    pub label: Option<String>,
    /// Optional contract for expected total input count (public + private)
    #[serde(default)]
    pub expected_inputs: Option<usize>,
    /// Optional contract for expected output count
    #[serde(default)]
    pub expected_outputs: Option<usize>,
}

/// Configuration for input wiring
///
/// Supports multiple YAML formats:
/// - Simple string: `input_wiring: fresh`
/// - Tagged map: `input_wiring: { from_prior_output: { step: 0, mapping: [[0, 0]] } }`
/// - Shorthand: `input_wiring: { step: 0, mapping: [[0, 0]] }` (implies from_prior_output)
#[derive(Debug, Serialize, Clone, Default)]
pub enum InputWiringConfig {
    /// Generate fresh random inputs
    #[default]
    Fresh,
    /// Use outputs from a prior step
    FromPriorOutput {
        /// Index of the prior step
        step: usize,
        /// Mapping of (output_index, input_index)
        mapping: Vec<[usize; 2]>,
    },
    /// Mix of prior outputs and fresh inputs
    Mixed {
        /// (step, output_index, input_index) for prior outputs
        prior: Vec<[usize; 3]>,
        /// Indices for fresh random values
        fresh_indices: Vec<usize>,
    },
    /// Use explicit constant values (MEDIUM PRIORITY FIX: Now exposed in YAML)
    Constant {
        /// Map of input_index -> constant value (hex string)
        values: std::collections::HashMap<usize, String>,
        /// Indices for fresh random values
        fresh_indices: Vec<usize>,
    },
}

impl<'de> serde::Deserialize<'de> for InputWiringConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct InputWiringVisitor;

        impl<'de> Visitor<'de> for InputWiringVisitor {
            type Value = InputWiringConfig;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("'fresh', a map with 'from_prior_output', 'mixed', 'constant', or shorthand {step, mapping}")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match v.to_lowercase().as_str() {
                    "fresh" => Ok(InputWiringConfig::Fresh),
                    _ => Err(de::Error::unknown_variant(v, &["fresh"])),
                }
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                // Try to peek at the first key to determine format
                let mut step: Option<usize> = None;
                let mut mapping: Option<Vec<[usize; 2]>> = None;
                let mut prior: Option<Vec<[usize; 3]>> = None;
                let mut fresh_indices: Option<Vec<usize>> = None;
                let mut values: Option<std::collections::HashMap<usize, String>> = None;
                let mut tag_found: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        // Tagged format: { from_prior_output: { step: 0, mapping: [[0,0]] } }
                        "from_prior_output" => {
                            #[derive(Deserialize)]
                            struct Inner {
                                step: usize,
                                mapping: Vec<[usize; 2]>,
                            }
                            let inner: Inner = map.next_value()?;
                            return Ok(InputWiringConfig::FromPriorOutput {
                                step: inner.step,
                                mapping: inner.mapping,
                            });
                        }
                        "mixed" => {
                            #[derive(Deserialize)]
                            struct Inner {
                                prior: Vec<[usize; 3]>,
                                fresh_indices: Vec<usize>,
                            }
                            let inner: Inner = map.next_value()?;
                            return Ok(InputWiringConfig::Mixed {
                                prior: inner.prior,
                                fresh_indices: inner.fresh_indices,
                            });
                        }
                        "constant" => {
                            #[derive(Deserialize)]
                            struct Inner {
                                values: std::collections::HashMap<usize, String>,
                                #[serde(default)]
                                fresh_indices: Vec<usize>,
                            }
                            let inner: Inner = map.next_value()?;
                            return Ok(InputWiringConfig::Constant {
                                values: inner.values,
                                fresh_indices: inner.fresh_indices,
                            });
                        }
                        "fresh" => {
                            let _: serde_yaml::Value = map.next_value()?;
                            tag_found = Some("fresh".to_string());
                        }
                        // Shorthand format: { step: 0, mapping: [[0,0]] }
                        "step" => {
                            step = Some(map.next_value()?);
                        }
                        "mapping" => {
                            mapping = Some(map.next_value()?);
                        }
                        "prior" => {
                            prior = Some(map.next_value()?);
                        }
                        "fresh_indices" => {
                            fresh_indices = Some(map.next_value()?);
                        }
                        "values" => {
                            values = Some(map.next_value()?);
                        }
                        _ => {
                            let _: serde_yaml::Value = map.next_value()?;
                        }
                    }
                }

                // Handle tagged fresh
                if tag_found.as_deref() == Some("fresh") {
                    return Ok(InputWiringConfig::Fresh);
                }

                // Handle shorthand formats
                if let (Some(s), Some(m)) = (step, mapping) {
                    return Ok(InputWiringConfig::FromPriorOutput {
                        step: s,
                        mapping: m,
                    });
                }
                if let (Some(p), Some(f)) = (prior, fresh_indices.clone()) {
                    return Ok(InputWiringConfig::Mixed {
                        prior: p,
                        fresh_indices: f,
                    });
                }
                if let Some(v) = values {
                    return Ok(InputWiringConfig::Constant {
                        values: v,
                        fresh_indices: fresh_indices.unwrap_or_default(),
                    });
                }

                // Default to fresh
                Ok(InputWiringConfig::Fresh)
            }
        }

        deserializer.deserialize_any(InputWiringVisitor)
    }
}

/// Configuration for a cross-step assertion
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AssertionConfig {
    /// Unique name for this assertion
    pub name: String,
    /// Relation expression (e.g., "step[0].out[0] == step[1].in[2]")
    pub relation: String,
    /// Severity if violated
    #[serde(default = "default_assertion_severity")]
    pub severity: String,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
}

fn default_assertion_severity() -> String {
    "high".to_string()
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

        let canonical = config_path.canonicalize();
        let canonical = match canonical {
            Ok(value) => value,
            Err(err) => {
                tracing::debug!(
                    "Using non-canonical config path '{}' due to canonicalize error: {}",
                    config_path.display(),
                    err
                );
                config_path.to_path_buf()
            }
        };

        // Check for circular includes
        if self.visited.contains(&canonical) {
            return Err(ConfigV2Error::CircularInclude(
                canonical.display().to_string(),
            ));
        }
        self.visited.push(canonical.clone());

        // Read and parse the file
        let content = std::fs::read_to_string(config_path)?;
        let mut yaml_value: Value = serde_yaml::from_str(&content)?;
        expand_env_in_value(&mut yaml_value);

        // Try parsing as v2 first
        if let Ok(v2_config) = serde_yaml::from_value::<FuzzConfigV2>(yaml_value.clone()) {
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
            merged.campaign.parameters.additional.insert(
                "v2_invariants".to_string(),
                serde_yaml::to_value(&v2_config.invariants)?,
            );
            merged.campaign.parameters.additional.insert(
                "v2_schedule".to_string(),
                serde_yaml::to_value(&v2_config.schedule)?,
            );
            merged.campaign.parameters.additional.insert(
                "v2_traits".to_string(),
                serde_yaml::to_value(&v2_config.target_traits)?,
            );

            // Merge chains defined in this v2 config (overrides included chains by name)
            merged.chains = Self::merge_chains(merged.chains, v2_config.chains);

            Ok(merged)
        } else {
            // Fall back to v1 parsing
            let config: FuzzConfig = serde_yaml::from_value(yaml_value)?;
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
            chains: Self::merge_chains(base.chains, overlay.chains),
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

    fn merge_chains(base: Vec<ChainConfig>, overlay: Vec<ChainConfig>) -> Vec<ChainConfig> {
        if base.is_empty() {
            return overlay;
        }
        if overlay.is_empty() {
            return base;
        }

        let mut merged = Vec::with_capacity(base.len() + overlay.len());
        let mut index_by_name: HashMap<String, usize> = HashMap::new();

        for chain in base {
            index_by_name.insert(chain.name.clone(), merged.len());
            merged.push(chain);
        }

        for chain in overlay {
            if let Some(idx) = index_by_name.get(&chain.name).copied() {
                merged[idx] = chain;
            } else {
                index_by_name.insert(chain.name.clone(), merged.len());
                merged.push(chain);
            }
        }

        merged
    }

    fn merge_additional(mut base: AdditionalConfig, overlay: AdditionalConfig) -> AdditionalConfig {
        let overlay_map = overlay.extra().clone();
        let base_map = base.extra_mut();

        for (key, value) in overlay_map {
            let merged_value = match (base_map.get(&key), value) {
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
            base_map.insert(key, merged_value);
        }

        base
    }

    fn apply_profile(mut config: FuzzConfig, profile: &Profile) -> FuzzConfig {
        if let Some(ref field) = profile.field {
            config.campaign.parameters.field = field.clone();
        }

        // Add profile parameters to additional config
        if let Some(depth) = profile.max_depth {
            config.campaign.parameters.additional.insert(
                "max_depth".to_string(),
                serde_yaml::Value::Number(depth.into()),
            );
        }

        if let Some(ref hash) = profile.hash_function {
            config.campaign.parameters.additional.insert(
                "hash_function".to_string(),
                serde_yaml::Value::String(hash.clone()),
            );
        }

        if let Some(bits) = profile.bit_length {
            config.campaign.parameters.additional.insert(
                "bit_length".to_string(),
                serde_yaml::Value::Number(bits.into()),
            );
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

fn expand_env_in_value(value: &mut Value) {
    match value {
        Value::String(s) => {
            *s = expand_env_string(s);
        }
        Value::Sequence(items) => {
            for item in items {
                expand_env_in_value(item);
            }
        }
        Value::Mapping(map) => {
            for (_key, val) in map.iter_mut() {
                expand_env_in_value(val);
            }
        }
        _ => {}
    }
}

fn expand_env_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }

        if matches!(chars.peek(), Some('{')) {
            chars.next();
            let mut name = String::new();
            for next in chars.by_ref() {
                if next == '}' {
                    break;
                }
                name.push(next);
            }
            if name.is_empty() {
                out.push('$');
                continue;
            }
            let var_name = if let Some((var, _legacy_default)) = name.split_once(":-") {
                // Strict mode: `${VAR:-default}` no longer injects defaults.
                var
            } else {
                name.as_str()
            };
            match std::env::var(var_name) {
                Ok(val) => out.push_str(&val),
                Err(std::env::VarError::NotPresent) => {
                    out.push_str(&format!("${{{}}}", name));
                }
                Err(e) => panic!("Invalid environment variable {}: {}", var_name, e),
            }
            continue;
        }

        let mut name = String::new();
        while let Some(&next) = chars.peek() {
            if next.is_ascii_alphanumeric() || next == '_' {
                name.push(next);
                chars.next();
            } else {
                break;
            }
        }
        if name.is_empty() {
            out.push('$');
            continue;
        }
        match std::env::var(&name) {
            Ok(val) => out.push_str(&val),
            Err(std::env::VarError::NotPresent) => {
                out.push('$');
                out.push_str(&name);
            }
            Err(e) => panic!("Invalid environment variable {}: {}", name, e),
        }
    }

    out
}

impl FuzzConfig {
    /// Create a default v2-compatible config
    pub fn default_v2() -> Self {
        Self {
            campaign: super::Campaign {
                name: String::new(),
                version: "2.0".to_string(),
                target: super::Target {
                    framework: zk_core::Framework::Circom,
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
            chains: Vec::new(),
        }
    }

    /// Load configuration from a YAML file with v2 support
    pub fn from_yaml_v2(path: &str) -> Result<Self, ConfigV2Error> {
        let base_path = Path::new(path)
            .parent()
            .map_or_else(|| Path::new("."), |p| p)
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
            .and_then(|v| match serde_yaml::from_value(v.clone()) {
                Ok(parsed) => Some(parsed),
                Err(err) => {
                    tracing::warn!("Invalid v2_invariants config: {}", err);
                    None
                }
            })
            .unwrap_or_default()
    }

    /// Extract v2 schedule from config
    pub fn get_schedule(&self) -> Vec<SchedulePhase> {
        self.campaign
            .parameters
            .additional
            .get("v2_schedule")
            .and_then(|v| match serde_yaml::from_value(v.clone()) {
                Ok(parsed) => Some(parsed),
                Err(err) => {
                    tracing::warn!("Invalid v2_schedule config: {}", err);
                    None
                }
            })
            .unwrap_or_default()
    }

    /// Extract v2 target traits from config
    pub fn get_target_traits(&self) -> TargetTraits {
        self.campaign
            .parameters
            .additional
            .get("v2_traits")
            .and_then(|v| match serde_yaml::from_value(v.clone()) {
                Ok(parsed) => Some(parsed),
                Err(err) => {
                    tracing::warn!("Invalid v2_traits config: {}", err);
                    None
                }
            })
            .unwrap_or_default()
    }

    /// Check if config uses v2 features
    pub fn is_v2(&self) -> bool {
        self.campaign.version.starts_with("2.")
            || self
                .campaign
                .parameters
                .additional
                .contains_key("v2_invariants")
            || self
                .campaign
                .parameters
                .additional
                .contains_key("v2_schedule")
    }
}

/// Parse an invariant relation expression
pub fn parse_invariant_relation(relation: &str) -> Result<InvariantAST, ConfigV2Error> {
    // Simple parser for invariant expressions
    // Supports: ==, <, >, <=, >=, ∈, ∀
    let relation = relation.trim();

    if relation.starts_with('∀') || relation.to_lowercase().starts_with("forall") {
        let trimmed = relation.trim_start_matches('∀').trim();
        let trimmed = match trimmed.strip_prefix("forall") {
            Some(value) => value,
            None => trimmed,
        }
        .trim();
        if let Some((binder, body)) = trimmed.split_once(':') {
            let expr = parse_invariant_relation(body.trim())?;
            return Ok(InvariantAST::ForAll {
                binder: binder.trim().to_string(),
                expr: Box::new(expr),
            });
        }
    }

    if let Some(range_ast) = parse_range_chain(relation)? {
        return Ok(range_ast);
    }

    if let Some((left, right)) = split_in_set(relation) {
        let element = parse_expr(left.trim())?;
        let set = parse_set(right.trim())?;
        return Ok(InvariantAST::InSet(Box::new(element), Box::new(set)));
    }

    if let Some(ast) = parse_binary_op(relation, "==", InvariantAST::Equals)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, "!=", InvariantAST::NotEquals)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, "<=", InvariantAST::LessThanOrEqual)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, ">=", InvariantAST::GreaterThanOrEqual)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, "<", InvariantAST::LessThan)? {
        return Ok(ast);
    }

    if let Some(ast) = parse_binary_op(relation, ">", InvariantAST::GreaterThan)? {
        return Ok(ast);
    }

    // Default to raw expression
    Ok(InvariantAST::Raw(relation.to_string()))
}

fn parse_expr(expr: &str) -> Result<InvariantAST, ConfigV2Error> {
    let expr = expr.trim();

    if expr.starts_with('{') && expr.ends_with('}') {
        return parse_set(expr);
    }

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

    if is_literal(expr) {
        return Ok(InvariantAST::Literal(expr.to_string()));
    }

    // Simple identifier
    Ok(InvariantAST::Identifier(expr.to_string()))
}

fn parse_binary_op<F>(
    relation: &str,
    op: &str,
    make: F,
) -> Result<Option<InvariantAST>, ConfigV2Error>
where
    F: Fn(Box<InvariantAST>, Box<InvariantAST>) -> InvariantAST,
{
    if relation.contains(op) {
        let parts: Vec<&str> = relation.splitn(2, op).collect();
        if parts.len() == 2 {
            return Ok(Some(make(
                Box::new(parse_expr(parts[0].trim())?),
                Box::new(parse_expr(parts[1].trim())?),
            )));
        }
    }
    Ok(None)
}

fn split_in_set(relation: &str) -> Option<(&str, &str)> {
    if let Some(pos) = relation.find('∈') {
        let (left, right) = relation.split_at(pos);
        let right = right.trim_start_matches('∈');
        return Some((left, right));
    }

    if let Some(pos) = relation.find(" in ") {
        let (left, right) = relation.split_at(pos);
        let right = right.trim_start_matches(" in ");
        return Some((left, right));
    }

    None
}

fn parse_set(expr: &str) -> Result<InvariantAST, ConfigV2Error> {
    let inner = expr
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    if inner.is_empty() {
        return Ok(InvariantAST::Set(Vec::new()));
    }
    let elements = inner
        .split(',')
        .map(|s| parse_expr(s.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(InvariantAST::Set(elements))
}

fn parse_range_chain(relation: &str) -> Result<Option<InvariantAST>, ConfigV2Error> {
    let tokens: Vec<&str> = relation.split_whitespace().collect();
    if tokens.len() != 5 {
        return Ok(None);
    }
    let op1 = tokens[1];
    let op2 = tokens[3];
    let valid_op = |op: &str| matches!(op, "<" | "<=" | ">" | ">=");
    if !valid_op(op1) || !valid_op(op2) {
        return Ok(None);
    }

    let lower = parse_expr(tokens[0].trim())?;
    let value = parse_expr(tokens[2].trim())?;
    let upper = parse_expr(tokens[4].trim())?;

    let (inclusive_lower, inclusive_upper) =
        (op1 == "<=" || op1 == ">=", op2 == "<=" || op2 == ">=");

    Ok(Some(InvariantAST::Range {
        lower: Box::new(lower),
        value: Box::new(value),
        upper: Box::new(upper),
        inclusive_lower,
        inclusive_upper,
    }))
}

fn is_literal(expr: &str) -> bool {
    let lower = expr.to_lowercase();
    if lower.starts_with("0x") {
        return true;
    }
    if lower.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    matches!(
        lower.as_str(),
        "p" | "p-1" | "max" | "max_field" | "(p-1)/2" | "bit_length"
    )
}

/// AST for invariant expressions
#[derive(Debug, Clone)]
pub enum InvariantAST {
    Identifier(String),
    Literal(String),
    Call(String, Vec<String>),
    ArrayAccess(String, String),
    Power(String, String),
    Set(Vec<InvariantAST>),
    Equals(Box<InvariantAST>, Box<InvariantAST>),
    NotEquals(Box<InvariantAST>, Box<InvariantAST>),
    LessThan(Box<InvariantAST>, Box<InvariantAST>),
    LessThanOrEqual(Box<InvariantAST>, Box<InvariantAST>),
    GreaterThan(Box<InvariantAST>, Box<InvariantAST>),
    GreaterThanOrEqual(Box<InvariantAST>, Box<InvariantAST>),
    InSet(Box<InvariantAST>, Box<InvariantAST>),
    Range {
        lower: Box<InvariantAST>,
        value: Box<InvariantAST>,
        upper: Box<InvariantAST>,
        inclusive_lower: bool,
        inclusive_upper: bool,
    },
    ForAll {
        binder: String,
        expr: Box<InvariantAST>,
    },
    Raw(String),
}

// ============================================================================
// Mode 3: Chain Config to Runtime Type Conversion
// ============================================================================

impl ChainConfig {
    /// Convert to runtime ChainSpec type
    pub fn to_chain_spec(&self) -> crate::chain_fuzzer::ChainSpec {
        let steps: Vec<crate::chain_fuzzer::StepSpec> =
            self.steps.iter().map(|s| s.to_step_spec()).collect();

        let assertions: Vec<crate::chain_fuzzer::CrossStepAssertion> = self
            .assertions
            .iter()
            .map(|a| a.to_cross_step_assertion())
            .collect();

        let mut spec = crate::chain_fuzzer::ChainSpec::new(&self.name, steps);
        for assertion in assertions {
            spec = spec.with_assertion(assertion);
        }
        if let Some(desc) = &self.description {
            spec = spec.with_description(desc);
        }
        spec
    }
}

impl StepConfig {
    /// Convert to runtime StepSpec type
    pub fn to_step_spec(&self) -> crate::chain_fuzzer::StepSpec {
        let wiring = self.input_wiring.to_input_wiring();
        let mut spec = match wiring {
            crate::chain_fuzzer::InputWiring::Fresh => {
                crate::chain_fuzzer::StepSpec::fresh(&self.circuit_ref)
            }
            crate::chain_fuzzer::InputWiring::FromPriorOutput { step, mapping } => {
                crate::chain_fuzzer::StepSpec::from_prior(&self.circuit_ref, step, mapping)
            }
            _ => {
                let mut s = crate::chain_fuzzer::StepSpec::fresh(&self.circuit_ref);
                s.input_wiring = wiring;
                s
            }
        };
        if let Some(label) = &self.label {
            spec = spec.with_label(label);
        }
        spec.expected_inputs = self.expected_inputs;
        spec.expected_outputs = self.expected_outputs;
        spec
    }
}

impl InputWiringConfig {
    /// Convert to runtime InputWiring type
    pub fn to_input_wiring(&self) -> crate::chain_fuzzer::InputWiring {
        match self {
            InputWiringConfig::Fresh => crate::chain_fuzzer::InputWiring::Fresh,
            InputWiringConfig::FromPriorOutput { step, mapping } => {
                crate::chain_fuzzer::InputWiring::FromPriorOutput {
                    step: *step,
                    mapping: mapping.iter().map(|m| (m[0], m[1])).collect(),
                }
            }
            InputWiringConfig::Mixed {
                prior,
                fresh_indices,
            } => crate::chain_fuzzer::InputWiring::Mixed {
                prior: prior.iter().map(|p| (p[0], p[1], p[2])).collect(),
                fresh_indices: fresh_indices.clone(),
            },
            // MEDIUM PRIORITY FIX: Support Constant wiring from YAML
            InputWiringConfig::Constant {
                values,
                fresh_indices,
            } => crate::chain_fuzzer::InputWiring::Constant {
                values: values.clone(),
                fresh_indices: fresh_indices.clone(),
            },
        }
    }
}

impl AssertionConfig {
    /// Convert to runtime CrossStepAssertion type
    pub fn to_cross_step_assertion(&self) -> crate::chain_fuzzer::CrossStepAssertion {
        let mut assertion =
            crate::chain_fuzzer::CrossStepAssertion::new(&self.name, &self.relation);
        assertion = assertion.with_severity(&self.severity);
        assertion
    }
}

/// Parse chain configurations from a FuzzConfigV2
pub fn parse_chains_v2(config: &FuzzConfigV2) -> Vec<crate::chain_fuzzer::ChainSpec> {
    config.chains.iter().map(|c| c.to_chain_spec()).collect()
}

/// Parse chain configurations from a FuzzConfig
pub fn parse_chains(config: &super::FuzzConfig) -> Vec<crate::chain_fuzzer::ChainSpec> {
    config.chains.iter().map(|c| c.to_chain_spec()).collect()
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
        match ast {
            InvariantAST::ForAll { expr, .. } => {
                assert!(matches!(*expr, InvariantAST::InSet(_, _)));
            }
            _ => panic!("Expected ForAll"),
        }
    }

    #[test]
    fn test_parse_range_chain() {
        let ast = parse_invariant_relation("0 <= value < 2^64").unwrap();
        match ast {
            InvariantAST::Range { .. } => {}
            _ => panic!("Expected Range"),
        }
    }

    #[test]
    fn test_parse_in_set() {
        let ast = parse_invariant_relation("pathIndices[i] ∈ {0,1}").unwrap();
        match ast {
            InvariantAST::InSet(left, right) => {
                assert!(matches!(*left, InvariantAST::ArrayAccess(_, _)));
                assert!(matches!(*right, InvariantAST::Set(_)));
            }
            _ => panic!("Expected InSet"),
        }
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
