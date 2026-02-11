//! Configuration module for ZK-Fuzzer
//!
//! Handles YAML parsing and validation of fuzzing campaigns.
//!
//! ## YAML v2 Features
//!
//! The v2 schema adds support for:
//! - **Includes**: Compose configs from multiple files
//! - **Profiles**: Reusable parameter sets
//! - **Target Traits**: Circuit-specific patterns (merkle, range, hash, etc.)
//! - **Invariants**: Explicit constraints for metamorphic testing
//! - **Schedule**: Phased attack execution with time budgets
//!
//! See [`v2`] module for details.

pub mod generator;
pub mod parser;
pub mod profiles;  // Phase 0: Embedded configuration profiles
pub mod readiness;  // Phase 4C: 0-day readiness validation
pub mod suggester;
pub mod v2;
pub mod additional;

pub use profiles::{ProfileName, EmbeddedProfile, apply_profile};
pub use readiness::{check_0day_readiness, ReadinessReport, ReadinessWarning, ReadinessLevel};
pub use suggester::YamlSuggester;
pub use v2::parse_chains;
pub use additional::AdditionalConfig;

use serde::{Deserialize, Serialize};
use anyhow::Context;
use std::path::PathBuf;

pub use zk_core::{AttackType, Framework, Severity};

/// Main configuration structure for a fuzzing campaign
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FuzzConfig {
    pub campaign: Campaign,
    #[serde(default)]
    pub attacks: Vec<Attack>,
    #[serde(default)]
    pub inputs: Vec<Input>,
    #[serde(default)]
    pub mutations: Vec<Mutation>,
    #[serde(default)]
    pub oracles: Vec<Oracle>,
    #[serde(default)]
    pub reporting: ReportingConfig,
    /// Mode 3: Multi-step chain specifications
    #[serde(default)]
    pub chains: Vec<v2::ChainConfig>,
}

/// Campaign metadata and target information
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Campaign {
    pub name: String,
    pub version: String,
    pub target: Target,
    #[serde(default)]
    pub parameters: Parameters,
}

/// Target circuit specification
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Target {
    pub framework: Framework,
    pub circuit_path: PathBuf,
    pub main_component: String,
}

/// Fuzzing parameters
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Parameters {
    #[serde(default = "default_field")]
    pub field: String,
    #[serde(default = "default_max_constraints")]
    pub max_constraints: u64,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Additional configuration options
    #[serde(default, flatten)]
    pub additional: AdditionalConfig,
}

fn default_field() -> String {
    "bn254".to_string()
}

fn default_max_constraints() -> u64 {
    100000
}

fn default_timeout() -> u64 {
    300
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            field: default_field(),
            max_constraints: default_max_constraints(),
            timeout_seconds: default_timeout(),
            additional: AdditionalConfig::default(),
        }
    }
}

/// Attack vector configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Attack {
    #[serde(rename = "type")]
    pub attack_type: AttackType,
    pub description: String,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub config: serde_yaml::Value,
}

/// Input specification for fuzzing
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Input {
    pub name: String,
    #[serde(rename = "type")]
    pub input_type: String,
    #[serde(default)]
    pub fuzz_strategy: FuzzStrategy,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub interesting: Vec<String>,
    #[serde(default)]
    pub length: Option<usize>,
}

/// Fuzzing strategies for input generation
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzStrategy {
    #[default]
    Random,
    InterestingValues,
    Mutation,
    ExhaustiveIfSmall,
    Symbolic,
    GuidedCoverage,
}

/// Mutation configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Mutation {
    pub name: String,
    #[serde(default = "default_probability")]
    pub probability: f64,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub use_values: Vec<String>,
    #[serde(default)]
    pub max_stacked_mutations: Option<usize>,
}

fn default_probability() -> f64 {
    0.1
}

/// Oracle definition for bug detection
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Oracle {
    pub name: String,
    pub severity: Severity,
    pub description: String,
}

/// Reporting configuration
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct ReportingConfig {
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default = "default_formats")]
    pub formats: Vec<String>,
    #[serde(default)]
    pub include_poc: bool,
    #[serde(default)]
    pub crash_reproduction: bool,
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("./reports")
}

fn default_formats() -> Vec<String> {
    vec!["json".to_string(), "markdown".to_string()]
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            output_dir: default_output_dir(),
            formats: default_formats(),
            include_poc: true,
            crash_reproduction: true,
        }
    }
}

impl FuzzConfig {
    /// Load configuration from a YAML file
    pub fn from_yaml(path: &str) -> anyhow::Result<Self> {
        let config = Self::from_yaml_v2(path)
            .with_context(|| format!("Failed to load config (v2) from {}", path))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> anyhow::Result<()> {
        // Skip circuit path validation for mock framework
        if self.campaign.target.framework != Framework::Mock
            && !self.campaign.target.circuit_path.exists()
        {
            tracing::warn!(
                "Circuit file not found: {:?} (will use mock mode)",
                self.campaign.target.circuit_path
            );
        }

        let has_chains = !self.chains.is_empty();

        // Validate attack configs (chain-only campaigns may omit attacks)
        if self.attacks.is_empty() && !has_chains {
            anyhow::bail!("At least one attack must be specified");
        }

        // Validate inputs (chain-only campaigns may omit inputs)
        if self.inputs.is_empty() && !has_chains {
            anyhow::bail!("At least one input must be specified");
        }

        Ok(())
    }
}
