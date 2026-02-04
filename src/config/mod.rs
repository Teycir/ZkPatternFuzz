//! Configuration module for ZK-Fuzzer
//!
//! Handles YAML parsing and validation of fuzzing campaigns.

pub mod parser;

pub use parser::*;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration structure for a fuzzing campaign
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FuzzConfig {
    pub campaign: Campaign,
    pub attacks: Vec<Attack>,
    pub inputs: Vec<Input>,
    #[serde(default)]
    pub mutations: Vec<Mutation>,
    #[serde(default)]
    pub oracles: Vec<Oracle>,
    #[serde(default)]
    pub reporting: ReportingConfig,
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

/// Supported ZK frameworks
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    Circom,
    Noir,
    Halo2,
    Cairo,
    Mock, // For testing without actual circuits
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
    pub config: serde_yaml::Value,
}

/// Supported attack types
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    Underconstrained,
    Soundness,
    ArithmeticOverflow,
    ConstraintBypass,
    TrustedSetup,
    WitnessLeakage,
    ReplayAttack,
    Collision,
    Boundary,
    BitDecomposition,
    Malleability,
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

/// Severity levels for findings
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Reporting configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
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
        let content = std::fs::read_to_string(path)?;
        let config: FuzzConfig = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> anyhow::Result<()> {
        // Skip circuit path validation for mock framework
        if self.campaign.target.framework != Framework::Mock {
            if !self.campaign.target.circuit_path.exists() {
                tracing::warn!(
                    "Circuit file not found: {:?} (will use mock mode)",
                    self.campaign.target.circuit_path
                );
            }
        }

        // Validate attack configs
        if self.attacks.is_empty() {
            anyhow::bail!("At least one attack must be specified");
        }

        // Validate inputs
        if self.inputs.is_empty() {
            anyhow::bail!("At least one input must be specified");
        }

        Ok(())
    }
}
