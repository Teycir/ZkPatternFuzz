//! Embedded Configuration Profiles (Phase 0: Milestone 0.3)
//!
//! Pre-defined profiles with sensible defaults for common use cases.
//! These profiles reduce the configuration burden from 20+ parameters
//! to a single `--profile` flag.
//!
//! # Usage
//!
//! ```bash
//! cargo run -- run campaign.yaml --profile quick    # Fast exploration
//! cargo run -- run campaign.yaml --profile standard # Balanced fuzzing
//! cargo run -- evidence campaign.yaml --profile deep # Deep analysis
//! cargo run -- run campaign.yaml --profile perf     # Throughput-first long runs
//! ```
//!
//! # Profile Comparison
//!
//! | Setting                  | Quick    | Standard  | Deep       | Perf      |
//! |--------------------------|----------|-----------|------------|-----------|
//! | max_iterations           | 10,000   | 100,000   | 1,000,000  | 500,000   |
//! | evidence_mode            | false    | true      | true       | false     |
//! | per_exec_isolation       | false    | false     | true       | false     |
//! | symbolic_enabled         | true     | true      | true       | false     |
//! | symbolic_max_depth       | 50       | 200       | 1,000      | 20        |
//! | constraint_guided        | false    | true      | true       | false     |

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Available profile names
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileName {
    /// Fast exploration for initial triage (10K iterations)
    Quick,
    /// Balanced fuzzing for most audits (100K iterations)
    Standard,
    /// Deep analysis for critical targets (1M iterations)
    Deep,
    /// Performance-first long-run profile (500K iterations)
    Perf,
}

impl std::str::FromStr for ProfileName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "quick" | "fast" | "triage" => Ok(ProfileName::Quick),
            "standard" | "default" | "balanced" => Ok(ProfileName::Standard),
            "deep" | "thorough" | "comprehensive" => Ok(ProfileName::Deep),
            "perf" | "performance" | "throughput" => Ok(ProfileName::Perf),
            _ => Err(format!(
                "Unknown profile '{}'. Available: quick, standard, deep, perf",
                s
            )),
        }
    }
}

impl std::fmt::Display for ProfileName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileName::Quick => write!(f, "quick"),
            ProfileName::Standard => write!(f, "standard"),
            ProfileName::Deep => write!(f, "deep"),
            ProfileName::Perf => write!(f, "perf"),
        }
    }
}

/// Embedded profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedProfile {
    /// Profile name for display
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Maximum fuzzing iterations
    pub max_iterations: u64,
    /// Enable evidence mode (proof generation)
    pub evidence_mode: bool,
    /// Enable per-execution isolation (slower but safer)
    pub per_exec_isolation: bool,
    /// Attack types to enable
    pub attacks: Vec<String>,
    /// Enable constraint-guided fuzzing
    pub constraint_guided_enabled: bool,
    /// Enable symbolic execution seeding
    pub symbolic_enabled: bool,
    /// Maximum symbolic execution depth
    pub symbolic_max_depth: u32,
    /// Timeout per circuit execution (seconds)
    pub timeout_per_execution: u64,
    /// Enable oracle validation
    pub oracle_validation: bool,
    /// Enable cross-oracle correlation
    pub cross_oracle_correlation: bool,
}

impl Default for EmbeddedProfile {
    fn default() -> Self {
        Self::standard()
    }
}

impl EmbeddedProfile {
    /// Quick profile: Fast exploration for initial triage
    pub fn quick() -> Self {
        Self {
            name: "quick".to_string(),
            description: "Fast exploration for initial triage (10K iterations)".to_string(),
            max_iterations: 10_000,
            evidence_mode: false,
            per_exec_isolation: false,
            attacks: vec![
                "boundary".to_string(),
                "arithmetic_overflow".to_string(),
                "underconstrained".to_string(),
            ],
            constraint_guided_enabled: false,
            symbolic_enabled: true,
            symbolic_max_depth: 50,
            timeout_per_execution: 5,
            oracle_validation: false,
            cross_oracle_correlation: false,
        }
    }

    /// Standard profile: Balanced fuzzing for most audits
    pub fn standard() -> Self {
        Self {
            name: "standard".to_string(),
            description: "Balanced fuzzing for most audits (100K iterations)".to_string(),
            max_iterations: 100_000,
            evidence_mode: true,
            per_exec_isolation: false,
            attacks: vec![
                "underconstrained".to_string(),
                "soundness".to_string(),
                "boundary".to_string(),
                "arithmetic_overflow".to_string(),
                "collision".to_string(),
                "constraint_inference".to_string(),
                "metamorphic".to_string(),
                "constraint_slice".to_string(),
                "spec_inference".to_string(),
                "witness_collision".to_string(),
            ],
            constraint_guided_enabled: true,
            symbolic_enabled: true,
            symbolic_max_depth: 200,
            timeout_per_execution: 30,
            oracle_validation: true,
            cross_oracle_correlation: true,
        }
    }

    /// Deep profile: Thorough analysis for critical targets
    pub fn deep() -> Self {
        Self {
            name: "deep".to_string(),
            description: "Thorough analysis for critical targets (1M iterations)".to_string(),
            max_iterations: 1_000_000,
            evidence_mode: true,
            per_exec_isolation: true,
            attacks: vec!["all".to_string()],
            constraint_guided_enabled: true,
            symbolic_enabled: true,
            symbolic_max_depth: 1_000,
            timeout_per_execution: 60,
            oracle_validation: true,
            cross_oracle_correlation: true,
        }
    }

    /// Perf profile: Throughput-first long runs (reduced seeding cost)
    pub fn perf() -> Self {
        Self {
            name: "perf".to_string(),
            description: "Performance-first long runs (500K iterations)".to_string(),
            max_iterations: 500_000,
            evidence_mode: false,
            per_exec_isolation: false,
            attacks: vec!["underconstrained".to_string(), "boundary".to_string()],
            constraint_guided_enabled: false,
            symbolic_enabled: false,
            symbolic_max_depth: 20,
            timeout_per_execution: 10,
            oracle_validation: false,
            cross_oracle_correlation: false,
        }
    }

    /// Get profile by name
    pub fn by_name(name: ProfileName) -> Self {
        match name {
            ProfileName::Quick => Self::quick(),
            ProfileName::Standard => Self::standard(),
            ProfileName::Deep => Self::deep(),
            ProfileName::Perf => Self::perf(),
        }
    }

    /// Convert profile settings to YAML additional parameters
    pub fn to_additional_params(&self) -> HashMap<String, serde_yaml::Value> {
        let mut params = HashMap::new();

        params.insert(
            "max_iterations".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(self.max_iterations)),
        );
        params.insert(
            "evidence_mode".to_string(),
            serde_yaml::Value::Bool(self.evidence_mode),
        );
        params.insert(
            "per_exec_isolation".to_string(),
            serde_yaml::Value::Bool(self.per_exec_isolation),
        );
        params.insert(
            "constraint_guided_enabled".to_string(),
            serde_yaml::Value::Bool(self.constraint_guided_enabled),
        );
        params.insert(
            "symbolic_enabled".to_string(),
            serde_yaml::Value::Bool(self.symbolic_enabled),
        );
        params.insert(
            "symbolic_max_depth".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(self.symbolic_max_depth)),
        );
        params.insert(
            "timeout_per_execution".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(self.timeout_per_execution)),
        );
        params.insert(
            "oracle_validation".to_string(),
            serde_yaml::Value::Bool(self.oracle_validation),
        );
        params.insert(
            "cross_oracle_correlation".to_string(),
            serde_yaml::Value::Bool(self.cross_oracle_correlation),
        );

        params
    }

    /// Merge profile settings into existing config, allowing YAML overrides
    pub fn merge_into(&self, additional: &mut HashMap<String, serde_yaml::Value>) {
        let profile_params = self.to_additional_params();

        for (key, value) in profile_params {
            // Only set if not already present (YAML takes precedence)
            additional.entry(key).or_insert(value);
        }
    }

    /// Get list of all available profiles
    pub fn list_all() -> Vec<Self> {
        vec![Self::quick(), Self::standard(), Self::deep(), Self::perf()]
    }

    /// Print profile comparison table
    pub fn print_comparison() {
        println!("Available Profiles:");
        println!();
        println!("| Setting                  | Quick    | Standard  | Deep       | Perf      |");
        println!("|--------------------------|----------|-----------|------------|-----------|");
        println!("| max_iterations           | 10,000   | 100,000   | 1,000,000  | 500,000   |");
        println!("| evidence_mode            | false    | true      | true       | false     |");
        println!("| per_exec_isolation       | false    | false     | true       | false     |");
        println!("| symbolic_enabled         | true     | true      | true       | false     |");
        println!("| symbolic_max_depth       | 50       | 200       | 1,000      | 20        |");
        println!("| constraint_guided        | false    | true      | true       | false     |");
        println!("| oracle_validation        | false    | true      | true       | false     |");
        println!();
        println!("Usage: cargo run -- run campaign.yaml --profile <quick|standard|deep|perf>");
    }
}

/// Apply a named profile to a FuzzConfig
pub fn apply_profile(config: &mut super::FuzzConfig, profile_name: ProfileName) {
    let profile = EmbeddedProfile::by_name(profile_name);
    profile.merge_into(&mut config.campaign.parameters.additional);
    merge_profile_attacks(config, &profile);

    tracing::info!(
        "Applied profile '{}': {} iterations, evidence_mode={}",
        profile.name,
        profile.max_iterations,
        profile.evidence_mode,
    );
}

fn merge_profile_attacks(config: &mut super::FuzzConfig, profile: &EmbeddedProfile) {
    let requested = expand_profile_attack_names(profile);
    for attack_name in requested {
        let Some(attack_type) = profile_attack_type(attack_name) else {
            tracing::warn!(
                "Ignoring unknown profile attack '{}' in profile '{}'",
                attack_name,
                profile.name
            );
            continue;
        };

        if config
            .attacks
            .iter()
            .any(|attack| attack.attack_type == attack_type)
        {
            continue;
        }

        config.attacks.push(super::Attack {
            attack_type: attack_type.clone(),
            description: format!("Profile-enabled attack: {}", attack_name),
            plugin: None,
            config: default_profile_attack_config(&attack_type),
        });
    }
}

fn expand_profile_attack_names(profile: &EmbeddedProfile) -> Vec<&str> {
    if profile
        .attacks
        .iter()
        .any(|name| name.eq_ignore_ascii_case("all"))
    {
        return vec![
            "underconstrained",
            "soundness",
            "boundary",
            "arithmetic_overflow",
            "collision",
            "constraint_inference",
            "metamorphic",
            "constraint_slice",
            "spec_inference",
            "witness_collision",
        ];
    }

    profile.attacks.iter().map(String::as_str).collect()
}

fn profile_attack_type(name: &str) -> Option<super::AttackType> {
    match name.trim().to_ascii_lowercase().as_str() {
        "underconstrained" => Some(super::AttackType::Underconstrained),
        "soundness" => Some(super::AttackType::Soundness),
        "boundary" => Some(super::AttackType::Boundary),
        "arithmetic_overflow" | "arithmeticoverflow" => Some(super::AttackType::ArithmeticOverflow),
        "collision" => Some(super::AttackType::Collision),
        "constraint_inference" | "constraintinference" => {
            Some(super::AttackType::ConstraintInference)
        }
        "metamorphic" => Some(super::AttackType::Metamorphic),
        "constraint_slice" | "constraintslice" => Some(super::AttackType::ConstraintSlice),
        "spec_inference" | "specinference" => Some(super::AttackType::SpecInference),
        "witness_collision" | "witnesscollision" => Some(super::AttackType::WitnessCollision),
        "witness_validation" | "witness_fuzzing" | "witnessfuzzing" => {
            Some(super::AttackType::WitnessFuzzing)
        }
        _ => None,
    }
}

fn default_profile_attack_config(attack_type: &super::AttackType) -> serde_yaml::Value {
    let mut mapping = serde_yaml::Mapping::new();
    if matches!(attack_type, super::AttackType::Soundness) {
        mapping.insert(
            serde_yaml::Value::String("forge_attempts".to_string()),
            serde_yaml::Value::Number(serde_yaml::Number::from(1000u64)),
        );
    }
    serde_yaml::Value::Mapping(mapping)
}

#[cfg(test)]
#[path = "tests/profiles_tests.rs"]
mod tests;
