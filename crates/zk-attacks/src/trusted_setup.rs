//! Trusted-setup poisoning checks.
//!
//! Detects cases where a proof generated under setup A verifies under setup B,
//! indicating key non-binding or setup contamination.

use serde::{Deserialize, Serialize};
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Configuration for trusted setup checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedSetupConfig {
    /// Whether trusted-setup checks are enabled.
    pub enabled: bool,
    /// Maximum cross-setup attempts.
    pub attempts: usize,
    /// Optional setup artifact path A (runtime wiring uses this).
    pub ptau_file_a: Option<String>,
    /// Optional setup artifact path B (runtime wiring uses this).
    pub ptau_file_b: Option<String>,
}

impl Default for TrustedSetupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            attempts: 10,
            ptau_file_a: None,
            ptau_file_b: None,
        }
    }
}

impl TrustedSetupConfig {
    /// Parse trusted-setup config from YAML root or `trusted_setup_test` section.
    pub fn from_yaml(config: &serde_yaml::Value) -> Self {
        let section = config.get("trusted_setup_test").unwrap_or(config);
        Self {
            enabled: section
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            attempts: section
                .get("attempts")
                .and_then(|v| v.as_u64())
                .unwrap_or(10)
                .max(1) as usize,
            ptau_file_a: section
                .get("ptau_file_a")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            ptau_file_b: section
                .get("ptau_file_b")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        }
    }
}

/// First-class trusted-setup checker.
pub struct TrustedSetupAttack {
    config: TrustedSetupConfig,
}

impl TrustedSetupAttack {
    /// Create a new trusted-setup checker.
    pub fn new(config: TrustedSetupConfig) -> Self {
        Self { config }
    }

    /// Borrow current configuration.
    pub fn config(&self) -> &TrustedSetupConfig {
        &self.config
    }

    /// Execute cross-setup verification checks.
    pub fn run(
        &self,
        executor_a: &dyn CircuitExecutor,
        executor_b: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if !self.config.enabled || self.config.attempts == 0 {
            return Vec::new();
        }

        let info = executor_a.circuit_info();
        let mut findings = Vec::new();

        for (idx, witness) in witnesses.iter().take(self.config.attempts).enumerate() {
            let proof_a = match executor_a.prove(witness) {
                Ok(p) => p,
                Err(err) => {
                    tracing::debug!(
                        "Skipping witness {} due to setup-A proof generation error: {}",
                        idx,
                        err
                    );
                    continue;
                }
            };

            if witness.len() < info.num_public_inputs {
                continue;
            }

            let public_inputs: Vec<FieldElement> = witness[..info.num_public_inputs].to_vec();
            if let Ok(true) = executor_b.verify(&proof_a, &public_inputs) {
                findings.push(Finding {
                    attack_type: AttackType::TrustedSetup,
                    severity: Severity::Critical,
                    description: format!(
                        "Cross-setup verification succeeded: proof from setup A verified under setup B key (witness {})",
                        idx
                    ),
                    poc: ProofOfConcept {
                        witness_a: witness.clone(),
                        witness_b: None,
                        public_inputs,
                        proof: Some(proof_a),
                    },
                    location: Some("trusted_setup:cross_verification".to_string()),
                });
            }
        }

        findings
    }
}

/// Backward-compatible detector alias around [`TrustedSetupAttack`].
pub struct SetupPoisoningDetector {
    attack: TrustedSetupAttack,
}

impl Default for SetupPoisoningDetector {
    fn default() -> Self {
        Self {
            attack: TrustedSetupAttack::new(TrustedSetupConfig {
                enabled: true,
                ..TrustedSetupConfig::default()
            }),
        }
    }
}

impl SetupPoisoningDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_attempts(mut self, attempts: usize) -> Self {
        self.attack.config.attempts = attempts.max(1);
        self
    }

    /// Run cross-verification between two setup-backed executors.
    pub fn run(
        &self,
        executor_a: &dyn CircuitExecutor,
        executor_b: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        self.attack.run(executor_a, executor_b, witnesses)
    }
}

#[cfg(test)]
#[path = "trusted_setup_tests.rs"]
mod tests;
