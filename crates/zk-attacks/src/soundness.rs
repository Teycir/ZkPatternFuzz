//! Soundness attack detection
//!
//! Soundness attacks attempt to create valid proofs for false statements.
//! A sound proof system should never accept a proof for an invalid statement.
//!
//! The soundness attack is implemented directly in the fuzzer engine
//! (see `FuzzingEngine::run_soundness_attack()`).

use super::{Attack, AttackContext};
use crate::registry::{AttackMetadata, AttackPlugin};
use zk_core::{AttackType, Finding, ProofOfConcept, Severity};

/// Soundness tester for proof systems
pub struct SoundnessTester {
    /// Number of forgery attempts
    forge_attempts: usize,
    /// Mutation rate for proof modification
    mutation_rate: f64,
}

impl Default for SoundnessTester {
    fn default() -> Self {
        Self {
            forge_attempts: 1000,
            mutation_rate: 0.1,
        }
    }
}

impl SoundnessTester {
    /// Create a new soundness tester
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of forgery attempts
    pub fn with_forge_attempts(mut self, attempts: usize) -> Self {
        self.forge_attempts = attempts;
        self
    }

    /// Set the mutation rate for proof modification
    pub fn with_mutation_rate(mut self, rate: f64) -> Self {
        self.mutation_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Get the configured forgery attempts
    pub fn forge_attempts(&self) -> usize {
        self.forge_attempts
    }

    /// Get the configured mutation rate
    pub fn mutation_rate(&self) -> f64 {
        self.mutation_rate
    }
}

impl Attack for SoundnessTester {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for circuits that might be vulnerable to soundness attacks
        if context.circuit_info.degrees_of_freedom() > 0 {
            findings.push(Finding {
                attack_type: AttackType::Soundness,
                severity: Severity::High,
                description: format!(
                    "Circuit '{}' has positive degrees of freedom ({}) - may be vulnerable to soundness attacks",
                    context.circuit_info.name,
                    context.circuit_info.degrees_of_freedom()
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        findings
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Soundness
    }

    fn description(&self) -> &str {
        "Attempt to forge proofs for invalid statements"
    }
}

impl AttackPlugin for SoundnessTester {
    fn metadata(&self) -> AttackMetadata {
        AttackMetadata::new(
            "soundness",
            self.description(),
            "0.1.0",
        )
    }
}
