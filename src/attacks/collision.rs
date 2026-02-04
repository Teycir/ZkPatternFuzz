//! Collision Detection for ZK Circuits
//!
//! Detects hash and nullifier collisions in ZK circuits using:
//! - Birthday paradox attacks (O(2^(n/2)) for n-bit outputs)
//! - Near-collision detection (Hamming distance analysis)
//! - Output distribution analysis
//!
//! The collision attack is implemented directly in the fuzzer engine
//! (see `FuzzingEngine::run_collision_attack()`).

use super::{Attack, AttackContext};
use crate::config::{AttackType, Severity};
use crate::fuzzer::{Finding, ProofOfConcept};

/// Collision detector for hash and nullifier collisions
pub struct CollisionDetector {
    /// Number of samples to test
    samples: usize,
    /// Hamming distance threshold for near-collisions
    hamming_threshold: usize,
}

impl Default for CollisionDetector {
    fn default() -> Self {
        Self {
            samples: 10000,
            hamming_threshold: 8,
        }
    }
}

impl CollisionDetector {
    /// Create a new collision detector
    pub fn new(samples: usize) -> Self {
        Self {
            samples,
            ..Default::default()
        }
    }

    /// Set the Hamming distance threshold for near-collision detection
    pub fn with_hamming_threshold(mut self, threshold: usize) -> Self {
        self.hamming_threshold = threshold;
        self
    }

    /// Get the configured sample count
    pub fn samples(&self) -> usize {
        self.samples
    }
}

impl Attack for CollisionDetector {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for small output space (vulnerable to birthday attack)
        if context.circuit_info.num_outputs < 2 {
            findings.push(Finding {
                attack_type: AttackType::Collision,
                severity: Severity::Medium,
                description: format!(
                    "Circuit '{}' has only {} output(s), potentially vulnerable to collision attacks",
                    context.circuit_info.name,
                    context.circuit_info.num_outputs
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        findings
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Collision
    }

    fn description(&self) -> &str {
        "Detect hash and nullifier collisions using birthday paradox attacks"
    }
}
