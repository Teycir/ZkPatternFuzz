//! Boundary Value Testing for ZK Circuits
//!
//! Implements systematic boundary value analysis to test circuit behavior at:
//! - Field element boundaries (0, 1, p-1, p, etc.)
//! - Bit boundaries (2^n - 1, 2^n, 2^n + 1)
//! - Application-specific boundaries (range proofs, age verification, etc.)
//! - Type transition boundaries
//!
//! The boundary attack is implemented directly in the fuzzer engine
//! (see `FuzzingEngine::run_boundary_attack()`).

use super::{Attack, AttackContext};
use crate::config::{AttackType, Severity};
use crate::fuzzer::{Finding, ProofOfConcept};

/// Boundary value tester
pub struct BoundaryTester {
    /// Boundary values to test
    test_values: Vec<String>,
    /// Whether to test bit boundaries
    test_bit_boundaries: bool,
}

impl Default for BoundaryTester {
    fn default() -> Self {
        Self {
            test_values: vec![
                "0".to_string(),
                "1".to_string(),
                "p-1".to_string(),
            ],
            test_bit_boundaries: true,
        }
    }
}

impl BoundaryTester {
    /// Create a new boundary tester
    pub fn new() -> Self {
        Self::default()
    }

    /// Add custom test values
    pub fn with_test_values(mut self, values: Vec<String>) -> Self {
        self.test_values = values;
        self
    }

    /// Enable/disable bit boundary testing
    pub fn with_bit_boundaries(mut self, enabled: bool) -> Self {
        self.test_bit_boundaries = enabled;
        self
    }

    /// Get configured test values
    pub fn test_values(&self) -> &[String] {
        &self.test_values
    }
}

impl Attack for BoundaryTester {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for circuits that might have boundary issues
        if context.circuit_info.num_constraints < context.circuit_info.num_private_inputs {
            findings.push(Finding {
                attack_type: AttackType::Boundary,
                severity: Severity::Low,
                description: format!(
                    "Circuit '{}' has fewer constraints than inputs - boundary checking may be incomplete",
                    context.circuit_info.name
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        findings
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Boundary
    }

    fn description(&self) -> &str {
        "Test circuit behavior at field element and bit boundaries"
    }
}
