//! Arithmetic Overflow/Underflow Detection
//!
//! Tests field arithmetic edge cases for vulnerabilities including:
//! - Overflow/underflow at field boundaries
//! - Division by zero handling
//! - Incorrect modular reduction
//!
//! The arithmetic attack is implemented directly in the fuzzer engine
//! (see `FuzzingEngine::run_arithmetic_attack()`).

use super::{Attack, AttackContext};
use crate::config::{AttackType, Severity};
use crate::fuzzer::{Finding, ProofOfConcept};

/// Arithmetic overflow/underflow tester
pub struct ArithmeticTester {
    /// Test values for arithmetic edge cases
    test_values: Vec<String>,
    /// Whether to test division by zero
    test_div_zero: bool,
}

impl Default for ArithmeticTester {
    fn default() -> Self {
        Self {
            test_values: vec![
                "0".to_string(),
                "1".to_string(),
                "p-1".to_string(),
                "p".to_string(),
            ],
            test_div_zero: true,
        }
    }
}

impl ArithmeticTester {
    /// Create a new arithmetic tester
    pub fn new() -> Self {
        Self::default()
    }

    /// Set custom test values
    pub fn with_test_values(mut self, values: Vec<String>) -> Self {
        self.test_values = values;
        self
    }

    /// Enable/disable division by zero testing
    pub fn with_div_zero_testing(mut self, enabled: bool) -> Self {
        self.test_div_zero = enabled;
        self
    }

    /// Get configured test values
    pub fn test_values(&self) -> &[String] {
        &self.test_values
    }
}

impl Attack for ArithmeticTester {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Heuristic: circuits with high constraint density might have unchecked arithmetic
        let density = context.circuit_info.constraint_density();
        if density > 2.0 {
            findings.push(Finding {
                attack_type: AttackType::ArithmeticOverflow,
                severity: Severity::Low,
                description: format!(
                    "Circuit '{}' has high constraint density ({:.2}) - complex arithmetic may have overflow risks",
                    context.circuit_info.name,
                    density
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        findings
    }

    fn attack_type(&self) -> AttackType {
        AttackType::ArithmeticOverflow
    }

    fn description(&self) -> &str {
        "Test field arithmetic for overflow/underflow vulnerabilities"
    }
}
