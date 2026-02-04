//! Attack modules for different vulnerability classes
//!
//! This module provides implementations of various attack types for ZK circuits:
//! - Underconstrained circuit detection
//! - Soundness attacks (proof forgery)
//! - Arithmetic overflow/underflow detection
//! - Collision detection (hash/nullifier collisions)
//! - Boundary value testing
//! - Verification and witness attacks

mod underconstrained;
mod soundness;
mod arithmetic;
pub mod verification;
pub mod witness;
mod collision;
mod boundary;

pub use underconstrained::UnderconstrainedDetector;
pub use collision::CollisionDetector;
pub use boundary::BoundaryTester;
pub use arithmetic::ArithmeticTester;
pub use soundness::SoundnessTester;

use crate::config::AttackType;
use crate::fuzzer::Finding;

/// Trait for attack implementations
pub trait Attack: Send + Sync {
    /// Run the attack and return any findings
    fn run(&self, context: &AttackContext) -> Vec<Finding>;

    /// Get the attack type
    fn attack_type(&self) -> AttackType;

    /// Get attack description
    fn description(&self) -> &str;
}

/// Context provided to attacks
pub struct AttackContext {
    pub circuit_info: CircuitInfo,
    pub samples: usize,
    pub timeout_seconds: u64,
}

impl AttackContext {
    /// Create a new attack context
    pub fn new(circuit_info: CircuitInfo, samples: usize, timeout_seconds: u64) -> Self {
        Self {
            circuit_info,
            samples,
            timeout_seconds,
        }
    }

    /// Get the circuit name
    pub fn circuit_name(&self) -> &str {
        &self.circuit_info.name
    }

    /// Check if we should continue based on timeout
    pub fn should_continue(&self, elapsed_secs: u64) -> bool {
        elapsed_secs < self.timeout_seconds
    }
}

/// Information about the circuit being tested
#[derive(Debug, Clone)]
pub struct CircuitInfo {
    pub name: String,
    pub num_constraints: usize,
    pub num_private_inputs: usize,
    pub num_public_inputs: usize,
    pub num_outputs: usize,
}

impl Default for CircuitInfo {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            num_constraints: 0,
            num_private_inputs: 0,
            num_public_inputs: 0,
            num_outputs: 0,
        }
    }
}

impl CircuitInfo {
    /// Create with all fields
    pub fn new(
        name: String,
        num_constraints: usize,
        num_private_inputs: usize,
        num_public_inputs: usize,
        num_outputs: usize,
    ) -> Self {
        Self {
            name,
            num_constraints,
            num_private_inputs,
            num_public_inputs,
            num_outputs,
        }
    }

    /// Check if circuit is potentially underconstrained based on constraint count
    pub fn degrees_of_freedom(&self) -> i64 {
        self.num_private_inputs as i64 - self.num_constraints as i64
    }

    /// Quick heuristic check for underconstraint
    pub fn is_likely_underconstrained(&self) -> bool {
        self.degrees_of_freedom() > 0
    }

    /// Get total number of inputs
    pub fn total_inputs(&self) -> usize {
        self.num_private_inputs + self.num_public_inputs
    }

    /// Get constraint density
    pub fn constraint_density(&self) -> f64 {
        let total_signals = self.total_inputs() + self.num_outputs;
        if total_signals == 0 {
            0.0
        } else {
            self.num_constraints as f64 / total_signals as f64
        }
    }
}
