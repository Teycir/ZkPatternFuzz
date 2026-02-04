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
mod verification;
mod witness;
mod collision;
mod boundary;

pub use underconstrained::*;
pub use soundness::*;
pub use arithmetic::*;
pub use verification::*;
pub use witness::*;
pub use collision::*;
pub use boundary::*;

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
    /// Check if circuit is potentially underconstrained based on constraint count
    pub fn degrees_of_freedom(&self) -> i64 {
        self.num_private_inputs as i64 - self.num_constraints as i64
    }

    /// Quick heuristic check for underconstraint
    pub fn is_likely_underconstrained(&self) -> bool {
        self.degrees_of_freedom() > 0
    }
}
