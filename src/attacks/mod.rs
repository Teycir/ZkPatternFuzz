//! Attack modules for different vulnerability classes
//!
//! This module provides implementations of various attack types for ZK circuits:
//! - Underconstrained circuit detection
//! - Soundness attacks (proof forgery)
//! - Arithmetic overflow/underflow detection
//! - Collision detection (hash/nullifier collisions)
//! - Boundary value testing
//! - Verification and witness attacks

mod arithmetic;
mod boundary;
mod collision;
mod soundness;
mod underconstrained;
pub mod verification;
pub mod witness;

pub use arithmetic::ArithmeticTester;
pub use boundary::{
    common_ranges, BoundaryCategory, BoundaryTestResult, BoundaryTestSummary, BoundaryTester,
    RangeSpec,
};
pub use collision::{CollisionAnalysis, CollisionDetector, CollisionPair, HashType};
pub use soundness::SoundnessTester;
pub use underconstrained::UnderconstrainedDetector;
pub use zk_core::{Attack, AttackContext, CircuitInfo};
