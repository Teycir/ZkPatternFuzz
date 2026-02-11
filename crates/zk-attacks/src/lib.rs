//! Attack modules for different vulnerability classes
//!
//! This module provides implementations of various attack types for ZK circuits:
//! - Underconstrained circuit detection
//! - Soundness attacks (proof forgery)
//! - Arithmetic overflow/underflow detection
//! - Collision detection (hash/nullifier collisions)
//! - Boundary value testing
//! - Verification and witness attacks

pub mod arithmetic;
pub mod batch_verifier;
pub mod batch_verification;
pub mod boundary;
pub mod collision;
pub mod constraint_inference;
pub mod metamorphic;
pub mod recursive;
pub mod registry;
pub mod soundness;
pub mod underconstrained;
pub mod verification;
pub mod witness;
pub mod zkevm;
pub mod zkevm_differential;

pub use arithmetic::ArithmeticTester;
pub use boundary::{
    common_ranges, BoundaryCategory, BoundaryTestResult, BoundaryTestSummary, BoundaryTester,
    RangeSpec,
};
pub use collision::{CollisionAnalysis, CollisionDetector, CollisionPair, HashType};
pub use registry::{
    AttackMetadata, AttackPlugin, AttackPluginLoader, AttackRegistry, DynamicLibraryLoader,
    NoopPluginLoader,
};
pub use soundness::SoundnessTester;
pub use underconstrained::UnderconstrainedDetector;
pub use zk_core::{Attack, AttackContext, CircuitInfo};
