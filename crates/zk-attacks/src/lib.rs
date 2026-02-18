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
pub mod batch_verification;
pub mod batch_verifier;
pub mod boundary;
pub mod circom_static_lint;
pub mod collision;
pub mod constraint_inference;
pub mod defi_advanced;
pub mod metamorphic;
pub mod privacy_advanced;
pub mod quantum_resistance;
pub mod recursive;
pub mod registry;
pub mod sidechannel_advanced;
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
pub use circom_static_lint::{CircomStaticLint, CircomStaticLintConfig, StaticCheck};
pub use collision::{CollisionAnalysis, CollisionDetector, CollisionPair, HashType};
pub use defi_advanced::{DefiAdvancedAttack, DefiAdvancedConfig};
pub use privacy_advanced::{PrivacyAdvancedAttack, PrivacyAdvancedConfig};
pub use quantum_resistance::{PrimitivePattern, QuantumResistanceAttack, QuantumResistanceConfig};
pub use registry::{
    AttackMetadata, AttackPlugin, AttackPluginLoader, AttackRegistry, DynamicLibraryLoader,
    NoopPluginLoader,
};
pub use sidechannel_advanced::{SidechannelAdvancedAttack, SidechannelAdvancedConfig};
pub use soundness::SoundnessTester;
pub use underconstrained::UnderconstrainedDetector;
pub use zk_core::{Attack, AttackContext, CircuitInfo};
