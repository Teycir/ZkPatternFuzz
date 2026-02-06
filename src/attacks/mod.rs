//! Re-exported attack modules from zk-attacks.
//!
//! ## Novel Oracles (Phase 4)
//!
//! - [`constraint_inference`]: Detect missing constraints via pattern analysis
//! - [`metamorphic`]: Transform-based testing for logic bugs
//! - [`constraint_slice`]: Dependency cone mutation and leak detection
//! - [`spec_inference`]: Auto-learn and violate circuit properties
//! - [`witness_collision`]: Enhanced collision detection with equivalence classes

pub mod arithmetic;
pub mod boundary;
pub mod collision;
pub mod constraint_inference;
pub mod constraint_slice;
pub mod metamorphic;
pub mod soundness;
pub mod spec_inference;
pub mod underconstrained;
pub mod verification;
pub mod witness;
pub mod witness_collision;

pub use arithmetic::*;
pub use boundary::*;
#[allow(ambiguous_glob_reexports)]
pub use collision::*;
pub use constraint_inference::*;
pub use constraint_slice::*;
pub use metamorphic::*;
pub use soundness::*;
pub use spec_inference::*;
pub use underconstrained::*;
pub use verification::*;
pub use witness::*;
#[allow(ambiguous_glob_reexports)]
pub use witness_collision::*;

pub use zk_attacks::{
    Attack, AttackContext, AttackMetadata, AttackPlugin, AttackPluginLoader, AttackRegistry,
    CircuitInfo, DynamicLibraryLoader, NoopPluginLoader,
};
