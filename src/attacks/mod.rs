//! Re-exported attack modules from zk-attacks.
//!
//! ## Novel Oracles (Phase 4)
//!
//! - [`constraint_inference`]: Detect missing constraints via pattern analysis
//! - [`metamorphic`]: Transform-based testing for logic bugs
//! - [`constraint_slice`]: Dependency cone mutation and leak detection
//! - [`spec_inference`]: Auto-learn and violate circuit properties
//! - [`witness_collision`]: Enhanced collision detection with equivalence classes
//!
//! ## DeFi/MEV Attacks (Phase 3)
//!
//! - [`mev`]: MEV extraction detection (ordering, sandwich, arbitrage)
//! - [`front_running`]: Front-running vulnerability detection
//!
//! ## zkEVM-Specific Attacks (Phase 3: Milestone 3.2)
//!
//! - [`zkevm`]: zkEVM state transition, opcode boundary, memory expansion,
//!   and storage proof attacks for L2 rollup security testing
//!
//! ## Batch Verification Attacks (Phase 3: Milestone 3.3)
//!
//! - [`batch_verification`]: Batch mixing, aggregation forgery, cross-circuit
//!   batch analysis, and randomness reuse detection for batch verifiers

pub mod arithmetic;
pub mod batch_verification;  // Phase 3: Batch verification bypass attacks
pub mod boundary;
pub mod collision;
pub mod constraint_inference;
pub mod constraint_slice;
pub mod front_running;  // Phase 3: Front-running attacks
pub mod metamorphic;
pub mod mev;  // Phase 3: MEV attacks
pub mod soundness;
pub mod spec_inference;
pub mod underconstrained;
pub mod verification;
pub mod witness;
pub mod witness_collision;
pub mod zkevm;  // Phase 3: zkEVM-specific attacks

pub use arithmetic::*;
pub use batch_verification::*;
pub use boundary::*;
#[allow(ambiguous_glob_reexports)]
pub use collision::*;
pub use constraint_inference::*;
pub use constraint_slice::*;
pub use front_running::*;
pub use metamorphic::*;
pub use mev::*;
pub use soundness::*;
pub use spec_inference::*;
pub use underconstrained::*;
pub use verification::*;
pub use witness::*;
#[allow(ambiguous_glob_reexports)]
pub use witness_collision::*;
pub use zkevm::*;

pub use zk_attacks::{
    Attack, AttackContext, AttackMetadata, AttackPlugin, AttackPluginLoader, AttackRegistry,
    CircuitInfo, DynamicLibraryLoader, NoopPluginLoader,
};
