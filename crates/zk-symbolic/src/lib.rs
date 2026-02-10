//! Symbolic execution and constraint-guided input generation for ZK circuits.
//!
//! # Modules
//!
//! - [`executor`]: Core Z3-powered symbolic execution framework
//! - [`enhanced`]: Enhanced symbolic execution with incremental solving, constraint simplification
//! - [`symbolic_v2`]: V2 executor with path explosion mitigation, caching, prioritization (Phase 4)
//! - [`targeted`]: Bug-directed and differential symbolic execution (Phase 4.3)
//! - [`concolic`]: Mixed concrete-symbolic execution
//! - [`constraint_guided`]: Constraint-guided seed generation
//! - [`constraint_symbolic`]: Symbolic constraint conversion utilities

pub mod executor;
pub mod enhanced;
pub mod symbolic_v2;
pub mod targeted;
pub mod concolic;
pub mod constraint_guided;
pub mod constraint_symbolic;

pub use executor::{
    SymbolicExecutor, SymbolicState, SymbolicConfig, SymbolicFuzzerIntegration,
    SymbolicConstraint, SymbolicValue, VulnerabilityPattern, Z3Solver, SolverResult,
    PathCondition, SymbolicStats,
};

pub use enhanced::{
    EnhancedSymbolicExecutor, EnhancedSymbolicConfig, EnhancedSymbolicStats,
    ConstraintSimplifier, IncrementalSolver, PathPruner, PruningStrategy,
};

// Phase 4: Symbolic Execution V2 with path explosion mitigation
pub use symbolic_v2::{
    SymbolicV2Executor, SymbolicV2Config, SymbolicV2Stats,
    PathMerger, MergeStrategy, MergedState, MergedValue,
    ConstraintCache, PathPriority, VulnerabilityTargetPattern, ConstraintPattern,
};

// Phase 4.3: Targeted symbolic execution
pub use targeted::{
    BugDirectedExecutor, BugDirectedConfig, BugDirectedStats,
    VulnerabilityTarget, DirectedFinding,
    DifferentialExecutor, DifferentialConfig, DifferentialStats, CircuitDifference,
};

pub use concolic::{
    ConcolicExecutor, ConcolicConfig, ConcolicTrace, ConcolicStats,
    ConcolicFuzzerIntegration,
};

pub use constraint_guided::{
    ConstraintSeedGenerator, ConstraintSeedOutput, ConstraintSeedStats, collect_input_wire_indices,
};

pub use constraint_symbolic::{
    SymbolicConversionOptions, ExtendedConstraintSymbolicExt, ConstraintCheckerSymbolicExt,
};
