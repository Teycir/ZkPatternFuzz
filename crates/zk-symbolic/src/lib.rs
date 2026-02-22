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

pub mod concolic;
pub mod constraint_guided;
pub mod constraint_symbolic;
pub mod enhanced;
pub mod executor;
pub mod symbolic_v2;
pub mod targeted;

pub use executor::{
    PathCondition, SolverResult, SymbolicConfig, SymbolicConstraint, SymbolicExecutor,
    SymbolicFuzzerIntegration, SymbolicState, SymbolicStats, SymbolicValue, VulnerabilityPattern,
    Z3Solver,
};

pub use enhanced::{
    ConstraintRemovalPlan, ConstraintSimplifier, ConstraintSubsetSelector,
    ConstraintSubsetStrategy, EnhancedSymbolicConfig, EnhancedSymbolicExecutor,
    EnhancedSymbolicStats, ExecutionMode, IncrementalSolver, PathPruner, PruningStrategy,
    WitnessExtensionConfig, WitnessExtensionResult,
};

// Phase 4: Symbolic Execution V2 with path explosion mitigation
pub use symbolic_v2::{
    ConstraintCache, ConstraintPattern, MergeStrategy, MergedState, MergedValue, PathMerger,
    PathPriority, SymbolicV2Config, SymbolicV2Executor, SymbolicV2Stats,
    VulnerabilityTargetPattern,
};

// Phase 4.3: Targeted symbolic execution
pub use targeted::{
    BugDirectedConfig, BugDirectedExecutor, BugDirectedStats, CircuitDifference,
    DifferentialConfig, DifferentialExecutor, DifferentialStats, DirectedFinding,
    VulnerabilityTarget,
};

pub use concolic::{
    ConcolicConfig, ConcolicExecutor, ConcolicFuzzerIntegration, ConcolicStats, ConcolicTrace,
};

pub use constraint_guided::{
    collect_input_wire_indices, ConstraintSeedGenerator, ConstraintSeedOutput, ConstraintSeedStats,
};

pub use constraint_symbolic::{
    ConstraintCheckerSymbolicExt, ExtendedConstraintSymbolicExt, SymbolicConversionOptions,
};
