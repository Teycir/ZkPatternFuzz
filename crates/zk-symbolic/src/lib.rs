//! Symbolic execution and constraint-guided input generation for ZK circuits.

pub mod executor;
pub mod enhanced;
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
