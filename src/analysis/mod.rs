//! Analysis modules for ZK circuit security testing
//!
//! Provides various analysis capabilities:
//! - Taint analysis: Track information flow from public inputs to private witnesses
//! - Performance profiling: Measure proof generation and verification times
//! - Constraint complexity: Analyze circuit complexity metrics
//! - Symbolic execution: Generate targeted inputs with Z3 integration
//! - Enhanced symbolic: Incremental solving, constraint simplification, path pruning
//! - Concolic execution: Mix concrete and symbolic execution for scalability

pub mod complexity;
pub mod constraint_types;
pub mod profiling;
pub mod symbolic;
pub mod symbolic_enhanced;
pub mod concolic;
pub mod taint;

pub use complexity::{ComplexityAnalyzer, ComplexityMetrics};
pub use profiling::{Profiler, PerformanceProfile};
pub use symbolic::{
    SymbolicExecutor, SymbolicState, SymbolicConfig, SymbolicFuzzerIntegration,
    SymbolicConstraint, SymbolicValue, VulnerabilityPattern, Z3Solver, SolverResult,
    PathCondition, SymbolicStats,
};
pub use symbolic_enhanced::{
    EnhancedSymbolicExecutor, EnhancedSymbolicConfig, EnhancedSymbolicStats,
    ConstraintSimplifier, IncrementalSolver, PathPruner, PruningStrategy,
};
pub use concolic::{
    ConcolicExecutor, ConcolicConfig, ConcolicTrace, ConcolicStats,
    ConcolicFuzzerIntegration,
};
pub use taint::{TaintAnalyzer, TaintFinding};
pub use constraint_types::{
    ExtendedConstraint, R1CSConstraint, PlonkGate, CustomGateConstraint,
    LookupConstraint, LookupTable, RangeConstraint, RangeMethod,
    PolynomialConstraint, PolynomialTerm, AcirOpcode, BlackBoxOp, MemoryOpType,
    AirConstraint, AirExpression, AirDomain, ConstraintParser, ConstraintChecker,
    WireRef, SymbolicConversionOptions,
};
