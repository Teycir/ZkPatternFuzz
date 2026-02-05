//! Analysis modules for ZK circuit security testing
//!
//! Provides various analysis capabilities:
//! - Taint analysis: Track information flow from public inputs to private witnesses
//! - Performance profiling: Measure proof generation and verification times
//! - Constraint complexity: Analyze circuit complexity metrics
//! - Symbolic execution: Generate targeted inputs with Z3 integration
//! - Enhanced symbolic: Incremental solving, constraint simplification, path pruning
//! - Concolic execution: Mix concrete and symbolic execution for scalability
//! - R1CS parsing: Direct parsing of Circom-compiled .r1cs files

pub mod complexity;
pub mod constraint_types;
pub mod constraint_guided;
pub mod profiling;
pub mod r1cs_parser;
pub mod r1cs_to_smt;
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
pub use constraint_guided::{
    ConstraintSeedGenerator, ConstraintSeedOutput, ConstraintSeedStats, collect_input_wire_indices,
};
pub use concolic::{
    ConcolicExecutor, ConcolicConfig, ConcolicTrace, ConcolicStats,
    ConcolicFuzzerIntegration,
};
pub use taint::{TaintAnalyzer, TaintFinding};
pub use r1cs_parser::{R1CS, R1CSConstraint as ParsedR1CSConstraint, parse_sym_file};
pub use r1cs_to_smt::{generate_constraint_guided_inputs, R1CSToSMT};
pub use constraint_types::{
    ExtendedConstraint, R1CSConstraint, PlonkGate, CustomGateConstraint,
    LookupConstraint, LookupTable, RangeConstraint, RangeMethod,
    PolynomialConstraint, PolynomialTerm, AcirOpcode, BlackBoxOp, MemoryOpType,
    AirConstraint, AirExpression, AirDomain, ConstraintParser, ConstraintChecker,
    WireRef, SymbolicConversionOptions, ParsedConstraintSet, UnknownLookupPolicy,
    ConstraintEvaluation,
};
