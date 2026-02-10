//! Analysis modules for ZK circuit security testing
//!
//! Provides various analysis capabilities:
//! - Taint analysis: Track information flow from public inputs to private witnesses
//! - Performance profiling: Measure proof generation and verification times
//! - Constraint complexity: Analyze circuit complexity metrics
//! - Symbolic execution: Generate targeted inputs with Z3 integration
//! - Enhanced symbolic: Incremental solving, constraint simplification, path pruning
//! - Symbolic V2: Path explosion mitigation, caching, prioritization (Phase 4)
//! - Targeted symbolic: Bug-directed and differential execution (Phase 4.3)
//! - Concolic execution: Mix concrete and symbolic execution for scalability
//! - R1CS parsing: Direct parsing of Circom-compiled .r1cs files
//! - Dependency analysis: Witness-dependency graph for coverage guidance
//! - Opus: Project-level analysis and YAML config generation

pub mod complexity;
pub mod constraint_symbolic;
pub mod constraint_types;
pub mod constraint_guided;
pub mod dependency;
pub mod opus;
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

// Phase 4: Symbolic V2 with path explosion mitigation
pub use zk_symbolic::symbolic_v2::{
    SymbolicV2Executor, SymbolicV2Config, SymbolicV2Stats,
    PathMerger, MergeStrategy, MergedState, MergedValue,
    ConstraintCache, PathPriority, VulnerabilityTargetPattern, ConstraintPattern,
};

// Phase 4.3: Targeted symbolic execution
pub use zk_symbolic::targeted::{
    BugDirectedExecutor, BugDirectedConfig, BugDirectedStats,
    VulnerabilityTarget, DirectedFinding,
    DifferentialExecutor, DifferentialConfig, DifferentialStats, CircuitDifference,
};

pub use constraint_guided::{
    ConstraintSeedGenerator, ConstraintSeedOutput, ConstraintSeedStats, collect_input_wire_indices,
};
pub use concolic::{
    ConcolicExecutor, ConcolicConfig, ConcolicTrace, ConcolicStats,
    ConcolicFuzzerIntegration,
};
pub use taint::{TaintAnalyzer, TaintFinding};
pub use dependency::{DependencyGraph, DependencyAnalyzer, DependencyCoverageStats};
pub use r1cs_parser::{
    R1CS, R1CSConstraint as ParsedR1CSConstraint, parse_sym_file, R1CSConstraintGuidedExt,
};
pub use r1cs_to_smt::{generate_constraint_guided_inputs, R1CSToSMT};

// Re-export underconstrained exploit detection
pub use zk_constraints::{
    find_alternative_witness, find_multiple_alternatives, AlternativeWitnessResult,
    AltWitnessSolver, R1CSMatrices, SolverStats as AltWitnessSolverStats,
    ProofForgeryDetector, ProofForgeryResult, VerificationResult, ForgeryStats,
    quick_underconstrained_check,
    UnderconstrainedExploitDetector, UnderconstrainedExploit, ExploitDetectorConfig,
    ExploitConfidence, WitnessBundle, ProofVerificationBundle, DifferenceAnalysis,
    ExploitStats, detect_underconstrained, detect_underconstrained_circom,
};
pub use constraint_types::{
    ExtendedConstraint, R1CSConstraint, PlonkGate, CustomGateConstraint,
    LookupConstraint, LookupTable, RangeConstraint, RangeMethod,
    PolynomialConstraint, PolynomialTerm, AcirOpcode, BlackBoxOp, MemoryOpType,
    AirConstraint, AirExpression, AirDomain, ConstraintParser, ConstraintChecker,
    WireRef, ParsedConstraintSet, UnknownLookupPolicy, ConstraintEvaluation,
};
pub use constraint_symbolic::{
    SymbolicConversionOptions, ExtendedConstraintSymbolicExt, ConstraintCheckerSymbolicExt,
};
pub use opus::{
    OpusAnalyzer, OpusConfig, CircuitAnalysisResult, GeneratedConfig,
    ZeroDayHint, ZeroDayCategory, AttackPriority, InputInfo, ComplexityEstimate,
};
