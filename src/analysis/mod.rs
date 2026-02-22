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
pub mod concolic;
pub mod constraint_guided;
pub mod constraint_symbolic;
pub mod constraint_types;
pub mod dependency;
pub mod opus;
pub mod profiling;
pub mod r1cs_parser;
pub mod r1cs_to_smt;
pub mod symbolic;
pub mod symbolic_enhanced;
pub mod taint;

pub use complexity::{ComplexityAnalyzer, ComplexityMetrics};
pub use profiling::{PerformanceProfile, Profiler};
pub use symbolic::{
    PathCondition, SolverResult, SymbolicConfig, SymbolicConstraint, SymbolicExecutor,
    SymbolicFuzzerIntegration, SymbolicState, SymbolicStats, SymbolicValue, VulnerabilityPattern,
    Z3Solver,
};
pub use symbolic_enhanced::{
    ConstraintRemovalPlan, ConstraintSimplifier, ConstraintSubsetSelector,
    ConstraintSubsetStrategy, EnhancedSymbolicConfig, EnhancedSymbolicExecutor,
    EnhancedSymbolicStats, ExecutionMode, IncrementalSolver, PathPruner, PruningStrategy,
    WitnessExtensionConfig, WitnessExtensionResult,
};

// Phase 4: Symbolic V2 with path explosion mitigation
pub use zk_symbolic::symbolic_v2::{
    ConstraintCache, ConstraintPattern, MergeStrategy, MergedState, MergedValue, PathMerger,
    PathPriority, SymbolicV2Config, SymbolicV2Executor, SymbolicV2Stats,
    VulnerabilityTargetPattern,
};

// Phase 4.3: Targeted symbolic execution
pub use zk_symbolic::targeted::{
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
pub use dependency::{DependencyAnalyzer, DependencyCoverageStats, DependencyGraph};
pub use r1cs_parser::{
    parse_sym_file, R1CSConstraint as ParsedR1CSConstraint, R1CSConstraintGuidedExt, R1CS,
};
pub use r1cs_to_smt::{generate_constraint_guided_inputs, R1CSToSMT};
pub use taint::{TaintAnalyzer, TaintFinding};

// Re-export underconstrained exploit detection
pub use constraint_symbolic::{
    ConstraintCheckerSymbolicExt, ExtendedConstraintSymbolicExt, SymbolicConversionOptions,
};
pub use constraint_types::{
    AcirOpcode, AirConstraint, AirDomain, AirExpression, BlackBoxOp, ConstraintChecker,
    ConstraintEvaluation, ConstraintParser, CustomGateConstraint, ExtendedConstraint,
    LookupConstraint, LookupTable, MemoryOpType, ParsedConstraintSet, PlonkGate,
    PolynomialConstraint, PolynomialTerm, R1CSConstraint, RangeConstraint, RangeMethod,
    UnknownLookupPolicy, WireRef,
};
pub use opus::{
    AttackPriority, CircuitAnalysisResult, ComplexityEstimate, GeneratedConfig, InputInfo,
    OpusAnalyzer, OpusConfig, ZeroDayCategory, ZeroDayHint,
};
pub use zk_constraints::{
    detect_underconstrained, detect_underconstrained_circom, find_alternative_witness,
    find_multiple_alternatives, quick_underconstrained_check, AltWitnessSolver,
    AlternativeWitnessResult, DifferenceAnalysis, ExploitConfidence, ExploitDetectorConfig,
    ExploitStats, ForgeryStats, ProofForgeryDetector, ProofForgeryResult, ProofVerificationBundle,
    R1CSMatrices, SolverStats as AltWitnessSolverStats, UnderconstrainedExploit,
    UnderconstrainedExploitDetector, VerificationResult, WitnessBundle,
};
