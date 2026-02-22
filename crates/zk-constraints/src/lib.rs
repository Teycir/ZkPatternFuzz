//! Constraint parsing and analysis utilities for ZK circuits.
//!
//! This crate provides tools for:
//! - Parsing R1CS binary files from Circom
//! - Extracting A, B, C constraint matrices
//! - Converting constraints to Z3 SMT formulas
//! - Finding alternative witnesses (underconstrained detection)
//! - Proof forgery verification

pub mod alt_witness_solver;
pub mod constraint_types;
pub mod limb_analysis;
pub mod limb_boundary_fuzzer;
pub mod lookup_coverage;
pub mod lookup_extractor;
pub mod proof_forgery;
pub mod r1cs_parser;
pub mod r1cs_to_smt;
pub mod underconstrained_exploit;

pub use alt_witness_solver::{
    find_alternative_witness, find_multiple_alternatives, AltWitnessSolver,
    AlternativeWitnessResult, R1CSMatrices, SolverStats,
};
pub use constraint_types::{
    AcirOpcode, AirConstraint, AirDomain, AirExpression, BlackBoxOp, ConstraintChecker,
    ConstraintEvaluation, ConstraintParser, CustomGateConstraint, ExtendedConstraint,
    LinearCombination, LookupConstraint, LookupTable, MemoryOpType, ParsedConstraintSet, PlonkGate,
    PolynomialConstraint, PolynomialTerm, R1CSConstraint, RangeConstraint, RangeMethod,
    UnknownLookupPolicy, WireRef,
};
pub use limb_analysis::{
    detect_limb_decomposition, DetectedLimb, LimbAnalysisConfig, LimbAnalysisReport, LimbAnalyzer,
    LimbReconstruction, LimbSignalSource, LimbTerm,
};
pub use limb_boundary_fuzzer::{
    LimbBoundaryCase, LimbBoundaryCaseKind, LimbBoundaryFuzzer, LimbBoundaryFuzzerConfig,
};
pub use lookup_coverage::{
    LookupCoverageAnalyzer, LookupCoverageAnalyzerConfig, LookupCoverageIssue,
    LookupCoverageIssueKind, LookupCoverageReport, WireLookupCoverage,
};
pub use lookup_extractor::{
    LookupExtractionReport, LookupExtractorConfig, LookupTableExtractor, LookupUsage,
    LookupUsageSource,
};

pub use proof_forgery::{
    quick_underconstrained_check, ForgeryStats, ProofForgeryDetector, ProofForgeryResult,
    VerificationResult,
};
pub use r1cs_parser::{parse_sym_file, R1CSConstraint as ParsedR1CSConstraint, R1CS};
pub use r1cs_to_smt::{generate_constraint_guided_inputs, R1CSToSMT};
pub use underconstrained_exploit::{
    detect_underconstrained, detect_underconstrained_circom, DifferenceAnalysis, ExploitConfidence,
    ExploitDetectorConfig, ExploitStats, ProofVerificationBundle, UnderconstrainedExploit,
    UnderconstrainedExploitDetector, WitnessBundle,
};
