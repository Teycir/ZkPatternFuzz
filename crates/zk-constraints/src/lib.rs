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
pub mod proof_forgery;
pub mod r1cs_parser;
pub mod r1cs_to_smt;
pub mod underconstrained_exploit;

pub use alt_witness_solver::{
    find_alternative_witness, find_multiple_alternatives, AlternativeWitnessResult,
    AltWitnessSolver, R1CSMatrices, SolverStats,
};
pub use constraint_types::{
    ExtendedConstraint, R1CSConstraint, PlonkGate, CustomGateConstraint,
    LookupConstraint, LookupTable, RangeConstraint, RangeMethod,
    PolynomialConstraint, PolynomialTerm, AcirOpcode, BlackBoxOp, MemoryOpType,
    AirConstraint, AirExpression, AirDomain, ConstraintParser, ConstraintChecker,
    WireRef, ParsedConstraintSet, UnknownLookupPolicy, ConstraintEvaluation,
    LinearCombination,
};

pub use r1cs_parser::{R1CS, R1CSConstraint as ParsedR1CSConstraint, parse_sym_file};
pub use r1cs_to_smt::{generate_constraint_guided_inputs, R1CSToSMT};
pub use proof_forgery::{
    ProofForgeryDetector, ProofForgeryResult, VerificationResult, ForgeryStats,
    quick_underconstrained_check,
};
pub use underconstrained_exploit::{
    UnderconstrainedExploitDetector, UnderconstrainedExploit, ExploitDetectorConfig,
    ExploitConfidence, WitnessBundle, ProofVerificationBundle, DifferenceAnalysis,
    ExploitStats, detect_underconstrained, detect_underconstrained_circom,
};
