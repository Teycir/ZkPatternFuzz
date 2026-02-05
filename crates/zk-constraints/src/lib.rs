//! Constraint parsing and analysis utilities for ZK circuits.

pub mod constraint_types;
pub mod r1cs_parser;
pub mod r1cs_to_smt;

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
