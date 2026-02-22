//! Core types and traits for ZkPatternFuzz.

mod error;
mod executor;
mod field;
mod info;
mod invariants;
mod traits;
mod types;

pub use error::CoreResult;
pub use executor::{
    BatchExecutor, CircuitExecutor, ConstraintEquation, ConstraintInspector, ConstraintResult,
    ExecutionCoverage, ExecutionResult, ParallelBatchExecutor, WitnessExtractor,
};
pub use field::FieldElement;
pub use info::CircuitInfo;
pub use invariants::{
    collect_identifiers, extract_identifiers_from_ast, extract_identifiers_from_relation,
    parse_invariant_relation, validate_invariant_against_inputs, InvariantAST, InvariantParseError,
    InvariantValidationError, InvariantValidationResult,
};
pub use traits::{Attack, AttackContext, OracleConfig, OracleStats, SemanticOracle};
pub use types::{
    AttackType, CoverageMap, Finding, Framework, ProofOfConcept, Severity, TestCase, TestMetadata,
};
