//! Core types and traits for ZkPatternFuzz.

mod error;
mod executor;
mod field;
mod info;
mod traits;
mod types;

pub use error::CoreResult;
pub use executor::{
    BatchExecutor, CircuitExecutor, ConstraintEquation, ConstraintInspector, ConstraintResult,
    ExecutionCoverage, ExecutionResult, ParallelBatchExecutor, WitnessExtractor,
};
pub use field::FieldElement;
pub use info::CircuitInfo;
pub use traits::{Attack, AttackContext, OracleConfig, OracleStats, SemanticOracle};
pub use types::{
    AttackType, CoverageMap, Finding, Framework, ProofOfConcept, Severity, TestCase,
    TestMetadata,
};
