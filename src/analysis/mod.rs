//! Analysis modules for ZK circuit security testing
//!
//! Provides various analysis capabilities:
//! - Taint analysis: Track information flow from public inputs to private witnesses
//! - Performance profiling: Measure proof generation and verification times
//! - Constraint complexity: Analyze circuit complexity metrics
//! - Symbolic execution: Generate targeted inputs with Z3 integration

pub mod complexity;
pub mod profiling;
pub mod symbolic;
pub mod taint;

pub use complexity::*;
pub use profiling::*;
pub use symbolic::{
    PathCondition, SolverResult, SymbolicConfig, SymbolicConstraint, SymbolicExecutor,
    SymbolicFuzzerIntegration, SymbolicState, SymbolicStats, SymbolicValue, VulnerabilityPattern,
    Z3Solver,
};
pub use taint::*;
