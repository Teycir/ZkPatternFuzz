//! Analysis modules for ZK circuit security testing
//!
//! Provides various analysis capabilities:
//! - Taint analysis: Track information flow from public inputs to private witnesses
//! - Performance profiling: Measure proof generation and verification times
//! - Constraint complexity: Analyze circuit complexity metrics
//! - Symbolic execution: Generate targeted inputs

pub mod taint;
pub mod profiling;
pub mod complexity;
pub mod symbolic;

pub use taint::*;
pub use profiling::*;
pub use complexity::*;
pub use symbolic::*;
