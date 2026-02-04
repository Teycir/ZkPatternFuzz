//! ZK-Fuzzer: Zero-Knowledge Proof Security Testing Framework
//!
//! This library provides a comprehensive fuzzing and security testing
//! framework for ZK circuits across multiple backends (Circom, Noir, Halo2, Cairo).
//!
//! # Architecture
//!
//! The fuzzer is organized into several key modules:
//!
//! - **executor**: Abstraction layer for circuit execution across backends
//! - **fuzzer**: Core fuzzing engine with mutation and coverage tracking
//! - **attacks**: Attack implementations for different vulnerability classes
//! - **corpus**: Test case management and persistence
//! - **reporting**: Result generation and output formatting
//! - **differential**: Differential fuzzing across multiple backends
//! - **analysis**: Taint analysis, profiling, and complexity analysis
//! - **multi_circuit**: Multi-circuit and recursive proof testing
//!
//! # Example
//!
//! ```ignore
//! use zk_fuzzer::{FuzzConfig, ZkFuzzer};
//!
//! let config = FuzzConfig::from_yaml("campaign.yaml")?;
//! let mut fuzzer = ZkFuzzer::new(config, Some(42));
//! let report = fuzzer.run().await?;
//! report.print_summary();
//! ```

pub mod attacks;
pub mod config;
pub mod corpus;
pub mod errors;
pub mod executor;
pub mod fuzzer;
pub mod progress;
pub mod reporting;
pub mod targets;

// New feature modules
pub mod analysis;
pub mod differential;
pub mod multi_circuit;

pub use attacks::CircuitInfo;
pub use config::{
    FuzzConfig, Campaign, Target, Parameters, Attack, AttackType, 
    Input, FuzzStrategy, Framework, Severity, ReportingConfig
};
pub use errors::{ZkFuzzerError, Result};
pub use executor::{CircuitExecutor, ExecutorFactory, MockCircuitExecutor};
pub use fuzzer::ZkFuzzer;
pub use reporting::FuzzReport;

// Re-export new feature types
pub use analysis::{
    TaintAnalyzer, TaintFinding, Profiler, PerformanceProfile,
    ComplexityAnalyzer, ComplexityMetrics, SymbolicExecutor, SymbolicState,
    SymbolicConfig, SymbolicFuzzerIntegration, SymbolicConstraint, SymbolicValue,
    VulnerabilityPattern, Z3Solver, SolverResult, PathCondition, SymbolicStats,
};
pub use differential::{DifferentialFuzzer, DifferentialConfig, DifferentialResult};
pub use multi_circuit::{MultiCircuitFuzzer, MultiCircuitConfig, CircuitChain};
