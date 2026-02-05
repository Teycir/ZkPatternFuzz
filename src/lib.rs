//! ZkPatternFuzz: Zero-Knowledge Proof Security Testing Framework
//!
//! A comprehensive fuzzing and security testing framework for ZK circuits across
//! multiple proving systems. Detects vulnerabilities through coverage-guided fuzzing,
//! symbolic execution, and specialized attack patterns.
//!
//! # Quick Start
//!
//! ```rust
//! use zk_fuzzer::{FuzzConfig, ZkFuzzer};
//!
//! # fn main() -> anyhow::Result<()> {
//! # let config_yaml = r#"
//! # campaign:
//! #   name: "Doc Test Campaign"
//! #   version: "1.0"
//! #   target:
//! #     framework: "mock"
//! #     circuit_path: "./circuits/mock.circom"
//! #     main_component: "MockCircuit"
//! #
//! # attacks:
//! #   - type: "boundary"
//! #     description: "Quick boundary check"
//! #     config:
//! #       test_values: ["0", "1"]
//! #
//! # inputs:
//! #   - name: "a"
//! #     type: "field"
//! #     fuzz_strategy: "random"
//! # "#;
//! # let temp = tempfile::NamedTempFile::new()?;
//! # std::fs::write(temp.path(), config_yaml)?;
//! # let config_path = temp.path().to_path_buf();
//! // Load campaign configuration
//! let config = FuzzConfig::from_yaml(config_path.to_str().unwrap())?;
//!
//! // Create fuzzer with deterministic seed
//! let mut fuzzer = ZkFuzzer::new(config, Some(42));
//!
//! // Run fuzzing campaign
//! let report = tokio::runtime::Runtime::new()?.block_on(async { fuzzer.run().await })?;
//!
//! // Display results
//! report.print_summary();
//! # Ok(())
//! # }
//! ```
//!
//! # Supported Backends
//!
//! | Backend | Status | Proof System | Use Cases |
//! |---------|--------|--------------|----------|
//! | **Circom** | ✅ Full | Groth16 (R1CS) | Semaphore, Tornado Cash |
//! | **Noir** | ✅ Full | Barretenberg (ACIR) | Aztec, privacy protocols |
//! | **Halo2** | ✅ Full | PLONK | zkEVM, PSE circuits |
//! | **Cairo** | ✅ Full | STARK | StarkNet, StarkEx |
//! | **Mock** | ✅ Full | Testing | Fuzzer development |
//!
//! # Attack Types
//!
//! ## Underconstrained Detection
//! Finds circuits that accept multiple valid witnesses for the same public inputs,
//! indicating missing constraints.
//!
//! ```yaml
//! attacks:
//!   - type: underconstrained
//!     config:
//!       witness_pairs: 1000
//!       symbolic_execution: true
//! ```
//!
//! ## Soundness Testing  
//! Attempts to forge proofs for invalid statements by manipulating witnesses.
//!
//! ```yaml
//! attacks:
//!   - type: soundness
//!     config:
//!       forge_attempts: 1000
//!       mutation_rate: 0.1
//! ```
//!
//! ## Arithmetic Overflow
//! Tests field arithmetic edge cases (0, 1, p-1, p) to detect overflow issues.
//!
//! ```yaml
//! attacks:
//!   - type: arithmetic_overflow
//!     config:
//!       test_values: ["0", "1", "p-1", "p"]
//! ```
//!
//! ## Witness Validation
//! Verifies witness consistency and correctness across multiple executions.
//!
//! ## Verification Testing
//! Tests proof verification with edge cases and malformed proofs.
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Campaign Config (YAML)                  │
//! └────────────────────────┬────────────────────────────────────┘
//!                          │
//!                          ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Fuzzing Engine                           │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
//! │  │   Corpus     │  │   Coverage   │  │   Oracles    │     │
//! │  │  Management  │  │   Tracking   │  │  (Bug Detect)│     │
//! │  └──────────────┘  └──────────────┘  └──────────────┘     │
//! └────────────────────────┬────────────────────────────────────┘
//!                          │
//!          ┌───────────────┼───────────────┐
//!          ▼               ▼               ▼
//!    ┌──────────┐    ┌──────────┐    ┌──────────┐
//!    │  Circom  │    │   Noir   │    │  Halo2   │
//!    │ Executor │    │ Executor │    │ Executor │
//!    └──────────┘    └──────────┘    └──────────┘
//!          │               │               │
//!          └───────────────┴───────────────┘
//!                          │
//!                          ▼
//!                  ┌──────────────┐
//!                  │    Report    │
//!                  │ (JSON/MD)    │
//!                  └──────────────┘
//! ```
//!
//! # Module Organization
//!
//! - [`executor`] - Circuit execution abstraction layer
//! - [`fuzzer`] - Core fuzzing engine with mutation strategies
//! - [`attacks`] - Vulnerability-specific attack implementations
//! - [`corpus`] - Test case storage and minimization
//! - [`analysis`] - Symbolic execution, taint analysis, profiling
//! - [`differential`] - Cross-backend differential testing
//! - [`multi_circuit`] - Composition and recursive proof analysis
//! - [`reporting`] - Result generation (JSON, Markdown, SARIF)
//! - [`config`] - YAML configuration parsing
//! - [`targets`] - Backend-specific integrations
//!
//! # Configuration Example
//!
//! ```yaml
//! campaign:
//!   name: "Merkle Tree Audit"
//!   version: "1.0"
//!   target:
//!     framework: circom
//!     circuit_path: "./circuits/merkle.circom"
//!     main_component: "MerkleTreeChecker"
//!   parameters:
//!     field: bn254
//!     max_constraints: 100000
//!     timeout_seconds: 300
//!
//! attacks:
//!   - type: underconstrained
//!     description: "Find multiple valid witnesses"
//!     config:
//!       witness_pairs: 1000
//!       symbolic_execution: true
//!
//! inputs:
//!   - name: "leaf"
//!     type: "field"
//!     fuzz_strategy: random
//!   - name: "pathElements"
//!     type: "field[]"
//!     length: 20
//!     fuzz_strategy: interesting_values
//!
//! reporting:
//!   output_dir: "./reports"
//!   formats: ["json", "markdown"]
//!   include_poc: true
//! ```
//!
//! # Performance Tips
//!
//! 1. **Use deterministic seeds** for reproducible fuzzing campaigns
//! 2. **Adjust worker count** based on circuit complexity (light circuits: 8+, heavy: 2-4)
//! 3. **Enable symbolic execution** for targeted constraint exploration
//! 4. **Use corpus minimization** to reduce redundant test cases
//! 5. **Set appropriate timeouts** based on circuit size
//!
//! # Safety and Soundness
//!
//! This fuzzer helps detect:
//! - ❌ Underconstrained circuits (multiple valid witnesses)
//! - ❌ Missing range checks
//! - ❌ Arithmetic overflows
//! - ❌ Information leaks through public outputs
//! - ❌ Proof malleability
//! - ❌ Verification bypass vulnerabilities
//!
//! However, fuzzing cannot prove absence of bugs - it can only find them.
//! Combine with formal verification for complete assurance.
//!
//! # References
//!
//! - [Trail of Bits ZK Security](https://blog.trailofbits.com/tag/zero-knowledge-proofs/)
//! - [0xPARC ZK Bug Tracker](https://github.com/0xPARC/zk-bug-tracker)
//! - [Circom Documentation](https://docs.circom.io/)
//! - [Noir Documentation](https://noir-lang.org/)

pub mod attacks;
pub mod config;
pub mod corpus;
pub mod cve;
pub mod errors;
pub mod executor;
pub mod fuzzer;
pub mod progress;
pub mod reporting;
pub mod targets;

// New feature modules
pub mod analysis;
pub mod differential;
pub mod distributed;
pub mod formal;
pub mod multi_circuit;

pub use attacks::CircuitInfo;
pub use config::{
    FuzzConfig, Campaign, Target, Parameters, Attack, AttackType, 
    Input, FuzzStrategy, Framework, Severity, ReportingConfig
};
pub use errors::{ZkFuzzerError, Result};
pub use executor::{CircuitExecutor, ExecutorFactory, ExecutorFactoryOptions, MockCircuitExecutor};
pub use fuzzer::ZkFuzzer;
pub use reporting::FuzzReport;

// Semantic oracles for ZK-specific vulnerability detection
pub use fuzzer::{
    SemanticOracle, OracleConfig, OracleStats, CombinedSemanticOracle,
    NullifierOracle, MerkleOracle, CommitmentOracle, RangeProofOracle,
};

// Re-export new feature types
pub use analysis::{
    TaintAnalyzer, TaintFinding, Profiler, PerformanceProfile,
    ComplexityAnalyzer, ComplexityMetrics, SymbolicExecutor, SymbolicState,
    SymbolicConfig, SymbolicFuzzerIntegration, SymbolicConstraint, SymbolicValue,
    VulnerabilityPattern, Z3Solver, SolverResult, PathCondition, SymbolicStats,
    // Enhanced symbolic execution
    EnhancedSymbolicExecutor, EnhancedSymbolicConfig, EnhancedSymbolicStats,
    ConstraintSimplifier, IncrementalSolver, PathPruner, PruningStrategy,
    // Constraint-guided symbolic seeding
    ConstraintSeedGenerator, ConstraintSeedOutput, ConstraintSeedStats, collect_input_wire_indices,
    // Concolic execution
    ConcolicExecutor, ConcolicConfig, ConcolicTrace, ConcolicStats,
    ConcolicFuzzerIntegration,
    // Extended constraint types
    ExtendedConstraint, R1CSConstraint, PlonkGate, CustomGateConstraint,
    LookupConstraint, LookupTable, RangeConstraint, RangeMethod,
    PolynomialConstraint, PolynomialTerm, AcirOpcode, BlackBoxOp, MemoryOpType,
    AirConstraint, AirExpression, AirDomain, ConstraintParser, ConstraintChecker,
    WireRef, SymbolicConversionOptions, ParsedConstraintSet, UnknownLookupPolicy,
    ConstraintEvaluation,
    // R1CS binary parsing
    R1CS, ParsedR1CSConstraint, parse_sym_file,
};
pub use differential::{DifferentialFuzzer, DifferentialConfig, DifferentialResult};
pub use distributed::{
    DistributedCoordinator, DistributedConfig, FuzzerNode, NodeRole,
    CorpusSyncManager, SyncStrategy, WorkUnit, NodeStatus, ClusterStats,
};
pub use formal::{
    FormalVerificationManager, FormalConfig, ProofSystem, ProofObligation,
    LeanExporter, CoqExporter, CircuitProperty, PropertyExtractor,
};
pub use multi_circuit::{MultiCircuitFuzzer, MultiCircuitConfig, CircuitChain};
