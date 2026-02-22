//! ZkPatternFuzz: Zero-Knowledge Proof Security Testing Framework
//!
//! A comprehensive fuzzing and security testing framework for ZK circuits across
//! multiple proving systems. Detects vulnerabilities through coverage-guided fuzzing,
//! symbolic execution, and specialized attack patterns.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use zk_fuzzer::{FuzzConfig, ZkFuzzer};
//!
//! # fn main() -> anyhow::Result<()> {
//! # let config_yaml = r#"
//! # campaign:
//! #   name: "Doc Test Campaign"
//! #   version: "1.0"
//! #   target:
//! #     framework: "circom"
//! #     circuit_path: "./circuits/example.circom"
//! #     main_component: "Main"
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
//!       public_input_names: ["root", "nullifier"]
//!       fixed_public_inputs: ["0x0", "0x0"]
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
//! - [`oracles`] - Vulnerability-specific attack implementations
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
//!       public_input_count: 1
//!       fixed_public_inputs: ["0x01"]
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

pub mod ai;
pub mod config;
pub mod corpus;
pub mod cve;
pub mod errors;
pub mod executor;
pub mod fuzzer;
pub mod oracles;
pub mod progress;
pub mod reporting;
pub mod targets;
pub mod util;

// New feature modules
pub mod analysis;
pub mod chain_fuzzer; // Mode 3: Multi-step chain fuzzing
pub mod differential;
pub mod formal;
pub mod multi_circuit;

pub use config::{
    Attack, AttackType, Campaign, Framework, FuzzConfig, FuzzStrategy, Input, Parameters,
    ReportingConfig, Severity, Target,
};
pub use errors::{Result, ZkFuzzerError};
pub use executor::{CircuitExecutor, ExecutorFactory, ExecutorFactoryOptions};
pub use fuzzer::ZkFuzzer;
pub use reporting::{FuzzReport, PoCFormat, PoCGenerator, PoCGeneratorConfig};
pub use zk_core::CircuitInfo;

/// Curated high-level imports for library consumers.
///
/// This prelude is additive and non-breaking: broad re-exports remain available for
/// existing users, while new integrations can prefer a smaller import surface.
pub mod prelude {
    pub use crate::config::{
        Attack, AttackType, Campaign, Framework, FuzzConfig, FuzzStrategy, Input, Parameters,
        ReportingConfig, Severity, Target,
    };
    pub use crate::errors::{Result, ZkFuzzerError};
    pub use crate::executor::{CircuitExecutor, ExecutorFactory, ExecutorFactoryOptions};
    pub use crate::fuzzer::ZkFuzzer;
    pub use crate::reporting::FuzzReport;
    pub use crate::CircuitInfo;
}

// Semantic oracles for ZK-specific vulnerability detection
pub use fuzzer::{
    AdaptiveCampaignResults,
    AdaptiveOrchestrator,
    AdaptiveOrchestratorBuilder,
    AdaptiveOrchestratorConfig,
    // Adaptive fuzzing
    AdaptiveScheduler,
    AdaptiveSchedulerConfig,
    AdaptiveSchedulerStats,
    CombinedSemanticOracle,
    CommitmentOracle,
    ConfirmedZeroDay,
    MerkleOracle,
    NearMiss,
    NearMissConfig,
    // Near-miss detection
    NearMissDetector,
    NearMissStats,
    NullifierOracle,
    OracleConfig,
    OracleStats,
    RangeProofOracle,
    SemanticOracle,
    SuggestionType,
    // YAML suggestions
    YamlSuggestion,
};

// Re-export new feature types
pub use analysis::{
    collect_input_wire_indices,
    detect_underconstrained,
    detect_underconstrained_circom,
    // Underconstrained exploit detection (R1CS matrix extraction + alt witness solving)
    find_alternative_witness,
    find_multiple_alternatives,
    parse_sym_file,
    quick_underconstrained_check,
    AcirOpcode,
    AirConstraint,
    AirDomain,
    AirExpression,
    AltWitnessSolver,
    AltWitnessSolverStats,
    AlternativeWitnessResult,
    AttackPriority,
    BlackBoxOp,
    CircuitAnalysisResult,
    ComplexityAnalyzer,
    ComplexityMetrics,
    ConcolicConfig,
    // Concolic execution
    ConcolicExecutor,
    ConcolicFuzzerIntegration,
    ConcolicStats,
    ConcolicTrace,
    ConstraintChecker,
    ConstraintCheckerSymbolicExt,
    ConstraintEvaluation,
    ConstraintParser,
    ConstraintRemovalPlan,
    // Constraint-guided symbolic seeding
    ConstraintSeedGenerator,
    ConstraintSeedOutput,
    ConstraintSeedStats,
    ConstraintSimplifier,
    ConstraintSubsetSelector,
    ConstraintSubsetStrategy,
    CustomGateConstraint,
    DifferenceAnalysis,
    EnhancedSymbolicConfig,
    // Enhanced symbolic execution
    EnhancedSymbolicExecutor,
    EnhancedSymbolicStats,
    ExecutionMode,
    ExploitConfidence,
    ExploitDetectorConfig,
    ExploitStats,
    // Extended constraint types
    ExtendedConstraint,
    ExtendedConstraintSymbolicExt,
    ForgeryStats,
    GeneratedConfig,
    IncrementalSolver,
    LookupConstraint,
    LookupTable,
    MemoryOpType,
    // Opus project analyzer
    OpusAnalyzer,
    OpusConfig,
    ParsedConstraintSet,
    ParsedR1CSConstraint,
    PathCondition,
    PathPruner,
    PerformanceProfile,
    PlonkGate,
    PolynomialConstraint,
    PolynomialTerm,
    Profiler,
    ProofForgeryDetector,
    ProofForgeryResult,
    ProofVerificationBundle,
    PruningStrategy,
    R1CSConstraint,
    R1CSConstraintGuidedExt,
    R1CSMatrices,
    RangeConstraint,
    RangeMethod,
    SolverResult,
    SymbolicConfig,
    SymbolicConstraint,
    SymbolicConversionOptions,
    SymbolicExecutor,
    SymbolicFuzzerIntegration,
    SymbolicState,
    SymbolicStats,
    SymbolicValue,
    TaintAnalyzer,
    TaintFinding,
    UnderconstrainedExploit,
    UnderconstrainedExploitDetector,
    UnknownLookupPolicy,
    VerificationResult,
    VulnerabilityPattern,
    WireRef,
    WitnessBundle,
    WitnessExtensionConfig,
    WitnessExtensionResult,
    Z3Solver,
    ZeroDayCategory,
    ZeroDayHint,
    // R1CS binary parsing
    R1CS,
};
pub use differential::{DifferentialConfig, DifferentialFuzzer, DifferentialResult};
pub use formal::{
    export_formal_bridge_artifacts, import_formal_invariants_from_file, CircuitProperty,
    CoqExporter, FormalBridgeArtifacts, FormalBridgeOptions, FormalConfig,
    FormalVerificationManager, LeanExporter, ProofObligation, ProofSystem, PropertyExtractor,
};
pub use multi_circuit::{CircuitChain, MultiCircuitConfig, MultiCircuitFuzzer};

// Mode 3: Chain fuzzing for multi-step vulnerabilities
pub use chain_fuzzer::{
    ChainCorpus, ChainCorpusEntry, ChainFinding, ChainMutator, ChainRunResult, ChainRunner,
    ChainScheduler, ChainShrinker, ChainSpec, ChainTrace, CrossStepAssertion,
    CrossStepInvariantChecker, CrossStepViolation, DepthMetrics, InputWiring, StepSpec, StepTrace,
};
