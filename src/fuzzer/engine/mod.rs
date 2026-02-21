//! Core fuzzing engine with coverage-guided execution
//!
//! This module implements the main fuzzing engine that orchestrates zero-knowledge
//! circuit security testing through intelligent test case generation, execution,
//! coverage tracking, and vulnerability detection.
//!
//! # Architecture
//!
//! The fuzzing engine combines multiple advanced techniques:
//!
//! - **Coverage-Guided Fuzzing**: Tracks constraint coverage to guide input generation
//!   toward unexplored code paths
//! - **Power Scheduling**: Prioritizes interesting test cases using energy-based selection
//!   (FAST, COE, EXPLORE, MMOPT, RARE, SEEK)
//! - **Structure-Aware Mutation**: Understands ZK-specific data structures (Merkle paths,
//!   signatures, nullifiers) for intelligent mutations
//! - **Symbolic Execution**: Uses Z3 SMT solver to generate inputs that satisfy specific
//!   constraint paths
//! - **Taint Analysis**: Tracks information flow to detect potential leaks
//! - **Bug Oracles**: Specialized detectors for underconstrained circuits, arithmetic
//!   overflows, and other ZK-specific vulnerabilities
//!
//! # Workflow
//!
//! 1. **Initialization**: Load circuit, analyze complexity, seed initial corpus
//! 2. **Test Case Selection**: Power scheduler picks interesting inputs from corpus
//! 3. **Mutation**: Structure-aware mutator generates new test cases
//! 4. **Execution**: Run circuit with mutated inputs, track coverage
//! 5. **Oracle Checking**: Detect bugs using specialized oracles
//! 6. **Corpus Update**: Add interesting cases that increase coverage
//! 7. **Repeat**: Continue until timeout or iteration limit
//!
//! # Example
//!
//! ```rust,no_run
//! use zk_fuzzer::fuzzer::FuzzingEngine;
//! use zk_fuzzer::config::FuzzConfig;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let config_yaml = r#"
//! # campaign:
//! #   name: "Doc Engine Campaign"
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
//! // Create fuzzing engine with 1 worker and deterministic seed
//! let mut engine = FuzzingEngine::new(config, Some(42), 1)?;
//!
//! // Run fuzzing campaign
//! let report = tokio::runtime::Runtime::new()?.block_on(async { engine.run(None).await })?;
//!
//! // Check results
//! println!("Found {} vulnerabilities", report.findings.len());
//! println!("Coverage: {:.1}%", report.statistics.coverage_percentage);
//! # Ok(())
//! # }
//! ```
//!
//! # Performance
//!
//! The engine supports parallel execution across multiple workers. Each worker:
//! - Maintains its own RNG for deterministic reproduction
//! - Shares corpus and coverage data via lock-free structures
//! - Reports findings to a central collector
//!
//! Typical throughput: 100-10,000 executions/second depending on circuit complexity.
//!
//! # Supported Backends
//!
//! - **Circom**: R1CS circuits via snarkjs
//! - **Noir**: ACIR circuits via Barretenberg  
//! - **Halo2**: PLONK circuits via halo2_proofs
//! - **Cairo**: STARK programs via stone-prover
//! - Synthetic backends are disabled in runtime execution paths

mod attack_runner;
mod attack_runner_advanced;
mod attack_runner_budget;
mod attack_runner_novel;
mod attack_runner_numeric;
mod attack_runner_protocol;
mod attack_runner_runtime;
mod attack_runner_static;
mod chain_runner;
mod config_helpers;
mod continuous_fuzzer;
mod corpus_manager;
mod engine_init;
mod finding_pipeline;
mod invariant_enforcer;
mod metamorphic_helpers;
mod report_generator;
mod run_bootstrap;
mod run_continuation;
mod run_dispatch;
mod run_lifecycle;
mod run_pattern;
mod run_reporting;

mod prelude {
    pub(super) use crate::analysis::complexity::ComplexityAnalyzer;
    pub(super) use crate::analysis::symbolic::{
        SymbolicConfig, SymbolicFuzzerIntegration, VulnerabilityPattern,
    };
    pub(super) use crate::analysis::taint::TaintAnalyzer;
    pub(super) use crate::analysis::{
        collect_input_wire_indices, ConstraintSeedGenerator, ConstraintSeedOutput,
        EnhancedSymbolicConfig, PruningStrategy,
    };
    pub(super) use crate::config::*;
    pub(super) use crate::corpus::{create_corpus, minimizer, storage as corpus_storage};
    pub(super) use crate::executor::{
        create_coverage_tracker, ExecutorFactory, ExecutorFactoryOptions, IsolatedExecutor,
    };
    pub(super) use crate::fuzzer::invariant_checker::InvariantChecker; // Phase 2: Fuzz-continuous invariant checking
    pub(super) use crate::fuzzer::mutate_field_element;
    pub(super) use crate::fuzzer::oracle::{
        ArithmeticOverflowOracle, BugOracle, UnderconstrainedOracle,
    };
    pub(super) use crate::fuzzer::oracle_correlation::{ConfidenceLevel, OracleCorrelator}; // Phase 6A: Cross-oracle correlation
    pub(super) use crate::fuzzer::oracle_validation::{
        filter_validated_findings, OracleValidationConfig, OracleValidator,
    };
    pub(super) use crate::fuzzer::power_schedule::{PowerSchedule, PowerScheduler};
    pub(super) use crate::fuzzer::structure_aware::StructureAwareMutator;
    pub(super) use crate::oracles::{
        Attack as AttackTrait, AttackContext, AttackRegistry, DynamicLibraryLoader,
    };
    pub(super) use crate::progress::{FuzzingStats, ProgressReporter, SimpleProgressTracker};
    pub(super) use crate::reporting::FuzzReport;
    pub(super) use rand::Rng;
    pub(super) use rayon::prelude::*;
    pub(super) use std::path::PathBuf;
    pub(super) use std::sync::Arc;
    pub(super) use std::time::{Duration, Instant};
    pub(super) use zk_core::{
        AttackType, CircuitExecutor, ConstraintInspector, ExecutionResult, FieldElement, Finding,
        ProofOfConcept, Severity, TestCase, TestMetadata,
    };
    pub(super) use zk_fuzzer_core::engine::FuzzingEngineCore;
}

use prelude::*;

/// Main fuzzing engine coordinating all security testing activities
///
/// The `FuzzingEngine` is the central component that orchestrates the entire
/// fuzzing campaign. It manages:
///
/// - Circuit execution through backend-specific executors
/// - Test case corpus with automatic minimization
/// - Coverage tracking for constraint exploration
/// - Multiple bug detection oracles
/// - Parallel worker coordination
/// - Progress reporting and statistics
///
/// # Thread Safety
///
/// The engine uses `Arc` and `RwLock` for safe concurrent access to shared state.
/// Multiple workers can execute test cases in parallel while safely updating
/// the corpus, coverage map, and findings list.
///
/// # Memory Management
///
/// The corpus is bounded to prevent unbounded memory growth. When the limit is
/// reached, less interesting test cases are evicted based on coverage contribution.
pub struct FuzzingEngine {
    config: FuzzConfig,
    seed: Option<u64>,
    executor: Arc<dyn CircuitExecutor>,
    executor_factory_options: ExecutorFactoryOptions,
    core: FuzzingEngineCore,
    attack_registry: AttackRegistry,
    workers: usize,
    /// Symbolic execution integration for guided test generation
    symbolic: Option<SymbolicFuzzerIntegration>,
    /// Taint analyzer for information flow tracking
    taint_analyzer: Option<TaintAnalyzer>,
    /// Complexity analyzer for circuit analysis
    complexity_analyzer: ComplexityAnalyzer,
    /// Simple progress tracker for non-interactive mode
    simple_tracker: Option<SimpleProgressTracker>,
    /// Phase 2: Cached invariant checker for fuzz-continuous checking
    /// Maintains state for uniqueness invariants across executions
    invariant_checker: Option<InvariantChecker>,
    /// Mode 3: Reusable thread pool for parallel execution (avoids per-attack allocation)
    thread_pool: Option<rayon::ThreadPool>,
    /// Optional wall-clock deadline for the entire run.
    ///
    /// When present, attacks and continuous fuzzing stop once this deadline is reached.
    wall_clock_deadline: Option<Instant>,
}
