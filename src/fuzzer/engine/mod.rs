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
mod attack_runner_protocol;
mod attack_runner_static;
mod chain_runner;
mod config_helpers;
mod continuous_fuzzer;
mod corpus_manager;
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

impl FuzzingEngine {
    /// Create a new fuzzing engine from configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Campaign configuration loaded from YAML
    /// * `seed` - Optional RNG seed for deterministic fuzzing (use for reproduction)
    /// * `workers` - Number of parallel workers (typically CPU count)
    ///
    /// # Returns
    ///
    /// Returns a configured engine ready to run, or an error if:
    /// - Circuit backend is not available (e.g., circom not installed)
    /// - Circuit compilation fails
    /// - Configuration is invalid
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use zk_fuzzer::config::FuzzConfig;
    /// use zk_fuzzer::fuzzer::FuzzingEngine;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// # let config_yaml = r#"
    /// # campaign:
    /// #   name: "Doc Engine New"
    /// #   version: "1.0"
    /// #   target:
    /// #     framework: "circom"
    /// #     circuit_path: "./circuits/example.circom"
    /// #     main_component: "Main"
    /// #
    /// # attacks:
    /// #   - type: "boundary"
    /// #     description: "Quick boundary check"
    /// #     config:
    /// #       test_values: ["0", "1"]
    /// #
    /// # inputs:
    /// #   - name: "a"
    /// #     type: "field"
    /// #     fuzz_strategy: "random"
    /// # "#;
    /// # let temp = tempfile::NamedTempFile::new()?;
    /// # std::fs::write(temp.path(), config_yaml)?;
    /// # let config = FuzzConfig::from_yaml(temp.path().to_str().unwrap())?;
    /// // Deterministic fuzzing with 4 workers
    /// let _engine = FuzzingEngine::new(config.clone(), Some(12345), 4)?;
    ///
    /// // Non-deterministic with 8 workers
    /// let _engine = FuzzingEngine::new(config, None, 8)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(mut config: FuzzConfig, seed: Option<u64>, workers: usize) -> anyhow::Result<Self> {
        // Phase 0 Fix: Extract additional config early for use throughout initialization
        let additional = &config.campaign.parameters.additional;

        // Create executor based on framework (with optional build dir overrides)
        let executor_factory_options = Self::parse_executor_factory_options(&config)?;
        let circuit_path_str = config
            .campaign
            .target
            .circuit_path
            .to_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Circuit path contains invalid UTF-8: {:?}",
                    config.campaign.target.circuit_path
                )
            })?;
        let mut executor = ExecutorFactory::create_with_options(
            config.campaign.target.framework,
            circuit_path_str,
            &config.campaign.target.main_component,
            &executor_factory_options,
        )?;

        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);

        // Phase 3A: Enable per_exec_isolation by default in evidence mode for hang safety
        let mut isolate_exec = Self::additional_bool(additional, "per_exec_isolation")
            .or_else(|| Self::additional_bool(additional, "exec_isolation"))
            .unwrap_or(false);

        let allow_no_isolation =
            Self::additional_bool(additional, "evidence_allow_no_isolation").unwrap_or(false);

        if evidence_mode && !isolate_exec {
            if allow_no_isolation {
                tracing::warn!(
                    "Evidence mode: per_exec_isolation disabled by user; runs may hang \
                     and long fuzzing sessions are less protected."
                );
            } else {
                tracing::warn!("Evidence mode: enabling per_exec_isolation for hang safety");
                isolate_exec = true;
            }
        }

        if isolate_exec {
            let execution_timeout_ms = Self::additional_u64(additional, "execution_timeout_ms")
                .or_else(|| {
                    Self::additional_u64(additional, "timeout_per_execution").map(|v| v * 1000)
                })
                .unwrap_or(30_000)
                .max(1);

            let kill_on_timeout =
                Self::additional_bool(additional, "kill_on_timeout").unwrap_or(true);

            let mut isolated_executor = IsolatedExecutor::new(
                executor,
                config.campaign.target.framework,
                config
                    .campaign
                    .target
                    .circuit_path
                    .to_string_lossy()
                    .to_string(),
                config.campaign.target.main_component.clone(),
                executor_factory_options.clone(),
                execution_timeout_ms,
            )?;

            // Configure kill_on_timeout if specified
            if !kill_on_timeout {
                use crate::executor::IsolationConfig;
                let isolation_config = IsolationConfig {
                    timeout_ms: execution_timeout_ms,
                    kill_on_timeout: false,
                    ..IsolationConfig::default()
                };
                isolated_executor = isolated_executor.with_config(isolation_config);
            }

            executor = Arc::new(isolated_executor);
            tracing::info!(
                "Per-exec isolation enabled (timeout {} ms, kill_on_timeout: {})",
                execution_timeout_ms,
                kill_on_timeout
            );
        }

        // Scan patterns are target-reusable; if their input schema does not match the actual
        // circuit interface, reconcile inputs to the live executor shape for this run.
        Self::reconcile_inputs_with_executor(&mut config, executor.as_ref())?;
        let additional = &config.campaign.parameters.additional;

        let num_constraints = executor.num_constraints().max(100);
        let coverage = create_coverage_tracker(num_constraints);

        // Phase 0 Fix: Make corpus size configurable instead of hardcoded 10000
        // Allows tuning based on circuit complexity and available memory
        let corpus_max_size = Self::additional_u64(additional, "corpus_max_size")
            .unwrap_or(100_000)
            .max(1) as usize; // Increased default from 10k to 100k
        let corpus = create_corpus(corpus_max_size);

        // Initialize symbolic execution integration
        // Phase 0 Fix: Increase symbolic execution depth for deeper bug discovery
        // Previous: max_paths=100, max_depth=20 (too shallow for complex circuits)
        // Now: max_paths=1000, max_depth=200 (closer to KLEE-level exploration)
        let num_inputs = config.inputs.len().max(1);
        let symbolic_enabled =
            Self::additional_bool(additional, "symbolic_enabled").unwrap_or(true);
        let symbolic = if symbolic_enabled {
            let symbolic_max_paths = Self::additional_u64(additional, "symbolic_max_paths")
                .unwrap_or(1000)
                .max(1) as usize;
            let symbolic_max_depth = Self::additional_u64(additional, "symbolic_max_depth")
                .unwrap_or(200)
                .max(1) as usize;
            let symbolic_solver_timeout =
                Self::additional_u64(additional, "symbolic_solver_timeout_ms")
                    .unwrap_or(5000)
                    .max(1)
                    .min(u32::MAX as u64) as u32;
            Some(
                SymbolicFuzzerIntegration::new(num_inputs).with_config(SymbolicConfig {
                    max_paths: symbolic_max_paths,
                    max_depth: symbolic_max_depth,
                    solver_timeout_ms: symbolic_solver_timeout,
                    random_seed: seed,
                    generate_boundary_tests: true,
                    solutions_per_path: 4, // Increased from 2 for better coverage
                }),
            )
        } else {
            tracing::info!("Symbolic seeding disabled by config");
            None
        };

        // Initialize taint analyzer based on circuit info
        let taint_analyzer = {
            let circuit_info = executor.circuit_info();
            let mut analyzer = TaintAnalyzer::new(
                circuit_info.num_public_inputs,
                circuit_info.num_private_inputs,
            );
            analyzer.initialize_inputs();
            Some(analyzer)
        };

        // Initialize power scheduler based on config (support all variants)
        let schedule = Self::parse_power_schedule(&config);
        let power_scheduler = PowerScheduler::new(schedule)
            .with_base_energy(100)
            .with_schedule(schedule);

        // Initialize structure-aware mutator with inferred structures
        let mut structure_mutator = StructureAwareMutator::new(config.campaign.target.framework);

        // Infer input structures from circuit source if available
        if let Some(path) = config.campaign.target.circuit_path.to_str() {
            if let Ok(source) = std::fs::read_to_string(path) {
                let structures = StructureAwareMutator::infer_structure_from_source(
                    &source,
                    config.campaign.target.framework,
                );
                structure_mutator = structure_mutator.with_structures(structures);
            }
        }

        // Initialize complexity analyzer
        let complexity_analyzer = ComplexityAnalyzer::new();

        // Analyze circuit complexity
        let complexity = complexity_analyzer.analyze(&executor);
        tracing::info!(
            "Circuit complexity: {} constraints, density: {:.2}, DOF: {}",
            complexity.r1cs_constraints,
            complexity.constraint_density,
            complexity.degrees_of_freedom
        );

        for suggestion in &complexity.optimization_suggestions {
            tracing::info!(
                "Optimization suggestion: {:?} - {}",
                suggestion.priority,
                suggestion.description
            );
        }

        // Initialize bug oracles including semantic oracles from config
        let mut oracles: Vec<Box<dyn BugOracle>> = vec![
            Box::new(
                UnderconstrainedOracle::new().with_public_input_count(executor.num_public_inputs()),
            ),
            Box::new(ArithmeticOverflowOracle::new_with_modulus(
                executor.field_modulus(),
            )),
        ];

        // Phase 0 Fix: Wire semantic oracles from config
        Self::add_semantic_oracles_from_config(&config, executor.field_modulus(), &mut oracles);
        let disabled = Self::disabled_oracle_names(&config);
        if !disabled.is_empty() {
            oracles.retain(|o| !disabled.contains(&Self::normalize_oracle_name(o.name())));
        }

        let core = FuzzingEngineCore::builder()
            .seed(seed)
            .input_count(config.inputs.len())
            .corpus(corpus)
            .coverage(coverage)
            .power_scheduler(power_scheduler)
            .structure_mutator(structure_mutator)
            .oracles(oracles)
            .build()?;

        let mut attack_registry = AttackRegistry::new();
        Self::load_attack_plugins(&config, &mut attack_registry);

        // Phase 2: Initialize invariant checker once (cached for uniqueness tracking)
        let invariant_checker = {
            let invariants = config.get_invariants();
            if invariants.is_empty() {
                None
            } else {
                tracing::info!(
                    "Initializing fuzz-continuous invariant checker with {} invariants",
                    invariants.len()
                );
                Some(InvariantChecker::new(invariants, &config.inputs))
            }
        };

        // Mode 3: Build reusable thread pool for chain fuzzing
        let thread_pool = if workers > 1 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .map_or_else(
                    |err| {
                        tracing::warn!(
                            "Failed to create rayon thread pool (workers={}): {}",
                            workers,
                            err
                        );
                        None
                    },
                    Some,
                )
        } else {
            None
        };

        Ok(Self {
            config,
            seed,
            executor,
            executor_factory_options,
            core,
            attack_registry,
            workers,
            symbolic,
            taint_analyzer,
            complexity_analyzer,
            simple_tracker: None,
            invariant_checker,
            thread_pool,
            wall_clock_deadline: None,
        })
    }
}
