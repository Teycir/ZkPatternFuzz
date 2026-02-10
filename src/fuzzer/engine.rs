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
//! ```rust
//! use zk_fuzzer::fuzzer::FuzzingEngine;
//! use zk_fuzzer::config::FuzzConfig;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let config_yaml = r#"
//! # campaign:
//! #   name: "Doc Engine Campaign"
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
//! - **Mock**: Testing backend for fuzzer development

use super::invariant_checker::InvariantChecker; // Phase 2: Fuzz-continuous invariant checking
use super::mutate_field_element;
use super::oracle::{ArithmeticOverflowOracle, BugOracle, UnderconstrainedOracle};
use super::oracle_correlation::{ConfidenceLevel, OracleCorrelator}; // Phase 6A: Cross-oracle correlation
use super::oracle_validation::{
    filter_validated_findings, OracleValidationConfig, OracleValidator,
};
use super::power_schedule::{PowerSchedule, PowerScheduler};
use super::structure_aware::StructureAwareMutator;
use crate::analysis::complexity::ComplexityAnalyzer;
use crate::analysis::symbolic::{SymbolicConfig, SymbolicFuzzerIntegration, VulnerabilityPattern};
use crate::analysis::taint::TaintAnalyzer;
use crate::analysis::{
    collect_input_wire_indices, ConstraintSeedGenerator, ConstraintSeedOutput,
    EnhancedSymbolicConfig, PruningStrategy,
};
use crate::attacks::{Attack as AttackTrait, AttackContext, AttackRegistry, DynamicLibraryLoader};
use crate::config::*;
use crate::corpus::{create_corpus, minimizer};
use crate::executor::{
    create_coverage_tracker, ExecutorFactory, ExecutorFactoryOptions, IsolatedExecutor,
};
use crate::progress::{FuzzingStats, ProgressReporter, SimpleProgressTracker};
use crate::reporting::FuzzReport;
use zk_core::{
    CircuitExecutor, ConstraintInspector, ExecutionResult, FieldElement, Finding, ProofOfConcept,
    TestCase, TestMetadata,
};
use zk_fuzzer_core::engine::FuzzingEngineCore;

use rand::Rng;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// ```rust
    /// use zk_fuzzer::config::FuzzConfig;
    /// use zk_fuzzer::fuzzer::FuzzingEngine;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// # let config_yaml = r#"
    /// # campaign:
    /// #   name: "Doc Engine New"
    /// #   version: "1.0"
    /// #   target:
    /// #     framework: "mock"
    /// #     circuit_path: "./circuits/mock.circom"
    /// #     main_component: "MockCircuit"
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
    pub fn new(config: FuzzConfig, seed: Option<u64>, workers: usize) -> anyhow::Result<Self> {
        // Phase 0 Fix: Extract additional config early for use throughout initialization
        let additional = &config.campaign.parameters.additional;

        // Create executor based on framework (with optional build dir overrides)
        let executor_factory_options = Self::parse_executor_factory_options(&config);
        let mut executor = ExecutorFactory::create_with_options(
            config.campaign.target.framework,
            config.campaign.target.circuit_path.to_str().unwrap_or(""),
            &config.campaign.target.main_component,
            &executor_factory_options,
        )?;

        // Phase 0 Fix: Detect and FAIL-FAST on mock fallback execution
        //
        // This is critical for preventing false vulnerability claims.
        // Any findings from mock execution are SYNTHETIC and should not
        // be reported as real 0-day vulnerabilities.
        //
        // When strict_backend=true (default for evidence mode), we fail immediately.
        // When strict_backend=false, we warn but continue (for development/testing).
        let strict_backend = Self::additional_bool(additional, "strict_backend").unwrap_or(false);

        if executor.is_fallback_mock() {
            let framework = config.campaign.target.framework;
            let install_hint = match framework {
                zk_core::Framework::Circom => {
                    "Install circom: https://docs.circom.io/getting-started/installation/"
                }
                zk_core::Framework::Noir => {
                    "Install nargo: https://noir-lang.org/docs/getting_started/installation/"
                }
                zk_core::Framework::Cairo => {
                    "Install scarb: https://docs.swmansion.com/scarb/download.html"
                }
                _ => "Install the required backend tooling",
            };

            if strict_backend {
                // Phase 0 Fix: FAIL-FAST in production/evidence mode
                anyhow::bail!(
                    "MOCK FALLBACK REJECTED: Using mock executor for {:?} backend. \
                     Real backend tooling is not available. All findings would be SYNTHETIC. \
                     {}. \
                     Set strict_backend=false to allow mock fallback (NOT recommended for evidence mode).",
                    framework,
                    install_hint
                );
            } else {
                // Development mode: warn but continue
                tracing::error!(
                    "⚠️  CRITICAL: Using MOCK FALLBACK executor for {:?} backend!",
                    framework
                );
                tracing::error!(
                    "⚠️  Real backend tooling is not available. All findings will be SYNTHETIC."
                );
                tracing::error!(
                    "⚠️  DO NOT report these as real vulnerabilities. {}",
                    install_hint
                );
                tracing::warn!(
                    "⚠️  Set strict_backend=true to fail-fast on missing backends (recommended for evidence mode)."
                );
            }
        } else if executor.is_mock() && config.campaign.target.framework != zk_core::Framework::Mock
        {
            tracing::warn!(
                "Using mock executor for {:?} framework. Results may not reflect real circuit behavior.",
                config.campaign.target.framework
            );
        }

        // Phase 1A: Block explicit mock in evidence mode
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);
        if evidence_mode && executor.is_mock() {
            anyhow::bail!(
                "EVIDENCE MODE REJECTED: Cannot use mock executor in evidence mode. \
                 All findings would be synthetic. Use a real backend (circom/noir/halo2/cairo)."
            );
        }

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
            executor = Arc::new(IsolatedExecutor::new(
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
            )?);
            tracing::info!(
                "Per-exec isolation enabled (timeout {} ms)",
                execution_timeout_ms
            );
        }

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
        Self::add_semantic_oracles_from_config(&config, &mut oracles);
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
                .ok()
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
        })
    }

    /// Parse power schedule strategy from configuration
    ///
    /// Power schedules determine how energy is assigned to test cases:
    /// - **FAST**: Favor fast-executing test cases
    /// - **COE**: Cut-Off Exponential - balance speed and coverage
    /// - **EXPLORE**: Prioritize unexplored paths
    /// - **MMOPT**: Min-Max Optimal - balanced approach (default)
    /// - **RARE**: Focus on rare edge cases
    /// - **SEEK**: Actively seek new coverage
    ///
    /// Specified in campaign YAML as:
    /// ```yaml
    /// campaign:
    ///   parameters:
    ///     power_schedule: "MMOPT"
    /// ```
    fn normalize_oracle_name(name: &str) -> String {
        name.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect()
    }

    fn disabled_oracle_names(config: &FuzzConfig) -> std::collections::HashSet<String> {
        use std::collections::HashSet;

        let mut disabled = HashSet::new();
        let Some(value) = config.campaign.parameters.additional.get("disabled_oracles") else {
            return disabled;
        };

        match value {
            serde_yaml::Value::Sequence(items) => {
                for item in items {
                    if let Some(s) = item.as_str() {
                        disabled.insert(Self::normalize_oracle_name(s));
                    }
                }
            }
            serde_yaml::Value::String(s) => {
                for part in s.split(',') {
                    let trimmed = part.trim();
                    if !trimmed.is_empty() {
                        disabled.insert(Self::normalize_oracle_name(trimmed));
                    }
                }
            }
            _ => {}
        }

        disabled
    }

    /// Phase 0 Fix: Wire semantic and auxiliary oracles from configuration
    ///
    /// Instantiates nullifier/merkle/range/commitment oracles based on config.oracles,
    /// and recognizes common alias names used in campaigns.
    fn add_semantic_oracles_from_config(
        config: &FuzzConfig,
        oracles: &mut Vec<Box<dyn BugOracle>>,
    ) {
        use crate::fuzzer::oracle::{ConstraintCountOracle, ProofForgeryOracle};
        use crate::fuzzer::oracles::{
            CommitmentOracle, MerkleOracle, NullifierOracle, RangeProofOracle,
        };
        use std::collections::HashSet;
        use zk_core::OracleConfig;
        use zk_fuzzer_core::oracle::SemanticOracleAdapter;

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        enum OracleKind {
            Nullifier,
            Merkle,
            Commitment,
            Range,
            Underconstrained,
            ArithmeticOverflow,
            ConstraintCount,
            ProofForgery,
        }

        let classify = |name: &str| -> Option<OracleKind> {
            let normalized = Self::normalize_oracle_name(name);
            match normalized.as_str() {
                "nullifier"
                | "nullifieroracle"
                | "nullifiercollision"
                | "nullifiercollisionoracle"
                | "nullifierreuse"
                | "determinism" => Some(OracleKind::Nullifier),
                "merkle"
                | "merkleoracle"
                | "merkleproof"
                | "merklesoundness"
                | "merklesoundnessoracle" => Some(OracleKind::Merkle),
                "commitment" | "commitmentoracle" => Some(OracleKind::Commitment),
                "range"
                | "rangeoracle"
                | "rangeproof"
                | "rangeprooforacle"
                | "rangebypass"
                | "bitconstraintbypass" => Some(OracleKind::Range),
                "underconstrained" | "underconstrainedoracle" | "differentwitnesssameoutput" => {
                    Some(OracleKind::Underconstrained)
                }
                "arithmeticoverflow" | "arithmeticoverfloworacle" | "overflow" => {
                    Some(OracleKind::ArithmeticOverflow)
                }
                "constraintcountmismatch" | "constraintcountoracle" => {
                    Some(OracleKind::ConstraintCount)
                }
                "proofforgery" | "proofforgeryoracle" => Some(OracleKind::ProofForgery),
                _ => None,
            }
        };

        let oracle_config = OracleConfig::default();
        let disabled = Self::disabled_oracle_names(config);
        let mut registered: HashSet<String> =
            oracles.iter().map(|o| o.name().to_string()).collect();

        let mut add_oracle = |oracle: Box<dyn BugOracle>| {
            let name = oracle.name().to_string();
            if registered.insert(name) {
                oracles.push(oracle);
            }
        };

        let mut requested: Vec<String> = config.oracles.iter().map(|o| o.name.clone()).collect();
        if let Some(enabled_oracles) = config.campaign.parameters.additional.get("enabled_oracles")
        {
            if let Some(seq) = enabled_oracles.as_sequence() {
                for item in seq {
                    if let Some(name) = item.as_str() {
                        requested.push(name.to_string());
                    }
                }
            }
        }

        for oracle_name in requested {
            let kind = classify(&oracle_name);
            if disabled.contains(&Self::normalize_oracle_name(&oracle_name)) {
                continue;
            }

            match kind {
                Some(OracleKind::Nullifier) => add_oracle(Box::new(SemanticOracleAdapter::new(
                    Box::new(NullifierOracle::new(oracle_config.clone())),
                ))),
                Some(OracleKind::Merkle) => add_oracle(Box::new(SemanticOracleAdapter::new(
                    Box::new(MerkleOracle::new(oracle_config.clone())),
                ))),
                Some(OracleKind::Commitment) => add_oracle(Box::new(SemanticOracleAdapter::new(
                    Box::new(CommitmentOracle::new(oracle_config.clone())),
                ))),
                Some(OracleKind::Range) => add_oracle(Box::new(SemanticOracleAdapter::new(
                    Box::new(RangeProofOracle::new(oracle_config.clone())),
                ))),
                Some(OracleKind::ConstraintCount) => {
                    let expected = config.campaign.parameters.max_constraints as usize;
                    add_oracle(Box::new(ConstraintCountOracle::new(expected)));
                }
                Some(OracleKind::ProofForgery) => add_oracle(Box::new(ProofForgeryOracle::new())),
                Some(OracleKind::Underconstrained) | Some(OracleKind::ArithmeticOverflow) => {
                    // These oracles are enabled by default; treat as recognized aliases.
                }
                None => {
                    tracing::warn!("Unknown oracle type in config: {}", oracle_name);
                }
            }
        }
    }

    fn parse_power_schedule(config: &FuzzConfig) -> PowerSchedule {
        // Check for power_schedule in campaign parameters
        if let Some(schedule_str) = config.campaign.parameters.additional.get("power_schedule") {
            if let Some(s) = schedule_str.as_str() {
                return s.parse().unwrap_or(PowerSchedule::Mmopt);
            }
        }
        // Default to MMOPT for balanced performance
        PowerSchedule::Mmopt
    }

    fn parse_executor_factory_options(config: &FuzzConfig) -> ExecutorFactoryOptions {
        let additional = &config.campaign.parameters.additional;
        let mut options = ExecutorFactoryOptions::default();

        let base = Self::additional_path(additional, "build_dir_base")
            .or_else(|| Self::additional_path(additional, "build_dir"));
        options.build_dir_base = base;

        options.circom_build_dir = Self::additional_path(additional, "circom_build_dir");
        options.noir_build_dir = Self::additional_path(additional, "noir_build_dir");
        options.halo2_build_dir = Self::additional_path(additional, "halo2_build_dir");
        options.cairo_build_dir = Self::additional_path(additional, "cairo_build_dir");

        if let Some(strict_backend) = Self::additional_bool(additional, "strict_backend") {
            options.strict_backend = strict_backend;
        }
        if let Some(mark_fallback) = Self::additional_bool(additional, "mark_fallback") {
            options.mark_fallback = mark_fallback;
        }
        if let Some(auto_setup) = Self::additional_bool(additional, "circom_auto_setup_keys") {
            tracing::info!("Circom auto setup keys: {}", auto_setup);
            options.circom_auto_setup_keys = auto_setup;
        }
        if let Some(ptau_path) = Self::additional_path(additional, "circom_ptau_path") {
            options.circom_ptau_path = Some(ptau_path);
        }
        if let Some(snarkjs_path) = Self::additional_path(additional, "circom_snarkjs_path") {
            options.circom_snarkjs_path = Some(snarkjs_path);
        }
        if let Some(skip_compile) =
            Self::additional_bool(additional, "circom_skip_compile_if_artifacts")
        {
            options.circom_skip_compile_if_artifacts = skip_compile;
        }

        if let Some(value) = additional.get("include_paths") {
            let mut paths = Vec::new();
            match value {
                serde_yaml::Value::Sequence(items) => {
                    for item in items {
                        if let Some(s) = item.as_str() {
                            let trimmed = s.trim();
                            if !trimmed.is_empty() {
                                paths.push(std::path::PathBuf::from(trimmed));
                            }
                        }
                    }
                }
                serde_yaml::Value::String(s) => {
                    for part in s.split(',') {
                        let trimmed = part.trim();
                        if !trimmed.is_empty() {
                            paths.push(std::path::PathBuf::from(trimmed));
                        }
                    }
                }
                _ => {}
            }
            if !paths.is_empty() {
                options.circom_include_paths = paths;
            }
        }

        options
    }

    fn oracle_validation_config(&self) -> OracleValidationConfig {
        let additional = &self.config.campaign.parameters.additional;
        let mut config = OracleValidationConfig::default();

        if let Some(ratio) =
            Self::additional_f64(additional, "oracle_validation_min_agreement_ratio")
        {
            config.min_agreement_ratio = ratio.clamp(0.0, 1.0);
        }
        if let Some(require_ground_truth) =
            Self::additional_bool(additional, "oracle_validation_require_ground_truth")
        {
            config.require_ground_truth = require_ground_truth;
        }
        if let Some(count) =
            Self::additional_usize(additional, "oracle_validation_mutation_test_count")
        {
            config.mutation_test_count = count.max(1);
        }
        if let Some(rate) =
            Self::additional_f64(additional, "oracle_validation_min_mutation_detection_rate")
        {
            config.min_mutation_detection_rate = rate.clamp(0.0, 1.0);
        }
        if let Some(skip_stateful) =
            Self::additional_bool(additional, "oracle_validation_skip_stateful")
        {
            config.skip_stateful_oracles = skip_stateful;
        }
        if let Some(allow_cross) =
            Self::additional_bool(additional, "oracle_validation_allow_cross_attack")
        {
            config.allow_cross_attack_type = allow_cross;
        }
        if let Some(weight) =
            Self::additional_f64(additional, "oracle_validation_cross_attack_weight")
        {
            config.cross_attack_weight = weight.clamp(0.0, 1.0);
        }
        if let Some(reset_stateful) =
            Self::additional_bool(additional, "oracle_validation_reset_stateful")
        {
            config.reset_stateful_oracles = reset_stateful;
        }

        config
    }

    fn build_validation_oracles(&self) -> Vec<Box<dyn BugOracle>> {
        let mut oracles: Vec<Box<dyn BugOracle>> = vec![
            Box::new(
                UnderconstrainedOracle::new()
                    .with_public_input_count(self.executor.num_public_inputs()),
            ),
            Box::new(ArithmeticOverflowOracle::new_with_modulus(
                self.executor.field_modulus(),
            )),
        ];

        // Reuse semantic oracle configuration for validation
        Self::add_semantic_oracles_from_config(&self.config, &mut oracles);
        let disabled = Self::disabled_oracle_names(&self.config);
        if !disabled.is_empty() {
            oracles.retain(|o| !disabled.contains(&Self::normalize_oracle_name(o.name())));
        }

        oracles
    }

    fn load_attack_plugins(config: &FuzzConfig, registry: &mut AttackRegistry) {
        let additional = &config.campaign.parameters.additional;
        let Some(value) = additional.get("attack_plugin_dirs") else {
            return;
        };

        let mut paths = Vec::new();
        match value {
            serde_yaml::Value::Sequence(items) => {
                for item in items {
                    if let Some(s) = item.as_str() {
                        paths.push(std::path::PathBuf::from(s));
                    }
                }
            }
            serde_yaml::Value::String(s) => {
                for part in s.split(',') {
                    let trimmed = part.trim();
                    if !trimmed.is_empty() {
                        paths.push(std::path::PathBuf::from(trimmed));
                    }
                }
            }
            _ => {}
        }

        if paths.is_empty() {
            return;
        }

        let loader = DynamicLibraryLoader::new(paths);
        if let Err(err) = registry.load_from_loader(&loader) {
            tracing::warn!("Attack plugin loading failed: {}", err);
        }
    }

    fn constraint_guided_config(&self) -> Option<EnhancedSymbolicConfig> {
        let additional = &self.config.campaign.parameters.additional;

        if let Some(enabled) = Self::additional_bool(additional, "constraint_guided_enabled") {
            if !enabled {
                return None;
            }
        }

        let mut config = EnhancedSymbolicConfig {
            max_depth: 200,
            solver_timeout_ms: 3000,
            solutions_per_path: 4,
            pruning_strategy: PruningStrategy::DepthBounded,
            simplify_constraints: true,
            incremental_solving: false,
            random_seed: self.seed,
            ..Default::default()
        };

        if let Some(max_depth) = Self::additional_usize(additional, "constraint_guided_max_depth") {
            config.max_depth = max_depth.max(1);
        }
        if let Some(max_paths) = Self::additional_usize(additional, "constraint_guided_max_paths") {
            config.max_paths = max_paths.max(1);
        }
        if let Some(timeout) =
            Self::additional_u32(additional, "constraint_guided_solver_timeout_ms")
        {
            config.solver_timeout_ms = timeout;
        }
        if let Some(solutions) =
            Self::additional_usize(additional, "constraint_guided_solutions_per_path")
        {
            config.solutions_per_path = solutions.max(1);
        }
        if let Some(loop_bound) = Self::additional_usize(additional, "constraint_guided_loop_bound")
        {
            config.loop_bound = loop_bound.max(1);
        }
        if let Some(simplify) =
            Self::additional_bool(additional, "constraint_guided_simplify_constraints")
        {
            config.simplify_constraints = simplify;
        }
        if let Some(incremental) =
            Self::additional_bool(additional, "constraint_guided_incremental_solving")
        {
            config.incremental_solving = incremental;
        }
        if let Some(strategy) =
            Self::additional_string(additional, "constraint_guided_pruning_strategy")
                .or_else(|| Self::additional_string(additional, "constraint_guided_pruning"))
        {
            config.pruning_strategy = Self::parse_pruning_strategy(&strategy);
        }

        Some(config)
    }

    fn parse_pruning_strategy(value: &str) -> PruningStrategy {
        let normalized = value.trim().to_lowercase();
        match normalized.as_str() {
            "none" | "off" => PruningStrategy::None,
            "depth" | "depth_bounded" | "depthbounded" => PruningStrategy::DepthBounded,
            "constraint" | "constraint_bounded" | "constraintbounded" => {
                PruningStrategy::ConstraintBounded
            }
            "coverage" | "coverage_guided" | "coverageguided" => PruningStrategy::CoverageGuided,
            "random" | "random_sampling" | "randomsampling" => PruningStrategy::RandomSampling,
            "loop" | "loop_bounded" | "loopbounded" => PruningStrategy::LoopBounded,
            "similarity" | "similarity_based" | "similaritybased" => {
                PruningStrategy::SimilarityBased
            }
            "subsumption" | "subsumption_based" | "subsumptionbased" => {
                PruningStrategy::SubsumptionBased
            }
            _ => {
                tracing::warn!(
                    "Unknown pruning strategy '{}', defaulting to DepthBounded",
                    value
                );
                PruningStrategy::DepthBounded
            }
        }
    }

    fn additional_bool(
        additional: &std::collections::HashMap<String, serde_yaml::Value>,
        key: &str,
    ) -> Option<bool> {
        match additional.get(key)? {
            serde_yaml::Value::Bool(v) => Some(*v),
            serde_yaml::Value::Number(n) => n.as_i64().map(|v| v != 0),
            serde_yaml::Value::String(s) => match s.to_lowercase().as_str() {
                "true" | "yes" | "1" => Some(true),
                "false" | "no" | "0" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    fn additional_usize(
        additional: &std::collections::HashMap<String, serde_yaml::Value>,
        key: &str,
    ) -> Option<usize> {
        match additional.get(key)? {
            serde_yaml::Value::Number(n) => n.as_u64().map(|v| v as usize),
            serde_yaml::Value::String(s) => s.parse::<usize>().ok(),
            _ => None,
        }
    }

    fn additional_u32(
        additional: &std::collections::HashMap<String, serde_yaml::Value>,
        key: &str,
    ) -> Option<u32> {
        match additional.get(key)? {
            serde_yaml::Value::Number(n) => n.as_u64().map(|v| v.min(u32::MAX as u64) as u32),
            _ => None,
        }
    }

    fn additional_f64(
        additional: &std::collections::HashMap<String, serde_yaml::Value>,
        key: &str,
    ) -> Option<f64> {
        match additional.get(key)? {
            serde_yaml::Value::Number(n) => n.as_f64(),
            serde_yaml::Value::String(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }

    /// Phase 0 Fix: Helper to extract u64 from additional config
    fn additional_u64(
        additional: &std::collections::HashMap<String, serde_yaml::Value>,
        key: &str,
    ) -> Option<u64> {
        match additional.get(key)? {
            serde_yaml::Value::Number(n) => n.as_u64(),
            serde_yaml::Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        }
    }

    fn additional_string(
        additional: &std::collections::HashMap<String, serde_yaml::Value>,
        key: &str,
    ) -> Option<String> {
        match additional.get(key)? {
            serde_yaml::Value::String(s) => Some(s.clone()),
            serde_yaml::Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }

    fn additional_path(
        additional: &std::collections::HashMap<String, serde_yaml::Value>,
        key: &str,
    ) -> Option<PathBuf> {
        Self::additional_string(additional, key).map(PathBuf::from)
    }

    fn resolve_attack_plugin(attack: &Attack) -> (Option<String>, bool) {
        if let Some(name) = attack.plugin.as_ref() {
            return (Some(name.clone()), true);
        }

        if let Some(value) = attack.config.get("plugin") {
            if let Some(name) = value.as_str() {
                return (Some(name.to_string()), true);
            }
        }

        (None, false)
    }

    fn attack_samples(config: &serde_yaml::Value) -> usize {
        config
            .get("samples")
            .or_else(|| config.get("witness_pairs"))
            .or_else(|| config.get("forge_attempts"))
            .or_else(|| config.get("tests"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize
    }

    /// Execute the complete fuzzing campaign
    ///
    /// This is the main entry point that runs the entire fuzzing workflow:
    /// 1. Analyzes circuit complexity and structure
    /// 2. Performs static analysis (taint, source code patterns)
    /// 3. Seeds initial corpus with interesting values
    /// 4. Executes configured attacks (underconstrained, soundness, etc.)
    /// 5. Runs coverage-guided fuzzing loop
    /// 6. Generates comprehensive report
    ///
    /// # Arguments
    ///
    /// * `progress` - Optional progress reporter for interactive display
    ///
    /// # Returns
    ///
    /// Returns a `FuzzReport` containing:
    /// - All discovered vulnerabilities with severity ratings
    /// - Proof-of-concept test cases for reproduction
    /// - Coverage statistics and execution metrics
    /// - Recommendations for fixing issues
    ///
    /// # Example
    ///
    /// ```rust
    /// use zk_fuzzer::config::FuzzConfig;
    /// use zk_fuzzer::fuzzer::FuzzingEngine;
    /// use zk_fuzzer::progress::ProgressReporter;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// # let config_yaml = r#"
    /// # campaign:
    /// #   name: "Doc Engine Run"
    /// #   version: "1.0"
    /// #   target:
    /// #     framework: "mock"
    /// #     circuit_path: "./circuits/mock.circom"
    /// #     main_component: "MockCircuit"
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
    /// let mut engine = FuzzingEngine::new(config, Some(12345), 1)?;
    ///
    /// let rt = tokio::runtime::Runtime::new()?;
    /// // Run with progress reporting
    /// let reporter = ProgressReporter::new("Doc Engine Run", 10, false);
    /// let _report = rt.block_on(async { engine.run(Some(&reporter)).await })?;
    ///
    /// // Run without progress (CI/CD mode)
    /// // let _report = rt.block_on(async { engine.run(None).await })?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run(&mut self, progress: Option<&ProgressReporter>) -> anyhow::Result<FuzzReport> {
        let start_time = Instant::now();
        self.core.set_start_time(start_time);

        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);
        let mode_label = if evidence_mode { "evidence" } else { "run" };

        tracing::warn!(
            "MILESTONE start mode={} target={} circuit={} output_dir={}",
            mode_label,
            self.config.campaign.name,
            self.config.campaign.target.circuit_path.display(),
            self.config.reporting.output_dir.display()
        );

        tracing::info!("Starting fuzzing campaign: {}", self.config.campaign.name);
        tracing::info!(
            "Circuit: {} ({:?})",
            self.executor.name(),
            self.executor.framework()
        );
        tracing::info!("Workers: {}", self.workers);

        // Check for underconstrained circuit
        if self.executor.is_likely_underconstrained() {
            tracing::warn!(
                "Circuit appears underconstrained (DOF = {})",
                self.executor.circuit_info().degrees_of_freedom()
            );
        }

        // Run taint analysis before fuzzing
        if let Some(ref analyzer) = self.taint_analyzer {
            let taint_findings = analyzer.to_findings();
            if !taint_findings.is_empty() {
                tracing::info!(
                    "Taint analysis found {} potential issues",
                    taint_findings.len()
                );
                for finding in taint_findings {
                    if let Some(p) = progress {
                        p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                    }
                    self.core.findings().write().unwrap().push(finding);
                }
            }
        }

        // Run source code analysis for vulnerability hints
        self.run_source_analysis(progress);

        // Seed corpus with external inputs if provided
        if let Err(err) = self.seed_external_inputs_from_config() {
            tracing::warn!("Failed to load external seed inputs: {}", err);
        }

        // Seed corpus
        self.seed_corpus()?;
        tracing::info!(
            "Seeded corpus with {} initial test cases",
            self.core.corpus().len()
        );
        tracing::warn!(
            "MILESTONE seeded_corpus target={} count={}",
            self.config.campaign.name,
            self.core.corpus().len()
        );

        // Initialize simple progress tracker for non-interactive environments
        self.simple_tracker = Some(SimpleProgressTracker::new());

        // Update power scheduler with initial global stats
        self.update_power_scheduler_globals();

        // Run attacks
        for attack_config in &self.config.attacks.clone() {
            tracing::warn!(
                "MILESTONE attack_start target={} type={:?}",
                self.config.campaign.name,
                attack_config.attack_type
            );
            if let Some(p) = progress {
                p.log_attack_start(&format!("{:?}", attack_config.attack_type));
            }

            let findings_before = self.core.findings().read().unwrap().len();
            let (plugin_name, plugin_explicit) = Self::resolve_attack_plugin(attack_config);
            let mut plugin_ran = false;

            if let Some(name) = plugin_name.as_deref() {
                let lookup = name.trim();
                let plugin = self
                    .attack_registry
                    .get(lookup)
                    .or_else(|| self.attack_registry.get(&lookup.to_lowercase()));

                if let Some(plugin) = plugin {
                    let samples = Self::attack_samples(&attack_config.config);
                    self.add_attack_findings(plugin, samples, progress);
                    plugin_ran = true;
                } else {
                    tracing::warn!("Attack plugin '{}' not found in registry", lookup);
                }
            }

            if !(plugin_ran && plugin_explicit) {
                match attack_config.attack_type {
                    AttackType::Underconstrained => {
                        self.run_underconstrained_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::Soundness => {
                        self.run_soundness_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::ArithmeticOverflow => {
                        self.run_arithmetic_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::Collision => {
                        self.run_collision_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::Boundary => {
                        self.run_boundary_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::VerificationFuzzing => {
                        self.run_verification_fuzzing_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::WitnessFuzzing => {
                        self.run_witness_fuzzing_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::Differential => {
                        self.run_differential_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::InformationLeakage => {
                        self.run_information_leakage_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::TimingSideChannel => {
                        self.run_timing_sidechannel_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::CircuitComposition => {
                        self.run_circuit_composition_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::RecursiveProof => {
                        self.run_recursive_proof_attack(&attack_config.config, progress)
                            .await?;
                    }
                    // Phase 4: Novel Oracle Attacks - Now Implemented!
                    AttackType::ConstraintInference => {
                        self.run_constraint_inference_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::Metamorphic => {
                        self.run_metamorphic_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::ConstraintSlice => {
                        self.run_constraint_slice_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::SpecInference => {
                        self.run_spec_inference_attack(&attack_config.config, progress)
                            .await?;
                    }
                    AttackType::WitnessCollision => {
                        self.run_witness_collision_attack(&attack_config.config, progress)
                            .await?;
                    }
                    _ => {
                        tracing::warn!(
                            "Attack type {:?} not yet implemented",
                            attack_config.attack_type
                        );
                    }
                }
            }

            let findings_after = self.core.findings().read().unwrap().len();
            let new_findings = findings_after - findings_before;

            if let Some(p) = progress {
                p.log_attack_complete(&format!("{:?}", attack_config.attack_type), new_findings);
            }
            tracing::warn!(
                "MILESTONE attack_complete target={} type={:?} new_findings={} total_findings={}",
                self.config.campaign.name,
                attack_config.attack_type,
                new_findings,
                findings_after
            );

            // Update power scheduler with current stats after each attack
            self.update_power_scheduler_globals();

            // Update simple tracker
            let current_stats = self.stats();
            if let Some(ref mut tracker) = self.simple_tracker {
                tracker.update(current_stats);
            }
        }

        // Finish simple tracker
        if let Some(ref tracker) = self.simple_tracker {
            tracker.finish();
        }

        // Phase 0 Fix: Run continuous fuzzing phase after attacks
        let iterations = self
            .config
            .campaign
            .parameters
            .additional
            .get("max_iterations")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                self.config
                    .campaign
                    .parameters
                    .additional
                    .get("fuzzing_iterations")
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(1000);

        let timeout = self
            .config
            .campaign
            .parameters
            .additional
            .get("fuzzing_timeout_seconds")
            .and_then(|v| v.as_u64());

        if iterations > 0 {
            tracing::warn!(
                "MILESTONE continuous_start target={} iterations={} timeout={:?}",
                self.config.campaign.name,
                iterations,
                timeout
            );
            self.run_continuous_fuzzing_phase(iterations, timeout, progress)
                .await?;
            tracing::warn!(
                "MILESTONE continuous_complete target={}",
                self.config.campaign.name
            );
        }

        // Export corpus to output directory
        let corpus_dir = self.config.reporting.output_dir.join("corpus");
        match self.export_corpus(&corpus_dir) {
            Ok(count) => tracing::info!(
                "Exported {} interesting test cases to {:?}",
                count,
                corpus_dir
            ),
            Err(e) => tracing::warn!("Failed to export corpus: {}", e),
        }

        // Generate report
        let elapsed = start_time.elapsed();
        let mut findings = self.core.findings().read().unwrap().clone();

        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);
        let oracle_validation_enabled =
            Self::additional_bool(additional, "oracle_validation").unwrap_or(evidence_mode);

        if oracle_validation_enabled {
            let validation_config = self.oracle_validation_config();
            let skip_stateful = validation_config.skip_stateful_oracles;
            let mut validator = OracleValidator::with_config(validation_config);
            let mut validation_oracles = self.build_validation_oracles();
            let before = findings.len();
            findings = filter_validated_findings(
                findings,
                &mut validator,
                &mut validation_oracles,
                self.executor.as_ref(),
            );
            let after = findings.len();
            tracing::info!(
                "Oracle validation complete: {} -> {} findings (skip_stateful={})",
                before,
                after,
                skip_stateful
            );
        }

        tracing::info!(
            "Fuzzing complete: {} findings in {:.2}s",
            findings.len(),
            elapsed.as_secs_f64()
        );
        tracing::warn!(
            "MILESTONE complete mode={} target={} findings={} duration_s={:.2}",
            mode_label,
            self.config.campaign.name,
            findings.len(),
            elapsed.as_secs_f64()
        );

        let mut report = self.generate_report(findings.clone(), elapsed.as_secs());

        // Phase 5B: Generate evidence bundles in evidence mode
        if evidence_mode && !findings.is_empty() {
            tracing::info!("Evidence mode: generating proof-level evidence bundles...");

            let evidence_dir = self.config.reporting.output_dir.join("evidence");
            let evidence_gen =
                crate::reporting::EvidenceGenerator::new(self.config.clone(), evidence_dir.clone());

            // Create backend identity from executor
            let backend_identity = crate::reporting::BackendIdentity::from_framework(
                self.config.campaign.target.framework,
                self.executor.is_mock(),
            );

            let bundles = evidence_gen.generate_all_bundles(&findings, backend_identity);

            // Count verification results
            let confirmed = bundles.iter().filter(|b| b.is_confirmed()).count();
            let skipped = bundles
                .iter()
                .filter(|b| {
                    matches!(
                        b.verification_result,
                        crate::reporting::VerificationResult::Skipped(_)
                    )
                })
                .count();
            let failed = bundles
                .iter()
                .filter(|b| {
                    matches!(
                        b.verification_result,
                        crate::reporting::VerificationResult::Failed(_)
                    )
                })
                .count();

            tracing::info!(
                "Evidence generation complete: {} confirmed, {} failed, {} skipped out of {} bundles",
                confirmed,
                failed,
                skipped,
                bundles.len()
            );

            // Write evidence summary to report
            if !bundles.is_empty() {
                let evidence_summary_path = evidence_dir.join("EVIDENCE_SUMMARY.md");
                if self
                    .write_evidence_summary(&bundles, &evidence_summary_path)
                    .is_ok()
                {
                    tracing::info!("Evidence summary written to {:?}", evidence_summary_path);
                    // Update report statistics
                    report.statistics.unique_crashes = confirmed as u64;
                }
            }
        }

        Ok(report)
    }

    /// Seed the corpus with initial interesting values
    fn seed_corpus(&mut self) -> anyhow::Result<()> {
        // Add zero case
        self.add_to_corpus(self.create_test_case_with_value(FieldElement::zero()));

        // Add one case
        self.add_to_corpus(self.create_test_case_with_value(FieldElement::one()));

        // Add interesting values from input specs
        for input in &self.config.inputs {
            for interesting in &input.interesting {
                if let Ok(fe) = FieldElement::from_hex(interesting) {
                    self.add_to_corpus(self.create_test_case_with_value(fe));
                }
            }
        }

        // Add field boundary values
        let boundary_values = vec![
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000", // p - 1
            "0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000", // (p-1)/2
        ];

        for hex in boundary_values {
            if let Ok(fe) = FieldElement::from_hex(hex) {
                self.add_to_corpus(self.create_test_case_with_value(fe));
            }
        }

        // Generate seeds from extracted constraints (R1CS/ACIR/PLONK) when available
        if let Some(inspector) = self.executor.constraint_inspector() {
            if let Some(config) = self.constraint_guided_config() {
                let expected_len = self.config.inputs.len().max(1);
                let input_wire_indices = collect_input_wire_indices(inspector, expected_len);
                let mut generator = ConstraintSeedGenerator::new(config);

                let constraints = inspector.get_constraints();
                let output = if constraints.is_empty() {
                    tracing::debug!("Constraint-guided seeds skipped: no constraints available");
                    ConstraintSeedOutput::default()
                } else {
                    tracing::info!(
                        "Generating constraint-guided seeds from {} R1CS constraints...",
                        constraints.len()
                    );
                    generator.generate_from_r1cs(&constraints, &input_wire_indices, expected_len)
                };

                if !output.seeds.is_empty() {
                    tracing::info!(
                        "Constraint-guided seeds: {} solutions ({} symbolic, {} skipped, {} pruned)",
                        output.stats.solutions,
                        output.stats.symbolic_constraints,
                        output.stats.skipped_constraints,
                        output.stats.pruned_constraints
                    );

                    for inputs in output.seeds {
                        if inputs.len() == expected_len {
                            self.add_to_corpus(TestCase {
                                inputs,
                                expected_output: None,
                                metadata: TestMetadata::default(),
                            });
                        }
                    }
                }
            } else {
                tracing::debug!("Constraint-guided seeds disabled via config");
            }
        } else {
            tracing::debug!("Constraint-guided seeds skipped: constraint inspector unavailable");
        }

        // Generate seeds from symbolic execution
        let symbolic_test_cases = if let Some(ref mut symbolic) = self.symbolic {
            tracing::info!("Generating symbolic execution seeds...");

            let mut test_cases = Vec::new();

            // Generate initial seeds using symbolic solver
            let symbolic_seeds = symbolic.generate_seeds(20);
            let expected_len = self.config.inputs.len();
            for inputs in symbolic_seeds {
                if inputs.len() == expected_len {
                    test_cases.push(TestCase {
                        inputs,
                        expected_output: None,
                        metadata: TestMetadata::default(),
                    });
                }
            }

            // Generate vulnerability-targeted test cases
            let vuln_patterns = vec![
                VulnerabilityPattern::OverflowBoundary,
                VulnerabilityPattern::ZeroDivision,
                VulnerabilityPattern::BitDecomposition { bits: 8 },
                VulnerabilityPattern::BitDecomposition { bits: 64 },
            ];

            for pattern in vuln_patterns {
                let targeted_tests = symbolic.generate_vulnerability_tests(pattern);
                for inputs in targeted_tests {
                    if inputs.len() >= expected_len {
                        let truncated: Vec<_> = inputs.into_iter().take(expected_len).collect();
                        test_cases.push(TestCase {
                            inputs: truncated,
                            expected_output: None,
                            metadata: TestMetadata::default(),
                        });
                    }
                }
            }

            let stats = symbolic.stats();
            tracing::info!(
                "Symbolic execution: {} paths explored, {} tests generated",
                stats.paths_explored,
                stats.tests_generated
            );

            test_cases
        } else {
            Vec::new()
        };

        // Add symbolic test cases to corpus
        for test_case in symbolic_test_cases {
            self.add_to_corpus(test_case);
        }

        // Add random cases
        for _ in 0..10 {
            let test_case = self.generate_random_test_case();
            self.add_to_corpus(test_case);
        }

        Ok(())
    }

    fn seed_external_inputs_from_config(&mut self) -> anyhow::Result<()> {
        let path = self
            .config
            .campaign
            .parameters
            .additional
            .get("seed_inputs_path")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());

        let Some(path) = path else {
            return Ok(());
        };

        let seeds = self.load_seed_inputs_from_path(&path)?;
        if seeds.is_empty() {
            tracing::warn!("External seed inputs were empty: {}", path);
            return Ok(());
        }

        let added = self.seed_corpus_from_inputs(&seeds);
        tracing::info!("Seeded corpus with {} external inputs from {}", added, path);
        Ok(())
    }

    fn load_seed_inputs_from_path(&self, path: &str) -> anyhow::Result<Vec<Vec<FieldElement>>> {
        let raw = std::fs::read_to_string(path)?;
        let json: serde_json::Value = serde_json::from_str(&raw)?;

        let mut seeds = Vec::new();
        match json {
            serde_json::Value::Array(entries) => {
                for entry in entries {
                    if let Some(seed) = self.build_seed_from_json(&entry) {
                        seeds.push(seed);
                    }
                }
            }
            serde_json::Value::Object(_) => {
                if let Some(seed) = self.build_seed_from_json(&json) {
                    seeds.push(seed);
                }
            }
            _ => {
                anyhow::bail!("seed_inputs_path must be a JSON object or array");
            }
        }

        Ok(seeds)
    }

    fn build_seed_from_json(&self, entry: &serde_json::Value) -> Option<Vec<FieldElement>> {
        let map = entry.as_object()?;
        let mut inputs = Vec::with_capacity(self.config.inputs.len());
        let mut missing = Vec::new();

        for spec in &self.config.inputs {
            let name = spec.name.as_str();
            let value = if let Some(v) = map.get(name) {
                Self::parse_field_value(v)
            } else if let Some((base, idx)) = Self::split_indexed_name(name) {
                map.get(base)
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.get(idx))
                    .and_then(Self::parse_field_value)
            } else {
                None
            };

            match value {
                Some(v) => inputs.push(v),
                None => missing.push(name.to_string()),
            }
        }

        if !missing.is_empty() {
            tracing::warn!(
                "Skipping external seed: missing {} inputs (e.g. {})",
                missing.len(),
                missing.first().cloned().unwrap_or_default()
            );
            return None;
        }

        Some(inputs)
    }

    fn split_indexed_name(name: &str) -> Option<(&str, usize)> {
        let (base, idx_str) = name.rsplit_once('_')?;
        if idx_str.chars().all(|c| c.is_ascii_digit()) {
            let idx = idx_str.parse::<usize>().ok()?;
            return Some((base, idx));
        }
        None
    }

    fn parse_field_value(value: &serde_json::Value) -> Option<FieldElement> {
        match value {
            serde_json::Value::String(s) => Self::parse_field_string(s),
            serde_json::Value::Number(n) => Self::parse_field_string(&n.to_string()),
            serde_json::Value::Bool(b) => {
                if *b {
                    Self::parse_field_string("1")
                } else {
                    Self::parse_field_string("0")
                }
            }
            _ => None,
        }
    }

    fn parse_field_string(raw: &str) -> Option<FieldElement> {
        let trimmed = raw.trim();
        if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            return FieldElement::from_hex(trimmed).ok();
        }

        let value = num_bigint::BigUint::parse_bytes(trimmed.as_bytes(), 10)?;
        let bytes = value.to_bytes_be();
        if bytes.len() > 32 {
            return None;
        }
        let mut buf = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        buf[start..start + bytes.len()].copy_from_slice(&bytes);
        Some(FieldElement(buf))
    }

    fn add_to_corpus(&self, test_case: TestCase) {
        self.core.add_to_corpus(self.executor.as_ref(), test_case);
    }

    fn create_test_case_with_value(&self, value: FieldElement) -> TestCase {
        self.core.create_test_case_with_value(value)
    }

    fn generate_random_test_case(&mut self) -> TestCase {
        self.core.generate_random_test_case()
    }

    fn generate_test_case(&mut self) -> TestCase {
        self.core.generate_test_case()
    }

    /// Execute test case and update coverage
    ///
    /// Note: There's a potential race condition between checking is_new and
    /// adding to corpus. However, the corpus.add() method has its own
    /// duplicate detection which prevents actual duplicates. The worst case
    /// is that we might miss adding a test case that another thread added
    /// first with the same coverage, which is acceptable behavior.
    /// Execute test case, update coverage, and learn patterns (mutable version)
    fn execute_and_learn(&mut self, test_case: &TestCase) -> ExecutionResult {
        self.core
            .execute_and_learn(self.executor.as_ref(), test_case)
    }

    /// Run underconstrained circuit detection with parallel execution
    ///
    /// # Phase 0 Fix: Proper Input Index Mapping
    ///
    /// This attack now uses the executor's constraint inspector to get the
    /// actual public input indices, rather than assuming the first N inputs
    /// are public. This fixes false positives/negatives caused by input
    /// ordering mismatches between config and executor.
    async fn run_underconstrained_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let witness_pairs: usize = config
            .get("witness_pairs")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        tracing::info!(
            "Testing {} witness pairs for underconstrained circuits",
            witness_pairs
        );
        {
            use crate::attacks::UnderconstrainedDetector;
            let tolerance = config.get("tolerance").and_then(|v| v.as_f64());
            let detector = if let Some(tol) = tolerance {
                UnderconstrainedDetector::new(witness_pairs).with_tolerance(tol)
            } else {
                UnderconstrainedDetector::new(witness_pairs)
            };
            self.add_attack_findings(&detector, witness_pairs, progress);
        }

        // Determine public input positions in the test_case.inputs vector
        let public_input_positions = Self::resolve_public_input_positions(
            config,
            &self.config.inputs,
            self.executor.num_public_inputs(),
        );

        tracing::debug!(
            "Using public input positions: {:?} (out of {} total inputs)",
            public_input_positions,
            self.config.inputs.len()
        );

        // Generate fixed public inputs that will be shared across all test cases
        let fixed_public = if public_input_positions.is_empty() {
            None
        } else if let Some(fixed) = Self::parse_fixed_public_inputs(config, &public_input_positions)
        {
            Some(fixed)
        } else {
            let base = self.generate_test_case();
            let fixed: Vec<(usize, FieldElement)> = public_input_positions
                .iter()
                .filter_map(|&pos| base.inputs.get(pos).map(|val| (pos, val.clone())))
                .collect();
            Some(fixed)
        };

        let mut test_cases = Vec::with_capacity(witness_pairs);
        for _ in 0..witness_pairs {
            let mut tc = self.generate_test_case();
            // Fix public inputs at their correct positions
            if let Some(ref fixed) = fixed_public {
                for (pos, val) in fixed {
                    if *pos < tc.inputs.len() {
                        tc.inputs[*pos] = val.clone();
                    }
                }
            }
            test_cases.push(tc);
        }

        // Execute in parallel and collect results with indices
        // Mode 3 optimization: collect only (index, result) to avoid cloning TestCase
        let executor = self.executor.clone();
        let indexed_results: Vec<(usize, ExecutionResult)> = if self.workers <= 1 {
            test_cases
                .iter()
                .enumerate()
                .map(|(i, tc)| {
                    let result = executor.execute_sync(&tc.inputs);
                    (i, result)
                })
                .collect()
        } else if let Some(ref pool) = self.thread_pool {
            // Mode 3: Reuse cached thread pool instead of creating new one per attack
            pool.install(|| {
                test_cases
                    .par_iter()
                    .enumerate()
                    .map(|(i, tc)| {
                        let result = executor.execute_sync(&tc.inputs);
                        (i, result)
                    })
                    .collect()
            })
        } else {
            // Fallback: sequential execution
            test_cases
                .iter()
                .enumerate()
                .map(|(i, tc)| {
                    let result = executor.execute_sync(&tc.inputs);
                    (i, result)
                })
                .collect()
        };

        // Group by output hash to find collisions
        // Mode 3: Pre-size HashMap to avoid rehashing
        // Use indices to reference test_cases, only clone when adding to collision set
        let num_pairs = test_cases.len();
        let mut output_map: std::collections::HashMap<Vec<u8>, Vec<usize>> =
            std::collections::HashMap::with_capacity(num_pairs / 2);

        for (idx, result) in indexed_results {
            if result.success {
                let output_hash = self.hash_output(&result.outputs);
                output_map.entry(output_hash).or_default().push(idx);
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        // Check for collisions
        for (_hash, witness_indices) in output_map {
            // Collect TestCases for indices that produced same output
            let witnesses: Vec<&TestCase> = witness_indices
                .iter()
                .filter_map(|&idx| test_cases.get(idx))
                .collect();

            if witnesses.len() > 1 && self.witnesses_are_different_refs(&witnesses) {
                let finding = Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: format!(
                        "Found {} different witnesses producing identical output",
                        witnesses.len()
                    ),
                    poc: super::ProofOfConcept {
                        witness_a: witnesses[0].inputs.clone(),
                        witness_b: Some(witnesses[1].inputs.clone()),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                };

                self.core.findings().write().unwrap().push(finding.clone());

                if let Some(p) = progress {
                    p.log_finding("CRITICAL", &finding.description);
                }
            }
        }

        Ok(())
    }

    fn resolve_public_input_positions(
        config: &serde_yaml::Value,
        inputs: &[Input],
        default_public_count: usize,
    ) -> Vec<usize> {
        use std::collections::{HashMap, HashSet};

        let mut seen = HashSet::new();
        let mut positions = Vec::new();

        if let Some(names) = config
            .get("public_input_names")
            .and_then(|v| v.as_sequence())
        {
            let mut name_to_index = HashMap::new();
            for (idx, input) in inputs.iter().enumerate() {
                name_to_index.insert(input.name.as_str(), idx);
            }

            for entry in names {
                if let Some(name) = entry.as_str() {
                    if let Some(&idx) = name_to_index.get(name) {
                        if seen.insert(idx) {
                            positions.push(idx);
                        }
                    } else {
                        tracing::warn!(
                            "Unknown public_input_name '{}' in underconstrained attack config",
                            name
                        );
                    }
                } else {
                    tracing::warn!(
                        "Non-string entry in public_input_names for underconstrained attack"
                    );
                }
            }

            if !positions.is_empty() {
                return positions;
            }
            tracing::warn!(
                "public_input_names provided but none matched config.inputs; falling back to defaults"
            );
        }

        if let Some(list) = config
            .get("public_input_positions")
            .and_then(|v| v.as_sequence())
        {
            for entry in list {
                let parsed = match entry {
                    serde_yaml::Value::Number(n) => n.as_u64().map(|v| v as usize),
                    serde_yaml::Value::String(s) => s.parse::<usize>().ok(),
                    _ => None,
                };
                if let Some(idx) = parsed {
                    if idx < inputs.len() {
                        if seen.insert(idx) {
                            positions.push(idx);
                        }
                    } else {
                        tracing::warn!(
                            "public_input_positions entry {} out of range ({} inputs)",
                            idx,
                            inputs.len()
                        );
                    }
                } else {
                    tracing::warn!(
                        "Invalid entry in public_input_positions for underconstrained attack"
                    );
                }
            }

            if !positions.is_empty() {
                return positions;
            }
            tracing::warn!(
                "public_input_positions provided but none were valid; falling back to defaults"
            );
        }

        if let Some(count) = config.get("public_input_count").and_then(|v| v.as_u64()) {
            let capped = count.min(inputs.len() as u64) as usize;
            if count as usize > inputs.len() {
                tracing::warn!(
                    "public_input_count {} exceeds input count {}; capping",
                    count,
                    inputs.len()
                );
            }
            return (0..capped).collect();
        }

        let capped = default_public_count.min(inputs.len());
        (0..capped).collect()
    }

    fn parse_fixed_public_inputs(
        config: &serde_yaml::Value,
        public_positions: &[usize],
    ) -> Option<Vec<(usize, FieldElement)>> {
        let values = config
            .get("fixed_public_inputs")
            .and_then(|v| v.as_sequence())?;

        if values.is_empty() {
            return None;
        }

        if values.len() != public_positions.len() {
            tracing::warn!(
                "fixed_public_inputs length ({}) does not match public input positions ({})",
                values.len(),
                public_positions.len()
            );
            return None;
        }

        let mut fixed = Vec::with_capacity(values.len());
        for (pos, entry) in public_positions.iter().zip(values.iter()) {
            let raw = match entry {
                serde_yaml::Value::String(s) => s.clone(),
                serde_yaml::Value::Number(n) => n.to_string(),
                serde_yaml::Value::Bool(b) => {
                    if *b {
                        "1".to_string()
                    } else {
                        "0".to_string()
                    }
                }
                _ => {
                    tracing::warn!(
                        "Unsupported fixed_public_inputs entry type for underconstrained attack"
                    );
                    return None;
                }
            };

            let fe = match Self::parse_field_element(&raw) {
                Some(value) => value,
                None => {
                    tracing::warn!(
                        "Could not parse fixed_public_inputs value '{}' in underconstrained attack",
                        raw
                    );
                    return None;
                }
            };

            fixed.push((*pos, fe));
        }

        Some(fixed)
    }

    async fn run_soundness_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let forge_attempts: usize = config
            .get("forge_attempts")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        let mutation_rate: f64 = config
            .get("mutation_rate")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.1);

        tracing::info!("Attempting {} proof forgeries", forge_attempts);
        {
            use crate::attacks::SoundnessTester;
            let tester = SoundnessTester::new()
                .with_forge_attempts(forge_attempts)
                .with_mutation_rate(mutation_rate);
            self.add_attack_findings(&tester, forge_attempts, progress);
        }

        let num_public = self.executor.num_public_inputs();
        if num_public == 0 {
            tracing::warn!("Soundness attack skipped: circuit has no public inputs to mutate");
            return Ok(());
        }

        for _ in 0..forge_attempts {
            let valid_case = self.generate_test_case();
            let valid_proof = self.executor.prove(&valid_case.inputs)?;

            let valid_public: Vec<FieldElement> =
                valid_case.inputs.iter().take(num_public).cloned().collect();

            // Mutate public inputs only
            let mutated_public: Vec<FieldElement> = {
                let rng = self.core.rng_mut();
                valid_public
                    .iter()
                    .map(|input| {
                        if rng.gen::<f64>() < mutation_rate {
                            mutate_field_element(input, rng)
                        } else {
                            input.clone()
                        }
                    })
                    .collect()
            };

            // Skip if mutation didn't change public inputs
            if mutated_public == valid_public {
                continue;
            }

            // Try to verify with mutated inputs
            let verified = self.executor.verify(&valid_proof, &mutated_public)?;
            let oracle_findings = self.core.check_proof_forgery(
                &valid_case.inputs,
                &mutated_public,
                &valid_proof,
                verified,
            );

            if verified {
                if oracle_findings.is_empty() {
                    let finding = Finding {
                        attack_type: AttackType::Soundness,
                        severity: Severity::Critical,
                        description: "Proof verified with mutated inputs - soundness violation!"
                            .to_string(),
                        poc: super::ProofOfConcept {
                            witness_a: valid_case.inputs,
                            witness_b: None,
                            public_inputs: mutated_public,
                            proof: Some(valid_proof),
                        },
                        location: None,
                    };

                    self.core.findings().write().unwrap().push(finding.clone());

                    if let Some(p) = progress {
                        p.log_finding("CRITICAL", &finding.description);
                    }
                } else if let Some(p) = progress {
                    for finding in &oracle_findings {
                        p.log_finding("CRITICAL", &finding.description);
                    }
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_arithmetic_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let test_values = config
            .get("test_values")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                vec![
                    "0".to_string(),
                    "1".to_string(),
                    "p-1".to_string(),
                    "p".to_string(),
                ]
            });

        tracing::info!("Testing {} arithmetic edge cases", test_values.len());
        {
            use crate::attacks::ArithmeticTester;
            let tester = ArithmeticTester::new().with_test_values(test_values.clone());
            self.add_attack_findings(&tester, test_values.len(), progress);
        }

        let field_modulus = self.get_field_modulus();

        for value in test_values {
            let expanded =
                match crate::config::parser::expand_value_placeholder(&value, &field_modulus) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tracing::warn!("Skipping invalid arithmetic test value '{}': {}", value, e);
                        continue;
                    }
                };
            let mut fe_bytes = [0u8; 32];
            let start = 32_usize.saturating_sub(expanded.len());
            fe_bytes[start..].copy_from_slice(&expanded[..expanded.len().min(32)]);
            let fe = FieldElement(fe_bytes);

            let test_case = self.create_test_case_with_value(fe);
            let result = self.execute_and_learn(&test_case);

            if result.success && self.detect_overflow_indicator(&result.outputs) {
                let finding = Finding {
                    attack_type: AttackType::ArithmeticOverflow,
                    severity: Severity::High,
                    description: format!("Potential arithmetic overflow with value: {}", value),
                    poc: super::ProofOfConcept {
                        witness_a: test_case.inputs,
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                };

                self.core.findings().write().unwrap().push(finding.clone());

                if let Some(p) = progress {
                    p.log_finding("HIGH", &finding.description);
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_collision_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let samples: usize = config
            .get("samples")
            .and_then(|v| v.as_u64())
            .unwrap_or(10000) as usize;

        tracing::info!("Running collision detection with {} samples", samples);
        {
            use crate::attacks::CollisionDetector;
            let detector = CollisionDetector::new(samples);
            self.add_attack_findings(&detector, samples, progress);
        }

        // Generate and execute in parallel
        let mut test_cases = Vec::with_capacity(samples);
        for _ in 0..samples {
            test_cases.push(self.generate_test_case());
        }

        let executor = self.executor.clone();
        let indexed_results: Vec<(usize, ExecutionResult)> = if self.workers <= 1 {
            test_cases
                .iter()
                .enumerate()
                .map(|(i, tc)| {
                    let result = executor.execute_sync(&tc.inputs);
                    (i, result)
                })
                .collect()
        } else if let Some(ref pool) = self.thread_pool {
            // Mode 3: Reuse cached thread pool instead of creating new one per attack
            pool.install(|| {
                test_cases
                    .par_iter()
                    .enumerate()
                    .map(|(i, tc)| {
                        let result = executor.execute_sync(&tc.inputs);
                        (i, result)
                    })
                    .collect()
            })
        } else {
            // Fallback: sequential execution
            test_cases
                .iter()
                .enumerate()
                .map(|(i, tc)| {
                    let result = executor.execute_sync(&tc.inputs);
                    (i, result)
                })
                .collect()
        };

        // Mode 3: Pre-size HashMap to avoid rehashing
        // Store indices to avoid cloning TestCase
        let mut hash_map: std::collections::HashMap<Vec<u8>, usize> =
            std::collections::HashMap::with_capacity(test_cases.len());

        for (idx, result) in indexed_results {
            if result.success {
                let output_hash = self.hash_output(&result.outputs);

                if let Some(&existing_idx) = hash_map.get(&output_hash) {
                    let existing = &test_cases[existing_idx];
                    let test_case = &test_cases[idx];
                    if existing.inputs != test_case.inputs {
                        let finding = Finding {
                            attack_type: AttackType::Collision,
                            severity: Severity::Critical,
                            description: "Found collision: different inputs produce same output"
                                .to_string(),
                            poc: super::ProofOfConcept {
                                witness_a: existing.inputs.clone(),
                                witness_b: Some(test_case.inputs.clone()),
                                public_inputs: vec![],
                                proof: None,
                            },
                            location: None,
                        };

                        self.core.findings().write().unwrap().push(finding.clone());

                        if let Some(p) = progress {
                            p.log_finding("CRITICAL", &finding.description);
                        }
                    }
                } else {
                    hash_map.insert(output_hash, idx);
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_boundary_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let test_values = config
            .get("test_values")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["0".to_string(), "1".to_string(), "p-1".to_string()]);

        tracing::info!("Testing {} boundary values", test_values.len());
        {
            use crate::attacks::BoundaryTester;
            let tester = BoundaryTester::new().with_custom_values(test_values.clone());
            self.add_attack_findings(&tester, test_values.len(), progress);
        }

        let field_modulus = self.get_field_modulus();

        for value in test_values {
            let expanded =
                match crate::config::parser::expand_value_placeholder(&value, &field_modulus) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tracing::warn!("Skipping invalid boundary test value '{}': {}", value, e);
                        continue;
                    }
                };
            let mut fe_bytes = [0u8; 32];
            let start = 32_usize.saturating_sub(expanded.len());
            fe_bytes[start..].copy_from_slice(&expanded[..expanded.len().min(32)]);
            let fe = FieldElement(fe_bytes);

            let test_case = self.create_test_case_with_value(fe);
            let _ = self.execute_and_learn(&test_case);

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_verification_fuzzing_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::attacks::verification::VerificationFuzzer;

        let malleability_tests = config
            .get("malleability_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;
        let malformed_tests = config
            .get("malformed_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;
        let edge_case_tests = config
            .get("edge_case_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(500) as usize;
        let mutation_rate = config
            .get("mutation_rate")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.05);

        tracing::info!(
            "Running verification fuzzing: malleability={}, malformed={}, edge_cases={}",
            malleability_tests,
            malformed_tests,
            edge_case_tests
        );

        let fuzzer = VerificationFuzzer::new()
            .with_malleability_tests(malleability_tests)
            .with_malformed_tests(malformed_tests)
            .with_edge_case_tests(edge_case_tests)
            .with_mutation_rate(mutation_rate);

        let mut rng = rand::thread_rng();
        let findings = fuzzer.fuzz(&self.executor, &mut rng);

        if !findings.is_empty() {
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        Ok(())
    }

    async fn run_witness_fuzzing_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::attacks::witness::WitnessFuzzer;

        let determinism_tests = config
            .get("determinism_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        let timing_tests = config
            .get("timing_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(500) as usize;
        let stress_tests = config
            .get("stress_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;
        let timing_threshold_us = config
            .get("timing_threshold_us")
            .and_then(|v| v.as_u64())
            .unwrap_or(10_000);
        let timing_cv_threshold = config
            .get("timing_cv_threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5);

        tracing::info!(
            "Running witness fuzzing: determinism={}, timing={}, stress={}",
            determinism_tests,
            timing_tests,
            stress_tests
        );

        let fuzzer = WitnessFuzzer::new()
            .with_determinism_tests(determinism_tests)
            .with_timing_tests(timing_tests)
            .with_stress_tests(stress_tests)
            .with_timing_threshold_us(timing_threshold_us)
            .with_timing_cv_threshold(timing_cv_threshold);

        let mut rng = rand::thread_rng();
        let findings = fuzzer.fuzz(&self.executor, &mut rng);

        if !findings.is_empty() {
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        Ok(())
    }

    async fn run_differential_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::differential::report::DifferentialReport;
        use crate::differential::{DifferentialConfig, DifferentialFuzzer};
        use std::collections::{HashMap, HashSet};

        let num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(500) as usize;
        let compare_coverage = config
            .get("compare_coverage")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let compare_timing = config
            .get("compare_timing")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let timing_tolerance_percent = config
            .get("timing_tolerance_percent")
            .and_then(|v| v.as_f64())
            .unwrap_or(50.0);
        let timing_min_us = config
            .get("timing_min_us")
            .and_then(|v| v.as_u64())
            .unwrap_or(2_000);
        let timing_abs_threshold_us = config
            .get("timing_abs_threshold_us")
            .and_then(|v| v.as_u64())
            .unwrap_or(5_000);
        let coverage_min_constraints = config
            .get("coverage_min_constraints")
            .and_then(|v| v.as_u64())
            .unwrap_or(16) as usize;
        let coverage_jaccard_threshold = config
            .get("coverage_jaccard_threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5);
        let coverage_abs_delta_threshold = config
            .get("coverage_abs_delta_threshold")
            .and_then(|v| v.as_u64())
            .unwrap_or(200) as usize;
        let coverage_rel_delta_threshold = config
            .get("coverage_rel_delta_threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.25);

        tracing::info!("Running differential fuzzing with {} tests", num_tests);

        let parse_framework = |name: &str| -> Option<Framework> {
            match name.to_lowercase().as_str() {
                "circom" => Some(Framework::Circom),
                "noir" => Some(Framework::Noir),
                "halo2" => Some(Framework::Halo2),
                "cairo" => Some(Framework::Cairo),
                "mock" => Some(Framework::Mock),
                _ => None,
            }
        };

        let backends: Vec<Framework> =
            if let Some(seq) = config.get("backends").and_then(|v| v.as_sequence()) {
                seq.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(parse_framework)
                    .collect()
            } else {
                vec![self.config.campaign.target.framework]
            };

        // Optional per-backend circuit paths
        let mut backend_paths: HashMap<Framework, String> = HashMap::new();
        if let Some(map) = config.get("backend_paths").and_then(|v| v.as_mapping()) {
            for (k, v) in map {
                if let (Some(key), Some(path)) = (k.as_str(), v.as_str()) {
                    if let Some(framework) = parse_framework(key) {
                        backend_paths.insert(framework, path.to_string());
                    }
                }
            }
        }

        let mut unique = HashSet::new();
        let mut selected_backends = Vec::new();
        for backend in backends {
            if unique.insert(backend) {
                selected_backends.push(backend);
            }
        }

        if selected_backends.len() < 2 {
            tracing::warn!("Differential fuzzing skipped: configure at least two backends");
            return Ok(());
        }

        let mut diff_fuzzer = DifferentialFuzzer::new(DifferentialConfig {
            num_tests,
            backends: selected_backends.clone(),
            compare_coverage,
            compare_proofs: false,
            timing_tolerance_percent,
            timing_min_us,
            timing_abs_threshold_us,
            coverage_min_constraints,
            coverage_jaccard_threshold,
            coverage_abs_delta_threshold,
            coverage_rel_delta_threshold,
            compare_timing,
        });

        // Add executors for each backend (skip any that fail to initialize)
        let mut active_backends = Vec::new();
        for backend in &selected_backends {
            let circuit_path = backend_paths
                .get(backend)
                .map(|s| s.as_str())
                .unwrap_or_else(|| {
                    self.config
                        .campaign
                        .target
                        .circuit_path
                        .to_str()
                        .unwrap_or("")
                });

            match ExecutorFactory::create_with_options(
                *backend,
                circuit_path,
                &self.config.campaign.target.main_component,
                &self.executor_factory_options,
            ) {
                Ok(executor) => {
                    diff_fuzzer.add_executor(*backend, executor);
                    active_backends.push(*backend);
                }
                Err(e) => {
                    tracing::warn!(
                        "Skipping backend {:?} for differential fuzzing: {}",
                        backend,
                        e
                    );
                }
            }
        }

        if active_backends.len() < 2 {
            tracing::warn!("Differential fuzzing skipped: fewer than two active backends");
            return Ok(());
        }

        let mut test_cases = Vec::with_capacity(num_tests);
        for _ in 0..num_tests {
            test_cases.push(self.generate_random_test_case());
        }

        let results = diff_fuzzer.run(&test_cases);

        // Create differential report
        let report = DifferentialReport::new(
            &self.config.campaign.name,
            active_backends.clone(),
            results.clone(),
            diff_fuzzer.stats().clone(),
        );

        if report.has_critical_issues() {
            tracing::warn!(
                "Differential fuzzing found {} critical issues",
                report.critical_findings().len()
            );
        }

        tracing::info!("{}", report.summary());

        if !results.is_empty() {
            let findings: Vec<Finding> = results
                .into_iter()
                .map(|result| Finding {
                    attack_type: AttackType::Differential,
                    severity: Severity::Medium,
                    description: format!("Differential discrepancy: {:?}", result.severity),
                    poc: super::ProofOfConcept {
                        witness_a: result.input,
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                })
                .collect();
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding("MEDIUM", &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            for _ in 0..num_tests {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_circuit_composition_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::multi_circuit::composition::{CompositionTester, CompositionType};
        use crate::multi_circuit::{CircuitChain, MultiCircuitFuzzer};

        let num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(200) as usize;

        tracing::info!(
            "Running circuit composition fuzzing with {} tests",
            num_tests
        );

        // Create composition tester for sequential composition
        let mut composition_tester = CompositionTester::new(CompositionType::Sequential);
        composition_tester.add_circuit(self.executor.clone());

        // Create circuit chain for chained execution testing
        let mut chain = CircuitChain::new();
        chain.add("main", self.executor.clone());

        // Test chain execution with random inputs
        for _ in 0..num_tests.min(10) {
            let inputs: Vec<FieldElement> = {
                let rng = self.core.rng_mut();
                (0..self.executor.num_private_inputs())
                    .map(|_| FieldElement::random(rng))
                    .collect()
            };

            let chain_result = chain.execute(&inputs);
            if !chain_result.success {
                tracing::debug!(
                    "Chain execution failed at step: {:?}",
                    chain_result.steps.last().map(|s| &s.circuit_name)
                );
            }
        }

        // Test composition with vulnerability detection
        let vulnerabilities = composition_tester.check_vulnerabilities();
        for vuln in &vulnerabilities {
            tracing::warn!(
                "Composition vulnerability: {:?} - {}",
                vuln.vuln_type,
                vuln.description
            );
        }

        let mut multi_fuzzer =
            MultiCircuitFuzzer::new(crate::multi_circuit::MultiCircuitConfig::default());

        multi_fuzzer.add_circuit("main", self.executor.clone());

        let mut rng = rand::thread_rng();
        let findings = multi_fuzzer.run(&mut rng);

        if !findings.is_empty() {
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            for _ in 0..num_tests {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_information_leakage_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::analysis::taint::TaintAnalyzer;

        let num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(300) as usize;

        tracing::info!(
            "Running information leakage detection with {} tests",
            num_tests
        );

        let inspector = match self.executor.constraint_inspector() {
            Some(inspector) => inspector,
            None => {
                tracing::warn!(
                    "Information leakage attack skipped: constraint inspector unavailable"
                );
                if let Some(p) = progress {
                    for _ in 0..num_tests {
                        p.inc();
                    }
                }
                return Ok(());
            }
        };

        let public_indices = inspector.public_input_indices();
        let private_indices = inspector.private_input_indices();
        let output_indices = inspector.output_indices();

        if private_indices.is_empty() {
            tracing::warn!("Information leakage attack skipped: no private inputs");
            if let Some(p) = progress {
                for _ in 0..num_tests {
                    p.inc();
                }
            }
            return Ok(());
        }

        let constraints = inspector.get_constraints();
        if constraints.is_empty() {
            tracing::warn!("Information leakage attack skipped: no constraints available");
            if let Some(p) = progress {
                for _ in 0..num_tests {
                    p.inc();
                }
            }
            return Ok(());
        }

        let mut analyzer = TaintAnalyzer::new(public_indices.len(), private_indices.len());
        if !public_indices.is_empty() || !private_indices.is_empty() {
            analyzer.initialize_inputs_with_indices(&public_indices, &private_indices);
        } else {
            analyzer.initialize_inputs();
        }
        if !output_indices.is_empty() {
            analyzer.mark_outputs(&output_indices);
        } else {
            analyzer.mark_outputs_from_constraints(&constraints);
        }
        analyzer.propagate_constraints(&constraints);

        let findings = analyzer.to_findings();
        if !findings.is_empty() {
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            for _ in 0..num_tests {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_timing_sidechannel_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::analysis::profiling::Profiler;

        let num_samples = config
            .get("num_samples")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        tracing::info!(
            "Running timing side-channel detection with {} samples",
            num_samples
        );

        let profiler = Profiler::new().with_samples(num_samples);
        let mut rng = rand::thread_rng();

        let profile = profiler.profile(&self.executor, &mut rng);

        if profile.execution_stats.has_timing_variation() {
            let finding = Finding {
                attack_type: AttackType::TimingSideChannel,
                severity: Severity::Medium,
                description: format!(
                    "Timing side-channel detected: execution time varies significantly (CV: {:.2}%)",
                    (profile.execution_stats.std_dev_us / profile.execution_stats.mean_us) * 100.0
                ),
                poc: super::ProofOfConcept {
                    witness_a: vec![],
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                },
                location: None,
            };

            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding("MEDIUM", &finding.description);
            }
        }

        if let Some(p) = progress {
            for _ in 0..num_samples {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_recursive_proof_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::multi_circuit::recursive::{RecursionResult, RecursiveTester};

        let num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;

        let max_depth = config
            .get("max_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(3) as usize;

        tracing::info!(
            "Running recursive proof fuzzing with {} tests, max depth {}",
            num_tests,
            max_depth
        );

        let tester = RecursiveTester::new(max_depth).with_verifier(self.executor.clone());

        for _ in 0..num_tests {
            let test_case = self.generate_random_test_case();
            let result = tester.test_recursion(&test_case.inputs, max_depth);

            match result {
                RecursionResult::VerificationFailed { depth, error } => {
                    let finding = Finding {
                        attack_type: AttackType::RecursiveProof,
                        severity: Severity::High,
                        description: format!(
                            "Recursive verification failed at depth {}: {}",
                            depth, error
                        ),
                        poc: super::ProofOfConcept {
                            witness_a: test_case.inputs.clone(),
                            witness_b: None,
                            public_inputs: vec![],
                            proof: None,
                        },
                        location: None,
                    };

                    self.core.findings().write().unwrap().push(finding.clone());
                    if let Some(p) = progress {
                        p.log_finding("HIGH", &finding.description);
                    }
                }
                RecursionResult::Error(err) => {
                    tracing::warn!("Recursive test error: {}", err);
                }
                _ => {}
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    fn add_attack_findings(
        &self,
        attack: &dyn AttackTrait,
        samples: usize,
        progress: Option<&ProgressReporter>,
    ) -> usize {
        let context = AttackContext::new(
            self.get_circuit_info(),
            samples,
            self.config.campaign.parameters.timeout_seconds,
        );
        let mut findings = attack.run(&context);

        let evidence_mode =
            Self::additional_bool(&self.config.campaign.parameters.additional, "evidence_mode")
                .unwrap_or(false);

        if evidence_mode {
            let before = findings.len();
            findings.retain(|f| !Self::poc_is_empty(&f.poc));
            let dropped = before.saturating_sub(findings.len());
            if dropped > 0 {
                tracing::info!(
                    "Evidence mode: dropped {} heuristic findings from {:?}",
                    dropped,
                    attack.attack_type()
                );
            }
        } else {
            for finding in findings.iter_mut() {
                if Self::poc_is_empty(&finding.poc) {
                    if !finding.description.starts_with("HINT:") {
                        finding.description = format!("HINT: {}", finding.description);
                    }
                    if finding.severity > Severity::Info {
                        finding.severity = Severity::Info;
                    }
                }
            }
        }

        let count = findings.len();
        if count > 0 {
            let findings_store = self.core.findings();
            let mut store = findings_store.write().unwrap();
            for finding in findings {
                if let Some(p) = progress {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
                store.push(finding);
            }
        }

        count
    }

    fn poc_is_empty(poc: &ProofOfConcept) -> bool {
        poc.witness_a.is_empty()
            && poc.witness_b.is_none()
            && poc.public_inputs.is_empty()
            && poc.proof.is_none()
    }

    fn get_circuit_info(&self) -> zk_core::CircuitInfo {
        zk_core::CircuitInfo {
            name: self.config.campaign.target.main_component.clone(),
            num_constraints: self.executor.num_constraints(),
            num_private_inputs: self.executor.num_private_inputs(),
            num_public_inputs: self.executor.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn hash_output(&self, output: &[FieldElement]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for fe in output {
            hasher.update(fe.0);
        }
        hasher.finalize().to_vec()
    }

    /// Check if witnesses have different inputs (Mode 3 optimized: takes references)
    fn witnesses_are_different_refs(&self, witnesses: &[&TestCase]) -> bool {
        if witnesses.len() < 2 {
            return false;
        }

        for (i, left) in witnesses.iter().enumerate() {
            for right in witnesses.iter().skip(i + 1) {
                if left.inputs != right.inputs {
                    return true;
                }
            }
        }
        false
    }

    fn get_field_modulus(&self) -> [u8; 32] {
        // Use executor's field modulus instead of hardcoded BN254
        self.executor.field_modulus()
    }

    fn detect_overflow_indicator(&self, output: &[FieldElement]) -> bool {
        for fe in output {
            let is_near_zero = fe.0.iter().take(30).all(|&b| b == 0);
            let is_near_max = fe.0.iter().take(30).all(|&b| b == 0xff);
            if is_near_zero || is_near_max {
                return true;
            }
        }
        false
    }

    // ========================================================================
    // Phase 4: Novel Oracle Attack Implementations
    // ========================================================================

    async fn run_constraint_inference_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::attacks::constraint_inference::{ConstraintInferenceEngine, InferenceContext};
        use crate::config::v2::InvariantType;

        let confidence_threshold = config
            .get("confidence_threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.7);

        let confirm_violations = config
            .get("confirm_violations")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        tracing::info!(
            "Running constraint inference attack (confidence >= {:.0}%)",
            confidence_threshold * 100.0
        );

        let engine = ConstraintInferenceEngine::new()
            .with_confidence_threshold(confidence_threshold)
            .with_generate_violations(true);

        let num_inputs = self.executor.num_public_inputs() + self.executor.num_private_inputs();
        let num_wires = num_inputs.saturating_add(100);
        let mut output_wires = std::collections::HashSet::new();
        let mut implied = if let Some(inspector) = self.executor.constraint_inspector() {
            let mut context = InferenceContext::from_inspector(inspector, num_wires);
            self.merge_config_input_labels(inspector, &mut context.wire_labels);
            self.merge_output_labels(inspector, &mut context.wire_labels);
            output_wires.extend(inspector.output_indices());
            engine.analyze_with_context(&context)
        } else {
            tracing::warn!("No constraint inspector available for constraint inference");
            Vec::new()
        };

        if confirm_violations && !implied.is_empty() {
            let base_inputs = self.generate_test_case().inputs;
            engine.confirm_violations(
                self.executor.as_ref(),
                &base_inputs,
                &mut implied,
                &output_wires,
            );
        }

        let findings = engine.to_findings(&implied);
        if !findings.is_empty() {
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        // Enforce v2 invariants (constraint/range/uniqueness) by attempting violations.
        let invariants: Vec<_> = self
            .config
            .get_invariants()
            .into_iter()
            .filter(|inv| inv.invariant_type != InvariantType::Metamorphic)
            .collect();
        let invariant_findings = self.enforce_invariants(&invariants);
        if !invariant_findings.is_empty() {
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(invariant_findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &invariant_findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    async fn run_metamorphic_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::attacks::metamorphic::MetamorphicOracle;

        let num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;

        tracing::info!(
            "Running metamorphic testing with {} base witnesses",
            num_tests
        );

        let mut oracle = MetamorphicOracle::new().with_standard_relations();
        let invariant_relations = self.build_metamorphic_relations();
        for relation in invariant_relations {
            oracle = oracle.with_relation(relation);
        }

        // Generate base witnesses and test metamorphic relations
        for _ in 0..num_tests {
            let base_witness = self.generate_test_case();
            let results = oracle
                .test_all(self.executor.as_ref(), &base_witness.inputs)
                .await;

            let findings = oracle.to_findings(&results);
            if !findings.is_empty() {
                {
                    let findings_store = self.core.findings();
                    let mut store = findings_store.write().unwrap();
                    store.extend(findings.iter().cloned());
                }
                if let Some(p) = progress {
                    for finding in &findings {
                        p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                    }
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        Ok(())
    }

    async fn run_constraint_slice_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::attacks::constraint_slice::{ConstraintSliceOracle, OutputMapping};

        let samples_per_cone = config
            .get("samples_per_cone")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;

        let base_witness_attempts = config
            .get("base_witness_attempts")
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as usize;

        tracing::info!(
            "Running constraint slice analysis ({} samples/cone)",
            samples_per_cone
        );

        let oracle = ConstraintSliceOracle::new().with_samples(samples_per_cone);

        // Generate a base witness that successfully executes
        let mut base_witness = None;
        let attempts = base_witness_attempts.max(1);
        for _ in 0..attempts {
            let candidate = self.generate_test_case();
            let result = self.executor.execute_sync(&candidate.inputs);
            if result.success {
                base_witness = Some(candidate);
                break;
            }
        }

        let Some(base_witness) = base_witness else {
            tracing::warn!("Constraint slice skipped: no valid base witness after {} attempts", attempts);
            if let Some(p) = progress {
                p.log_finding("WARN", "Constraint slice skipped: no valid base witness");
                p.inc();
            }
            return Ok(());
        };

        // Determine output wire indices (prefer inspector-provided outputs)
        let outputs: Vec<OutputMapping> = if let Some(inspector) =
            self.executor.constraint_inspector()
        {
            let output_wires = inspector.output_indices();
            if !output_wires.is_empty() {
                output_wires
                    .into_iter()
                    .enumerate()
                    .map(|(output_index, output_wire)| OutputMapping {
                        output_index,
                        output_wire,
                    })
                    .collect()
            } else {
                let num_inputs =
                    self.executor.num_public_inputs() + self.executor.num_private_inputs();
                vec![OutputMapping {
                    output_index: 0,
                    output_wire: num_inputs,
                }]
            }
        } else {
            let num_inputs = self.executor.num_public_inputs() + self.executor.num_private_inputs();
            vec![OutputMapping {
                output_index: 0,
                output_wire: num_inputs,
            }]
        };

        let findings = oracle
            .run(self.executor.as_ref(), &base_witness.inputs, &outputs)
            .await;

        if !findings.is_empty() {
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    async fn run_spec_inference_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::attacks::spec_inference::SpecInferenceOracle;

        let sample_count = config
            .get("sample_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(500) as usize;

        tracing::info!("Running spec inference attack ({} samples)", sample_count);

        let oracle = SpecInferenceOracle::new()
            .with_sample_count(sample_count)
            .with_confidence_threshold(0.9)
            .with_wire_labels(self.input_labels());

        // Generate initial witnesses
        let mut initial_witnesses = Vec::with_capacity(sample_count.max(1));
        for _ in 0..sample_count.max(1) {
            initial_witnesses.push(self.generate_test_case().inputs);
        }

        let findings = oracle.run(self.executor.as_ref(), &initial_witnesses).await;

        if !findings.is_empty() {
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    async fn run_witness_collision_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::attacks::witness_collision::WitnessCollisionDetector;

        let samples = config
            .get("samples")
            .and_then(|v| v.as_u64())
            .unwrap_or(10000) as usize;

        let scope_public_inputs = config
            .get("scope_public_inputs")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        tracing::info!("Running witness collision detection ({} samples)", samples);

        let mut detector = WitnessCollisionDetector::new()
            .with_samples(samples)
            .with_public_input_scope(scope_public_inputs);

        if scope_public_inputs {
            let public_input_indices = if let Some(inspector) = self.executor.constraint_inspector()
            {
                let public_wires: std::collections::HashSet<_> =
                    inspector.public_input_indices().into_iter().collect();
                let mut wire_indices = inspector.public_input_indices();
                wire_indices.extend(inspector.private_input_indices());
                if wire_indices.is_empty() {
                    wire_indices = (0..self.config.inputs.len()).collect();
                }
                wire_indices
                    .into_iter()
                    .enumerate()
                    .filter_map(|(input_idx, wire_idx)| {
                        if public_wires.contains(&wire_idx) {
                            Some(input_idx)
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                (0..self
                    .executor
                    .num_public_inputs()
                    .min(self.config.inputs.len()))
                    .collect()
            };
            detector = detector.with_public_input_indices(public_input_indices);
        }

        // Generate witnesses
        let mut witnesses = Vec::with_capacity(samples);
        for _ in 0..samples {
            witnesses.push(self.generate_test_case().inputs);
        }

        let collisions = detector.run(self.executor.as_ref(), &witnesses).await;
        let findings = detector.to_findings(&collisions);

        if !findings.is_empty() {
            {
                let findings_store = self.core.findings();
                let mut store = findings_store.write().unwrap();
                store.extend(findings.iter().cloned());
            }
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    // ========================================================================
    // Phase 0: Continuous Fuzzing Loop
    // ========================================================================

    /// Run continuous coverage-guided fuzzing phase
    ///
    /// This is the critical missing piece - after running structured attacks,
    /// we need to continue fuzzing to explore more of the state space.
    ///
    /// Phase 0 Fix: Added crash/hang detection with per-execution timeout
    async fn run_continuous_fuzzing_phase(
        &mut self,
        iterations: u64,
        timeout_seconds: Option<u64>,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        let timeout = timeout_seconds.map(Duration::from_secs);

        // Phase 0 Fix: Per-execution timeout for hang detection (configurable, default 30s)
        let additional = &self.config.campaign.parameters.additional;
        let execution_timeout_ms = Self::additional_u64(additional, "execution_timeout_ms")
            .or_else(|| Self::additional_u64(additional, "timeout_per_execution").map(|v| v * 1000))
            .unwrap_or(30_000)
            .max(1);

        let minimize_enabled =
            Self::additional_bool(additional, "corpus_minimize_enabled").unwrap_or(true);
        let minimize_interval = Self::additional_u64(additional, "corpus_minimize_interval")
            .unwrap_or(10_000)
            .max(1);
        let minimize_min_size = Self::additional_u64(additional, "corpus_minimize_min_size")
            .unwrap_or(1_000)
            .max(1) as usize;
        let execution_timeout = Duration::from_millis(execution_timeout_ms);

        tracing::info!(
            "Starting continuous fuzzing phase: {} iterations, timeout: {:?}, per-exec timeout: {:?}",
            iterations,
            timeout,
            execution_timeout
        );

        let mut completed = 0u64;
        let mut hang_count = 0u64;
        let mut crash_count = 0u64;

        while completed < iterations {
            // Check overall timeout
            if let Some(t) = timeout {
                if start.elapsed() >= t {
                    tracing::info!(
                        "Continuous fuzzing timeout reached after {} iterations",
                        completed
                    );
                    break;
                }
            }

            // Core fuzzing loop: select_from_corpus → mutate → execute_and_learn
            let test_case = self.generate_test_case();

            // Phase 0 Fix: Execute with timeout for hang detection
            let exec_start = Instant::now();
            let result = self.execute_and_learn(&test_case);
            let exec_duration = exec_start.elapsed();

            // Phase 0 Fix: Detect hangs (execution took too long)
            if exec_duration >= execution_timeout {
                hang_count += 1;
                tracing::warn!(
                    "🐢 HANG DETECTED at iteration {}: execution took {:?} (limit: {:?})",
                    completed,
                    exec_duration,
                    execution_timeout
                );
                // Add to findings as potential DoS vulnerability
                self.record_hang_finding(&test_case, exec_duration);
            }

            // Phase 0 Fix: Detect crashes (execution returned error/panic indicators)
            if result.is_crash() {
                crash_count += 1;
                tracing::warn!(
                    "💥 CRASH DETECTED at iteration {}: {:?}",
                    completed,
                    result.error_message()
                );
                // Add to findings as potential crash vulnerability
                self.record_crash_finding(&test_case, &result);
            }

            // Phase 2A: Check invariants against every accepted witness
            if result.success {
                self.check_invariants_against(&test_case, &result);
            }

            // Track coverage improvements
            if result.coverage.new_coverage {
                tracing::debug!(
                    "New coverage at iteration {}: {} constraints",
                    completed,
                    result.coverage.satisfied_constraints.len()
                );
            }

            completed += 1;

            if let Some(p) = progress {
                if completed.is_multiple_of(100) {
                    p.inc();
                }
            }

            // Update power scheduler periodically
            if completed.is_multiple_of(1000) {
                self.update_power_scheduler_globals();
            }

            // Phase 0 Fix: Periodic corpus minimization to maintain quality
            // Run every 10,000 iterations to reduce redundant test cases
            if minimize_enabled
                && completed.is_multiple_of(minimize_interval)
                && completed > 0
                && self.core.corpus().len() >= minimize_min_size
            {
                let stats = self.core.corpus().minimize();
                tracing::debug!(
                    "Periodic corpus minimization: {} → {} entries",
                    stats.original_size,
                    stats.minimized_size
                );
            }
        }

        // Phase 0 Fix: Final corpus minimization before reporting
        let final_stats = if minimize_enabled {
            self.core.corpus().minimize()
        } else {
            let size = self.core.corpus().len();
            minimizer::MinimizationStats::compute(size, size)
        };

        tracing::info!(
            "Continuous fuzzing complete: {} iterations in {:.2}s, {} findings, {} hangs, {} crashes, corpus: {}",
            completed,
            start.elapsed().as_secs_f64(),
            self.core.findings().read().unwrap().len(),
            hang_count,
            crash_count,
            final_stats.minimized_size
        );

        Ok(())
    }

    /// Phase 0 Fix: Record a hang as a potential DoS finding
    fn record_hang_finding(&mut self, test_case: &TestCase, duration: Duration) {
        use zk_core::{Finding, ProofOfConcept, Severity};

        let finding = Finding {
            attack_type: zk_core::AttackType::WitnessFuzzing,
            severity: Severity::Medium,
            description: format!(
                "Execution Hang Detected: Circuit execution took {:?}, exceeding timeout. Potential DoS vulnerability.",
                duration
            ),
            poc: ProofOfConcept {
                witness_a: test_case.inputs.clone(),
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some(format!(
                "Hang at iteration {} after {:?}",
                self.core.execution_count(),
                duration
            )),
        };

        if let Ok(mut findings) = self.core.findings().write() {
            findings.push(finding);
        }
    }

    /// Phase 0 Fix: Record a crash as a finding
    fn record_crash_finding(&mut self, test_case: &TestCase, result: &ExecutionResult) {
        use zk_core::{Finding, ProofOfConcept, Severity};

        let error_msg = result
            .error_message()
            .unwrap_or_else(|| "Unknown crash".to_string());

        let finding = Finding {
            attack_type: zk_core::AttackType::WitnessFuzzing,
            severity: Severity::High,
            description: format!(
                "Execution Crash Detected: {}. Potential vulnerability or implementation bug.",
                error_msg
            ),
            poc: ProofOfConcept {
                witness_a: test_case.inputs.clone(),
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some(format!(
                "Crash at iteration {}: {}",
                self.core.execution_count(),
                error_msg
            )),
        };

        if let Ok(mut findings) = self.core.findings().write() {
            findings.push(finding);
        }
    }

    /// Phase 2A: Check invariants against every accepted witness
    ///
    /// Unlike the one-shot enforce_invariants(), this is called for every
    /// successful execution in the fuzzing loop, enabling continuous
    /// invariant violation detection.
    ///
    /// IMPORTANT: Uses cached InvariantChecker to maintain uniqueness tracking state
    /// across executions. Without caching, uniqueness invariants (e.g., nullifier_unique)
    /// would never detect duplicates because each execution would start with a fresh empty set.
    fn check_invariants_against(&mut self, test_case: &TestCase, result: &ExecutionResult) {
        // Use cached checker to maintain uniqueness tracking state
        let Some(checker) = self.invariant_checker.as_mut() else {
            return;
        };

        // Check all invariants using cached state
        let violations = checker.check(&test_case.inputs, &result.outputs, result.success);

        // Record violations as findings
        for violation in violations {
            self.record_invariant_violation(&violation, test_case);
        }
    }

    /// Record an invariant violation as a finding
    fn record_invariant_violation(
        &self,
        violation: &crate::fuzzer::invariant_checker::Violation,
        test_case: &TestCase,
    ) {
        use zk_core::{Finding, ProofOfConcept};

        let severity = match violation.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Medium,
        };

        let finding = Finding {
            attack_type: AttackType::ConstraintInference,
            severity,
            description: format!(
                "Invariant '{}' violated: {}\nRelation: {}\nEvidence: {}",
                violation.invariant_name,
                if violation.circuit_accepted {
                    "Circuit ACCEPTED violating witness"
                } else {
                    "Violation detected"
                },
                violation.relation,
                violation.evidence
            ),
            poc: ProofOfConcept {
                witness_a: test_case.inputs.clone(),
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some(format!("Invariant: {}", violation.invariant_name)),
        };

        if let Ok(mut findings) = self.core.findings().write() {
            findings.push(finding);
        }
    }

    fn generate_report(&self, findings: Vec<Finding>, duration: u64) -> FuzzReport {
        // Phase 6A: Apply cross-oracle correlation for confidence scoring
        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);

        let processed_findings = if evidence_mode && !findings.is_empty() {
            // In evidence mode, filter to only HIGH+ confidence findings
            let correlator = OracleCorrelator::new();
            let correlated = correlator.correlate(&findings);

            tracing::info!(
                "Cross-oracle correlation: {} raw findings → {} correlation groups",
                findings.len(),
                correlated.len()
            );

            // Log confidence breakdown
            let mut critical_count = 0;
            let mut high_count = 0;
            let mut medium_count = 0;
            let mut low_count = 0;
            for cf in &correlated {
                match cf.confidence {
                    ConfidenceLevel::Critical => critical_count += 1,
                    ConfidenceLevel::High => high_count += 1,
                    ConfidenceLevel::Medium => medium_count += 1,
                    ConfidenceLevel::Low => low_count += 1,
                }
            }
            tracing::info!(
                "Confidence distribution: CRITICAL={}, HIGH={}, MEDIUM={}, LOW={}",
                critical_count,
                high_count,
                medium_count,
                low_count
            );

            // Filter to only MEDIUM+ confidence in evidence mode
            let min_confidence = Self::additional_string(additional, "min_evidence_confidence")
                .map(|s| match s.to_lowercase().as_str() {
                    "critical" => ConfidenceLevel::Critical,
                    "high" => ConfidenceLevel::High,
                    "low" => ConfidenceLevel::Low,
                    _ => ConfidenceLevel::Medium,
                })
                .unwrap_or(ConfidenceLevel::Medium);

            let filtered: Vec<Finding> = correlated
                .into_iter()
                .filter(|cf| cf.confidence >= min_confidence)
                .map(|cf| cf.primary)
                .collect();

            if filtered.len() < findings.len() {
                tracing::info!(
                    "Evidence mode: filtered {} low-confidence findings (kept {})",
                    findings.len() - filtered.len(),
                    filtered.len()
                );
            }

            filtered
        } else {
            findings
        };

        let mut report = FuzzReport::new(
            self.config.campaign.name.clone(),
            processed_findings,
            zk_core::CoverageMap {
                constraint_hits: std::collections::HashMap::new(),
                edge_coverage: self.core.coverage().unique_constraints_hit() as u64,
                max_coverage: self.executor.num_constraints() as u64,
            },
            self.config.reporting.clone(),
        );
        report.duration_seconds = duration;
        report.statistics.total_executions = self.core.execution_count();
        report
    }

    /// Write evidence summary markdown file using format_bundle_markdown()
    fn write_evidence_summary(
        &self,
        bundles: &[crate::reporting::EvidenceBundle],
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        use crate::reporting::evidence::format_bundle_markdown;
        use std::fs;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut md = String::new();
        md.push_str("# Evidence Summary\n\n");
        md.push_str(&format!("**Campaign:** {}\n", self.config.campaign.name));
        md.push_str(&format!(
            "**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        // Summary statistics
        let confirmed = bundles.iter().filter(|b| b.is_confirmed()).count();
        let failed = bundles
            .iter()
            .filter(|b| {
                matches!(
                    b.verification_result,
                    crate::reporting::VerificationResult::Failed(_)
                )
            })
            .count();
        let skipped = bundles
            .iter()
            .filter(|b| {
                matches!(
                    b.verification_result,
                    crate::reporting::VerificationResult::Skipped(_)
                )
            })
            .count();

        md.push_str("## Verification Summary\n\n");
        md.push_str("| Status | Count |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!("| ✅ CONFIRMED | {} |\n", confirmed));
        md.push_str(&format!("| ❌ NOT CONFIRMED | {} |\n", failed));
        md.push_str(&format!("| ⏭ SKIPPED | {} |\n", skipped));
        md.push_str(&format!("| **TOTAL** | {} |\n\n", bundles.len()));

        if confirmed > 0 {
            md.push_str("## ⚠️ CONFIRMED VULNERABILITIES\n\n");
            md.push_str("The following findings have been cryptographically verified. ");
            md.push_str("The circuit accepts witnesses that violate expected invariants.\n\n");
        }

        // Write each bundle using format_bundle_markdown
        for bundle in bundles {
            md.push_str(&format_bundle_markdown(bundle));
        }

        fs::write(path, md)?;
        Ok(())
    }

    /// Get current statistics
    pub fn stats(&self) -> FuzzingStats {
        self.core.stats()
    }

    /// Update power scheduler with global statistics
    fn update_power_scheduler_globals(&mut self) {
        self.core.update_power_scheduler_globals();
    }

    /// Export corpus to disk for persistence
    pub fn export_corpus(&self, output_dir: &std::path::Path) -> anyhow::Result<usize> {
        self.core.export_corpus(output_dir)
    }

    /// Seed corpus with externally supplied inputs (for phased scheduling).
    /// Returns the number of inputs added.
    pub fn seed_corpus_from_inputs(&mut self, inputs: &[Vec<FieldElement>]) -> usize {
        if inputs.is_empty() {
            return 0;
        }

        let expected = self.config.inputs.len();
        let mut added = 0usize;

        for input in inputs {
            if expected > 0 && input.len() != expected {
                continue;
            }
            let test_case = TestCase {
                inputs: input.clone(),
                expected_output: None,
                metadata: TestMetadata::default(),
            };
            self.add_to_corpus(test_case);
            added += 1;
        }

        added
    }

    /// Collect inputs from the current corpus (for phased scheduling).
    pub fn collect_corpus_inputs(&self, limit: usize) -> Vec<Vec<FieldElement>> {
        if limit == 0 {
            return Vec::new();
        }

        let mut collected = Vec::new();
        let mut entries = self.core.corpus().interesting_entries();
        if entries.is_empty() {
            entries = self.core.corpus().all_entries();
        }

        for entry in entries {
            if collected.len() >= limit {
                break;
            }
            collected.push(entry.test_case.inputs);
        }

        collected
    }

    /// Number of unique constraints hit so far.
    pub fn coverage_edges(&self) -> u64 {
        self.core.coverage().unique_constraints_hit() as u64
    }

    /// Constraint IDs hit so far.
    pub fn coverage_constraint_ids(&self) -> Vec<usize> {
        self.core.coverage().constraint_ids()
    }

    /// Total constraints in the target circuit.
    pub fn max_coverage(&self) -> u64 {
        self.executor.num_constraints() as u64
    }

    /// Current corpus size.
    pub fn corpus_len(&self) -> usize {
        self.core.corpus().len()
    }

    /// Get complexity metrics for the circuit
    pub fn get_complexity_metrics(&self) -> crate::analysis::complexity::ComplexityMetrics {
        self.complexity_analyzer.analyze(&self.executor)
    }

    /// Run source code analysis to find vulnerability hints
    fn run_source_analysis(&self, progress: Option<&ProgressReporter>) {
        use crate::targets::{cairo_analysis, circom_analysis, halo2_analysis, noir_analysis};

        // Try to read the circuit source file
        let source = match std::fs::read_to_string(&self.config.campaign.target.circuit_path) {
            Ok(s) => s,
            Err(_) => return, // Skip if source not readable
        };

        let hints: Vec<String> = match self.config.campaign.target.framework {
            Framework::Circom => circom_analysis::analyze_for_vulnerabilities(&source)
                .into_iter()
                .map(|h| {
                    format!(
                        "{:?}: {} at line {}",
                        h.hint_type,
                        h.description,
                        h.line.unwrap_or(0)
                    )
                })
                .collect(),
            Framework::Noir => noir_analysis::analyze_for_vulnerabilities(&source)
                .into_iter()
                .map(|h| {
                    format!(
                        "{:?}: {} at line {}",
                        h.hint_type,
                        h.description,
                        h.line.unwrap_or(0)
                    )
                })
                .collect(),
            Framework::Halo2 => halo2_analysis::analyze_circuit(&source)
                .into_iter()
                .map(|h| format!("[{}] {}: {}", h.severity, h.gate_type, h.description))
                .collect(),
            Framework::Cairo => cairo_analysis::analyze_for_vulnerabilities(&source)
                .into_iter()
                .map(|h| format!("{:?}: {}", h.issue_type, h.description))
                .collect(),
            _ => Vec::new(),
        };

        if !hints.is_empty() {
            tracing::info!("Source analysis found {} vulnerability hints", hints.len());
            for hint in &hints {
                tracing::warn!("Vulnerability hint: {}", hint);
                if let Some(p) = progress {
                    p.log_finding("INFO", hint);
                }
            }
        }
    }

    fn build_metamorphic_relations(&self) -> Vec<crate::attacks::metamorphic::MetamorphicRelation> {
        use crate::attacks::metamorphic::MetamorphicRelation;
        use crate::config::v2::InvariantType;

        let invariants = self.config.get_invariants();
        let mut relations = Vec::new();

        let input_map = self.input_index_map();
        for invariant in invariants {
            if invariant.invariant_type != InvariantType::Metamorphic {
                continue;
            }

            let transform = match invariant.transform.as_deref() {
                Some(raw) => self.parse_transform(raw, &input_map),
                None => None,
            };

            let Some(transform) = transform else {
                continue;
            };

            let expected = self.parse_expected_behavior(invariant.expected.as_deref());
            let severity = self.severity_from_invariant(&invariant);

            let mut relation = MetamorphicRelation::new(&invariant.name, transform, expected)
                .with_severity(severity);
            if let Some(desc) = invariant.description.as_deref() {
                relation = relation.with_description(desc);
            }

            relations.push(relation);
        }

        relations.extend(self.auto_metamorphic_relations());

        relations
    }

    fn auto_metamorphic_relations(&self) -> Vec<crate::attacks::metamorphic::MetamorphicRelation> {
        use crate::attacks::metamorphic::{ExpectedBehavior, MetamorphicRelation, Transform};
        let traits = self.config.get_target_traits();
        if Self::traits_are_empty(&traits) {
            return Vec::new();
        }

        let mut relations = Vec::new();

        if traits.uses_merkle {
            if let Some(idx) = self.find_input_index_by_patterns(&[
                "pathindices",
                "path_indices",
                "pathindex",
                "path_index",
            ]) {
                let mut assignments = std::collections::HashMap::new();
                assignments.insert(idx, FieldElement::from_u64(2));
                relations.push(
                    MetamorphicRelation::new(
                        "auto_merkle_path_index_binary",
                        Transform::SetInputs { assignments },
                        ExpectedBehavior::ShouldReject,
                    )
                    .with_severity(Severity::Critical)
                    .with_description("Merkle path indices should be binary (0/1)"),
                );
            }

            if let Some(idx) = self.find_input_index_by_patterns(&["leaf"]) {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_merkle_leaf_flip",
                        Transform::BitFlipInput {
                            index: idx,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Flipping the Merkle leaf should change the root/output"),
                );
            }

            if let Some(idx) = self.find_input_index_by_patterns(&["root"]) {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_merkle_root_flip",
                        Transform::BitFlipInput {
                            index: idx,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Changing the root input should change output/verification"),
                );
            }
        }

        if traits.uses_nullifier {
            if let Some(idx) = self.find_input_index_by_patterns(&["nullifier"]) {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_nullifier_variation",
                        Transform::AddToInputs {
                            indices: vec![idx],
                            value: FieldElement::one(),
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Nullifier changes should affect outputs"),
                );
            }
        }

        if traits.uses_commitment {
            if let Some(idx) = self.find_input_index_by_patterns(&["commitment", "commit"]) {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_commitment_flip",
                        Transform::BitFlipInput {
                            index: idx,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Commitment mutation should affect outputs"),
                );
            }
        }

        if traits.uses_signature {
            if let Some(idx) = self.find_signature_input_index() {
                relations.push(
                    MetamorphicRelation::new(
                        "auto_signature_flip",
                        Transform::BitFlipInput {
                            index: idx,
                            bit_position: 0,
                        },
                        ExpectedBehavior::OutputChanged,
                    )
                    .with_severity(Severity::High)
                    .with_description("Mutating the signature should change verification outcome"),
                );
            }
        }

        if !traits.range_checks.is_empty() {
            if let Some(idx) = self
                .find_input_index_by_patterns(&["amount", "value", "balance", "quantity", "qty"])
            {
                let mut assignments = std::collections::HashMap::new();
                assignments.insert(idx, FieldElement::max_value());
                relations.push(
                    MetamorphicRelation::new(
                        "auto_range_overflow",
                        Transform::SetInputs { assignments },
                        ExpectedBehavior::ShouldReject,
                    )
                    .with_severity(Severity::High)
                    .with_description("Range-checked inputs should reject overflow values"),
                );
            }
        }

        relations
    }

    fn traits_are_empty(traits: &crate::config::v2::TargetTraits) -> bool {
        !traits.uses_merkle
            && !traits.uses_nullifier
            && !traits.uses_commitment
            && !traits.uses_signature
            && traits.range_checks.is_empty()
            && traits.hash_function.is_none()
            && traits.curve.is_none()
            && traits.custom.is_empty()
    }

    fn find_input_index_by_patterns(&self, patterns: &[&str]) -> Option<usize> {
        let patterns: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();
        for (idx, input) in self.config.inputs.iter().enumerate() {
            let name = input.name.to_lowercase();
            if patterns.iter().any(|p| name.contains(p)) {
                return Some(idx);
            }
        }
        None
    }

    fn find_signature_input_index(&self) -> Option<usize> {
        for (idx, input) in self.config.inputs.iter().enumerate() {
            let name = input.name.to_lowercase();
            if name.contains("signature")
                || name.starts_with("sig")
                || name.contains("_sig")
                || name.contains("sig_")
            {
                return Some(idx);
            }
        }
        None
    }

    fn enforce_invariants(&self, invariants: &[crate::config::v2::Invariant]) -> Vec<Finding> {
        use crate::config::v2::{InvariantOracle, InvariantType};

        use crate::config::v2::parse_invariant_relation;

        let input_ranges = self.input_index_ranges();
        let mut findings = Vec::new();

        for invariant in invariants {
            if matches!(invariant.invariant_type, InvariantType::Metamorphic) {
                continue;
            }
            if matches!(
                invariant.oracle,
                InvariantOracle::Custom | InvariantOracle::Differential | InvariantOracle::Symbolic
            ) {
                continue;
            }

            let ast = parse_invariant_relation(&invariant.relation).ok();
            let target_indices = if let Some(ast) = ast.as_ref() {
                self.extract_target_indices_from_ast(ast, &input_ranges)
            } else {
                self.extract_target_indices_from_relation(&invariant.relation, &input_ranges)
            };
            if target_indices.is_empty() {
                continue;
            }

            let violation_value = match self.invariant_violation_value(invariant, ast.as_ref()) {
                Some(value) => value,
                None => continue,
            };

            let mut witness = vec![FieldElement::zero(); self.config.inputs.len().max(1)];
            for idx in target_indices {
                if idx < witness.len() {
                    witness[idx] = violation_value.clone();
                }
            }

            let result = self.executor.execute_sync(&witness);
            if result.success {
                let severity = self.severity_from_invariant(invariant);
                let description = format!(
                    "Invariant '{}' violated but circuit accepted input.\nRelation: {}",
                    invariant.name, invariant.relation
                );
                findings.push(Finding {
                    attack_type: AttackType::ConstraintInference,
                    severity,
                    description,
                    poc: ProofOfConcept {
                        witness_a: witness,
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                });
            }
        }

        findings
    }

    fn input_index_map(&self) -> std::collections::HashMap<String, usize> {
        self.config
            .inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| (input.name.to_lowercase(), idx))
            .collect()
    }

    fn input_index_ranges(&self) -> std::collections::HashMap<String, (usize, usize)> {
        let mut map = std::collections::HashMap::new();
        let mut offset = 0usize;
        for input in &self.config.inputs {
            let len = if input.input_type.starts_with("array") {
                input.length.unwrap_or(1)
            } else {
                1
            };
            map.insert(input.name.to_lowercase(), (offset, len));
            offset = offset.saturating_add(len);
        }
        map
    }

    fn input_labels(&self) -> std::collections::HashMap<usize, String> {
        self.config
            .inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| (idx, input.name.clone()))
            .collect()
    }

    fn merge_config_input_labels(
        &self,
        inspector: &dyn ConstraintInspector,
        labels: &mut std::collections::HashMap<usize, String>,
    ) {
        let mut wire_indices = inspector.public_input_indices();
        wire_indices.extend(inspector.private_input_indices());

        if wire_indices.is_empty() {
            wire_indices = (0..self.config.inputs.len()).collect();
        }

        for (input_idx, input) in self.config.inputs.iter().enumerate() {
            if let Some(&wire_idx) = wire_indices.get(input_idx) {
                labels.entry(wire_idx).or_insert_with(|| input.name.clone());
            }
        }
    }

    fn merge_output_labels(
        &self,
        inspector: &dyn ConstraintInspector,
        labels: &mut std::collections::HashMap<usize, String>,
    ) {
        for (idx, wire_idx) in inspector.output_indices().iter().enumerate() {
            labels
                .entry(*wire_idx)
                .or_insert_with(|| format!("output_{}", idx));
        }
    }

    fn extract_target_indices_from_relation(
        &self,
        relation: &str,
        input_ranges: &std::collections::HashMap<String, (usize, usize)>,
    ) -> Vec<usize> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        for ch in relation.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                current.push(ch);
            } else if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }

        let mut indices = Vec::new();
        for token in tokens {
            let key = Self::normalize_input_name(&token).to_lowercase();
            if let Some((start, len)) = input_ranges.get(&key) {
                for idx in *start..start.saturating_add(*len) {
                    indices.push(idx);
                }
            }
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    fn invariant_violation_value(
        &self,
        invariant: &crate::config::v2::Invariant,
        ast: Option<&crate::config::v2::InvariantAST>,
    ) -> Option<FieldElement> {
        if let Some(ast) = ast {
            if let Some(value) = self.violation_from_ast(ast, invariant) {
                return Some(value);
            }
        }

        let relation = invariant.relation.to_lowercase();

        if relation.contains("∈ {0,1}") || relation.contains("binary") {
            return Some(FieldElement::from_u64(2));
        }

        let bit_length = self.extract_bit_length(&relation);

        if matches!(
            invariant.invariant_type,
            crate::config::v2::InvariantType::Range
        ) || relation.contains('<')
        {
            if let Some(bits) = bit_length {
                if bits <= 63 {
                    return Some(FieldElement::from_u64(1u64 << bits));
                }
            }
            return Some(FieldElement::max_value());
        }

        None
    }

    fn extract_target_indices_from_ast(
        &self,
        ast: &crate::config::v2::InvariantAST,
        input_ranges: &std::collections::HashMap<String, (usize, usize)>,
    ) -> Vec<usize> {
        let mut names = Vec::new();
        self.collect_identifiers(ast, &mut names);
        let mut indices = Vec::new();
        for name in names {
            let key = Self::normalize_input_name(&name).to_lowercase();
            if let Some((start, len)) = input_ranges.get(&key) {
                for idx in *start..start.saturating_add(*len) {
                    indices.push(idx);
                }
            }
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    fn collect_identifiers(&self, ast: &crate::config::v2::InvariantAST, out: &mut Vec<String>) {
        use crate::config::v2::InvariantAST;

        match ast {
            InvariantAST::Identifier(name) => out.push(name.clone()),
            InvariantAST::ArrayAccess(name, _) => out.push(name.clone()),
            InvariantAST::Call(_, args) => {
                for arg in args {
                    out.push(arg.clone());
                }
            }
            InvariantAST::Equals(a, b)
            | InvariantAST::NotEquals(a, b)
            | InvariantAST::LessThan(a, b)
            | InvariantAST::LessThanOrEqual(a, b)
            | InvariantAST::GreaterThan(a, b)
            | InvariantAST::GreaterThanOrEqual(a, b)
            | InvariantAST::InSet(a, b) => {
                self.collect_identifiers(a, out);
                self.collect_identifiers(b, out);
            }
            InvariantAST::Range {
                lower,
                value,
                upper,
                ..
            } => {
                self.collect_identifiers(lower, out);
                self.collect_identifiers(value, out);
                self.collect_identifiers(upper, out);
            }
            InvariantAST::ForAll { expr, .. } => self.collect_identifiers(expr, out),
            InvariantAST::Set(values) => {
                for value in values {
                    self.collect_identifiers(value, out);
                }
            }
            _ => {}
        }
    }

    fn extract_bit_length(&self, relation: &str) -> Option<u32> {
        if let Some(pos) = relation.find("2^") {
            let suffix = &relation[pos + 2..];
            let digits: String = suffix.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() {
                if let Ok(value) = digits.parse::<u32>() {
                    return Some(value);
                }
            } else if suffix.starts_with("bit_length") {
                if let Some(value) = self
                    .config
                    .campaign
                    .parameters
                    .additional
                    .get("bit_length")
                    .and_then(|v| v.as_u64())
                {
                    return Some(value as u32);
                }
            }
        }

        let traits = self.config.get_target_traits();
        for entry in traits.range_checks {
            let entry = entry.to_lowercase();
            if let Some(bits) = entry.strip_prefix("bitlen:") {
                if let Ok(value) = bits.parse::<u32>() {
                    return Some(value);
                }
            }
            if entry == "u64" {
                return Some(64);
            }
            if entry == "u32" {
                return Some(32);
            }
            if entry == "u8" {
                return Some(8);
            }
        }

        None
    }

    fn normalize_input_name(raw: &str) -> String {
        raw.trim()
            .split('[')
            .next()
            .unwrap_or(raw)
            .trim()
            .to_string()
    }

    fn violation_from_ast(
        &self,
        ast: &crate::config::v2::InvariantAST,
        invariant: &crate::config::v2::Invariant,
    ) -> Option<FieldElement> {
        use crate::config::v2::InvariantAST;

        match ast {
            InvariantAST::ForAll { expr, .. } => self.violation_from_ast(expr, invariant),
            InvariantAST::InSet(_, set) => self.violation_from_in_set(set),
            InvariantAST::Range {
                lower,
                upper,
                inclusive_lower,
                inclusive_upper,
                ..
            } => self.violation_from_range(lower, upper, *inclusive_lower, *inclusive_upper),
            InvariantAST::LessThan(_, rhs) => self.violation_from_comparison(rhs, false, false),
            InvariantAST::LessThanOrEqual(_, rhs) => {
                self.violation_from_comparison(rhs, false, true)
            }
            InvariantAST::GreaterThan(_, rhs) => self.violation_from_comparison(rhs, true, false),
            InvariantAST::GreaterThanOrEqual(_, rhs) => {
                self.violation_from_comparison(rhs, true, true)
            }
            InvariantAST::Equals(_, rhs) => self.violation_from_not_equal(rhs),
            InvariantAST::NotEquals(_, rhs) => self.violation_from_equal(rhs),
            _ => None,
        }
    }

    fn violation_from_in_set(&self, set: &crate::config::v2::InvariantAST) -> Option<FieldElement> {
        use crate::config::v2::InvariantAST;

        if let InvariantAST::Set(values) = set {
            let mut has_zero = false;
            let mut has_one = false;
            for value in values {
                if let Some(num) = self.eval_expr_to_u64(value) {
                    if num == 0 {
                        has_zero = true;
                    } else if num == 1 {
                        has_one = true;
                    }
                }
            }
            if has_zero && has_one {
                return Some(FieldElement::from_u64(2));
            }
        }

        None
    }

    fn violation_from_range(
        &self,
        lower: &crate::config::v2::InvariantAST,
        upper: &crate::config::v2::InvariantAST,
        inclusive_lower: bool,
        inclusive_upper: bool,
    ) -> Option<FieldElement> {
        if let Some(upper_val) = self.eval_expr_to_u64(upper) {
            if inclusive_upper {
                return Some(FieldElement::from_u64(upper_val.saturating_add(1)));
            }
            return Some(FieldElement::from_u64(upper_val));
        }

        if let Some(lower_val) = self.eval_expr_to_u64(lower) {
            let val = if inclusive_lower {
                lower_val.saturating_sub(1)
            } else {
                lower_val
            };
            return Some(FieldElement::from_u64(val));
        }

        Some(FieldElement::max_value())
    }

    fn violation_from_comparison(
        &self,
        rhs: &crate::config::v2::InvariantAST,
        is_greater: bool,
        inclusive: bool,
    ) -> Option<FieldElement> {
        if let Some(bound) = self.eval_expr_to_u64(rhs) {
            if is_greater {
                let value = if inclusive {
                    bound.saturating_sub(1)
                } else {
                    bound
                };
                return Some(FieldElement::from_u64(value));
            }
            let value = if inclusive {
                bound.saturating_add(1)
            } else {
                bound
            };
            return Some(FieldElement::from_u64(value));
        }
        Some(FieldElement::max_value())
    }

    fn violation_from_not_equal(
        &self,
        rhs: &crate::config::v2::InvariantAST,
    ) -> Option<FieldElement> {
        let base = self.eval_expr_to_u64(rhs);
        match base {
            Some(value) => Some(FieldElement::from_u64(value.saturating_add(1))),
            None => Some(FieldElement::max_value()),
        }
    }

    fn violation_from_equal(&self, rhs: &crate::config::v2::InvariantAST) -> Option<FieldElement> {
        if let Some(value) = self.eval_expr_to_u64(rhs) {
            return Some(FieldElement::from_u64(value));
        }
        None
    }

    fn eval_expr_to_u64(&self, expr: &crate::config::v2::InvariantAST) -> Option<u64> {
        use crate::config::v2::InvariantAST;

        match expr {
            InvariantAST::Literal(value) => self.parse_u64_literal(value),
            InvariantAST::Power(base, exp) => {
                if base.trim() != "2" {
                    return None;
                }
                if let Some(bits) = self.parse_u64_literal(exp) {
                    if bits <= 63 {
                        return Some(1u64 << bits);
                    }
                }
                None
            }
            InvariantAST::Identifier(name) if name.trim().eq_ignore_ascii_case("bit_length") => {
                self.config
                    .campaign
                    .parameters
                    .additional
                    .get("bit_length")
                    .and_then(|v| v.as_u64())
            }
            _ => None,
        }
    }

    fn parse_u64_literal(&self, raw: &str) -> Option<u64> {
        let trimmed = raw.trim().to_lowercase();
        if trimmed.starts_with("0x") {
            return u64::from_str_radix(trimmed.trim_start_matches("0x"), 16).ok();
        }
        if let Some(expr) = trimmed.strip_prefix("2^") {
            let expr = expr.trim();
            if let Some(exp) = expr
                .strip_suffix("-1")
                .or_else(|| expr.strip_suffix(" - 1"))
            {
                if let Ok(bits) = exp.trim().parse::<u32>() {
                    if bits <= 63 {
                        return Some((1u64 << bits).saturating_sub(1));
                    }
                }
                return None;
            }
            if let Ok(bits) = expr.trim().parse::<u32>() {
                if bits <= 63 {
                    return Some(1u64 << bits);
                }
            }
        }
        trimmed.parse::<u64>().ok()
    }

    fn parse_transform(
        &self,
        transform: &str,
        input_map: &std::collections::HashMap<String, usize>,
    ) -> Option<crate::attacks::metamorphic::Transform> {
        use crate::attacks::metamorphic::Transform;

        let raw = transform.trim();
        if raw.eq_ignore_ascii_case("swap_sibling_order") {
            let candidate = ["pathindices", "path_indices", "pathindex", "indices"];
            for name in candidate {
                if let Some(idx) = input_map.get(name) {
                    return Some(Transform::BitFlipInput {
                        index: *idx,
                        bit_position: 0,
                    });
                }
            }
        }

        let (name, args) = Self::parse_call(raw)?;

        match name.as_str() {
            "scale_input" => {
                let (input_name, factor) = Self::parse_two_args(&args)?;
                let (input_name, _) = Self::parse_transform_target(&input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                let factor = Self::parse_field_element(&factor)?;
                Some(Transform::ScaleInputs {
                    indices: vec![*idx],
                    factor,
                })
            }
            "add_input" => {
                let (input_name, value) = Self::parse_two_args(&args)?;
                let (input_name, _) = Self::parse_transform_target(&input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                let value = Self::parse_field_element(&value)?;
                Some(Transform::AddToInputs {
                    indices: vec![*idx],
                    value,
                })
            }
            "negate_input" => {
                let input_name = args.first()?;
                let (input_name, _) = Self::parse_transform_target(input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                Some(Transform::NegateInputs {
                    indices: vec![*idx],
                })
            }
            "swap_inputs" => {
                let (left, right) = Self::parse_two_args(&args)?;
                let (left, _) = Self::parse_transform_target(&left);
                let (right, _) = Self::parse_transform_target(&right);
                let a = input_map.get(&Self::normalize_input_name(&left).to_lowercase())?;
                let b = input_map.get(&Self::normalize_input_name(&right).to_lowercase())?;
                Some(Transform::SwapInputs {
                    index_a: *a,
                    index_b: *b,
                })
            }
            "bit_flip" => {
                let (input_name, bit) = Self::parse_two_args(&args)?;
                let (input_name, _) = Self::parse_transform_target(&input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                let bit_position = bit.parse::<usize>().ok()?;
                Some(Transform::BitFlipInput {
                    index: *idx,
                    bit_position,
                })
            }
            "double_input" => {
                let input_name = args.first()?;
                let (input_name, _) = Self::parse_transform_target(input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                Some(Transform::DoubleInput { index: *idx })
            }
            "set_input" => {
                let (input_name, value) = if args.len() == 1 {
                    if let Some((left, right)) = args[0].split_once('=') {
                        (left.trim().to_string(), right.trim().to_string())
                    } else {
                        Self::parse_two_args(&args)?
                    }
                } else {
                    Self::parse_two_args(&args)?
                };
                let (input_name, _) = Self::parse_transform_target(&input_name);
                let idx = input_map.get(&Self::normalize_input_name(&input_name).to_lowercase())?;
                let value = Self::parse_field_element(&value)?;
                let mut assignments = std::collections::HashMap::new();
                assignments.insert(*idx, value);
                Some(Transform::SetInputs { assignments })
            }
            _ => None,
        }
    }

    fn parse_expected_behavior(
        &self,
        expected: Option<&str>,
    ) -> crate::attacks::metamorphic::ExpectedBehavior {
        use crate::attacks::metamorphic::ExpectedBehavior;

        let Some(raw) = expected else {
            return ExpectedBehavior::OutputChanged;
        };
        let lower = raw.trim().to_lowercase();

        if lower.contains("output_unchanged") || lower.contains("unchanged") {
            return ExpectedBehavior::OutputUnchanged;
        }
        if lower.contains("output_changes")
            || lower.contains("output_changed")
            || lower.contains("changes")
        {
            return ExpectedBehavior::OutputChanged;
        }
        if let Some(arg) = lower
            .strip_prefix("output_scaled(")
            .and_then(|s| s.strip_suffix(')'))
        {
            if let Some(factor) = Self::parse_field_element(arg) {
                return ExpectedBehavior::OutputScaled(factor);
            }
        }
        if lower.contains("reject") {
            return ExpectedBehavior::ShouldReject;
        }
        if lower.contains("accept") {
            return ExpectedBehavior::ShouldAccept;
        }

        ExpectedBehavior::Custom(raw.to_string())
    }

    fn parse_call(raw: &str) -> Option<(String, Vec<String>)> {
        let open = raw.find('(')?;
        let close = raw.rfind(')')?;
        if close <= open {
            return None;
        }
        let name = raw[..open].trim().to_lowercase();
        let args = raw[open + 1..close]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Some((name, args))
    }

    fn parse_two_args(args: &[String]) -> Option<(String, String)> {
        if args.len() < 2 {
            return None;
        }
        Some((args[0].clone(), args[1].clone()))
    }

    fn parse_transform_target(raw: &str) -> (String, Option<usize>) {
        let trimmed = raw.trim();
        if let Some(start) = trimmed.find('[') {
            if trimmed.ends_with(']') {
                let base = trimmed[..start].trim();
                let index = trimmed[start + 1..trimmed.len() - 1].trim();
                let parsed = index.parse::<usize>().ok();
                return (base.to_string(), parsed);
            }
        }
        (trimmed.to_string(), None)
    }

    fn parse_field_element(raw: &str) -> Option<FieldElement> {
        let trimmed = raw.trim();
        let lower = trimmed.to_lowercase();

        if lower == "p-1" || lower == "max" || lower == "max_field" {
            return Some(FieldElement::max_value());
        }
        if lower == "(p-1)/2" {
            return Some(FieldElement::half_modulus());
        }

        if lower.starts_with("0x") {
            return FieldElement::from_hex(trimmed).ok();
        }

        if let Some(exp) = lower.strip_prefix("2^") {
            let exp = exp.trim();
            if let Some(exp) = exp.strip_suffix("-1").or_else(|| exp.strip_suffix(" - 1")) {
                if let Ok(bits) = exp.trim().parse::<u32>() {
                    if bits <= 63 {
                        return Some(FieldElement::from_u64((1u64 << bits).saturating_sub(1)));
                    }
                }
                return Some(FieldElement::max_value());
            }

            if let Ok(bits) = exp.parse::<u32>() {
                if bits <= 63 {
                    return Some(FieldElement::from_u64(1u64 << bits));
                }
            }
            return Some(FieldElement::max_value());
        }

        trimmed.parse::<u64>().ok().map(FieldElement::from_u64)
    }

    fn severity_from_invariant(&self, invariant: &crate::config::v2::Invariant) -> Severity {
        match invariant.severity.as_deref().map(|s| s.to_lowercase()) {
            Some(ref s) if s == "critical" => Severity::Critical,
            Some(ref s) if s == "high" => Severity::High,
            Some(ref s) if s == "medium" => Severity::Medium,
            Some(ref s) if s == "low" => Severity::Low,
            Some(ref s) if s == "info" => Severity::Info,
            _ => match invariant.invariant_type {
                crate::config::v2::InvariantType::Range => Severity::High,
                crate::config::v2::InvariantType::Uniqueness => Severity::Critical,
                crate::config::v2::InvariantType::Metamorphic => Severity::High,
                _ => Severity::Medium,
            },
        }
    }

    // ========================================================================
    // Mode 3: Multi-Step Chain Fuzzing
    // ========================================================================

    /// Run multi-step chain fuzzing (Mode 3: Deepest)
    ///
    /// Executes chain specifications to find vulnerabilities that only
    /// manifest through specific sequences of circuit operations.
    pub async fn run_chains(
        &mut self,
        chains: &[crate::chain_fuzzer::ChainSpec],
        progress: Option<&ProgressReporter>,
    ) -> Vec<crate::chain_fuzzer::ChainFinding> {
        use crate::chain_fuzzer::{
            ChainCorpus, ChainFinding, ChainMutator, ChainRunner, ChainScheduler, ChainShrinker,
            CrossStepInvariantChecker, DepthMetrics,
        };
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::time::{Duration, Instant};

        if chains.is_empty() {
            tracing::info!("No chain specifications provided");
            return Vec::new();
        }

        tracing::info!("Starting Mode 3 chain fuzzing with {} chains", chains.len());

        // Get chain fuzzing budget from config
        let additional = &self.config.campaign.parameters.additional;
        let chain_budget_secs =
            Self::additional_u64(additional, "chain_budget_seconds").unwrap_or(300);
        let chain_iterations =
            Self::additional_u64(additional, "chain_iterations").unwrap_or(1000) as usize;

        // CRITICAL FIX: Check strict_backend for chain circuit loading
        let strict_backend = Self::additional_bool(additional, "strict_backend").unwrap_or(false);

        // Build executor map from circuit configurations
        let mut executors = std::collections::HashMap::new();

        // Collect all circuit_refs and their path configurations from chains
        let circuit_configs = self.collect_circuit_configs(chains);

        // Load an executor for each unique circuit_ref
        for (circuit_ref, path_config) in &circuit_configs {
            let executor = match path_config {
                Some(config) => {
                    // Load the circuit from the specified path
                    let framework = config
                        .framework
                        .unwrap_or(self.config.campaign.target.framework);
                    let main_component = config
                        .main_component
                        .clone()
                        .unwrap_or_else(|| circuit_ref.clone());

                    match crate::executor::ExecutorFactory::create_with_options(
                        framework,
                        config.path.to_str().unwrap_or(""),
                        &main_component,
                        &self.executor_factory_options,
                    ) {
                        Ok(exec) => exec,
                        Err(e) => {
                            // CRITICAL FIX: Fail in strict_backend mode instead of silent fallback
                            if strict_backend {
                                tracing::error!(
                                    "CHAIN CIRCUIT LOAD FAILED: Circuit '{}' at {:?} failed to load: {}. \
                                     In strict_backend mode, we cannot fall back to primary executor. \
                                     All findings would be against the wrong circuit.",
                                    circuit_ref, config.path, e
                                );
                                return Vec::new(); // Return empty findings - chain fuzzing cannot proceed
                            }
                            tracing::warn!(
                                "Failed to load executor for circuit '{}' at {:?}: {}. Using primary executor.",
                                circuit_ref, config.path, e
                            );
                            self.executor.clone()
                        }
                    }
                }
                None => {
                    if std::path::Path::new(circuit_ref).exists() {
                        match crate::executor::ExecutorFactory::create_with_options(
                            self.config.campaign.target.framework,
                            circuit_ref,
                            circuit_ref,
                            &self.executor_factory_options,
                        ) {
                            Ok(exec) => exec,
                            Err(e) => {
                                // CRITICAL FIX: Fail in strict_backend mode instead of silent fallback
                                if strict_backend {
                                    tracing::error!(
                                        "CHAIN CIRCUIT LOAD FAILED: Circuit '{}' failed to load: {}. \
                                         In strict_backend mode, we cannot fall back to primary executor.",
                                        circuit_ref, e
                                    );
                                    return Vec::new();
                                }
                                tracing::warn!(
                                    "Failed to load circuit '{}' from path: {}. Falling back to primary executor.",
                                    circuit_ref, e
                                );
                                self.executor.clone()
                            }
                        }
                    } else {
                        // CRITICAL FIX: Fail in strict_backend mode instead of silent fallback
                        if strict_backend {
                            tracing::error!(
                                "CHAIN CIRCUIT MISSING: No circuit path configured for '{}' and no file found. \
                                 In strict_backend mode, we cannot fall back to primary executor. \
                                 Add a 'circuits' mapping in your chain config to specify circuit paths.",
                                circuit_ref
                            );
                            return Vec::new();
                        }
                        tracing::warn!(
                            "No circuit path configured for '{}' and no file found at that path. \
                             Using primary executor. Add a 'circuits' mapping in your chain config \
                             to load distinct circuits per step.",
                            circuit_ref
                        );
                        self.executor.clone()
                    }
                }
            };
            executors.insert(circuit_ref.clone(), executor);
        }

        let runner = ChainRunner::new(executors).with_timeout(Duration::from_secs(30));
        let mutator = ChainMutator::new();

        // Initialize scheduler with budget
        let scheduler =
            ChainScheduler::new(chains.to_vec(), Duration::from_secs(chain_budget_secs));

        // Initialize corpus for persistence
        let output_dir = self.config.reporting.output_dir.clone();
        let corpus_path = std::path::PathBuf::from(&output_dir).join("chain_corpus.json");
        let mut corpus = ChainCorpus::load(&corpus_path)
            .unwrap_or_else(|_| ChainCorpus::with_storage(&corpus_path));

        let mut all_findings = Vec::new();
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed.unwrap_or(42));

        // Optional seed inputs for chain fuzzing (reuse evidence seed inputs if provided)
        let seed_inputs_path = Self::additional_string(
            &self.config.campaign.parameters.additional,
            "seed_inputs_path",
        );
        let seed_inputs = match seed_inputs_path {
            Some(path) => match self.load_seed_inputs_from_path(&path) {
                Ok(seeds) => seeds,
                Err(e) => {
                    tracing::warn!("Failed to load chain seed inputs from {}: {}", path, e);
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        let mut seed_index: usize = 0;

        // Run chains according to schedule
        let allocations = scheduler.allocate();

        for allocation in &allocations {
            let chain = &allocation.spec;
            let chain_budget = allocation.budget;
            let chain_start = Instant::now();

            if let Some(p) = progress {
                p.log_message(&format!(
                    "Chain: {} (budget: {:?})",
                    chain.name, chain_budget
                ));
            }

            // Initial inputs (seeded if available; otherwise generated fresh)
            let mut current_inputs = std::collections::HashMap::new();
            if !seed_inputs.is_empty() {
                if let Some(first_step) = chain.steps.first() {
                    if let Some(executor) = runner.executors.get(&first_step.circuit_ref) {
                        let expected = executor.num_private_inputs() + executor.num_public_inputs();
                        let seed = &seed_inputs[seed_index % seed_inputs.len()];
                        if seed.len() >= expected {
                            current_inputs
                                .insert(first_step.circuit_ref.clone(), seed[..expected].to_vec());
                        } else {
                            tracing::warn!(
                                "Seed input too short for circuit '{}': expected {}, got {}",
                                first_step.circuit_ref,
                                expected,
                                seed.len()
                            );
                        }
                    }
                }
                seed_index = seed_index.wrapping_add(1);
            }
            let mut iterations = 0;
            let mut current_spec: Option<crate::chain_fuzzer::ChainSpec> = None;

            while chain_start.elapsed() < chain_budget && iterations < chain_iterations {
                let spec_to_use = current_spec.as_ref().unwrap_or(chain);

                // Execute chain
                let result = runner.execute(spec_to_use, &current_inputs, &mut rng);

                if result.completed {
                    // Rebuild checker if spec was mutated
                    let active_checker = if current_spec.is_some() {
                        CrossStepInvariantChecker::from_spec(spec_to_use)
                    } else {
                        CrossStepInvariantChecker::from_spec(chain)
                    };

                    let violations = active_checker.check(&result.trace);

                    for violation in violations {
                        let shrinker = ChainShrinker::new(
                            ChainRunner::new(runner.executors.clone()),
                            CrossStepInvariantChecker::from_spec(spec_to_use),
                        )
                        .with_seed(self.seed.unwrap_or(42));

                        let shrink_result =
                            shrinker.minimize(spec_to_use, &current_inputs, &violation);

                        let finding = Finding {
                            attack_type: AttackType::CircuitComposition,
                            severity: match violation.severity.to_lowercase().as_str() {
                                "critical" => Severity::Critical,
                                "high" => Severity::High,
                                "medium" => Severity::Medium,
                                "low" => Severity::Low,
                                _ => Severity::High,
                            },
                            description: format!(
                                "[Chain: {} | L_min: {}] {}: {}",
                                chain.name,
                                shrink_result.l_min,
                                violation.assertion_name,
                                violation.description
                            ),
                            poc: ProofOfConcept {
                                witness_a: result
                                    .trace
                                    .steps
                                    .first()
                                    .map(|s| s.inputs.clone())
                                    .unwrap_or_default(),
                                witness_b: result.trace.steps.get(1).map(|s| s.inputs.clone()),
                                public_inputs: vec![],
                                proof: None,
                            },
                            location: Some(format!("chain:{}", chain.name)),
                        };

                        let chain_finding = ChainFinding::new(
                            finding,
                            spec_to_use.len(),
                            shrink_result.l_min,
                            result.trace.clone(),
                            &chain.name,
                        )
                        .with_violated_assertion(&violation.assertion_name);

                        all_findings.push(chain_finding);

                        if let Some(p) = progress {
                            p.log_finding(
                                &violation.severity.to_uppercase(),
                                &format!(
                                    "Chain violation: {} (L_min={})",
                                    violation.assertion_name, shrink_result.l_min
                                ),
                            );
                        }
                    }

                    let coverage_bits = Self::compute_chain_coverage_bits(&result.trace);
                    corpus.add(crate::chain_fuzzer::ChainCorpusEntry::new(
                        &chain.name,
                        current_inputs.clone(),
                        coverage_bits,
                        result.trace.depth(),
                    ));
                }

                // Mutate for next iteration (may produce a modified spec)
                let mutation = mutator.mutate(spec_to_use, &current_inputs, &mut rng);
                current_inputs = mutation.inputs;
                current_spec = mutation.spec;
                iterations += 1;

                if let Some(p) = progress {
                    p.inc();
                }
            }

            tracing::info!(
                "Chain {} completed: {} iterations, {} findings",
                chain.name,
                iterations,
                all_findings
                    .iter()
                    .filter(|f| f.spec_name == chain.name)
                    .count()
            );
        }

        // Save corpus
        if let Err(e) = corpus.save() {
            tracing::warn!("Failed to save chain corpus: {}", e);
        }

        // Compute and log metrics
        let metrics = DepthMetrics::new(all_findings.clone());
        let summary = metrics.summary();
        tracing::info!(
            "Chain fuzzing complete: {} findings, D={:.2}, P_deep={:.2}%",
            summary.total_findings,
            summary.d_mean,
            summary.p_deep * 100.0
        );

        all_findings
    }

    /// Collect circuit configurations from all chain specs
    /// Returns a map of circuit_ref -> optional path configuration
    fn collect_circuit_configs(
        &self,
        chains: &[crate::chain_fuzzer::ChainSpec],
    ) -> std::collections::HashMap<String, Option<crate::config::v2::CircuitPathConfig>> {
        use std::collections::HashMap;

        let mut circuit_configs: HashMap<String, Option<crate::config::v2::CircuitPathConfig>> =
            HashMap::new();

        // First, collect all unique circuit_refs from chains
        for chain in chains {
            for step in &chain.steps {
                circuit_configs
                    .entry(step.circuit_ref.clone())
                    .or_insert(None);
            }
        }

        // Then, look up path configurations from the config's chains
        for chain_config in &self.config.chains {
            for (ref_name, path_config) in &chain_config.circuits {
                if circuit_configs.contains_key(ref_name) {
                    circuit_configs.insert(ref_name.clone(), Some(path_config.clone()));
                }
            }
        }

        circuit_configs
    }

    /// Compute coverage bits from a chain trace
    /// Combines coverage from all steps into a single u64 hash
    fn compute_chain_coverage_bits(trace: &crate::chain_fuzzer::ChainTrace) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        for step in &trace.steps {
            // Hash the constraints hit in each step
            let mut constraints: Vec<_> = step.constraints_hit.iter().copied().collect();
            constraints.sort_unstable();

            for constraint_id in constraints {
                constraint_id.hash(&mut hasher);
            }

            // Also factor in step success and circuit ref
            step.success.hash(&mut hasher);
            step.circuit_ref.hash(&mut hasher);
        }

        hasher.finish()
    }
}
