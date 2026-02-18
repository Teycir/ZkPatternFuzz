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
mod chain_runner;
mod config_helpers;
mod continuous_fuzzer;
mod corpus_manager;
mod invariant_enforcer;
mod metamorphic_helpers;
mod report_generator;

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
    /// ```rust,no_run
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
    fn with_findings_write<R>(
        &self,
        apply: impl FnOnce(&mut Vec<Finding>) -> R,
    ) -> anyhow::Result<R> {
        let findings_store = self.core.findings();
        let mut store = findings_store.write();
        Ok(apply(&mut store))
    }

    fn with_findings_read<R>(&self, apply: impl FnOnce(&Vec<Finding>) -> R) -> anyhow::Result<R> {
        let findings_store = self.core.findings();
        let store = findings_store.read();
        Ok(apply(&store))
    }

    fn select_executable_witness_for_pattern_finding(
        &mut self,
        max_attempts: usize,
    ) -> Option<Vec<FieldElement>> {
        let attempts = max_attempts.max(1);

        for inputs in self.collect_corpus_inputs(attempts) {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping pattern witness selection early: wall-clock timeout reached"
                );
                return None;
            }
            let result = self.executor.execute_sync(&inputs);
            if result.success {
                return Some(inputs);
            }
        }

        for _ in 0..attempts {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping pattern witness probing early: wall-clock timeout reached"
                );
                return None;
            }
            let candidate = self.generate_test_case().inputs;
            let result = self.executor.execute_sync(&candidate);
            if result.success {
                return Some(candidate);
            }
        }

        None
    }

    fn record_scan_pattern_findings(
        &mut self,
        progress: Option<&ProgressReporter>,
        evidence_mode: bool,
    ) -> anyhow::Result<usize> {
        let Some(summary_text) = self
            .config
            .campaign
            .parameters
            .additional
            .get_string("scan_pattern_summary_text")
        else {
            return Ok(0);
        };

        let pattern_lines: Vec<String> = summary_text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if pattern_lines.is_empty() {
            return Ok(0);
        }

        let Some(witness) = self.select_executable_witness_for_pattern_finding(64) else {
            tracing::warn!(
                "Pattern selectors matched ({}), but no executable witness was available \
                 to materialize evidence-grade findings.",
                pattern_lines.len()
            );
            return Ok(0);
        };

        let mut inserted = 0usize;
        self.with_findings_write(|store| {
            for line in &pattern_lines {
                let finding = Finding {
                    // Keep static CVE-pattern hits separate from dynamic attack families.
                    // This avoids false differential-oracle rejection in evidence mode.
                    attack_type: AttackType::ZkEvm,
                    severity: Severity::Info,
                    description: format!("Static pattern match: {}", line),
                    poc: ProofOfConcept {
                        witness_a: witness.clone(),
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: Some(
                        self.config
                            .campaign
                            .target
                            .circuit_path
                            .display()
                            .to_string(),
                    ),
                };
                store.push(finding.clone());
                if let Some(p) = progress {
                    p.log_finding("INFO", &finding.description);
                }
                inserted += 1;
            }
        })?;

        if inserted > 0 {
            let mode = if evidence_mode { "evidence" } else { "run" };
            tracing::info!(
                "Recorded {} static regex-pattern findings in {} mode",
                inserted,
                mode
            );
        }
        Ok(inserted)
    }

    fn configure_wall_clock_deadline(&mut self, start_time: Instant) -> Option<u64> {
        let timeout_seconds = self
            .config
            .campaign
            .parameters
            .additional
            .get("fuzzing_timeout_seconds")
            .and_then(|v| v.as_u64());

        self.wall_clock_deadline = timeout_seconds.and_then(|seconds| {
            let bounded = seconds.max(1);
            start_time.checked_add(Duration::from_secs(bounded))
        });

        if let Some(seconds) = timeout_seconds {
            if self.wall_clock_deadline.is_some() {
                tracing::info!(
                    "Global wall-clock timeout enabled for this run: {}s",
                    seconds.max(1)
                );
            } else {
                tracing::warn!(
                    "Failed to configure global wall-clock timeout from {}s (overflow)",
                    seconds
                );
            }
        }

        timeout_seconds
    }

    pub(super) fn wall_clock_timeout_reached(&self) -> bool {
        self.wall_clock_deadline
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(false)
    }

    pub(super) fn wall_clock_remaining(&self) -> Option<Duration> {
        self.wall_clock_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    pub async fn run(&mut self, progress: Option<&ProgressReporter>) -> anyhow::Result<FuzzReport> {
        let start_time = Instant::now();
        self.core.set_start_time(start_time);
        let _configured_wall_clock_timeout = self.configure_wall_clock_deadline(start_time);

        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);
        // Engagement contract: in evidence mode, fail fast on misconfiguration that would cause
        // patterns/attacks to be silently skipped.
        let engagement_strict =
            Self::additional_bool(additional, "engagement_strict").unwrap_or(evidence_mode);
        let mode_label = if evidence_mode { "evidence" } else { "run" };
        let phases_total = 1u64
            .saturating_add(self.config.attacks.len() as u64)
            .saturating_add(1)
            .saturating_add(1); // seeded_corpus + attacks + continuous + reporting

        tracing::warn!(
            "MILESTONE start mode={} target={} circuit={} output_dir={}",
            mode_label,
            self.config.campaign.name,
            self.config.campaign.target.circuit_path.display(),
            self.config.reporting.output_dir.display()
        );
        self.write_progress_snapshot(
            mode_label,
            "start",
            phases_total,
            0,
            None,
            serde_json::json!({}),
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
                for finding in &taint_findings {
                    if let Some(p) = progress {
                        p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                    }
                }
                self.with_findings_write(|store| store.extend(taint_findings))?;
            }
        }

        // Run source code analysis for vulnerability hints
        self.run_source_analysis(progress);

        // Seed corpus with external inputs if provided
        if let Err(err) = self.seed_external_inputs_from_config() {
            tracing::warn!("Failed to load external seed inputs: {}", err);
        }

        // Phase 0: Load resume corpus if --resume was specified
        match self.maybe_load_resume_corpus() {
            Ok(count) if count > 0 => {
                tracing::info!("Resumed from {} previous test cases", count);
            }
            Err(err) => {
                tracing::warn!("Failed to load resume corpus: {}", err);
            }
            _ => {}
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
        self.write_progress_snapshot(
            mode_label,
            "seeded_corpus",
            phases_total,
            1,
            None,
            serde_json::json!({
                "corpus_len": self.core.corpus().len(),
            }),
        );

        // Regex selector hits are static CVE-pattern evidence. Record them as findings
        // with executable witness context so they survive evidence-mode validation.
        let pattern_findings = self.record_scan_pattern_findings(progress, evidence_mode)?;
        if pattern_findings > 0 {
            tracing::warn!(
                "MILESTONE pattern_findings target={} count={}",
                self.config.campaign.name,
                pattern_findings
            );
        }

        // Initialize simple progress tracker for non-interactive environments
        self.simple_tracker = Some(SimpleProgressTracker::new());

        // Update power scheduler with initial global stats
        self.update_power_scheduler_globals();

        // Run attacks
        let attacks_total = self.config.attacks.len() as u64;
        let run_id_for_snapshots =
            Self::additional_string(&self.config.campaign.parameters.additional, "run_id");
        let command_for_snapshots = match Self::additional_string(
            &self.config.campaign.parameters.additional,
            "run_command",
        ) {
            Some(value) => value,
            None => {
                if mode_label == "evidence" {
                    "evidence".to_string()
                } else {
                    "run".to_string()
                }
            }
        };

        struct _StopAttackHeartbeat(tokio::sync::watch::Sender<bool>);
        impl Drop for _StopAttackHeartbeat {
            fn drop(&mut self) {
                if let Err(err) = self.0.send(true) {
                    tracing::warn!("Failed to stop attack progress heartbeat: {}", err);
                }
            }
        }

        let mut wall_clock_timed_out = false;
        for (attack_idx, attack_config) in self.config.attacks.clone().into_iter().enumerate() {
            if self.wall_clock_timeout_reached() {
                wall_clock_timed_out = true;
                let phases_completed = 1u64.saturating_add(attack_idx as u64);
                tracing::warn!(
                    "Global wall-clock timeout reached before attack {:?}; ending run early",
                    attack_config.attack_type
                );
                self.write_progress_snapshot(
                    mode_label,
                    "timeout_reached",
                    phases_total,
                    phases_completed,
                    Some(0.0),
                    serde_json::json!({
                        "reason": "wall_clock_timeout",
                        "elapsed_seconds": start_time.elapsed().as_secs_f64(),
                        "remaining_seconds": self.wall_clock_remaining().map(|d| d.as_secs_f64()),
                        "next_attack_type": format!("{:?}", attack_config.attack_type),
                    }),
                );
                break;
            }

            let phases_completed = 1u64.saturating_add(attack_idx as u64);
            self.write_progress_snapshot(
                mode_label,
                "attack_start",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "attack_idx": attack_idx,
                    "attacks_total": attacks_total,
                    "attack_type": format!("{:?}", attack_config.attack_type),
                }),
            );
            tracing::warn!(
                "MILESTONE attack_start target={} type={:?}",
                self.config.campaign.name,
                attack_config.attack_type
            );
            if let Some(p) = progress {
                p.log_attack_start(&format!("{:?}", attack_config.attack_type));
            }

            // Keep machine-readable progress alive for long-running attacks that do not
            // emit internal progress updates (e.g. non-SpecInference attacks).
            let _attack_heartbeat_guard =
                if !matches!(attack_config.attack_type, AttackType::SpecInference) {
                    let (hb_stop_tx, mut hb_stop_rx) = tokio::sync::watch::channel(false);
                    let output_dir = self.config.reporting.output_dir.clone();
                    let campaign_name = self.config.campaign.name.clone();
                    let mode_label_owned = mode_label.to_string();
                    let command_owned = command_for_snapshots.clone();
                    let run_id_owned = run_id_for_snapshots.clone();
                    let attack_idx_u64 = attack_idx as u64;
                    let attack_type_label = format!("{:?}", attack_config.attack_type);

                    tokio::spawn(async move {
                        let heartbeat_start = std::time::Instant::now();
                        let progress_path = output_dir.join("progress.json");
                        loop {
                            if *hb_stop_rx.borrow() {
                                break;
                            }

                            tokio::select! {
                                _ = hb_stop_rx.changed() => {},
                                _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {},
                            }

                            if *hb_stop_rx.borrow() {
                                break;
                            }

                            let now_epoch = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            let overall = if phases_total == 0 {
                                0.0
                            } else {
                                (phases_completed as f64 / phases_total as f64).clamp(0.0, 1.0)
                            };
                            let steps_total = phases_total.max(1);
                            let steps_done = phases_completed.min(steps_total);
                            let step_current = (steps_done.saturating_add(1)).min(steps_total);
                            let elapsed = heartbeat_start.elapsed().as_secs();

                            let snapshot = serde_json::json!({
                                "updated_unix_seconds": now_epoch,
                                "run_id": run_id_owned.clone(),
                                "command": command_owned.clone(),
                                "mode_label": mode_label_owned.clone(),
                                "campaign_name": campaign_name.clone(),
                                "output_dir": output_dir.display().to_string(),
                                "stage": "attack_progress",
                                "progress": {
                                    "steps_total": steps_total,
                                    "steps_done": steps_done,
                                    "step_current": step_current,
                                    "step_fraction": format!("{}/{}", step_current, steps_total),
                                    "overall_fraction": overall,
                                    "overall_percent": (overall * 100.0),
                                    "phase_progress": serde_json::Value::Null,
                                },
                                "details": {
                                    "attack_idx": attack_idx_u64,
                                    "attacks_total": attacks_total,
                                    "attack_type": attack_type_label,
                                    "heartbeat": true,
                                    "elapsed_seconds": elapsed,
                                },
                            });

                            if let Some(parent) = progress_path.parent() {
                                if let Err(err) = std::fs::create_dir_all(parent) {
                                    tracing::warn!(
                                        "Failed to create attack heartbeat progress dir '{}': {}",
                                        parent.display(),
                                        err
                                    );
                                    continue;
                                }
                            }
                            let data = match serde_json::to_vec_pretty(&snapshot) {
                                Ok(data) => data,
                                Err(err) => {
                                    tracing::warn!(
                                        "Failed serializing attack heartbeat snapshot: {}",
                                        err
                                    );
                                    continue;
                                }
                            };
                            if let Err(err) = crate::util::write_file_atomic(&progress_path, &data)
                            {
                                tracing::warn!(
                                    "Failed writing attack heartbeat progress '{}': {}",
                                    progress_path.display(),
                                    err
                                );
                            }
                        }
                    });

                    Some(_StopAttackHeartbeat(hb_stop_tx))
                } else {
                    None
                };

            let findings_before = self.with_findings_read(|store| store.len())?;
            let (plugin_name, plugin_explicit) = Self::resolve_attack_plugin(&attack_config);
            let mut plugin_ran = false;
            let mut attack_executed = false;

            if let Some(name) = plugin_name.as_deref() {
                let lookup = name.trim();
                let plugin = self
                    .attack_registry
                    .get(lookup)
                    .or_else(|| self.attack_registry.get(&lookup.to_lowercase()));

                if let Some(plugin) = plugin {
                    let samples = Self::attack_samples(&attack_config.config);
                    self.add_attack_findings(plugin, samples, progress)?;
                    plugin_ran = true;
                    attack_executed = true;
                } else {
                    if plugin_explicit && engagement_strict {
                        anyhow::bail!(
                            "Engagement contract violation: attack[{}] specifies plugin '{}' \
                             but it was not found in the registry. In strict evidence mode this \
                             is a hard error because it would silently skip intended patterns.",
                            attack_idx,
                            lookup
                        );
                    }
                    tracing::warn!("Attack plugin '{}' not found in registry", lookup);
                }
            }

            if !(plugin_ran && plugin_explicit) {
                match attack_config.attack_type {
                    AttackType::Underconstrained => {
                        self.run_underconstrained_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Soundness => {
                        self.run_soundness_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::TrustedSetup => {
                        self.run_setup_poisoning_attack(
                            &attack_config.config,
                            AttackType::TrustedSetup,
                            progress,
                        )?;
                        attack_executed = true;
                    }
                    AttackType::ArithmeticOverflow => {
                        self.run_arithmetic_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Collision => {
                        self.run_collision_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Boundary => {
                        self.run_boundary_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::ConstraintBypass => {
                        self.run_canonicalization_attack(
                            &attack_config.config,
                            AttackType::ConstraintBypass,
                            progress,
                        )?;
                        attack_executed = true;
                    }
                    AttackType::Malleability => {
                        self.run_proof_malleability_attack(
                            &attack_config.config,
                            AttackType::Malleability,
                            progress,
                        )?;
                        attack_executed = true;
                    }
                    AttackType::ReplayAttack => {
                        self.run_nullifier_replay_attack(
                            &attack_config.config,
                            AttackType::ReplayAttack,
                            progress,
                        )?;
                        attack_executed = true;
                    }
                    AttackType::VerificationFuzzing => {
                        self.run_verification_fuzzing_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::WitnessFuzzing => {
                        self.run_witness_fuzzing_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Differential => {
                        self.run_differential_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::InformationLeakage => {
                        self.run_information_leakage_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::WitnessLeakage => {
                        self.run_information_leakage_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::TimingSideChannel => {
                        self.run_timing_sidechannel_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::CircuitComposition => {
                        self.run_circuit_composition_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::RecursiveProof => {
                        self.run_recursive_proof_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Mev => {
                        self.run_mev_attack(&attack_config.config, progress).await?;
                        attack_executed = true;
                    }
                    AttackType::FrontRunning => {
                        self.run_front_running_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::ZkEvm => {
                        self.run_zkevm_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::BatchVerification => {
                        self.run_batch_verification_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::SidechannelAdvanced => {
                        self.run_sidechannel_advanced_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::QuantumResistance => {
                        self.run_quantum_resistance_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::PrivacyAdvanced => {
                        self.run_privacy_advanced_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::DefiAdvanced => {
                        self.run_defi_advanced_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    // Phase 4: Novel Oracle Attacks - Now Implemented!
                    AttackType::ConstraintInference => {
                        match self
                            .run_constraint_inference_attack(&attack_config.config, progress)
                            .await
                        {
                            Ok(_) => {
                                tracing::info!(
                                    "✓ Constraint inference attack completed successfully"
                                );
                            }
                            Err(e) => {
                                tracing::error!("✗ Constraint inference attack FAILED: {}", e);
                                tracing::error!("Error details: {:?}", e);
                                if let Some(p) = progress {
                                    p.log_finding(
                                        "ERROR",
                                        &format!("Constraint inference failed: {}", e),
                                    );
                                }
                                return Err(e);
                            }
                        }
                        attack_executed = true;
                    }
                    AttackType::Metamorphic => {
                        self.run_metamorphic_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::ConstraintSlice => {
                        self.run_constraint_slice_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::SpecInference => {
                        self.run_spec_inference_attack(
                            &attack_config.config,
                            progress,
                            Some((
                                phases_total,
                                phases_completed,
                                attack_idx as u64,
                                attacks_total,
                            )),
                        )
                        .await?;
                        attack_executed = true;
                    }
                    AttackType::WitnessCollision => {
                        self.run_witness_collision_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    _ => {
                        tracing::warn!(
                            "Attack type {:?} not yet implemented",
                            attack_config.attack_type
                        );
                    }
                }
            }

            if engagement_strict && !attack_executed {
                anyhow::bail!(
                    "Engagement contract violation: attack[{}] type {:?} is configured but did not execute \
                     (unimplemented or skipped). In strict evidence mode, this run is invalid because it \
                     would silently skip attack patterns.",
                    attack_idx,
                    attack_config.attack_type
                );
            }

            let findings_after = self.with_findings_read(|store| store.len())?;
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
            let phases_completed = 1u64.saturating_add((attack_idx as u64).saturating_add(1));
            self.write_progress_snapshot(
                mode_label,
                "attack_complete",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "attack_idx": attack_idx,
                    "attacks_total": attacks_total,
                    "attack_type": format!("{:?}", attack_config.attack_type),
                    "new_findings": new_findings,
                    "total_findings": findings_after,
                }),
            );

            // Update power scheduler with current stats after each attack
            self.update_power_scheduler_globals();

            // Update simple tracker
            let current_stats = self.stats();
            if let Some(ref mut tracker) = self.simple_tracker {
                tracker.update(current_stats);
            }

            if self.wall_clock_timeout_reached() {
                wall_clock_timed_out = true;
                let phases_completed = 1u64.saturating_add((attack_idx as u64).saturating_add(1));
                tracing::warn!(
                    "Global wall-clock timeout reached after attack {:?}; ending run early",
                    attack_config.attack_type
                );
                self.write_progress_snapshot(
                    mode_label,
                    "timeout_reached",
                    phases_total,
                    phases_completed,
                    Some(0.0),
                    serde_json::json!({
                        "reason": "wall_clock_timeout",
                        "elapsed_seconds": start_time.elapsed().as_secs_f64(),
                        "remaining_seconds": self.wall_clock_remaining().map(|d| d.as_secs_f64()),
                        "last_attack_type": format!("{:?}", attack_config.attack_type),
                    }),
                );
                break;
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

        if iterations > 0 && !wall_clock_timed_out && !self.wall_clock_timeout_reached() {
            let phases_completed = 1u64.saturating_add(attacks_total);
            self.write_progress_snapshot(
                mode_label,
                "continuous_start",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "iterations": iterations,
                    "timeout_seconds": timeout,
                }),
            );
            tracing::warn!(
                "MILESTONE continuous_start target={} iterations={} timeout={:?}",
                self.config.campaign.name,
                iterations,
                timeout
            );
            self.run_continuous_fuzzing_phase(
                iterations,
                timeout,
                progress,
                mode_label,
                phases_total,
                phases_completed,
            )
            .await?;
            tracing::warn!(
                "MILESTONE continuous_complete target={}",
                self.config.campaign.name
            );
            let phases_completed = phases_completed.saturating_add(1);
            self.write_progress_snapshot(
                mode_label,
                "continuous_complete",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({}),
            );
        } else if iterations > 0 {
            tracing::warn!(
                "Skipping continuous fuzzing phase: global wall-clock timeout already reached"
            );
            let phases_completed = 1u64.saturating_add(attacks_total);
            self.write_progress_snapshot(
                mode_label,
                "continuous_skipped_timeout",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "reason": "wall_clock_timeout",
                    "elapsed_seconds": start_time.elapsed().as_secs_f64(),
                }),
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
        let mut findings = self.with_findings_read(Clone::clone)?;

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
                evidence_mode,
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
        // Reporting/evidence generation can still take time; don't mark 100% until the end.
        self.write_progress_snapshot(
            mode_label,
            "reporting",
            phases_total,
            phases_total.saturating_sub(1),
            Some(0.0),
            serde_json::json!({
                "findings_total": findings.len(),
                "duration_seconds": elapsed.as_secs_f64(),
            }),
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

        self.write_progress_snapshot(
            mode_label,
            "completed",
            phases_total,
            phases_total,
            None,
            serde_json::json!({
                "findings_total": report.findings.len(),
            }),
        );

        Ok(report)
    }
}
