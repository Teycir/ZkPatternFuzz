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

use super::oracle::{ArithmeticOverflowOracle, BugOracle, UnderconstrainedOracle};
use super::power_schedule::{PowerSchedule, PowerScheduler};
use super::structure_aware::StructureAwareMutator;
use super::mutate_field_element;
use crate::analysis::complexity::ComplexityAnalyzer;
use crate::analysis::symbolic::{SymbolicConfig, SymbolicFuzzerIntegration, VulnerabilityPattern};
use crate::analysis::taint::TaintAnalyzer;
use crate::analysis::{
    collect_input_wire_indices, ConstraintSeedGenerator, ConstraintSeedOutput,
    EnhancedSymbolicConfig, PruningStrategy,
};
use crate::attacks::{Attack as AttackTrait, AttackContext, AttackRegistry, DynamicLibraryLoader};
use crate::config::*;
use crate::corpus::create_corpus;
use crate::executor::{create_coverage_tracker, ExecutorFactory, ExecutorFactoryOptions};
use crate::progress::{FuzzingStats, ProgressReporter, SimpleProgressTracker};
use crate::reporting::FuzzReport;
use zk_core::{CircuitExecutor, ExecutionResult, FieldElement, Finding, ProofOfConcept, TestCase, TestMetadata};
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
        // Create executor based on framework (with optional build dir overrides)
        let executor_factory_options = Self::parse_executor_factory_options(&config);
        let executor = ExecutorFactory::create_with_options(
            config.campaign.target.framework,
            config.campaign.target.circuit_path.to_str().unwrap_or(""),
            &config.campaign.target.main_component,
            &executor_factory_options,
        )?;

        let num_constraints = executor.num_constraints().max(100);
        let coverage = create_coverage_tracker(num_constraints);
        let corpus = create_corpus(10000);

        // Initialize symbolic execution integration
        let num_inputs = config.inputs.len().max(1);
        let symbolic = Some(SymbolicFuzzerIntegration::new(num_inputs).with_config(
            SymbolicConfig {
                max_paths: 100,
                max_depth: 20,
                solver_timeout_ms: 2000,
                generate_boundary_tests: true,
                solutions_per_path: 2,
            },
        ));

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
                UnderconstrainedOracle::new()
                    .with_public_input_count(executor.num_public_inputs()),
            ),
            Box::new(ArithmeticOverflowOracle::new_with_modulus(
                executor.field_modulus(),
            )),
        ];
        
        // Phase 0 Fix: Wire semantic oracles from config
        Self::add_semantic_oracles_from_config(&config, &mut oracles);

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

        Ok(Self {
            config,
            executor,
            executor_factory_options,
            core,
            attack_registry,
            workers,
            symbolic,
            taint_analyzer,
            complexity_analyzer,
            simple_tracker: None,
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
    /// Phase 0 Fix: Wire semantic oracles from configuration
    /// 
    /// Instantiates nullifier/merkle/range/commitment oracles based on config.oracles
    fn add_semantic_oracles_from_config(config: &FuzzConfig, oracles: &mut Vec<Box<dyn BugOracle>>) {
        use crate::fuzzer::oracles::{
            NullifierOracle, MerkleOracle, CommitmentOracle, RangeProofOracle,
        };
        use zk_core::OracleConfig;
        use zk_fuzzer_core::oracle::SemanticOracleAdapter;
        
        let oracle_config = OracleConfig::default();
        
        for oracle_def in &config.oracles {
            let name_lower = oracle_def.name.to_lowercase();
            
            match name_lower.as_str() {
                "nullifier" | "nullifier_oracle" => {
                    tracing::info!("Enabling nullifier oracle from config");
                    oracles.push(Box::new(SemanticOracleAdapter::new(
                        Box::new(NullifierOracle::new(oracle_config.clone()))
                    )));
                }
                "merkle" | "merkle_oracle" => {
                    tracing::info!("Enabling merkle oracle from config");
                    oracles.push(Box::new(SemanticOracleAdapter::new(
                        Box::new(MerkleOracle::new(oracle_config.clone()))
                    )));
                }
                "commitment" | "commitment_oracle" => {
                    tracing::info!("Enabling commitment oracle from config");
                    oracles.push(Box::new(SemanticOracleAdapter::new(
                        Box::new(CommitmentOracle::new(oracle_config.clone()))
                    )));
                }
                "range" | "range_oracle" | "range_proof" => {
                    tracing::info!("Enabling range proof oracle from config");
                    oracles.push(Box::new(SemanticOracleAdapter::new(
                        Box::new(RangeProofOracle::new(oracle_config.clone()))
                    )));
                }
                _ => {
                    tracing::warn!("Unknown oracle type in config: {}", oracle_def.name);
                }
            }
        }
        
        // Also check for oracles in campaign parameters (alternative syntax)
        if let Some(enabled_oracles) = config.campaign.parameters.additional.get("enabled_oracles") {
            if let Some(seq) = enabled_oracles.as_sequence() {
                for item in seq {
                    if let Some(name) = item.as_str() {
                        match name.to_lowercase().as_str() {
                            "nullifier" => {
                                tracing::info!("Enabling nullifier oracle from parameters");
                                oracles.push(Box::new(SemanticOracleAdapter::new(
                                    Box::new(NullifierOracle::new(oracle_config.clone()))
                                )));
                            }
                            "merkle" => {
                                tracing::info!("Enabling merkle oracle from parameters");
                                oracles.push(Box::new(SemanticOracleAdapter::new(
                                    Box::new(MerkleOracle::new(oracle_config.clone()))
                                )));
                            }
                            "commitment" => {
                                tracing::info!("Enabling commitment oracle from parameters");
                                oracles.push(Box::new(SemanticOracleAdapter::new(
                                    Box::new(CommitmentOracle::new(oracle_config.clone()))
                                )));
                            }
                            "range" => {
                                tracing::info!("Enabling range proof oracle from parameters");
                                oracles.push(Box::new(SemanticOracleAdapter::new(
                                    Box::new(RangeProofOracle::new(oracle_config.clone()))
                                )));
                            }
                            _ => {}
                        }
                    }
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

        options
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
            serde_yaml::Value::String(s) => s.parse::<u32>().ok(),
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

        // Seed corpus
        self.seed_corpus()?;
        tracing::info!(
            "Seeded corpus with {} initial test cases",
            self.core.corpus().len()
        );

        // Initialize simple progress tracker for non-interactive environments
        self.simple_tracker = Some(SimpleProgressTracker::new());

        // Update power scheduler with initial global stats
        self.update_power_scheduler_globals();

        // Run attacks
        for attack_config in &self.config.attacks.clone() {
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
        let iterations = self.config.campaign.parameters.additional
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
        
        let timeout = self.config.campaign.parameters.additional
            .get("fuzzing_timeout_seconds")
            .and_then(|v| v.as_u64());
        
        if iterations > 0 {
            self.run_continuous_fuzzing_phase(iterations, timeout, progress).await?;
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
        let findings = self.core.findings().read().unwrap().clone();

        tracing::info!(
            "Fuzzing complete: {} findings in {:.2}s",
            findings.len(),
            elapsed.as_secs_f64()
        );

        Ok(self.generate_report(findings, elapsed.as_secs()))
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
                    generator.generate_from_r1cs(
                        &constraints,
                        &input_wire_indices,
                        expected_len,
                    )
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
        self.core.execute_and_learn(self.executor.as_ref(), test_case)
    }

    /// Run underconstrained circuit detection with parallel execution
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

        // Generate test cases
        let num_public = self.executor.num_public_inputs().min(self.config.inputs.len());
        let fixed_public = if num_public > 0 {
            let base = self.generate_test_case();
            let end = num_public.min(base.inputs.len());
            Some(base.inputs[..end].to_vec())
        } else {
            None
        };

        let test_cases: Vec<TestCase> = (0..witness_pairs)
            .map(|_| {
                let mut tc = self.generate_test_case();
                if let Some(ref public_inputs) = fixed_public {
                    let end = num_public.min(tc.inputs.len());
                    if end == public_inputs.len() {
                        tc.inputs[..end].clone_from_slice(public_inputs);
                    }
                }
                tc
            })
            .collect();

        // Execute in parallel and collect outputs
        let executor = self.executor.clone();
        let results: Vec<_> = if self.workers <= 1 {
            test_cases
                .iter()
                .map(|tc| {
                    let result = executor.execute_sync(&tc.inputs);
                    (tc.clone(), result)
                })
                .collect()
        } else {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(self.workers)
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build thread pool: {}", e))?;

            pool.install(|| {
                test_cases
                    .par_iter()
                    .map(|tc| {
                        let result = executor.execute_sync(&tc.inputs);
                        (tc.clone(), result)
                    })
                    .collect()
            })
        };

        // Group by output hash to find collisions
        let mut output_map: std::collections::HashMap<Vec<u8>, Vec<TestCase>> =
            std::collections::HashMap::new();

        for (test_case, result) in results {
            if result.success {
                let output_hash = self.hash_output(&result.outputs);
                output_map.entry(output_hash).or_default().push(test_case);
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        // Check for collisions
        for (_hash, witnesses) in output_map {
            if witnesses.len() > 1 && self.witnesses_are_different(&witnesses) {
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
            if self.executor.verify(&valid_proof, &mutated_public)? {
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
        let test_cases: Vec<TestCase> = (0..samples).map(|_| self.generate_test_case()).collect();

        let executor = self.executor.clone();
        let results: Vec<_> = if self.workers <= 1 {
            test_cases
                .iter()
                .map(|tc| {
                    let result = executor.execute_sync(&tc.inputs);
                    (tc.clone(), result)
                })
                .collect()
        } else {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(self.workers)
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build thread pool: {}", e))?;

            pool.install(|| {
                test_cases
                    .par_iter()
                    .map(|tc| {
                        let result = executor.execute_sync(&tc.inputs);
                        (tc.clone(), result)
                    })
                    .collect()
            })
        };

        let mut hash_map: std::collections::HashMap<Vec<u8>, TestCase> =
            std::collections::HashMap::new();

        for (test_case, result) in results {
            if result.success {
                let output_hash = self.hash_output(&result.outputs);

                if let Some(existing) = hash_map.get(&output_hash) {
                    if existing.inputs != test_case.inputs {
                        let finding = Finding {
                            attack_type: AttackType::Collision,
                            severity: Severity::Critical,
                            description: "Found collision: different inputs produce same output"
                                .to_string(),
                            poc: super::ProofOfConcept {
                                witness_a: existing.inputs.clone(),
                                witness_b: Some(test_case.inputs),
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
                    hash_map.insert(output_hash, test_case);
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

        for finding in findings {
            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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

        for finding in findings {
            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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
            compare_coverage: true,
            compare_proofs: false,
            timing_tolerance_percent: 50.0,
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

        let test_cases: Vec<_> = (0..num_tests)
            .map(|_| self.generate_random_test_case())
            .collect();

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

        for result in results {
            let finding = Finding {
                attack_type: AttackType::Differential,
                severity: Severity::Medium,
                description: format!("Differential discrepancy: {:?}", result.severity),
                poc: super::ProofOfConcept {
                    witness_a: result.input.clone(),
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

        for finding in findings {
            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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
        for finding in findings {
            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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
        let findings = attack.run(&context);
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

    fn witnesses_are_different(&self, witnesses: &[TestCase]) -> bool {
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
        use crate::attacks::constraint_inference::ConstraintInferenceEngine;
        use crate::config::v2::InvariantType;
        
        let confidence_threshold = config
            .get("confidence_threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.7);
        
        tracing::info!("Running constraint inference attack (confidence >= {:.0}%)", confidence_threshold * 100.0);
        
        let engine = ConstraintInferenceEngine::new()
            .with_confidence_threshold(confidence_threshold)
            .with_generate_violations(true);
        
        let findings = engine.run(self.executor.as_ref());
        
        for finding in findings {
            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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
        for finding in invariant_findings {
            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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
        
        tracing::info!("Running metamorphic testing with {} base witnesses", num_tests);
        
        let mut oracle = MetamorphicOracle::new().with_standard_relations();
        let invariant_relations = self.build_metamorphic_relations();
        for relation in invariant_relations {
            oracle = oracle.with_relation(relation);
        }
        
        // Generate base witnesses and test metamorphic relations
        for _ in 0..num_tests {
            let base_witness = self.generate_test_case();
            let results = oracle.test_all(self.executor.as_ref(), &base_witness.inputs).await;
            
            let findings = oracle.to_findings(&results);
            for finding in findings {
                self.core.findings().write().unwrap().push(finding.clone());
                if let Some(p) = progress {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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
        use crate::attacks::constraint_slice::ConstraintSliceOracle;
        
        let samples_per_cone = config
            .get("samples_per_cone")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        
        tracing::info!("Running constraint slice analysis ({} samples/cone)", samples_per_cone);
        
        let oracle = ConstraintSliceOracle::new().with_samples(samples_per_cone);
        
        // Generate a base witness
        let base_witness = self.generate_test_case();
        
        // Determine output wire indices (prefer inspector-provided outputs)
        let output_wires: Vec<usize> = if let Some(inspector) = self.executor.constraint_inspector() {
            let outputs = inspector.output_indices();
            if !outputs.is_empty() {
                outputs
            } else {
                let num_inputs = self.executor.num_public_inputs() + self.executor.num_private_inputs();
                (num_inputs..num_inputs + 5).collect()
            }
        } else {
            let num_inputs = self.executor.num_public_inputs() + self.executor.num_private_inputs();
            (num_inputs..num_inputs + 5).collect()
        };
        
        let findings = oracle.run(
            self.executor.as_ref(),
            &base_witness.inputs,
            &output_wires,
        ).await;
        
        for finding in findings {
            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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
            .with_confidence_threshold(0.9);
        
        // Generate initial witnesses
        let initial_witnesses: Vec<Vec<FieldElement>> = (0..sample_count.min(100))
            .map(|_| self.generate_test_case().inputs)
            .collect();
        
        let findings = oracle.run(self.executor.as_ref(), &initial_witnesses).await;
        
        for finding in findings {
            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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
        
        tracing::info!("Running witness collision detection ({} samples)", samples);
        
        let detector = WitnessCollisionDetector::new().with_samples(samples);
        
        // Generate witnesses
        let witnesses: Vec<Vec<FieldElement>> = (0..samples)
            .map(|_| self.generate_test_case().inputs)
            .collect();
        
        let collisions = detector.run(self.executor.as_ref(), &witnesses).await;
        let findings = detector.to_findings(&collisions);
        
        for finding in findings {
            self.core.findings().write().unwrap().push(finding.clone());
            if let Some(p) = progress {
                p.log_finding(&format!("{:?}", finding.severity), &finding.description);
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
    async fn run_continuous_fuzzing_phase(
        &mut self,
        iterations: u64,
        timeout_seconds: Option<u64>,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        let timeout = timeout_seconds.map(Duration::from_secs);
        
        tracing::info!(
            "Starting continuous fuzzing phase: {} iterations, timeout: {:?}",
            iterations,
            timeout
        );
        
        let mut completed = 0u64;
        
        while completed < iterations {
            // Check timeout
            if let Some(t) = timeout {
                if start.elapsed() >= t {
                    tracing::info!("Continuous fuzzing timeout reached after {} iterations", completed);
                    break;
                }
            }
            
            // Core fuzzing loop: select_from_corpus → mutate → execute_and_learn
            let test_case = self.generate_test_case();
            let result = self.execute_and_learn(&test_case);
            
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
                if completed % 100 == 0 {
                    p.inc();
                }
            }
            
            // Update power scheduler periodically
            if completed % 1000 == 0 {
                self.update_power_scheduler_globals();
            }
        }
        
        tracing::info!(
            "Continuous fuzzing complete: {} iterations in {:.2}s, {} findings",
            completed,
            start.elapsed().as_secs_f64(),
            self.core.findings().read().unwrap().len()
        );
        
        Ok(())
    }
    
    fn generate_report(&self, findings: Vec<Finding>, duration: u64) -> FuzzReport {
        let mut report = FuzzReport::new(
            self.config.campaign.name.clone(),
            findings,
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
        if invariants.is_empty() {
            return Vec::new();
        }

        let input_map = self.input_index_map();
        let mut relations = Vec::new();

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

        relations
    }

    fn enforce_invariants(
        &self,
        invariants: &[crate::config::v2::Invariant],
    ) -> Vec<Finding> {
        use crate::config::v2::{InvariantOracle, InvariantType};

        let input_map = self.input_index_map();
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

            let target_indices = self.extract_target_indices(&invariant.relation, &input_map);
            if target_indices.is_empty() {
                continue;
            }

            let violation_value = match self.invariant_violation_value(invariant) {
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

    fn extract_target_indices(
        &self,
        relation: &str,
        input_map: &std::collections::HashMap<String, usize>,
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
            let key = token.to_lowercase();
            if let Some(idx) = input_map.get(&key) {
                indices.push(*idx);
            }
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    fn invariant_violation_value(
        &self,
        invariant: &crate::config::v2::Invariant,
    ) -> Option<FieldElement> {
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

        let (name, args) = match Self::parse_call(raw) {
            Some(call) => call,
            None => return None,
        };

        match name.as_str() {
            "scale_input" => {
                let (input_name, factor) = Self::parse_two_args(&args)?;
                let idx = input_map.get(&input_name.to_lowercase())?;
                let factor = Self::parse_field_element(&factor)?;
                Some(Transform::ScaleInputs {
                    indices: vec![*idx],
                    factor,
                })
            }
            "add_input" => {
                let (input_name, value) = Self::parse_two_args(&args)?;
                let idx = input_map.get(&input_name.to_lowercase())?;
                let value = Self::parse_field_element(&value)?;
                Some(Transform::AddToInputs {
                    indices: vec![*idx],
                    value,
                })
            }
            "negate_input" => {
                let input_name = args.get(0)?;
                let idx = input_map.get(&input_name.to_lowercase())?;
                Some(Transform::NegateInputs { indices: vec![*idx] })
            }
            "swap_inputs" => {
                let (left, right) = Self::parse_two_args(&args)?;
                let a = input_map.get(&left.to_lowercase())?;
                let b = input_map.get(&right.to_lowercase())?;
                Some(Transform::SwapInputs {
                    index_a: *a,
                    index_b: *b,
                })
            }
            "bit_flip" => {
                let (input_name, bit) = Self::parse_two_args(&args)?;
                let idx = input_map.get(&input_name.to_lowercase())?;
                let bit_position = bit.parse::<usize>().ok()?;
                Some(Transform::BitFlipInput {
                    index: *idx,
                    bit_position,
                })
            }
            "double_input" => {
                let input_name = args.get(0)?;
                let idx = input_map.get(&input_name.to_lowercase())?;
                Some(Transform::DoubleInput { index: *idx })
            }
            "set_input" => {
                let (input_name, value) = Self::parse_two_args(&args)?;
                let idx = input_map.get(&input_name.to_lowercase())?;
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
        if lower.contains("output_changes") || lower.contains("output_changed") || lower.contains("changes") {
            return ExpectedBehavior::OutputChanged;
        }
        if let Some(arg) = lower.strip_prefix("output_scaled(").and_then(|s| s.strip_suffix(')')) {
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

    fn parse_field_element(raw: &str) -> Option<FieldElement> {
        let trimmed = raw.trim();
        if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            FieldElement::from_hex(trimmed).ok()
        } else if let Some(exp) = trimmed.strip_prefix("2^") {
            if let Ok(bits) = exp.trim().parse::<u32>() {
                if bits <= 63 {
                    return Some(FieldElement::from_u64(1u64 << bits));
                }
            }
            Some(FieldElement::max_value())
        } else {
            trimmed.parse::<u64>().ok().map(FieldElement::from_u64)
        }
    }

    fn severity_from_invariant(
        &self,
        invariant: &crate::config::v2::Invariant,
    ) -> Severity {
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
}
