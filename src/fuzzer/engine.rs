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
//! ```ignore
//! use zk_fuzzer::fuzzer::engine::FuzzingEngine;
//! use zk_fuzzer::config::FuzzConfig;
//!
//! // Load campaign configuration
//! let config = FuzzConfig::from_yaml("campaign.yaml")?;
//!
//! // Create fuzzing engine with 4 workers and deterministic seed
//! let mut engine = FuzzingEngine::new(config, Some(42), 4)?;
//!
//! // Run fuzzing campaign
//! let report = engine.run(None).await?;
//!
//! // Check results
//! println!("Found {} vulnerabilities", report.findings.len());
//! println!("Coverage: {:.1}%", report.statistics.coverage_percentage);
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

use super::{Finding, FieldElement, TestCase, TestMetadata, mutate_field_element, bn254_modulus_bytes};
use super::power_schedule::{PowerSchedule, PowerScheduler, TestCaseMetrics};
use super::structure_aware::{StructureAwareMutator, Splicer};
use super::oracle::{BugOracle, UnderconstrainedOracle, ArithmeticOverflowOracle};
use crate::analysis::complexity::ComplexityAnalyzer;
use crate::analysis::symbolic::{SymbolicFuzzerIntegration, SymbolicConfig, VulnerabilityPattern};
use crate::analysis::taint::TaintAnalyzer;
use crate::config::*;
use crate::corpus::{CorpusEntry, SharedCorpus, create_corpus, storage as corpus_storage};
use crate::executor::{CircuitExecutor, ExecutorFactory, SharedCoverageTracker, create_coverage_tracker};
use crate::progress::{FuzzingStats, ProgressReporter, SimpleProgressTracker};
use crate::reporting::FuzzReport;

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use rayon::prelude::*;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
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
    corpus: SharedCorpus,
    coverage: SharedCoverageTracker,
    findings: Arc<std::sync::RwLock<Vec<Finding>>>,
    rng: StdRng,
    stats: Arc<std::sync::RwLock<FuzzingStats>>,
    execution_count: AtomicU64,
    workers: usize,
    /// Symbolic execution integration for guided test generation
    symbolic: Option<SymbolicFuzzerIntegration>,
    /// Taint analyzer for information flow tracking
    taint_analyzer: Option<TaintAnalyzer>,
    /// Power scheduler for energy-based test case selection
    power_scheduler: PowerScheduler,
    /// Structure-aware mutator for intelligent mutations
    structure_mutator: StructureAwareMutator,
    /// Start time for time-based metrics
    start_time: Option<Instant>,
    /// Global average execution time (exponential moving average)
    avg_exec_time: Arc<std::sync::RwLock<Duration>>,
    /// Complexity analyzer for circuit analysis
    complexity_analyzer: ComplexityAnalyzer,
    /// Bug oracles for detection
    oracles: Vec<Box<dyn BugOracle>>,
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
    /// ```ignore
    /// // Deterministic fuzzing with 4 workers
    /// let engine = FuzzingEngine::new(config, Some(12345), 4)?;
    ///
    /// // Non-deterministic with 8 workers
    /// let engine = FuzzingEngine::new(config, None, 8)?;
    /// ```
    pub fn new(config: FuzzConfig, seed: Option<u64>, workers: usize) -> anyhow::Result<Self> {
        let rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };

        // Create executor based on framework
        let executor = ExecutorFactory::create(
            config.campaign.target.framework,
            config.campaign.target.circuit_path.to_str().unwrap_or(""),
            &config.campaign.target.main_component,
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
            }
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
            tracing::info!("Optimization suggestion: {:?} - {}", suggestion.priority, suggestion.description);
        }

        // Initialize bug oracles
        let oracles: Vec<Box<dyn BugOracle>> = vec![
            Box::new(UnderconstrainedOracle::new()),
            Box::new(ArithmeticOverflowOracle::new()),
        ];

        Ok(Self {
            config,
            executor,
            corpus,
            coverage,
            findings: Arc::new(std::sync::RwLock::new(Vec::new())),
            rng,
            stats: Arc::new(std::sync::RwLock::new(FuzzingStats::default())),
            execution_count: AtomicU64::new(0),
            workers,
            symbolic,
            taint_analyzer,
            power_scheduler,
            structure_mutator,
            start_time: None,
            avg_exec_time: Arc::new(std::sync::RwLock::new(Duration::from_micros(100))),
            complexity_analyzer,
            oracles,
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
    fn parse_power_schedule(config: &FuzzConfig) -> PowerSchedule {
        // Check for power_schedule in campaign parameters
        if let Some(schedule_str) = config.campaign.parameters.additional.get("power_schedule") {
            if let Some(s) = schedule_str.as_str() {
                return PowerSchedule::from_str(s);
            }
        }
        // Default to MMOPT for balanced performance
        PowerSchedule::Mmopt
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
    /// ```ignore
    /// // Run with progress reporting
    /// let reporter = ProgressReporter::new();
    /// let report = engine.run(Some(&reporter)).await?;
    ///
    /// // Run without progress (CI/CD mode)
    /// let report = engine.run(None).await?;
    /// ```
    pub async fn run(&mut self, progress: Option<&ProgressReporter>) -> anyhow::Result<FuzzReport> {
        let start_time = Instant::now();
        self.start_time = Some(start_time);

        tracing::info!("Starting fuzzing campaign: {}", self.config.campaign.name);
        tracing::info!("Circuit: {} ({:?})", 
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
                tracing::info!("Taint analysis found {} potential issues", taint_findings.len());
                for finding in taint_findings {
                    if let Some(p) = progress {
                        p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                    }
                    self.findings.write().unwrap().push(finding);
                }
            }
        }

        // Run source code analysis for vulnerability hints
        self.run_source_analysis(progress);

        // Seed corpus
        self.seed_corpus()?;
        tracing::info!("Seeded corpus with {} initial test cases", self.corpus.len());

        // Initialize simple progress tracker for non-interactive environments
        self.simple_tracker = Some(SimpleProgressTracker::new());

        // Update power scheduler with initial global stats
        self.update_power_scheduler_globals();

        // Run attacks
        for attack_config in &self.config.attacks.clone() {
            if let Some(p) = progress {
                p.log_attack_start(&format!("{:?}", attack_config.attack_type));
            }

            let findings_before = self.findings.read().unwrap().len();

            match attack_config.attack_type {
                AttackType::Underconstrained => {
                    self.run_underconstrained_attack(&attack_config.config, progress).await?;
                }
                AttackType::Soundness => {
                    self.run_soundness_attack(&attack_config.config, progress).await?;
                }
                AttackType::ArithmeticOverflow => {
                    self.run_arithmetic_attack(&attack_config.config, progress).await?;
                }
                AttackType::Collision => {
                    self.run_collision_attack(&attack_config.config, progress).await?;
                }
                AttackType::Boundary => {
                    self.run_boundary_attack(&attack_config.config, progress).await?;
                }
                AttackType::VerificationFuzzing => {
                    self.run_verification_fuzzing_attack(&attack_config.config, progress).await?;
                }
                AttackType::WitnessFuzzing => {
                    self.run_witness_fuzzing_attack(&attack_config.config, progress).await?;
                }
                AttackType::Differential => {
                    self.run_differential_attack(&attack_config.config, progress).await?;
                }
                AttackType::InformationLeakage => {
                    self.run_information_leakage_attack(&attack_config.config, progress).await?;
                }
                AttackType::TimingSideChannel => {
                    self.run_timing_sidechannel_attack(&attack_config.config, progress).await?;
                }
                AttackType::CircuitComposition => {
                    self.run_circuit_composition_attack(&attack_config.config, progress).await?;
                }
                AttackType::RecursiveProof => {
                    self.run_recursive_proof_attack(&attack_config.config, progress).await?;
                }
                _ => {
                    tracing::warn!("Attack type {:?} not yet implemented", attack_config.attack_type);
                }
            }

            let findings_after = self.findings.read().unwrap().len();
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

        // Export corpus to output directory
        let corpus_dir = self.config.reporting.output_dir.join("corpus");
        match self.export_corpus(&corpus_dir) {
            Ok(count) => tracing::info!("Exported {} interesting test cases to {:?}", count, corpus_dir),
            Err(e) => tracing::warn!("Failed to export corpus: {}", e),
        }

        // Generate report
        let elapsed = start_time.elapsed();
        let findings = self.findings.read().unwrap().clone();

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
                        let truncated: Vec<_> = inputs.into_iter()
                            .take(expected_len)
                            .collect();
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
        let result = self.executor.execute_sync(&test_case.inputs);
        let coverage_hash = result.coverage.coverage_hash;

        let entry = CorpusEntry::new(test_case, coverage_hash);
        self.corpus.add(entry);

        // Record coverage
        if result.coverage.satisfied_constraints.is_empty() {
            self.coverage.record_coverage_hash(result.coverage.coverage_hash);
        } else {
            self.coverage
                .record_execution(&result.coverage.satisfied_constraints);
        }
    }

    fn create_test_case_with_value(&self, value: FieldElement) -> TestCase {
        let inputs: Vec<FieldElement> = self.config.inputs.iter()
            .map(|_| value.clone())
            .collect();

        TestCase {
            inputs,
            expected_output: None,
            metadata: TestMetadata::default(),
        }
    }

    fn generate_random_test_case(&mut self) -> TestCase {
        let inputs: Vec<FieldElement> = self.config.inputs.iter()
            .map(|_| FieldElement::random(&mut self.rng))
            .collect();

        TestCase {
            inputs,
            expected_output: None,
            metadata: TestMetadata::default(),
        }
    }

    fn generate_test_case(&mut self) -> TestCase {
        // Try to get from corpus using energy-weighted selection
        if let Some(entry) = self.corpus.get_random(&mut self.rng) {
            // Calculate energy using power scheduler
            let metrics = TestCaseMetrics {
                selection_count: entry.execution_count,
                new_coverage_count: if entry.discovered_new_coverage { 1 } else { 0 },
                findings_count: 0, // Would need to track per-entry
                avg_execution_time: Duration::from_micros(100),
                path_frequency: 1,
                generation: entry.test_case.metadata.generation as u32,
                depth: entry.test_case.metadata.generation as u32,
                time_since_finding: self.start_time
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::ZERO),
            };
            
            let energy = self.power_scheduler.calculate_energy(&metrics);
            
            // Decide mutation strategy based on energy and randomness
            let mutation_strategy = self.rng.gen_range(0..100);
            
            let mutated_inputs = if mutation_strategy < 40 {
                // 40%: Structure-aware mutation
                self.structure_mutator.mutate(&entry.test_case.inputs, &mut self.rng)
            } else if mutation_strategy < 70 {
                // 30%: Standard byte-level mutation
                entry.test_case.inputs.iter()
                    .map(|input| {
                        if self.rng.gen::<f64>() < 0.3 {
                            mutate_field_element(input, &mut self.rng)
                        } else {
                            input.clone()
                        }
                    })
                    .collect()
            } else if mutation_strategy < 85 {
                // 15%: Splice with another corpus entry
                if let Some(other) = self.corpus.get_random(&mut self.rng) {
                    Splicer::splice(&entry.test_case.inputs, &other.test_case.inputs, &mut self.rng)
                } else {
                    entry.test_case.inputs.clone()
                }
            } else {
                // 15%: Havoc - multiple random mutations
                let mut inputs = entry.test_case.inputs.clone();
                let num_mutations = self.rng.gen_range(1..=energy.min(10));
                for _ in 0..num_mutations {
                    let idx = self.rng.gen_range(0..inputs.len().max(1));
                    if idx < inputs.len() {
                        inputs[idx] = mutate_field_element(&inputs[idx], &mut self.rng);
                    }
                }
                inputs
            };

            TestCase {
                inputs: mutated_inputs,
                expected_output: None,
                metadata: TestMetadata {
                    generation: entry.test_case.metadata.generation + 1,
                    ..Default::default()
                },
            }
        } else {
            self.generate_random_test_case()
        }
    }

    /// Execute test case and update coverage
    /// 
    /// Note: There's a potential race condition between checking is_new and
    /// adding to corpus. However, the corpus.add() method has its own
    /// duplicate detection which prevents actual duplicates. The worst case
    /// is that we might miss adding a test case that another thread added
    /// first with the same coverage, which is acceptable behavior.
    fn execute_and_track(&self, test_case: &TestCase) -> crate::executor::ExecutionResult {
        let exec_start = Instant::now();
        let result = self.executor.execute_sync(&test_case.inputs);
        let exec_time = exec_start.elapsed();
        
        self.execution_count.fetch_add(1, Ordering::Relaxed);

        // Update average execution time (using exponential moving average with alpha=0.1)
        if let Ok(mut avg_time) = self.avg_exec_time.write() {
            let current_avg_micros = avg_time.as_micros() as f64;
            let new_exec_micros = exec_time.as_micros() as f64;
            let updated_avg = current_avg_micros * 0.9 + new_exec_micros * 0.1;
            *avg_time = Duration::from_micros(updated_avg as u64);
        }

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.executions = self.execution_count.load(Ordering::Relaxed);
            stats.corpus_size = self.corpus.len();
            stats.crashes = self.findings.read().unwrap().len() as u64;
            stats.unique_crashes = self.findings.read().unwrap().len() as u64;
            stats.coverage_percentage = self.coverage.coverage_percentage();
            if let Some(start) = self.start_time {
                stats.update_exec_rate(start);
            }
        }

        // Track coverage - record_execution is already thread-safe
        let is_new = if result.coverage.satisfied_constraints.is_empty() {
            self.coverage.record_coverage_hash(result.coverage.coverage_hash)
        } else {
            self.coverage
                .record_execution(&result.coverage.satisfied_constraints)
        };

        // Add to corpus if new coverage discovered
        // The corpus.add() method has built-in deduplication, so even if
        // another thread adds the same coverage between our check and add,
        // we won't get duplicates (add returns false for duplicates)
        if is_new && result.success {
            let entry = CorpusEntry::new(test_case.clone(), result.coverage.coverage_hash)
                .with_new_coverage();
            // add() returns false if entry already exists, preventing duplicates
            if self.corpus.add(entry) {
                if let Ok(mut stats) = self.stats.write() {
                    stats.new_coverage_count += 1;
                }
            }
        }

        // Run bug oracles on successful executions
        if result.success {
            let oracle_findings = self.run_oracles(test_case, &result.outputs);
            if !oracle_findings.is_empty() {
                let mut findings = self.findings.write().unwrap();
                findings.extend(oracle_findings);
            }
        }

        result
    }

    /// Execute test case, update coverage, and learn patterns (mutable version)
    fn execute_and_learn(&mut self, test_case: &TestCase) -> crate::executor::ExecutionResult {
        let result = self.execute_and_track(test_case);
        
        // Learn mutation patterns from successful executions
        if result.success {
            self.learn_mutation_patterns(test_case, &result);
        }
        
        result
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

        tracing::info!("Testing {} witness pairs for underconstrained circuits", witness_pairs);

        // Generate test cases
        let test_cases: Vec<TestCase> = (0..witness_pairs)
            .map(|_| self.generate_test_case())
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

                self.findings.write().unwrap().push(finding.clone());

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

        let num_public = self.executor.num_public_inputs();
        if num_public == 0 {
            tracing::warn!("Soundness attack skipped: circuit has no public inputs to mutate");
            return Ok(());
        }

        for _ in 0..forge_attempts {
            let valid_case = self.generate_test_case();
            let valid_proof = self.executor.prove(&valid_case.inputs)?;

            let valid_public: Vec<FieldElement> = valid_case
                .inputs
                .iter()
                .take(num_public)
                .cloned()
                .collect();

            // Mutate public inputs only
            let mutated_public: Vec<FieldElement> = valid_public
                .iter()
                .map(|input| {
                    if self.rng.gen::<f64>() < mutation_rate {
                        mutate_field_element(input, &mut self.rng)
                    } else {
                        input.clone()
                    }
                })
                .collect();

            // Skip if mutation didn't change public inputs
            if mutated_public == valid_public {
                continue;
            }

            // Try to verify with mutated inputs
            if self.executor.verify(&valid_proof, &mutated_public)? {
                let finding = Finding {
                    attack_type: AttackType::Soundness,
                    severity: Severity::Critical,
                    description: "Proof verified with mutated inputs - soundness violation!".to_string(),
                    poc: super::ProofOfConcept {
                        witness_a: valid_case.inputs,
                        witness_b: None,
                        public_inputs: mutated_public,
                        proof: Some(valid_proof),
                    },
                    location: None,
                };

                self.findings.write().unwrap().push(finding.clone());

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
            .unwrap_or_else(|| vec![
                "0".to_string(),
                "1".to_string(),
                "p-1".to_string(),
                "p".to_string(),
            ]);

        tracing::info!("Testing {} arithmetic edge cases", test_values.len());

        let field_modulus = self.get_field_modulus();

        for value in test_values {
            let expanded = match crate::config::parser::expand_value_placeholder(&value, &field_modulus) {
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

                self.findings.write().unwrap().push(finding.clone());

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

        // Generate and execute in parallel
        let test_cases: Vec<TestCase> = (0..samples)
            .map(|_| self.generate_test_case())
            .collect();

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
                            description: "Found collision: different inputs produce same output".to_string(),
                            poc: super::ProofOfConcept {
                                witness_a: existing.inputs.clone(),
                                witness_b: Some(test_case.inputs),
                                public_inputs: vec![],
                                proof: None,
                            },
                            location: None,
                        };

                        self.findings.write().unwrap().push(finding.clone());

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
            .unwrap_or_else(|| vec![
                "0".to_string(),
                "1".to_string(),
                "p-1".to_string(),
            ]);

        tracing::info!("Testing {} boundary values", test_values.len());

        let field_modulus = self.get_field_modulus();

        for value in test_values {
            let expanded = match crate::config::parser::expand_value_placeholder(&value, &field_modulus) {
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
            malleability_tests, malformed_tests, edge_case_tests
        );

        let fuzzer = VerificationFuzzer::new()
            .with_malleability_tests(malleability_tests)
            .with_malformed_tests(malformed_tests)
            .with_edge_case_tests(edge_case_tests)
            .with_mutation_rate(mutation_rate);

        let mut rng = rand::thread_rng();
        let findings = fuzzer.fuzz(&self.executor, &mut rng);
        
        for finding in findings {
            self.findings.write().unwrap().push(finding.clone());
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
            determinism_tests, timing_tests, stress_tests
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
            self.findings.write().unwrap().push(finding.clone());
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
        use crate::differential::{DifferentialFuzzer, DifferentialConfig};
        use crate::differential::report::DifferentialReport;
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

        let backends: Vec<Framework> = if let Some(seq) = config.get("backends").and_then(|v| v.as_sequence()) {
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
                .unwrap_or_else(|| self.config.campaign.target.circuit_path.to_str().unwrap_or(""));

            match ExecutorFactory::create(*backend, circuit_path, &self.config.campaign.target.main_component) {
                Ok(executor) => {
                    diff_fuzzer.add_executor(*backend, executor);
                    active_backends.push(*backend);
                }
                Err(e) => {
                    tracing::warn!("Skipping backend {:?} for differential fuzzing: {}", backend, e);
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
            tracing::warn!("Differential fuzzing found {} critical issues", report.critical_findings().len());
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

            self.findings.write().unwrap().push(finding.clone());
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
        use crate::multi_circuit::{MultiCircuitFuzzer, CircuitChain};
        use crate::multi_circuit::composition::{CompositionTester, CompositionType};
        
        let num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(200) as usize;

        tracing::info!("Running circuit composition fuzzing with {} tests", num_tests);

        // Create composition tester for sequential composition
        let mut composition_tester = CompositionTester::new(CompositionType::Sequential);
        composition_tester.add_circuit(self.executor.clone());

        // Create circuit chain for chained execution testing
        let mut chain = CircuitChain::new();
        chain.add("main", self.executor.clone());

        // Test chain execution with random inputs
        for _ in 0..num_tests.min(10) {
            let inputs: Vec<FieldElement> = (0..self.executor.num_private_inputs())
                .map(|_| FieldElement::random(&mut self.rng))
                .collect();
            
            let chain_result = chain.execute(&inputs);
            if !chain_result.success {
                tracing::debug!("Chain execution failed at step: {:?}", 
                    chain_result.steps.last().map(|s| &s.circuit_name));
            }
        }

        // Test composition with vulnerability detection
        let vulnerabilities = composition_tester.check_vulnerabilities();
        for vuln in &vulnerabilities {
            tracing::warn!("Composition vulnerability: {:?} - {}", 
                vuln.vuln_type, vuln.description);
        }

        let mut multi_fuzzer = MultiCircuitFuzzer::new(
            crate::multi_circuit::MultiCircuitConfig::default()
        );
        
        multi_fuzzer.add_circuit("main", self.executor.clone());

        let mut rng = rand::thread_rng();
        let findings = multi_fuzzer.run(&mut rng);
        
        for finding in findings {
            self.findings.write().unwrap().push(finding.clone());
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

        tracing::info!("Running information leakage detection with {} tests", num_tests);

        let public_indices;
        let private_indices;
        let output_indices;

        let inspector = match self.executor.constraint_inspector() {
            Some(inspector) => inspector,
            None => {
                tracing::warn!("Information leakage attack skipped: constraint inspector unavailable");
                if let Some(p) = progress {
                    for _ in 0..num_tests {
                        p.inc();
                    }
                }
                return Ok(());
            }
        };

        public_indices = inspector.public_input_indices();
        private_indices = inspector.private_input_indices();
        output_indices = inspector.output_indices();

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
            self.findings.write().unwrap().push(finding.clone());
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

        tracing::info!("Running timing side-channel detection with {} samples", num_samples);

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

            self.findings.write().unwrap().push(finding.clone());
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
        use crate::multi_circuit::recursive::{RecursiveTester, RecursionResult};
        
        let num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        
        let max_depth = config
            .get("max_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(3) as usize;

        tracing::info!("Running recursive proof fuzzing with {} tests, max depth {}", num_tests, max_depth);

        let tester = RecursiveTester::new(max_depth).with_verifier(self.executor.clone());

        for _ in 0..num_tests {
            let test_case = self.generate_random_test_case();
            let result = tester.test_recursion(&test_case.inputs, max_depth);
            
            match result {
                RecursionResult::VerificationFailed { depth, error } => {
                    let finding = Finding {
                        attack_type: AttackType::RecursiveProof,
                        severity: Severity::High,
                        description: format!("Recursive verification failed at depth {}: {}", depth, error),
                        poc: super::ProofOfConcept {
                            witness_a: test_case.inputs.clone(),
                            witness_b: None,
                            public_inputs: vec![],
                            proof: None,
                        },
                        location: None,
                    };
                    
                    self.findings.write().unwrap().push(finding.clone());
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

    fn get_circuit_info(&self) -> crate::attacks::CircuitInfo {
        crate::attacks::CircuitInfo {
            name: self.config.campaign.target.main_component.clone(),
            num_constraints: self.executor.num_constraints(),
            num_private_inputs: self.executor.num_private_inputs(),
            num_public_inputs: self.executor.num_public_inputs(),
            num_outputs: 1,
        }
    }

    fn hash_output(&self, output: &[FieldElement]) -> Vec<u8> {
        use sha2::{Sha256, Digest};
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

        for i in 0..witnesses.len() {
            for j in (i + 1)..witnesses.len() {
                if witnesses[i].inputs != witnesses[j].inputs {
                    return true;
                }
            }
        }
        false
    }

    fn get_field_modulus(&self) -> [u8; 32] {
        // Use centralized field constants
        bn254_modulus_bytes()
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

    fn generate_report(&self, findings: Vec<Finding>, duration: u64) -> FuzzReport {
        let mut report = FuzzReport::new(
            self.config.campaign.name.clone(),
            findings,
            crate::fuzzer::CoverageMap {
                constraint_hits: std::collections::HashMap::new(),
                edge_coverage: self.coverage.unique_constraints_hit() as u64,
                max_coverage: self.executor.num_constraints() as u64,
            },
            self.config.reporting.clone(),
        );
        report.duration_seconds = duration;
        report.statistics.total_executions = self.execution_count.load(Ordering::Relaxed);
        report
    }

    /// Get current statistics
    pub fn stats(&self) -> FuzzingStats {
        // Return cached stats if available, otherwise compute fresh
        if let Ok(stats) = self.stats.read() {
            stats.clone()
        } else {
            FuzzingStats {
                executions: self.execution_count.load(Ordering::Relaxed),
                crashes: self.findings.read().unwrap().len() as u64,
                coverage_percentage: self.coverage.coverage_percentage(),
                unique_crashes: self.findings.read().unwrap().len() as u64,
                corpus_size: self.corpus.len(),
                new_coverage_count: self.coverage.new_coverage_count(),
                ..Default::default()
            }
        }
    }

    /// Run bug oracles on test case results
    fn run_oracles(&self, test_case: &TestCase, outputs: &[FieldElement]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for oracle in &self.oracles {
            if let Some(finding) = oracle.check(test_case, outputs) {
                tracing::warn!("Oracle '{}' detected issue: {}", oracle.name(), finding.description);
                findings.push(finding);
            }
        }
        findings
    }

    /// Update power scheduler with global statistics
    fn update_power_scheduler_globals(&mut self) {
        let avg_time = self.avg_exec_time.read()
            .map(|t| *t)
            .unwrap_or(Duration::from_micros(100));
        let total_edges = self.coverage.unique_constraints_hit() as u64;
        self.power_scheduler.update_globals(avg_time, total_edges);
    }

    /// Export corpus to disk for persistence
    pub fn export_corpus(&self, output_dir: &std::path::Path) -> anyhow::Result<usize> {
        let entries = self.corpus.all_entries();
        corpus_storage::export_interesting_cases(&entries, output_dir)
    }

    /// Get complexity metrics for the circuit
    pub fn get_complexity_metrics(&self) -> crate::analysis::complexity::ComplexityMetrics {
        self.complexity_analyzer.analyze(&self.executor)
    }

    /// Learn patterns from successful executions for structure-aware mutations
    fn learn_mutation_patterns(&mut self, test_case: &TestCase, result: &crate::executor::ExecutionResult) {
        if result.success && !result.outputs.is_empty() {
            // Learn patterns from inputs that produce interesting outputs
            for (i, input) in test_case.inputs.iter().enumerate() {
                let pattern_name = format!("input_{}", i);
                self.structure_mutator.learn_pattern(&pattern_name, vec![input.clone()]);
            }
        }
    }

    /// Run source code analysis to find vulnerability hints
    fn run_source_analysis(&self, progress: Option<&ProgressReporter>) {
        use crate::targets::{circom_analysis, noir_analysis, halo2_analysis, cairo_analysis};
        
        // Try to read the circuit source file
        let source = match std::fs::read_to_string(&self.config.campaign.target.circuit_path) {
            Ok(s) => s,
            Err(_) => return, // Skip if source not readable
        };

        let hints: Vec<String> = match self.config.campaign.target.framework {
            Framework::Circom => {
                circom_analysis::analyze_for_vulnerabilities(&source)
                    .into_iter()
                    .map(|h| format!("{:?}: {} at line {}", h.hint_type, h.description, h.line.unwrap_or(0)))
                    .collect()
            }
            Framework::Noir => {
                noir_analysis::analyze_for_vulnerabilities(&source)
                    .into_iter()
                    .map(|h| format!("{:?}: {} at line {}", h.hint_type, h.description, h.line.unwrap_or(0)))
                    .collect()
            }
            Framework::Halo2 => {
                halo2_analysis::analyze_circuit(&source)
                    .into_iter()
                    .map(|h| format!("[{}] {}: {}", h.severity, h.gate_type, h.description))
                    .collect()
            }
            Framework::Cairo => {
                cairo_analysis::analyze_for_vulnerabilities(&source)
                    .into_iter()
                    .map(|h| format!("{:?}: {}", h.issue_type, h.description))
                    .collect()
            }
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
}
