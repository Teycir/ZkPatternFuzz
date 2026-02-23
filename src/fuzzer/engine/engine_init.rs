use super::prelude::*;
use super::FuzzingEngine;

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

        let num_constraints = executor.num_constraints().max(1);
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
            Box::new(
                ArithmeticOverflowOracle::new_with_modulus(executor.field_modulus())
                    .with_public_input_count(executor.num_public_inputs()),
            ),
        ];

        // Phase 0 Fix: Wire semantic oracles from config
        Self::add_semantic_oracles_from_config(
            &config,
            executor.field_modulus(),
            executor.num_constraints(),
            executor.num_public_inputs(),
            &mut oracles,
        );
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
