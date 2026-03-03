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
        let allow_worker_oversubscription =
            Self::additional_bool(additional, "allow_worker_oversubscription").unwrap_or(false);
        let host_parallelism = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1)
            .max(1);
        let requested_workers = workers.max(1);
        let workers = if allow_worker_oversubscription {
            requested_workers
        } else {
            requested_workers.min(host_parallelism)
        };
        if workers != requested_workers {
            tracing::warn!(
                "Capping workers {} -> {} to match host parallelism {}; set \
                 additional.allow_worker_oversubscription=true to opt out",
                requested_workers,
                workers,
                host_parallelism
            );
        }

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
            let memory_limit_bytes =
                Self::additional_u64(additional, "isolation_memory_limit_bytes")
                    .or_else(|| {
                        Self::additional_u64(additional, "isolation_memory_limit_mb")
                            .map(|mb| mb.saturating_mul(1024 * 1024))
                    })
                    .or_else(|| {
                        std::env::var("ZK_FUZZER_ISOLATION_MEMORY_LIMIT_MB")
                            .ok()
                            .and_then(|raw| raw.trim().parse::<u64>().ok())
                            .map(|mb| mb.saturating_mul(1024 * 1024))
                    })
                    .unwrap_or_else(|| {
                        Self::default_isolation_memory_limit_bytes(additional, workers)
                    });
            let cpu_limit_secs = Self::additional_u64(additional, "isolation_cpu_limit_secs")
                .or_else(|| {
                    std::env::var("ZK_FUZZER_ISOLATION_CPU_LIMIT_SECS")
                        .ok()
                        .and_then(|raw| raw.trim().parse::<u64>().ok())
                })
                .unwrap_or(0);
            Self::enforce_resource_preflight(additional, workers, Some(memory_limit_bytes))?;

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
            use crate::executor::IsolationConfig;
            let isolation_config = IsolationConfig {
                timeout_ms: execution_timeout_ms,
                memory_limit_bytes,
                cpu_limit_secs,
                kill_on_timeout,
                ..IsolationConfig::default()
            };
            isolated_executor = isolated_executor.with_config(isolation_config);

            executor = Arc::new(isolated_executor);
            tracing::info!(
                "Per-exec isolation enabled (timeout {} ms, kill_on_timeout: {}, memory_limit={} MiB, cpu_limit={}s)",
                execution_timeout_ms,
                kill_on_timeout,
                memory_limit_bytes / (1024 * 1024),
                cpu_limit_secs
            );
        } else {
            Self::enforce_resource_preflight(additional, workers, None)?;
        }

        // Scan patterns are target-reusable; if their input schema does not match the actual
        // circuit interface, reconcile inputs to the live executor shape for this run.
        Self::reconcile_inputs_with_executor(&mut config, executor.as_ref())?;
        let additional = &config.campaign.parameters.additional;

        let num_constraints = executor.num_constraints().max(1);
        let coverage = create_coverage_tracker(num_constraints);

        // Phase 0 Fix: Make corpus size configurable instead of hardcoded 10000
        // Allows tuning based on circuit complexity and available memory
        let corpus_max_size = Self::bounded_corpus_max_size(additional);
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

        let expected_constraint_count = Self::expected_constraint_count(executor.as_ref());

        // Phase 0 Fix: Wire semantic oracles from config
        Self::add_semantic_oracles_from_config(
            &config,
            executor.field_modulus(),
            expected_constraint_count,
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

    fn enforce_resource_preflight(
        additional: &crate::config::AdditionalConfig,
        workers: usize,
        isolation_memory_limit_bytes: Option<u64>,
    ) -> anyhow::Result<()> {
        if !Self::additional_bool(additional, "fail_on_resource_risk").unwrap_or(true) {
            return Ok(());
        }

        let Some((available_mb, total_mb)) = Self::host_memory_snapshot_mb() else {
            return Ok(());
        };

        let min_available_mb = Self::additional_u64(additional, "resource_guard_min_available_mb")
            .or_else(|| {
                std::env::var("ZK_FUZZER_RESOURCE_GUARD_MIN_AVAILABLE_MB")
                    .ok()
                    .and_then(|raw| raw.trim().parse::<u64>().ok())
            })
            .unwrap_or(2048)
            .max(1);
        let min_available_ratio =
            Self::additional_f64(additional, "resource_guard_min_available_ratio")
                .unwrap_or(0.03)
                .clamp(0.0, 1.0);
        let available_ratio = if total_mb == 0 {
            0.0
        } else {
            available_mb as f64 / total_mb as f64
        };

        if available_mb <= min_available_mb || available_ratio <= min_available_ratio {
            anyhow::bail!(
                "Resource preflight failed: available memory is unsafe \
                 (available={} MiB, total={} MiB, min_available={} MiB, min_ratio={:.3}, observed_ratio={:.3}). \
                 No runtime fallback/skip is applied; aborting run.",
                available_mb,
                total_mb,
                min_available_mb,
                min_available_ratio,
                available_ratio
            );
        }

        let Some(memory_limit_bytes) = isolation_memory_limit_bytes else {
            return Ok(());
        };

        let reserved_mb = Self::additional_u64(additional, "resource_guard_reserved_mb")
            .or_else(|| Self::additional_u64(additional, "isolation_memory_reserved_mb"))
            .unwrap_or(4096);
        let max_commit_fraction =
            Self::additional_f64(additional, "resource_guard_max_commit_fraction")
                .unwrap_or(0.85)
                .clamp(0.05, 1.0);
        let max_commit_mb = ((total_mb as f64) * max_commit_fraction).round() as u64;
        let per_worker_limit_mb = (memory_limit_bytes / (1024 * 1024)).max(1);
        let projected_commit_mb =
            reserved_mb.saturating_add(per_worker_limit_mb.saturating_mul(workers.max(1) as u64));

        if projected_commit_mb > max_commit_mb {
            anyhow::bail!(
                "Resource preflight failed: projected isolation memory commit {} MiB exceeds cap {} MiB \
                 (workers={}, per_worker_limit={} MiB, reserved={} MiB, max_commit_fraction={:.2}). \
                 No runtime fallback/skip is applied; aborting run.",
                projected_commit_mb,
                max_commit_mb,
                workers.max(1),
                per_worker_limit_mb,
                reserved_mb,
                max_commit_fraction
            );
        }

        Ok(())
    }

    fn bounded_corpus_max_size(additional: &crate::config::AdditionalConfig) -> usize {
        let configured = Self::additional_u64(additional, "corpus_max_size")
            .unwrap_or(100_000)
            .max(1) as usize;
        let hard_cap = Self::additional_usize(additional, "corpus_max_size_hard_cap")
            .or_else(|| {
                std::env::var("ZK_FUZZER_CORPUS_MAX_SIZE_HARD_CAP")
                    .ok()
                    .and_then(|raw| raw.trim().parse::<usize>().ok())
            })
            .unwrap_or(100_000)
            .max(1);
        let bounded = configured.min(hard_cap).max(1);
        if bounded < configured {
            tracing::warn!(
                "Corpus size cap applied: {} -> {} (hard_cap={})",
                configured,
                bounded,
                hard_cap
            );
        }
        bounded
    }

    pub(super) fn host_memory_snapshot_mb() -> Option<(u64, u64)> {
        let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
        let mut mem_available_kib: Option<u64> = None;
        let mut mem_total_kib: Option<u64> = None;

        for line in raw.lines() {
            let mut parts = line.split_whitespace();
            let Some(key) = parts.next() else {
                continue;
            };
            let Some(raw_value) = parts.next() else {
                continue;
            };
            let Ok(value) = raw_value.parse::<u64>() else {
                continue;
            };
            match key {
                "MemAvailable:" => mem_available_kib = Some(value),
                "MemTotal:" => mem_total_kib = Some(value),
                _ => {}
            }
        }

        let total_mb = mem_total_kib.map(|kib| (kib / 1024).max(1))?;
        let available_mb = mem_available_kib
            .map(|kib| (kib / 1024).max(1))
            .unwrap_or(total_mb);
        Some((available_mb, total_mb))
    }

    fn host_total_memory_mb() -> Option<u64> {
        Self::host_memory_snapshot_mb().map(|(_available_mb, total_mb)| total_mb)
    }

    fn default_isolation_memory_limit_bytes(
        additional: &crate::config::AdditionalConfig,
        workers: usize,
    ) -> u64 {
        let workers = workers.max(1) as u64;
        let reserved_mb =
            Self::additional_u64(additional, "isolation_memory_reserved_mb").unwrap_or(4096);
        let min_per_worker_mb =
            Self::additional_u64(additional, "isolation_memory_min_mb").unwrap_or(1024);
        let max_per_worker_mb = Self::additional_u64(additional, "isolation_memory_max_mb")
            .unwrap_or(8192)
            .max(min_per_worker_mb);
        let worker_budget_fraction =
            Self::additional_f64(additional, "isolation_memory_worker_budget_fraction")
                .unwrap_or(0.5)
                .clamp(0.05, 1.0);

        let per_worker_mb = Self::host_total_memory_mb()
            .map(|total_mb| {
                let budget_mb = total_mb.saturating_sub(reserved_mb).max(min_per_worker_mb);
                let scaled_budget_mb = ((budget_mb as f64 * worker_budget_fraction).round() as u64)
                    .max(min_per_worker_mb);
                (scaled_budget_mb / workers).clamp(min_per_worker_mb, max_per_worker_mb)
            })
            .unwrap_or(4096);

        per_worker_mb.saturating_mul(1024 * 1024)
    }
}
