use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
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

                    let circuit_path = match config.path.to_str() {
                        Some(path) => path,
                        None => {
                            tracing::error!(
                                "CHAIN CIRCUIT LOAD FAILED: Circuit '{}' path contains invalid UTF-8: {:?}",
                                circuit_ref,
                                config.path
                            );
                            return Vec::new();
                        }
                    };

                    match crate::executor::ExecutorFactory::create_with_options(
                        framework,
                        circuit_path,
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
        
        // Phase 5 Fix (Milestone 5.3): Use framework-aware chain mutator
        // Previously used ChainMutator::new() which defaults to Framework::Mock,
        // causing reduced mutation validity for real circuits.
        let mutator = ChainMutator::new_with_framework(self.config.campaign.target.framework);

        // Initialize scheduler with budget
        let scheduler =
            ChainScheduler::new(chains.to_vec(), Duration::from_secs(chain_budget_secs));

        // Initialize corpus for persistence
        let output_dir = self.config.reporting.output_dir.clone();
        let corpus_path = std::path::PathBuf::from(&output_dir).join("chain_corpus.json");
        let mut corpus = ChainCorpus::load(&corpus_path)
            .unwrap_or_else(|_| ChainCorpus::with_storage(&corpus_path));

        let mut all_findings = Vec::new();
        let mut rng = match self.seed {
            Some(s) => ChaCha8Rng::seed_from_u64(s),
            None => ChaCha8Rng::from_entropy(),
        };

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
    pub(super) fn collect_circuit_configs(
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
    pub(super) fn compute_chain_coverage_bits(trace: &crate::chain_fuzzer::ChainTrace) -> u64 {
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
