use super::prelude::*;
use super::FuzzingEngine;

#[derive(Debug, Clone, Copy, PartialEq)]
struct ResumeAggregation {
    found_violation: bool,
    near_miss_score: f64,
    executions: usize,
    new_coverage: u64,
}

fn aggregate_resume_entries(
    entries: &[&crate::chain_fuzzer::ChainCorpusEntry],
) -> ResumeAggregation {
    let mut found_violation = false;
    let mut near_miss_score = 0.0f64;
    let mut executions = 0usize;
    let mut unique_coverage: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for entry in entries {
        found_violation |= entry.triggered_violation;
        near_miss_score = near_miss_score.max(entry.near_miss_score);
        executions = executions.saturating_add(entry.execution_count.max(1));
        // Failed traces are persisted with coverage_bits=0; this sentinel must not
        // contribute to resume coverage boosts.
        if entry.coverage_bits > 0 {
            unique_coverage.insert(entry.coverage_bits);
        }
    }

    ResumeAggregation {
        found_violation,
        near_miss_score,
        executions,
        new_coverage: unique_coverage.len() as u64,
    }
}

impl FuzzingEngine {
    pub async fn run_chains(
        &mut self,
        chains: &[crate::chain_fuzzer::ChainSpec],
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<Vec<crate::chain_fuzzer::ChainFinding>> {
        use crate::chain_fuzzer::{
            scheduler::ChainRunStats, ChainCorpus, ChainFinding, ChainMutator, ChainRunner,
            ChainScheduler, ChainShrinker, CrossStepInvariantChecker, DepthMetrics,
        };
        use anyhow::Context as _;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::time::{Duration, Instant};

        if chains.is_empty() {
            tracing::info!("No chain specifications provided");
            return Ok(Vec::new());
        }

        tracing::info!("Starting Mode 3 chain fuzzing with {} chains", chains.len());

        // Get chain fuzzing budget from config
        let additional = &self.config.campaign.parameters.additional;
        let chain_budget_secs =
            Self::additional_u64(additional, "chain_budget_seconds").unwrap_or(300);
        let chain_iterations =
            Self::additional_u64(additional, "chain_iterations").unwrap_or(1000) as usize;
        let chain_resume = Self::additional_bool(additional, "chain_resume").unwrap_or(false);
        let chain_step_timeout = Self::additional_u64(additional, "chain_step_timeout_ms")
            .map(Duration::from_millis)
            .or_else(|| {
                Self::additional_u64(additional, "chain_step_timeout_seconds")
                    .map(Duration::from_secs)
            })
            .unwrap_or(Duration::from_secs(30));

        // Build executor map from circuit configurations
        let mut executors = std::collections::HashMap::new();

        // Collect all circuit_refs and their path configurations from chains
        let circuit_configs = self.collect_circuit_configs(chains)?;

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
                            anyhow::bail!(
                                "CHAIN CIRCUIT LOAD FAILED: Circuit '{}' path contains invalid UTF-8: {:?}",
                                circuit_ref,
                                config.path
                            );
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
                            anyhow::bail!(
                                "CHAIN CIRCUIT LOAD FAILED: Circuit '{}' at {:?} failed to load: {}. \
                                 Chain fuzzing cannot proceed without a valid executor.",
                                circuit_ref,
                                config.path,
                                e
                            );
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
                                anyhow::bail!(
                                    "CHAIN CIRCUIT LOAD FAILED: Circuit '{}' failed to load: {}. \
                                     Chain fuzzing cannot proceed without a valid executor.",
                                    circuit_ref,
                                    e
                                );
                            }
                        }
                    } else {
                        anyhow::bail!(
                            "CHAIN CIRCUIT MISSING: No circuit path configured for '{}' and no file found. \
                             Add a 'circuits' mapping in your chain config to specify circuit paths.",
                            circuit_ref
                        );
                    }
                }
            };
            executors.insert(circuit_ref.clone(), executor);
        }

        let runner = match ChainRunner::new(executors) {
            Ok(runner) => runner.with_timeout(chain_step_timeout),
            Err(err) => {
                return Err(err.context("Failed to initialize chain runner"));
            }
        };

        // Phase 5 Fix (Milestone 5.3): Use framework-aware chain mutator
        // Previously used ChainMutator::new() default settings,
        // causing reduced mutation validity for real circuits.
        let allow_spec_mutations =
            Self::additional_bool(additional, "chain_allow_spec_mutations").unwrap_or(false);

        let mutator = if allow_spec_mutations {
            tracing::info!("Chain spec mutations: enabled");
            ChainMutator::new_with_framework(self.config.campaign.target.framework)
        } else {
            // Default: do not mutate chain structure (reorders/duplications) to avoid generating
            // misleading assertion violations and to keep throughput stable. Campaigns that want
            // structural mutations can opt-in with `chain_allow_spec_mutations: true`.
            tracing::info!("Chain spec mutations: disabled (inputs-only)");
            let weights = crate::chain_fuzzer::mutator::MutationWeights {
                step_reorder: 0.0,
                step_duplication: 0.0,
                ..crate::chain_fuzzer::mutator::MutationWeights::default()
            };
            ChainMutator::new_with_framework(self.config.campaign.target.framework)
                .with_weights(weights)
        };

        // Initialize scheduler with budget
        let mut scheduler =
            ChainScheduler::new(chains.to_vec(), Duration::from_secs(chain_budget_secs));

        // Initialize corpus for persistence
        let output_dir = self.config.reporting.output_dir.clone();
        let corpus_path = std::path::PathBuf::from(&output_dir).join("chain_corpus.json");
        let mut corpus = if chain_resume && corpus_path.exists() {
            match ChainCorpus::load(&corpus_path) {
                Ok(corpus) => corpus,
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("Failed to load chain corpus '{}'", corpus_path.display())
                    });
                }
            }
        } else {
            if !chain_resume && corpus_path.exists() {
                tracing::info!(
                    "Mode 3 resume disabled: starting a fresh chain corpus at '{}'",
                    corpus_path.display()
                );
            }
            ChainCorpus::with_storage(&corpus_path)
        };

        // Resume seeds and schedule priors from persisted corpus.
        let mut resume_inputs_by_chain: std::collections::HashMap<
            String,
            Vec<std::collections::HashMap<String, Vec<FieldElement>>>,
        > = std::collections::HashMap::new();
        if chain_resume && !corpus.is_empty() {
            for entry in corpus.entries() {
                resume_inputs_by_chain
                    .entry(entry.spec_name.clone())
                    .or_default()
                    .push(entry.get_inputs());
            }

            for chain in chains {
                let entries = corpus.entries_for_chain(&chain.name);
                if entries.is_empty() {
                    continue;
                }

                let resume = aggregate_resume_entries(&entries);

                scheduler.update_priority(&ChainRunStats {
                    chain_name: chain.name.clone(),
                    found_violation: resume.found_violation,
                    new_coverage: resume.new_coverage,
                    near_miss_score: resume.near_miss_score,
                    executions: resume.executions,
                    time_spent: Duration::from_millis(0),
                });
            }

            tracing::info!(
                "Mode 3 resume: loaded {} corpus seed entries across {} chains",
                resume_inputs_by_chain
                    .values()
                    .map(|v| v.len())
                    .sum::<usize>(),
                resume_inputs_by_chain.len()
            );
        }

        let mut all_findings = Vec::new();
        let mut rng = match self.seed {
            Some(s) => ChaCha8Rng::seed_from_u64(s),
            None => ChaCha8Rng::from_entropy(),
        };

        // Optional per-circuit baseline inputs for chain fuzzing.
        //
        // This is critical for cross-circuit chains where downstream circuits require a valid
        // structured witness (e.g. full query circuits). A baseline vector is used as a stable
        // starting point, and `from_prior_output` wiring overlays only the mapped indices.
        //
        // YAML shape (campaign.parameters.additional via flatten):
        //
        //   chain_seed_inputs:
        //     nullify: "campaigns/zk0d/nullify_passthrough_wrapper_seed_flat.json"
        //     query:   "campaigns/zk0d/credentialAtomicQueryV3_16_16_64_seed_flat.json"
        //
        // Each file may be:
        // - a JSON array: ["0x..", ...]
        // - a corpus test_case JSON object: { "inputs": ["0x..", ...], ... }
        let chain_seed_inputs_by_ref: std::collections::HashMap<String, Vec<FieldElement>> = {
            use std::collections::HashMap;

            fn parse_field_element_str(raw: &str) -> anyhow::Result<FieldElement> {
                let trimmed = raw.trim();
                if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                    return FieldElement::from_hex(trimmed);
                }

                // Decimal string
                use num_bigint::BigUint;
                let value = BigUint::parse_bytes(trimmed.as_bytes(), 10)
                    .ok_or_else(|| anyhow::anyhow!("Invalid decimal field element: {}", trimmed))?;
                let bytes = value.to_bytes_be();
                if bytes.len() > 32 {
                    anyhow::bail!(
                        "Decimal field element too large: {} bytes (max 32)",
                        bytes.len()
                    );
                }
                Ok(FieldElement::from_bytes(&bytes))
            }

            fn load_seed_vec_from_json(
                path: &std::path::Path,
            ) -> anyhow::Result<Vec<FieldElement>> {
                let raw = std::fs::read_to_string(path)
                    .with_context(|| format!("Read chain seed inputs: {}", path.display()))?;
                let json: serde_json::Value = serde_json::from_str(&raw)
                    .with_context(|| format!("Parse chain seed JSON: {}", path.display()))?;

                let arr = match json {
                    serde_json::Value::Array(a) => a,
                    serde_json::Value::Object(mut o) => match o.remove("inputs") {
                        Some(serde_json::Value::Array(a)) => a,
                        Some(_) => anyhow::bail!(
                            "Chain seed object must contain an 'inputs' JSON array: {}",
                            path.display()
                        ),
                        None => anyhow::bail!(
                            "Chain seed object must contain an 'inputs' JSON array: {}",
                            path.display()
                        ),
                    },
                    _ => anyhow::bail!(
                        "Chain seed file must be a JSON array or an object with 'inputs': {}",
                        path.display()
                    ),
                };

                let mut out = Vec::with_capacity(arr.len());
                for (i, v) in arr.into_iter().enumerate() {
                    let fe = match v {
                        serde_json::Value::String(s) => {
                            parse_field_element_str(&s).with_context(|| {
                                format!("Parse chain seed element {} from {}", i, path.display())
                            })?
                        }
                        serde_json::Value::Number(n) => parse_field_element_str(&n.to_string())
                            .with_context(|| {
                                format!("Parse chain seed element {} from {}", i, path.display())
                            })?,
                        _ => anyhow::bail!(
                            "Chain seed element {} must be a string or number: {}",
                            i,
                            path.display()
                        ),
                    };
                    out.push(fe);
                }
                Ok(out)
            }

            match additional.get("chain_seed_inputs") {
                Some(serde_yaml::Value::Mapping(map)) => {
                    let mut out: HashMap<String, Vec<FieldElement>> = HashMap::new();
                    for (k, v) in map {
                        let Some(circuit_ref) = k.as_str() else {
                            anyhow::bail!("chain_seed_inputs has a non-string key: {:?}", k);
                        };
                        let Some(path_str) = v.as_str() else {
                            anyhow::bail!(
                                "chain_seed_inputs[{}] must be a string path",
                                circuit_ref
                            );
                        };
                        let path = std::path::Path::new(path_str);
                        match load_seed_vec_from_json(path) {
                            Ok(vec) => {
                                tracing::info!(
                                    "Loaded chain seed inputs for '{}': {} ({} elems)",
                                    circuit_ref,
                                    path.display(),
                                    vec.len()
                                );
                                out.insert(circuit_ref.to_string(), vec);
                            }
                            Err(e) => {
                                anyhow::bail!(
                                    "Failed to load chain seed inputs for '{}' from {}: {:#}",
                                    circuit_ref,
                                    path.display(),
                                    e
                                );
                            }
                        }
                    }
                    out
                }
                Some(other) => {
                    anyhow::bail!(
                        "chain_seed_inputs must be a mapping of circuit_ref -> json_path; got {:?}",
                        other
                    );
                }
                None => HashMap::new(),
            }
        };

        // Optional per-circuit mutation index mask.
        //
        // When provided, only the listed indices are allowed to remain mutated for that circuit.
        // All other indices are reset back to the baseline seed inputs (if available). This helps
        // keep deep chains executable by preserving known-good structure while mutating specific
        // "safe" knobs.
        //
        // YAML shape (campaign.parameters.additional via flatten):
        //
        //   chain_mutate_indices:
        //     nullify: [4]
        //
        // For the nullify wrapper this means mutate only `nullifierSessionID`, while keeping
        // genesis/profile/schema/verifier pinned to seed.
        let chain_mutate_indices_by_ref: std::collections::HashMap<
            String,
            std::collections::HashSet<usize>,
        > = {
            use std::collections::{HashMap, HashSet};

            match additional.get("chain_mutate_indices") {
                Some(serde_yaml::Value::Mapping(map)) => {
                    let mut out: HashMap<String, HashSet<usize>> = HashMap::new();
                    for (k, v) in map {
                        let Some(circuit_ref) = k.as_str() else {
                            anyhow::bail!("chain_mutate_indices has a non-string key: {:?}", k);
                        };
                        let Some(seq) = v.as_sequence() else {
                            anyhow::bail!(
                                "chain_mutate_indices[{}] must be a list of indices",
                                circuit_ref
                            );
                        };

                        let mut indices = HashSet::new();
                        for item in seq {
                            match item.as_u64() {
                                Some(i) => {
                                    indices.insert(i as usize);
                                }
                                None => {
                                    anyhow::bail!(
                                        "chain_mutate_indices[{}] contains non-integer entry",
                                        circuit_ref
                                    );
                                }
                            }
                        }

                        if !indices.is_empty() {
                            tracing::info!(
                                "Loaded chain mutation mask for '{}': {:?}",
                                circuit_ref,
                                indices
                            );
                            out.insert(circuit_ref.to_string(), indices);
                        }
                    }
                    out
                }
                Some(other) => {
                    anyhow::bail!(
                        "chain_mutate_indices must be a mapping of circuit_ref -> [indices]; got {:?}",
                        other
                    );
                }
                None => HashMap::new(),
            }
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
        let mut resume_seed_index: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let global_budget = Duration::from_secs(chain_budget_secs);
        let global_start = Instant::now();
        let mut abort_remaining_chains = false;

        // Run chains according to schedule
        let allocations = scheduler.allocate();

        for allocation in &allocations {
            if abort_remaining_chains {
                tracing::warn!("Stopping chain campaign early after timeout-safe abort condition");
                break;
            }
            if global_start.elapsed() >= global_budget {
                tracing::info!("Global chain budget exhausted before scheduling next chain");
                break;
            }

            let chain = &allocation.spec;
            let remaining_global = global_budget.saturating_sub(global_start.elapsed());
            let chain_budget = allocation.budget.min(remaining_global);
            if chain_budget.is_zero() {
                tracing::info!("No remaining global chain budget for '{}'", chain.name);
                break;
            }
            let chain_start = Instant::now();

            if let Some(p) = progress {
                p.log_message(&format!(
                    "Chain: {} (budget: {:?})",
                    chain.name, chain_budget
                ));
            }

            // Initial inputs (seeded if available; otherwise generated fresh)
            let mut current_inputs = chain_seed_inputs_by_ref.clone();
            if let Some(entries) = resume_inputs_by_chain.get(&chain.name) {
                if !entries.is_empty() {
                    let cursor = resume_seed_index
                        .entry(chain.name.clone())
                        .or_insert(0usize);
                    let resume_inputs = &entries[*cursor % entries.len()];
                    for (circuit_ref, values) in resume_inputs {
                        current_inputs.insert(circuit_ref.clone(), values.clone());
                    }
                    *cursor = cursor.wrapping_add(1);
                }
            }
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

            let mut ok_completed = 0usize;
            let mut failed = 0usize;
            let mut failed_by_step: std::collections::HashMap<usize, usize> =
                std::collections::HashMap::new();
            let mut sample_errors: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            let mut iterations = 0;
            let mut current_spec: Option<crate::chain_fuzzer::ChainSpec> = None;

            while chain_start.elapsed() < chain_budget
                && iterations < chain_iterations
                && global_start.elapsed() < global_budget
                && !abort_remaining_chains
            {
                let spec_to_use = match current_spec.as_ref() {
                    Some(spec) => spec,
                    None => chain,
                };

                // Execute chain
                let result = runner.execute(spec_to_use, &current_inputs, &mut rng);

                if result.completed {
                    ok_completed += 1;
                    // Rebuild checker if spec was mutated
                    let active_checker = if current_spec.is_some() {
                        CrossStepInvariantChecker::from_spec(spec_to_use)
                    } else {
                        CrossStepInvariantChecker::from_spec(chain)
                    };

                    let violations = active_checker.check(&result.trace);
                    let triggered_violation = !violations.is_empty();

                    for violation in violations {
                        let shrink_runner = match ChainRunner::new(runner.executors.clone()) {
                            Ok(value) => value,
                            Err(err) => {
                                anyhow::bail!("Failed to initialize shrink runner: {}", err);
                            }
                        }
                        .with_timeout(chain_step_timeout);
                        let shrinker = ChainShrinker::new(
                            shrink_runner,
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

                    let coverage_bits = Self::compute_chain_coverage_bits(&result.trace)
                        .with_context(|| {
                            format!(
                                "CHAIN COVERAGE ERROR: unable to compute coverage for chain '{}'",
                                chain.name
                            )
                        })?;
                    let mut corpus_entry = crate::chain_fuzzer::ChainCorpusEntry::new(
                        &chain.name,
                        current_inputs.clone(),
                        coverage_bits,
                        result.trace.depth(),
                    );
                    if triggered_violation {
                        corpus_entry = corpus_entry.with_violation().with_near_miss(1.0);
                    }
                    corpus.add(corpus_entry);
                } else {
                    failed += 1;
                    if let Some(failed_at) = result.failed_at {
                        *failed_by_step.entry(failed_at).or_insert(0) += 1;
                        if let Some(step) = result.trace.steps.get(failed_at) {
                            if let Some(err) = &step.error {
                                if sample_errors.len() < 3 {
                                    sample_errors.insert(err.clone());
                                }
                                if err.contains("Step timed out") {
                                    tracing::error!(
                                        "Chain '{}' hit a step timeout; aborting remaining chains \
                                         to avoid detached timeout-worker buildup",
                                        chain.name
                                    );
                                    abort_remaining_chains = true;
                                }
                            }
                        }
                    }

                    // Preserve failed-chain attempts in corpus with near-miss signal based on how
                    // far execution progressed. This allows resume scheduling to prioritize chains
                    // that consistently reach deep steps but still fail to satisfy full contracts.
                    let depth = result.trace.depth();
                    let denom = spec_to_use.len().max(1) as f64;
                    let progress_ratio = ((depth as f64) / denom).clamp(0.0, 1.0);
                    let near_miss_score = (progress_ratio * 0.9).clamp(0.0, 0.99);
                    if near_miss_score > 0.0 {
                        corpus.add(
                            crate::chain_fuzzer::ChainCorpusEntry::new(
                                &chain.name,
                                current_inputs.clone(),
                                0,
                                depth,
                            )
                            .with_near_miss(near_miss_score),
                        );
                    }
                }

                if abort_remaining_chains {
                    break;
                }

                // Mutate for next iteration (may produce a modified spec)
                let mutation = mutator.mutate(spec_to_use, &current_inputs, &mut rng);
                current_inputs = mutation.inputs;

                // Apply optional mutation masks to keep specified circuits near a valid baseline.
                if !chain_mutate_indices_by_ref.is_empty() {
                    for (circuit_ref, allowed_indices) in &chain_mutate_indices_by_ref {
                        let Some(inputs) = current_inputs.get_mut(circuit_ref) else {
                            anyhow::bail!(
                                "chain_mutate_indices references unknown circuit_ref '{}'",
                                circuit_ref
                            );
                        };
                        let Some(seed) = chain_seed_inputs_by_ref.get(circuit_ref) else {
                            anyhow::bail!(
                                "chain_mutate_indices for '{}' requires chain_seed_inputs entry",
                                circuit_ref
                            );
                        };

                        for idx in 0..inputs.len() {
                            if !allowed_indices.contains(&idx) && idx < seed.len() {
                                inputs[idx] = seed[idx].clone();
                            }
                        }
                    }
                }

                current_spec = mutation.spec;
                iterations += 1;

                if let Some(p) = progress {
                    p.inc();
                }
            }

            tracing::info!(
                "Chain {} completed: {} iterations (ok={}, failed={}, failed_by_step={:?}), {} findings",
                chain.name,
                iterations,
                ok_completed,
                failed,
                failed_by_step,
                all_findings
                    .iter()
                    .filter(|f| f.spec_name == chain.name)
                    .count()
            );

            if ok_completed == 0 && failed > 0 && !sample_errors.is_empty() {
                tracing::warn!(
                    "Chain {} had 0 completed traces; sample errors: {:?}",
                    chain.name,
                    sample_errors
                );
            }
            if abort_remaining_chains {
                break;
            }
        }

        // Save corpus
        corpus
            .save()
            .with_context(|| "Failed to save chain corpus".to_string())?;

        // Compute and log metrics
        let metrics = DepthMetrics::new(all_findings.clone());
        let summary = metrics.summary();
        tracing::info!(
            "Chain fuzzing complete: {} findings, D={:.2}, P_deep={:.2}%",
            summary.total_findings,
            summary.d_mean,
            summary.p_deep * 100.0
        );

        Ok(all_findings)
    }

    /// Collect circuit configurations from all chain specs
    /// Returns a map of circuit_ref -> optional path configuration
    pub(super) fn collect_circuit_configs(
        &self,
        chains: &[crate::chain_fuzzer::ChainSpec],
    ) -> anyhow::Result<
        std::collections::HashMap<String, Option<crate::config::v2::CircuitPathConfig>>,
    > {
        use std::collections::HashMap;

        let mut circuit_configs: HashMap<String, Option<crate::config::v2::CircuitPathConfig>> =
            HashMap::new();
        let mut owner_chain_by_ref: HashMap<String, String> = HashMap::new();

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
                    match circuit_configs
                        .get(ref_name)
                        .and_then(|value| value.as_ref())
                    {
                        Some(existing) => {
                            let same_path = existing.path == path_config.path;
                            let same_component =
                                existing.main_component == path_config.main_component;
                            let same_framework = existing.framework == path_config.framework;
                            if !same_path || !same_component || !same_framework {
                                let owner = owner_chain_by_ref
                                    .get(ref_name)
                                    .cloned()
                                    .unwrap_or_else(|| "<unknown>".to_string());
                                anyhow::bail!(
                                    "Conflicting circuit config for ref '{}': chain '{}' sets {:?} but chain '{}' sets {:?}. \
                                     Use unique circuit_ref aliases per distinct circuit.",
                                    ref_name,
                                    owner,
                                    existing.path,
                                    chain_config.name,
                                    path_config.path
                                );
                            }
                        }
                        None => {
                            owner_chain_by_ref.insert(ref_name.clone(), chain_config.name.clone());
                            circuit_configs.insert(ref_name.clone(), Some(path_config.clone()));
                        }
                    }
                }
            }
        }

        Ok(circuit_configs)
    }

    /// Compute coverage bits from a chain trace
    /// Combines coverage from all steps into a single u64 hash
    pub(super) fn compute_chain_coverage_bits(
        trace: &crate::chain_fuzzer::ChainTrace,
    ) -> anyhow::Result<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        for step in &trace.steps {
            // Hash the constraints hit in each step.
            let mut constraints: Vec<_> = step.constraints_hit.iter().copied().collect();
            constraints.sort_unstable();

            if constraints.is_empty() {
                tracing::error!(
                    "Missing constraint coverage for chain step {} ('{}'); refusing fallback hashing",
                    step.step_index,
                    step.circuit_ref
                );
                anyhow::bail!(
                    "Missing constraint coverage for chain step {} ('{}'). \
                     Chain coverage requires real constraint hits and cannot fall back to output hashing.",
                    step.step_index,
                    step.circuit_ref
                );
            } else {
                for constraint_id in constraints {
                    constraint_id.hash(&mut hasher);
                }
            }

            // Also factor in step success and circuit ref
            step.success.hash(&mut hasher);
            step.circuit_ref.hash(&mut hasher);
        }

        Ok(hasher.finish())
    }
}
