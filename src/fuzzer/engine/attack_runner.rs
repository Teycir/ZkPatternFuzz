use super::prelude::*;
use super::FuzzingEngine;

trait OptionValueExt<T> {
    fn or_value(self, default: T) -> T;
    fn or_else_value<F>(self, default: F) -> T
    where
        F: FnOnce() -> T;
}

impl<T> OptionValueExt<T> for Option<T> {
    fn or_value(self, default: T) -> T {
        match self {
            Some(value) => value,
            None => default,
        }
    }

    fn or_else_value<F>(self, default: F) -> T
    where
        F: FnOnce() -> T,
    {
        match self {
            Some(value) => value,
            None => default(),
        }
    }
}

fn deterministic_attack_cap(
    additional: &crate::config::AdditionalConfig,
    evidence_mode: bool,
    floor: usize,
    per_attack_cap_key: &str,
) -> Option<(usize, usize, usize)> {
    let deterministic =
        super::FuzzingEngine::additional_bool(additional, "evidence_deterministic_runtime")
            .unwrap_or(evidence_mode);
    if !deterministic {
        return None;
    }

    let iterations = super::FuzzingEngine::additional_u64(additional, "max_iterations")
        .or_else(|| super::FuzzingEngine::additional_u64(additional, "fuzzing_iterations"))
        .unwrap_or(1000)
        .max(1) as usize;
    let multiplier =
        super::FuzzingEngine::additional_usize(additional, "evidence_attack_budget_multiplier")
            .unwrap_or(4)
            .max(1);

    let auto_cap = iterations.saturating_mul(multiplier).max(floor);
    let global_cap =
        super::FuzzingEngine::additional_usize(additional, "evidence_attack_budget_cap")
            .unwrap_or(auto_cap)
            .max(floor);
    let cap = super::FuzzingEngine::additional_usize(additional, per_attack_cap_key)
        .unwrap_or(global_cap)
        .max(floor);

    Some((cap, iterations, multiplier))
}

fn strict_attack_floor(
    additional: &crate::config::AdditionalConfig,
    configured: usize,
    minimum: usize,
    label: &str,
) -> usize {
    let evidence_mode =
        super::FuzzingEngine::additional_bool(additional, "evidence_mode").unwrap_or(false);
    let engagement_strict = super::FuzzingEngine::additional_bool(additional, "engagement_strict")
        .unwrap_or(evidence_mode);
    let deterministic_runtime =
        super::FuzzingEngine::additional_bool(additional, "evidence_deterministic_runtime")
            .unwrap_or(evidence_mode);

    if deterministic_runtime {
        return configured;
    }

    if !engagement_strict || configured >= minimum {
        return configured;
    }

    tracing::info!(
        "Strict mode floor applied: {} {} -> {}",
        label,
        configured,
        minimum
    );
    minimum
}

impl FuzzingEngine {
    fn bounded_attack_units(
        &self,
        configured: usize,
        floor: usize,
        per_attack_cap_key: &str,
        label: &str,
    ) -> usize {
        let configured = configured.max(floor);
        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);

        let Some((cap, iterations, multiplier)) =
            deterministic_attack_cap(additional, evidence_mode, floor, per_attack_cap_key)
        else {
            return configured;
        };

        let effective = configured.min(cap).max(floor);
        if effective < configured {
            tracing::warn!(
                "Deterministic attack budget applied: {} {} -> {} (cap={}, iterations={}, multiplier={}, key={})",
                label,
                configured,
                effective,
                cap,
                iterations,
                multiplier,
                per_attack_cap_key
            );
        }
        effective
    }

    pub(super) async fn run_underconstrained_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let configured_witness_pairs: usize = config
            .get("witness_pairs")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let witness_pairs = self.bounded_attack_units(
            configured_witness_pairs,
            1,
            "underconstrained_witness_pairs_cap",
            "underconstrained.witness_pairs",
        );

        tracing::info!(
            "Testing {} witness pairs for underconstrained circuits",
            witness_pairs
        );
        {
            use crate::oracles::UnderconstrainedDetector;
            let tolerance = config.get("tolerance").and_then(|v| v.as_f64());
            let detector = if let Some(tol) = tolerance {
                UnderconstrainedDetector::new(witness_pairs).with_tolerance(tol)
            } else {
                UnderconstrainedDetector::new(witness_pairs)
            };
            self.add_attack_findings(&detector, witness_pairs, progress)?;
        }

        let inputs_reconciled = self
            .config
            .campaign
            .parameters
            .additional
            .get("inputs_reconciled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Determine public input positions in the test_case.inputs vector.
        // If input schema was reconciled at runtime, ignore stale per-template
        // public_input_* overrides and derive positions from the live executor.
        let public_input_positions = if inputs_reconciled {
            if config.get("public_input_names").is_some()
                || config.get("public_input_positions").is_some()
            {
                anyhow::bail!(
                    "Underconstrained attack config contains public_input_names/public_input_positions, \
                     but inputs were reconciled to the live target interface. \
                     Remove hardcoded public-input mappings from generic YAML templates."
                );
            }
            let capped = self
                .executor
                .num_public_inputs()
                .min(self.config.inputs.len());
            tracing::info!(
                "Input schema reconciled: deriving {} public input positions from executor metadata",
                capped
            );
            (0..capped).collect()
        } else {
            Self::resolve_public_input_positions(
                config,
                &self.config.inputs,
                self.executor.num_public_inputs(),
            )
        };

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
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping underconstrained attack witness generation early: wall-clock timeout reached"
                );
                break;
            }
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
        let indexed_results: Vec<(usize, ExecutionResult)> =
            if let Some(ref pool) = self.thread_pool {
                // Reuse cached thread pool instead of creating new one per attack
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
                // Fall back to rayon global pool, still parallel.
                test_cases
                    .par_iter()
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

                self.with_findings_write(|store| store.push(finding.clone()))?;

                if let Some(p) = progress {
                    p.log_finding("CRITICAL", &finding.description);
                }
            }
        }

        self.run_frozen_wire_detector(config, progress)?;

        Ok(())
    }

    pub(super) fn run_frozen_wire_detector(
        &self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::FrozenWireDetector;
        use std::collections::HashSet;

        let section = config.get("frozen_wire");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        if !enabled {
            return Ok(());
        }

        let min_samples = section
            .and_then(|v| v.get("min_samples"))
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;

        let mut constants = HashSet::new();
        if let Some(list) = section
            .and_then(|v| v.get("known_constants"))
            .and_then(|v| v.as_sequence())
        {
            for entry in list {
                let parsed = match entry {
                    serde_yaml::Value::Number(n) => n.as_u64().map(|v| v as usize),
                    serde_yaml::Value::String(s) => match s.parse::<usize>() {
                        Ok(value) => Some(value),
                        Err(err) => {
                            tracing::debug!(
                                "Invalid known_constants entry '{}' in underconstrained config: {}",
                                s,
                                err
                            );
                            None
                        }
                    },
                    _ => None,
                };
                if let Some(idx) = parsed {
                    constants.insert(idx);
                }
            }
        }

        let witnesses = self.collect_corpus_inputs(min_samples.max(1));
        if witnesses.is_empty() {
            anyhow::bail!("Frozen wire detector requires corpus witnesses, but none are available");
        }

        let detector = if constants.is_empty() {
            FrozenWireDetector::new().with_min_samples(min_samples)
        } else {
            FrozenWireDetector::new()
                .with_min_samples(min_samples)
                .with_known_constants(constants)
        };

        let findings = detector.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Underconstrained, progress)?;
        Ok(())
    }

    pub(super) fn resolve_public_input_positions(
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
                    serde_yaml::Value::String(s) => match s.parse::<usize>() {
                        Ok(value) => Some(value),
                        Err(err) => {
                            tracing::debug!(
                                "Invalid public_input_positions entry '{}': {}",
                                s,
                                err
                            );
                            None
                        }
                    },
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

    pub(super) fn parse_fixed_public_inputs(
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

    pub(super) async fn run_soundness_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let num_public = self.executor.num_public_inputs();
        if num_public == 0 {
            tracing::warn!(
                "Skipping soundness attack: circuit exposes 0 public inputs, so proof-forgery checks are inapplicable"
            );
            return Ok(());
        }

        let configured_forge_attempts: usize = config
            .get("forge_attempts")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let configured_forge_attempts = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_forge_attempts,
            1000,
            "soundness.forge_attempts",
        );
        let forge_attempts = self.bounded_attack_units(
            configured_forge_attempts,
            1,
            "soundness_forge_attempts_cap",
            "soundness.forge_attempts",
        );

        let mutation_rate: f64 = config
            .get("mutation_rate")
            .and_then(|v| v.as_f64())
            .or_value(0.1);

        tracing::info!("Attempting {} proof forgeries", forge_attempts);
        {
            use crate::oracles::SoundnessTester;
            let tester = SoundnessTester::new()
                .with_forge_attempts(forge_attempts)
                .with_mutation_rate(mutation_rate);
            self.add_attack_findings(&tester, forge_attempts, progress)?;
        }

        let corpus_witnesses = self.collect_corpus_inputs(forge_attempts.max(1));
        let corpus_seed_count = corpus_witnesses.len().min(forge_attempts);
        if corpus_seed_count > 0 {
            tracing::info!(
                "Soundness attack seeded {} witness(es) from corpus before random generation",
                corpus_seed_count
            );
        } else {
            tracing::warn!(
                "Soundness attack has no corpus witnesses; relying on random witness generation"
            );
        }

        let mut successful_proofs = 0usize;
        let mut proof_generation_failures = 0usize;
        let mut last_proof_error: Option<String> = None;

        for attempt in 0..forge_attempts {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping soundness attack at attempt {}/{}: wall-clock timeout reached",
                    attempt,
                    forge_attempts
                );
                break;
            }
            let valid_inputs = if attempt < corpus_witnesses.len() {
                corpus_witnesses[attempt].clone()
            } else {
                self.generate_test_case().inputs
            };

            let valid_proof = match self.executor.prove(&valid_inputs) {
                Ok(proof) => proof,
                Err(err) => {
                    proof_generation_failures += 1;
                    last_proof_error = Some(err.to_string());
                    tracing::debug!(
                        "Soundness attempt {}/{} skipped: witness failed proof generation: {}",
                        attempt + 1,
                        forge_attempts,
                        err
                    );
                    if let Some(p) = progress {
                        p.inc();
                    }
                    continue;
                }
            };
            successful_proofs += 1;

            let valid_public: Vec<FieldElement> =
                valid_inputs.iter().take(num_public).cloned().collect();

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

            // Enforce at least one public-input mutation per attempt.
            let mutated_public = if mutated_public == valid_public {
                let mut forced = valid_public.clone();
                let idx = self.core.rng_mut().gen_range(0..forced.len());
                let mut bytes = forced[idx].0;
                bytes[31] ^= 0x01;
                forced[idx] = FieldElement(bytes);
                forced
            } else {
                mutated_public
            };

            // Try to verify with mutated inputs
            let verified = self.executor.verify(&valid_proof, &mutated_public)?;
            let oracle_findings = self.core.check_proof_forgery(
                &valid_inputs,
                &mutated_public,
                &valid_proof,
                verified,
            );

            if verified {
                // Always store the PoC finding with proof bytes so evidence
                // is preserved regardless of oracle findings.
                let finding = Finding {
                    attack_type: AttackType::Soundness,
                    severity: Severity::Critical,
                    description: "Proof verified with mutated inputs - soundness violation!"
                        .to_string(),
                    poc: super::ProofOfConcept {
                        witness_a: valid_inputs,
                        witness_b: None,
                        public_inputs: mutated_public,
                        proof: Some(valid_proof),
                    },
                    location: None,
                };

                self.with_findings_write(|store| store.push(finding.clone()))?;

                if let Some(p) = progress {
                    p.log_finding("CRITICAL", &finding.description);
                    for of in &oracle_findings {
                        p.log_finding("CRITICAL", &of.description);
                    }
                }
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        if successful_proofs == 0 {
            let detail = last_proof_error.unwrap_or_else(|| "unknown error".to_string());
            tracing::warn!(
                "Skipping active soundness verification: no valid base proof was generated across {} attempts ({} failures). Last error: {}",
                forge_attempts,
                proof_generation_failures,
                detail
            );
            return Ok(());
        }

        if proof_generation_failures > 0 {
            tracing::warn!(
                "Soundness attack skipped {}/{} attempts due to proof generation failures",
                proof_generation_failures,
                forge_attempts
            );
        }

        self.run_proof_malleability_attack(config, AttackType::Soundness, progress)?;
        self.run_determinism_check(config, progress)?;
        self.run_setup_poisoning_attack(config, AttackType::Soundness, progress)?;

        Ok(())
    }

    pub(super) fn run_proof_malleability_attack(
        &self,
        config: &serde_yaml::Value,
        finding_attack_type: AttackType,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::ProofMalleabilityScanner;

        let section = config.get("proof_malleability");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        if !enabled {
            return Ok(());
        }

        let proof_samples = section
            .and_then(|v| v.get("proof_samples"))
            .and_then(|v| v.as_u64())
            .or_value(10) as usize;
        let random_mutations = section
            .and_then(|v| v.get("random_mutations"))
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;
        let structured_mutations = section
            .and_then(|v| v.get("structured_mutations"))
            .and_then(|v| v.as_bool())
            .or_value(true);

        let witnesses = self.collect_corpus_inputs(proof_samples.max(1));
        if witnesses.is_empty() {
            anyhow::bail!(
                "Proof malleability scanner requires corpus witnesses, but none are available"
            );
        }

        let scanner = ProofMalleabilityScanner::new()
            .with_proof_samples(proof_samples)
            .with_random_mutations(random_mutations)
            .with_structured_mutations(structured_mutations);

        let findings = scanner.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, finding_attack_type, progress)?;
        Ok(())
    }

    pub(super) fn run_determinism_check(
        &self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::DeterminismOracle;

        let section = config.get("determinism");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        if !enabled {
            return Ok(());
        }

        let repetitions = section
            .and_then(|v| v.get("repetitions"))
            .and_then(|v| v.as_u64())
            .or_value(5) as usize;
        let sample_count = section
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_value(50) as usize;

        let witnesses = self.collect_corpus_inputs(sample_count.max(1));
        if witnesses.is_empty() {
            anyhow::bail!("Determinism oracle requires corpus witnesses, but none are available");
        }

        let oracle = DeterminismOracle::new()
            .with_repetitions(repetitions)
            .with_sample_count(sample_count);

        let findings = oracle.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Soundness, progress)?;
        Ok(())
    }

    pub(super) fn run_setup_poisoning_attack(
        &self,
        config: &serde_yaml::Value,
        finding_attack_type: AttackType,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{TrustedSetupAttack, TrustedSetupConfig};
        use std::path::PathBuf;

        let trusted_setup_config = TrustedSetupConfig::from_yaml(config);
        if !trusted_setup_config.enabled {
            return Ok(());
        }

        let attempts = trusted_setup_config.attempts.max(1);
        if attempts == 0 {
            anyhow::bail!("Trusted setup test requires attempts > 0");
        }

        let ptau_a = trusted_setup_config.ptau_file_a.as_deref();
        let ptau_b = trusted_setup_config.ptau_file_b.as_deref();

        let Some(ptau_a) = ptau_a else {
            anyhow::bail!("Trusted setup test missing required key: ptau_file_a");
        };
        let Some(ptau_b) = ptau_b else {
            anyhow::bail!("Trusted setup test missing required key: ptau_file_b");
        };
        if ptau_a == ptau_b {
            anyhow::bail!("Trusted setup test requires distinct ptau_file_a and ptau_file_b");
        }

        if !std::path::Path::new(ptau_a).exists() {
            anyhow::bail!("Trusted setup test ptau_file_a not found: {}", ptau_a);
        }
        if !std::path::Path::new(ptau_b).exists() {
            anyhow::bail!("Trusted setup test ptau_file_b not found: {}", ptau_b);
        }

        let circuit_path = self
            .config
            .campaign
            .target
            .circuit_path
            .to_str()
            .or_value("");
        if circuit_path.is_empty() {
            anyhow::bail!("Trusted setup test requires a valid UTF-8 circuit path");
        }

        let backend = self.config.campaign.target.framework;
        let main_component = &self.config.campaign.target.main_component;

        let mut options_a = self.executor_factory_options.clone();
        options_a.circom_ptau_path = Some(PathBuf::from(ptau_a));
        options_a.circom_auto_setup_keys = true;

        let mut options_b = self.executor_factory_options.clone();
        options_b.circom_ptau_path = Some(PathBuf::from(ptau_b));
        options_b.circom_auto_setup_keys = true;

        let executor_a = match ExecutorFactory::create_with_options(
            backend,
            circuit_path,
            main_component,
            &options_a,
        ) {
            Ok(exec) => exec,
            Err(e) => {
                anyhow::bail!("Trusted setup test failed to create executor A: {}", e);
            }
        };

        let executor_b = match ExecutorFactory::create_with_options(
            backend,
            circuit_path,
            main_component,
            &options_b,
        ) {
            Ok(exec) => exec,
            Err(e) => {
                anyhow::bail!("Trusted setup test failed to create executor B: {}", e);
            }
        };

        let witnesses = self.collect_corpus_inputs(attempts.max(1));
        if witnesses.is_empty() {
            anyhow::bail!("Trusted setup test requires corpus witnesses, but none are available");
        }

        let trusted_setup_attack = TrustedSetupAttack::new(trusted_setup_config);
        let mut findings =
            trusted_setup_attack.run(executor_a.as_ref(), executor_b.as_ref(), &witnesses);
        for finding in &mut findings {
            finding.attack_type = finding_attack_type.clone();
        }
        self.record_custom_findings(findings, finding_attack_type, progress)?;
        Ok(())
    }

    pub(super) async fn run_arithmetic_attack(
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
            .or_else_value(|| {
                vec![
                    "0".to_string(),
                    "1".to_string(),
                    "p-1".to_string(),
                    "p".to_string(),
                ]
            });

        tracing::info!("Testing {} arithmetic edge cases", test_values.len());
        {
            use crate::oracles::ArithmeticTester;
            let tester = ArithmeticTester::new().with_test_values(test_values.clone());
            self.add_attack_findings(&tester, test_values.len(), progress)?;
        }

        let field_modulus = self.get_field_modulus();

        for value in test_values {
            let expanded =
                match crate::config::parser::expand_value_placeholder(&value, &field_modulus) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        anyhow::bail!("Invalid arithmetic test value '{}': {}", value, e);
                    }
                };
            let mut fe_bytes = [0u8; 32];
            let start = 32_usize.saturating_sub(expanded.len());
            fe_bytes[start..].copy_from_slice(&expanded[..expanded.len().min(32)]);
            let fe = FieldElement(fe_bytes);

            let test_case = self.create_test_case_with_value(fe);
            let result = self.execute_and_learn(&test_case);

            if result.success && self.detect_overflow_indicator(&test_case, &result.outputs) {
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

                self.with_findings_write(|store| store.push(finding.clone()))?;

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

    pub(super) async fn run_collision_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        let configured_samples: usize = config
            .get("samples")
            .and_then(|v| v.as_u64())
            .or_value(10000) as usize;
        let samples = self.bounded_attack_units(
            configured_samples,
            1,
            "collision_samples_cap",
            "collision.samples",
        );

        tracing::info!("Running collision detection with {} samples", samples);
        {
            use crate::oracles::CollisionDetector;
            let detector = CollisionDetector::new(samples);
            self.add_attack_findings(&detector, samples, progress)?;
        }

        // Generate and execute in parallel
        let mut test_cases = Vec::with_capacity(samples);
        for _ in 0..samples {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping collision attack witness generation early: wall-clock timeout reached"
                );
                break;
            }
            test_cases.push(self.generate_test_case());
        }

        let executor = self.executor.clone();
        let indexed_results: Vec<(usize, ExecutionResult)> =
            if let Some(ref pool) = self.thread_pool {
                // Reuse cached thread pool instead of creating new one per attack
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
                // Fall back to rayon global pool, still parallel.
                test_cases
                    .par_iter()
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

                        self.with_findings_write(|store| store.push(finding.clone()))?;

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

        self.run_nullifier_replay_attack(config, AttackType::Collision, progress)?;

        Ok(())
    }

    pub(super) fn run_nullifier_replay_attack(
        &self,
        config: &serde_yaml::Value,
        finding_attack_type: AttackType,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::NullifierReplayScanner;

        let section = config.get("nullifier_replay");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        if !enabled {
            return Ok(());
        }

        let replay_attempts = section
            .and_then(|v| v.get("replay_attempts"))
            .and_then(|v| v.as_u64())
            .or_value(50) as usize;
        let base_samples = section
            .and_then(|v| v.get("base_samples"))
            .and_then(|v| v.as_u64())
            .or_value(10) as usize;

        let mut scanner = NullifierReplayScanner::new()
            .with_replay_attempts(replay_attempts)
            .with_base_samples(base_samples);

        if let Some(list) = section
            .and_then(|v| v.get("nullifier_indices"))
            .and_then(|v| v.as_sequence())
        {
            let mut indices = Vec::new();
            for entry in list {
                let parsed = match entry {
                    serde_yaml::Value::Number(n) => n.as_u64().map(|v| v as usize),
                    serde_yaml::Value::String(s) => match s.parse::<usize>() {
                        Ok(value) => Some(value),
                        Err(err) => {
                            tracing::debug!("Invalid constant index '{}' in config: {}", s, err);
                            None
                        }
                    },
                    _ => None,
                };
                if let Some(idx) = parsed {
                    indices.push(idx);
                }
            }
            if !indices.is_empty() {
                scanner = scanner.with_nullifier_indices(indices);
            }
        }

        let witnesses = self.collect_corpus_inputs(base_samples.max(1));
        if witnesses.is_empty() {
            anyhow::bail!(
                "Nullifier replay scanner requires corpus witnesses, but none are available"
            );
        }

        let findings = scanner.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, finding_attack_type, progress)?;
        Ok(())
    }

    pub(super) async fn run_boundary_attack(
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
            .or_else_value(|| vec!["0".to_string(), "1".to_string(), "p-1".to_string()]);

        tracing::info!("Testing {} boundary values", test_values.len());
        {
            use crate::oracles::BoundaryTester;
            let tester = BoundaryTester::new()
                .with_modulus(self.get_field_modulus())
                .with_custom_values(test_values.clone());
            self.add_attack_findings(&tester, test_values.len(), progress)?;
        }

        let field_modulus = self.get_field_modulus();

        for value in test_values {
            let expanded =
                match crate::config::parser::expand_value_placeholder(&value, &field_modulus) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        anyhow::bail!("Invalid boundary test value '{}': {}", value, e);
                    }
                };
            let mut fe_bytes = [0u8; 32];
            let start = 32_usize.saturating_sub(expanded.len());
            fe_bytes[start..].copy_from_slice(&expanded[..expanded.len().min(32)]);
            let fe = FieldElement(fe_bytes);

            let test_case = self.create_test_case_with_value(fe);
            let result = self.execute_and_learn(&test_case);
            if !result.success {
                tracing::warn!(
                    "Boundary testcase execution failed for value '{}': {}",
                    value,
                    result.error.as_deref().or_value("unknown execution error")
                );
            }

            if let Some(p) = progress {
                p.inc();
            }
        }

        self.run_canonicalization_attack(config, AttackType::Boundary, progress)?;

        Ok(())
    }

    pub(super) fn run_canonicalization_attack(
        &self,
        config: &serde_yaml::Value,
        finding_attack_type: AttackType,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::CanonicalizationChecker;

        let section = config.get("canonicalization");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        if !enabled {
            return Ok(());
        }

        let sample_count = section
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_value(20) as usize;
        let test_field_wrap = section
            .and_then(|v| v.get("test_field_wrap"))
            .and_then(|v| v.as_bool())
            .or_value(true);
        let test_additive_inverse = section
            .and_then(|v| v.get("test_additive_inverse"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        let test_negative_zero = section
            .and_then(|v| v.get("test_negative_zero"))
            .and_then(|v| v.as_bool())
            .or_value(true);

        let witnesses = self.collect_corpus_inputs(sample_count.max(1));
        if witnesses.is_empty() {
            anyhow::bail!(
                "Canonicalization checker requires corpus witnesses, but none are available"
            );
        }

        let checker = CanonicalizationChecker::new()
            .with_sample_count(sample_count)
            .with_field_wrap(test_field_wrap)
            .with_additive_inverse(test_additive_inverse)
            .with_negative_zero(test_negative_zero);

        let findings = checker.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, finding_attack_type, progress)?;
        Ok(())
    }

    pub(super) async fn run_verification_fuzzing_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::verification::VerificationFuzzer;

        let configured_malleability_tests = config
            .get("malleability_tests")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let configured_malformed_tests = config
            .get("malformed_tests")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let configured_edge_case_tests = config
            .get("edge_case_tests")
            .and_then(|v| v.as_u64())
            .or_value(500) as usize;
        let malleability_tests = self.bounded_attack_units(
            configured_malleability_tests,
            1,
            "verification_malleability_tests_cap",
            "verification.malleability_tests",
        );
        let malformed_tests = self.bounded_attack_units(
            configured_malformed_tests,
            1,
            "verification_malformed_tests_cap",
            "verification.malformed_tests",
        );
        let edge_case_tests = self.bounded_attack_units(
            configured_edge_case_tests,
            1,
            "verification_edge_case_tests_cap",
            "verification.edge_case_tests",
        );
        let mutation_rate = config
            .get("mutation_rate")
            .and_then(|v| v.as_f64())
            .or_value(0.05);

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

        let findings = {
            let rng = self.core.rng_mut();
            fuzzer.fuzz(&self.executor, rng)
        };

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        Ok(())
    }

    pub(super) async fn run_witness_fuzzing_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::witness::WitnessFuzzer;

        let configured_determinism_tests = config
            .get("determinism_tests")
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;
        let configured_timing_tests = config
            .get("timing_tests")
            .and_then(|v| v.as_u64())
            .or_value(500) as usize;
        let configured_stress_tests = config
            .get("stress_tests")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let determinism_tests = self.bounded_attack_units(
            configured_determinism_tests,
            1,
            "witness_determinism_tests_cap",
            "witness.determinism_tests",
        );
        let timing_tests = self.bounded_attack_units(
            configured_timing_tests,
            1,
            "witness_timing_tests_cap",
            "witness.timing_tests",
        );
        let stress_tests = self.bounded_attack_units(
            configured_stress_tests,
            1,
            "witness_stress_tests_cap",
            "witness.stress_tests",
        );
        let timing_threshold_us = config
            .get("timing_threshold_us")
            .and_then(|v| v.as_u64())
            .or_value(10_000);
        let timing_cv_threshold = config
            .get("timing_cv_threshold")
            .and_then(|v| v.as_f64())
            .or_value(0.5);

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

        let findings = {
            let rng = self.core.rng_mut();
            fuzzer.fuzz(&self.executor, rng)
        };

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
            if let Some(p) = progress {
                for finding in &findings {
                    p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                }
            }
        }

        Ok(())
    }

    pub(super) async fn run_differential_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::differential::report::DifferentialReport;
        use crate::differential::{DifferentialConfig, DifferentialFuzzer};
        use std::collections::{HashMap, HashSet};

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .or_value(500) as usize;
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "differential_num_tests_cap",
            "differential.num_tests",
        );
        let compare_coverage = config
            .get("compare_coverage")
            .and_then(|v| v.as_bool())
            .or_value(true);
        let compare_timing = config
            .get("compare_timing")
            .and_then(|v| v.as_bool())
            .or_value(true);
        let timing_tolerance_percent = config
            .get("timing_tolerance_percent")
            .and_then(|v| v.as_f64())
            .or_value(50.0);
        let timing_min_us = config
            .get("timing_min_us")
            .and_then(|v| v.as_u64())
            .or_value(2_000);
        let timing_abs_threshold_us = config
            .get("timing_abs_threshold_us")
            .and_then(|v| v.as_u64())
            .or_value(5_000);
        let coverage_min_constraints = config
            .get("coverage_min_constraints")
            .and_then(|v| v.as_u64())
            .or_value(16) as usize;
        let coverage_jaccard_threshold = config
            .get("coverage_jaccard_threshold")
            .and_then(|v| v.as_f64())
            .or_value(0.5);
        let coverage_abs_delta_threshold = config
            .get("coverage_abs_delta_threshold")
            .and_then(|v| v.as_u64())
            .or_value(200) as usize;
        let coverage_rel_delta_threshold = config
            .get("coverage_rel_delta_threshold")
            .and_then(|v| v.as_f64())
            .or_value(0.25);

        let cross_backend_section = config.get("cross_backend");
        let cross_backend_enabled = cross_backend_section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .or_value(false);
        let configured_cross_backend_samples = cross_backend_section
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;
        let cross_backend_samples = self.bounded_attack_units(
            configured_cross_backend_samples,
            1,
            "differential_cross_backend_sample_count_cap",
            "differential.cross_backend.sample_count",
        );
        let cross_backend_tolerance_bits = cross_backend_section
            .and_then(|v| v.get("tolerance_bits"))
            .and_then(|v| v.as_u64())
            .or_value(0) as usize;

        tracing::info!("Running differential fuzzing with {} tests", num_tests);

        let parse_framework = |name: &str| -> Option<Framework> {
            match name.to_lowercase().as_str() {
                "circom" => Some(Framework::Circom),
                "noir" => Some(Framework::Noir),
                "halo2" => Some(Framework::Halo2),
                "cairo" => Some(Framework::Cairo),
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
            anyhow::bail!(
                "Differential fuzzing requires at least two configured backends; got {}",
                selected_backends.len()
            );
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

        // Add executors for each backend.
        let mut active_backends = Vec::new();
        let mut cross_backend_execs: Vec<Arc<dyn CircuitExecutor>> = Vec::new();
        for backend in &selected_backends {
            let circuit_path = backend_paths
                .get(backend)
                .map(|s| s.as_str())
                .or_else_value(|| {
                    self.config
                        .campaign
                        .target
                        .circuit_path
                        .to_str()
                        .or_value("")
                });

            let executor = ExecutorFactory::create_with_options(
                *backend,
                circuit_path,
                &self.config.campaign.target.main_component,
                &self.executor_factory_options,
            )
            .map_err(|e| anyhow::anyhow!("Failed to initialize backend {:?}: {}", backend, e))?;
            if cross_backend_enabled && cross_backend_execs.len() < 2 {
                cross_backend_execs.push(executor.clone());
            }
            diff_fuzzer.add_executor(*backend, executor);
            active_backends.push(*backend);
        }

        if active_backends.len() < 2 {
            anyhow::bail!(
                "Differential fuzzing requires at least two active backends; got {}",
                active_backends.len()
            );
        }

        if cross_backend_enabled {
            if cross_backend_execs.len() >= 2 {
                self.run_cross_backend_differential(
                    cross_backend_execs[0].clone(),
                    cross_backend_execs[1].clone(),
                    cross_backend_samples,
                    cross_backend_tolerance_bits,
                    progress,
                )?;
            } else {
                anyhow::bail!(
                    "Cross-backend differential enabled but fewer than two active executors are available"
                );
            }
        }

        let mut test_cases = Vec::with_capacity(num_tests);
        for _ in 0..num_tests {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping differential attack witness generation early: wall-clock timeout reached"
                );
                break;
            }
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
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
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

    pub(super) fn run_cross_backend_differential(
        &self,
        executor_a: Arc<dyn CircuitExecutor>,
        executor_b: Arc<dyn CircuitExecutor>,
        sample_count: usize,
        tolerance_bits: usize,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::CrossBackendDifferential;

        if sample_count == 0 {
            anyhow::bail!("Cross-backend differential requires sample_count > 0");
        }

        let witnesses = self.collect_corpus_inputs(sample_count.max(1));
        if witnesses.is_empty() {
            anyhow::bail!(
                "Cross-backend differential requires corpus witnesses, but none are available"
            );
        }

        let oracle = CrossBackendDifferential::new()
            .with_sample_count(sample_count)
            .with_tolerance_bits(tolerance_bits);

        let findings = oracle.run(executor_a.as_ref(), executor_b.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Differential, progress)?;
        Ok(())
    }

    pub(super) async fn run_circuit_composition_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::multi_circuit::composition::{CompositionTester, CompositionType};
        use crate::multi_circuit::{CircuitChain, MultiCircuitFuzzer};

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .or_value(200) as usize;
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "circuit_composition_num_tests_cap",
            "circuit_composition.num_tests",
        );

        tracing::info!(
            "Running circuit composition fuzzing with {} tests",
            num_tests
        );

        // Create composition tester
        let mut composition_tester = CompositionTester::new(CompositionType::Parallel);
        composition_tester.add_circuit(self.executor.clone());

        // Create circuit chain for chained execution testing
        let mut chain = CircuitChain::new();
        chain.add("main", self.executor.clone());

        // Test chain execution with random inputs
        for _ in 0..num_tests.min(10) {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping circuit composition smoke checks early: wall-clock timeout reached"
                );
                break;
            }
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

        let findings = {
            let rng = self.core.rng_mut();
            multi_fuzzer.run(rng)
        };

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
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

    pub(super) async fn run_information_leakage_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::analysis::taint::TaintAnalyzer;

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .or_value(300) as usize;
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "information_leakage_num_tests_cap",
            "information_leakage.num_tests",
        );

        tracing::info!(
            "Running information leakage detection with {} tests",
            num_tests
        );

        let inspector = match self.executor.constraint_inspector() {
            Some(inspector) => inspector,
            None => {
                anyhow::bail!(
                    "Information leakage attack requires constraint inspector, but none is available"
                );
            }
        };

        let public_indices = inspector.public_input_indices();
        let private_indices = inspector.private_input_indices();
        let output_indices = inspector.output_indices();

        if private_indices.is_empty() {
            anyhow::bail!(
                "Information leakage attack requires private inputs, but none were discovered"
            );
        }

        let constraints = inspector.get_constraints();
        if constraints.is_empty() {
            anyhow::bail!(
                "Information leakage attack requires constraint data, but inspector returned none"
            );
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
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
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

    pub(super) async fn run_timing_sidechannel_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::analysis::profiling::Profiler;

        let configured_num_samples = config
            .get("num_samples")
            .and_then(|v| v.as_u64())
            .or_value(1000) as usize;
        let num_samples = self.bounded_attack_units(
            configured_num_samples,
            1,
            "timing_sidechannel_num_samples_cap",
            "timing_sidechannel.num_samples",
        );

        tracing::info!(
            "Running timing side-channel detection with {} samples",
            num_samples
        );

        let profiler = Profiler::new().with_samples(num_samples);
        let profile = {
            let rng = self.core.rng_mut();
            profiler.profile(&self.executor, rng)
        };

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

            self.with_findings_write(|store| store.push(finding.clone()))?;
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

    pub(super) async fn run_recursive_proof_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::multi_circuit::recursive::{RecursionResult, RecursiveTester};

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;
        let configured_num_tests = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_num_tests,
            256,
            "metamorphic.num_tests",
        );
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "recursive_proof_num_tests_cap",
            "recursive_proof.num_tests",
        );

        let max_depth = config.get("max_depth").and_then(|v| v.as_u64()).or_value(3) as usize;

        tracing::info!(
            "Running recursive proof fuzzing with {} tests, max depth {}",
            num_tests,
            max_depth
        );

        let tester = RecursiveTester::new(max_depth).with_verifier(self.executor.clone());

        for _ in 0..num_tests {
            if self.wall_clock_timeout_reached() {
                tracing::warn!("Stopping recursive proof attack early: wall-clock timeout reached");
                break;
            }
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

                    self.with_findings_write(|store| store.push(finding.clone()))?;
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

    pub(super) async fn run_mev_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{MevAttack, MevConfig};

        let section = config
            .get("mev")
            .or_else(|| config.get("mev_patterns"))
            .or_else(|| config.get("defi"))
            .or_else(|| config.get("defi_advanced"))
            .unwrap_or(config);
        let mut mev_config = MevConfig::default();
        if let Some(v) = section
            .get("ordering_permutations")
            .and_then(|v| v.as_u64())
        {
            mev_config.ordering_permutations = v as usize;
        }
        if let Some(v) = section.get("sandwich_attempts").and_then(|v| v.as_u64()) {
            mev_config.sandwich_attempts = v as usize;
        }
        if let Some(v) = section.get("profit_threshold").and_then(|v| v.as_f64()) {
            mev_config.profit_threshold = v;
        }
        if let Some(v) = section.get("detect_ordering").and_then(|v| v.as_bool()) {
            mev_config.detect_ordering = v;
        }
        if let Some(v) = section.get("detect_sandwich").and_then(|v| v.as_bool()) {
            mev_config.detect_sandwich = v;
        }
        if let Some(v) = section.get("detect_leakage").and_then(|v| v.as_bool()) {
            mev_config.detect_leakage = v;
        }
        if let Some(v) = section.get("timeout_ms").and_then(|v| v.as_u64()) {
            mev_config.timeout_ms = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            mev_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);

        let mut attack = MevAttack::new(mev_config);
        let mut findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        for finding in &mut findings {
            finding.attack_type = AttackType::Mev;
        }
        self.record_custom_findings(findings, AttackType::Mev, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_front_running_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{FrontRunningAttack, FrontRunningConfig};

        let section = config
            .get("front_running")
            .or_else(|| config.get("front_running_patterns"))
            .or_else(|| config.get("defi"))
            .or_else(|| config.get("defi_advanced"))
            .unwrap_or(config);
        let mut front_config = FrontRunningConfig::default();
        if let Some(v) = section.get("leakage_tests").and_then(|v| v.as_u64()) {
            front_config.leakage_tests = v as usize;
        }
        if let Some(v) = section.get("commitment_tests").and_then(|v| v.as_u64()) {
            front_config.commitment_tests = v as usize;
        }
        if let Some(v) = section.get("detect_leakage").and_then(|v| v.as_bool()) {
            front_config.detect_leakage = v;
        }
        if let Some(v) = section
            .get("detect_commitment_bypass")
            .and_then(|v| v.as_bool())
        {
            front_config.detect_commitment_bypass = v;
        }
        if let Some(v) = section.get("detect_delay_attack").and_then(|v| v.as_bool()) {
            front_config.detect_delay_attack = v;
        }
        if let Some(v) = section.get("entropy_threshold").and_then(|v| v.as_f64()) {
            front_config.entropy_threshold = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            front_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);

        let mut attack = FrontRunningAttack::new(front_config);
        let mut findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        for finding in &mut findings {
            finding.attack_type = AttackType::FrontRunning;
        }
        self.record_custom_findings(findings, AttackType::FrontRunning, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_zkevm_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{ZkEvmAttack, ZkEvmConfig};

        let section = config
            .get("zkevm")
            .or_else(|| config.get("evm"))
            .unwrap_or(config);
        let mut zkevm_config = ZkEvmConfig::default();
        if let Some(v) = section
            .get("state_transition_tests")
            .and_then(|v| v.as_u64())
        {
            zkevm_config.state_transition_tests = v as usize;
        }
        if let Some(v) = section
            .get("opcode_boundary_tests")
            .and_then(|v| v.as_u64())
        {
            zkevm_config.opcode_boundary_tests = v as usize;
        }
        if let Some(v) = section
            .get("memory_expansion_tests")
            .and_then(|v| v.as_u64())
        {
            zkevm_config.memory_expansion_tests = v as usize;
        }
        if let Some(v) = section.get("storage_proof_tests").and_then(|v| v.as_u64()) {
            zkevm_config.storage_proof_tests = v as usize;
        }
        if let Some(v) = section
            .get("detect_state_transition")
            .and_then(|v| v.as_bool())
        {
            zkevm_config.detect_state_transition = v;
        }
        if let Some(v) = section
            .get("detect_opcode_boundary")
            .and_then(|v| v.as_bool())
        {
            zkevm_config.detect_opcode_boundary = v;
        }
        if let Some(v) = section
            .get("detect_memory_expansion")
            .and_then(|v| v.as_bool())
        {
            zkevm_config.detect_memory_expansion = v;
        }
        if let Some(v) = section
            .get("detect_storage_proof")
            .and_then(|v| v.as_bool())
        {
            zkevm_config.detect_storage_proof = v;
        }
        if let Some(v) = section.get("max_memory_offset").and_then(|v| v.as_u64()) {
            zkevm_config.max_memory_offset = v;
        }
        if let Some(v) = section.get("timeout_ms").and_then(|v| v.as_u64()) {
            zkevm_config.timeout_ms = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            zkevm_config.seed = Some(v);
        }
        if let Some(values) = section.get("target_opcodes").and_then(|v| v.as_sequence()) {
            let opcodes: Vec<String> = values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            if !opcodes.is_empty() {
                zkevm_config.target_opcodes = opcodes;
            }
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);

        let mut attack = ZkEvmAttack::new(zkevm_config);
        let mut findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        for finding in &mut findings {
            finding.attack_type = AttackType::ZkEvm;
        }
        self.record_custom_findings(findings, AttackType::ZkEvm, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_batch_verification_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{
            AggregationMethod, BatchVerificationAttack, BatchVerificationConfig, InvalidPosition,
        };

        let section = config.get("batch_verification").unwrap_or(config);
        let mut batch_config = BatchVerificationConfig::default();
        if let Some(v) = section.get("batch_mixing_tests").and_then(|v| v.as_u64()) {
            batch_config.batch_mixing_tests = v as usize;
        }
        if let Some(v) = section
            .get("aggregation_forgery_tests")
            .and_then(|v| v.as_u64())
        {
            batch_config.aggregation_forgery_tests = v as usize;
        }
        if let Some(v) = section.get("cross_circuit_tests").and_then(|v| v.as_u64()) {
            batch_config.cross_circuit_tests = v as usize;
        }
        if let Some(v) = section
            .get("randomness_reuse_tests")
            .and_then(|v| v.as_u64())
        {
            batch_config.randomness_reuse_tests = v as usize;
        }
        if let Some(v) = section.get("detect_batch_mixing").and_then(|v| v.as_bool()) {
            batch_config.detect_batch_mixing = v;
        }
        if let Some(v) = section
            .get("detect_aggregation_forgery")
            .and_then(|v| v.as_bool())
        {
            batch_config.detect_aggregation_forgery = v;
        }
        if let Some(v) = section
            .get("detect_cross_circuit_batch")
            .and_then(|v| v.as_bool())
        {
            batch_config.detect_cross_circuit_batch = v;
        }
        if let Some(v) = section
            .get("detect_randomness_reuse")
            .and_then(|v| v.as_bool())
        {
            batch_config.detect_randomness_reuse = v;
        }
        if let Some(v) = section
            .get("correlation_threshold")
            .and_then(|v| v.as_f64())
        {
            batch_config.correlation_threshold = v;
        }
        if let Some(v) = section.get("timeout_ms").and_then(|v| v.as_u64()) {
            batch_config.timeout_ms = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            batch_config.seed = Some(v);
        }

        if let Some(values) = section.get("batch_sizes").and_then(|v| v.as_sequence()) {
            let parsed: Vec<usize> = values
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as usize))
                .filter(|v| *v > 0)
                .collect();
            if !parsed.is_empty() {
                batch_config.batch_sizes = parsed;
            }
        }

        if let Some(values) = section
            .get("aggregation_methods")
            .and_then(|v| v.as_sequence())
        {
            let mut parsed = Vec::new();
            for value in values {
                if let Some(raw) = value.as_str() {
                    match raw.trim().to_ascii_lowercase().as_str() {
                        "naive_batch" => parsed.push(AggregationMethod::NaiveBatch),
                        "snarkpack" => parsed.push(AggregationMethod::SnarkPack),
                        "groth16_aggregation" => parsed.push(AggregationMethod::Groth16Aggregation),
                        "plonk_aggregation" => parsed.push(AggregationMethod::PlonkAggregation),
                        "halo2_aggregation" => parsed.push(AggregationMethod::Halo2Aggregation),
                        _ => {}
                    }
                }
            }
            if !parsed.is_empty() {
                batch_config.aggregation_methods = parsed;
            }
        }

        if let Some(values) = section
            .get("invalid_positions")
            .and_then(|v| v.as_sequence())
        {
            let mut parsed = Vec::new();
            for value in values {
                if let Some(raw) = value.as_str() {
                    match raw.trim().to_ascii_lowercase().as_str() {
                        "first" => parsed.push(InvalidPosition::First),
                        "last" => parsed.push(InvalidPosition::Last),
                        "middle" => parsed.push(InvalidPosition::Middle),
                        "random" => parsed.push(InvalidPosition::Random),
                        _ => {}
                    }
                }
            }
            if !parsed.is_empty() {
                batch_config.invalid_positions = parsed;
            }
        }

        let sample_count = batch_config
            .batch_sizes
            .iter()
            .copied()
            .max()
            .unwrap_or(2)
            .max(2);
        let mut base_inputs = self.collect_corpus_inputs(sample_count);
        if base_inputs.is_empty() {
            base_inputs.push(self.generate_test_case().inputs);
        }

        let mut attack = BatchVerificationAttack::new(batch_config);
        let raw_findings = attack.run(self.executor.as_ref(), &base_inputs);
        let mut findings: Vec<Finding> = raw_findings
            .into_iter()
            .map(|finding| finding.to_finding())
            .collect();
        for finding in &mut findings {
            finding.attack_type = AttackType::BatchVerification;
        }
        self.record_custom_findings(findings, AttackType::BatchVerification, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_sidechannel_advanced_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{SidechannelAdvancedAttack, SidechannelAdvancedConfig};

        let section = config.get("sidechannel_advanced").unwrap_or(config);
        let mut advanced_config = SidechannelAdvancedConfig::default();

        if let Some(samples) = section
            .get("cache_timing")
            .and_then(|v| v.get("sample_size"))
            .and_then(|v| v.as_u64())
            .or_else(|| section.get("num_samples").and_then(|v| v.as_u64()))
        {
            advanced_config.timing_samples = self.bounded_attack_units(
                samples as usize,
                1,
                "sidechannel_advanced_timing_samples_cap",
                "sidechannel_advanced.timing_samples",
            );
        }

        if let Some(samples) = section
            .get("memory_patterns")
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_else(|| section.get("num_tests").and_then(|v| v.as_u64()))
        {
            advanced_config.leakage_samples = self.bounded_attack_units(
                samples as usize,
                1,
                "sidechannel_advanced_leakage_samples_cap",
                "sidechannel_advanced.leakage_samples",
            );
        }

        if let Some(v) = section.get("detect_timing").and_then(|v| v.as_bool()) {
            advanced_config.detect_timing = v;
        }
        if let Some(v) = section.get("detect_leakage").and_then(|v| v.as_bool()) {
            advanced_config.detect_leakage = v;
        }
        if let Some(v) = section.get("timing_cv_threshold").and_then(|v| v.as_f64()) {
            advanced_config.timing_cv_threshold = v;
        }
        if let Some(v) = section
            .get("leakage_uniqueness_threshold")
            .and_then(|v| v.as_f64())
        {
            advanced_config.leakage_uniqueness_threshold = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            advanced_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);

        let mut attack = SidechannelAdvancedAttack::new(advanced_config);
        let findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        self.record_custom_findings(findings, AttackType::SidechannelAdvanced, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_circom_static_lint_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{CircomStaticLint, CircomStaticLintConfig};

        if self.config.campaign.target.framework != Framework::Circom {
            tracing::warn!(
                "CircomStaticLint skipped: framework is {:?} (requires Circom)",
                self.config.campaign.target.framework
            );
            return Ok(());
        }

        let section = config.get("circom_static_lint").unwrap_or(config);
        let mut lint_config = CircomStaticLintConfig::default();

        if let Some(values) = section.get("enabled_checks").and_then(|v| v.as_sequence()) {
            let check_names: Vec<String> = values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect();
            let parsed_checks = CircomStaticLint::parse_checks(&check_names);
            if !parsed_checks.is_empty() {
                lint_config.enabled_checks = parsed_checks;
            }
        }

        if let Some(v) = section
            .get("max_findings_per_check")
            .and_then(|v| v.as_u64())
        {
            lint_config.max_findings_per_check = v as usize;
        }
        if let Some(v) = section.get("case_sensitive").and_then(|v| v.as_bool()) {
            lint_config.case_sensitive = v;
        }

        let lint = CircomStaticLint::new(lint_config);
        let source_path = self.config.campaign.target.circuit_path.clone();
        let findings = match lint.scan_file(&source_path) {
            Ok(findings) => findings,
            Err(err) => {
                tracing::warn!(
                    "CircomStaticLint skipped source read '{}': {}",
                    source_path.display(),
                    err
                );
                return Ok(());
            }
        };

        self.record_custom_findings(findings, AttackType::CircomStaticLint, progress)?;
        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_quantum_resistance_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{PrimitivePattern, QuantumResistanceAttack, QuantumResistanceConfig};

        fn parse_severity(raw: &str) -> Severity {
            match raw.trim().to_ascii_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            }
        }

        let section = config.get("quantum_resistance").unwrap_or(config);
        let mut quantum_config = QuantumResistanceConfig::default();
        if let Some(v) = section.get("case_sensitive").and_then(|v| v.as_bool()) {
            quantum_config.case_sensitive = v;
        }

        if let Some(entries) = section
            .get("vulnerable_primitives")
            .and_then(|v| v.get("detect"))
            .and_then(|v| v.as_sequence())
        {
            let mut parsed = Vec::new();
            for entry in entries {
                let Some(name) = entry.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let severity = entry
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(parse_severity)
                    .unwrap_or(Severity::High);
                let patterns: Vec<String> = entry
                    .get("patterns")
                    .and_then(|v| v.as_sequence())
                    .map(|seq| {
                        seq.iter()
                            .filter_map(|value| value.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_else(|| vec![name.to_ascii_lowercase()]);
                parsed.push(PrimitivePattern {
                    name: name.to_string(),
                    severity,
                    patterns,
                });
            }
            if !parsed.is_empty() {
                quantum_config.vulnerable_primitives = parsed;
            }
        }

        let source_path = self.config.campaign.target.circuit_path.clone();
        let witness: Vec<FieldElement> = Vec::new();
        let attack = QuantumResistanceAttack::new(quantum_config);
        let findings = match attack.scan_file(&source_path, &witness) {
            Ok(findings) => findings,
            Err(err) => {
                tracing::warn!(
                    "QuantumResistance scan skipped source read '{}': {}",
                    source_path.display(),
                    err
                );
                return Ok(());
            }
        };

        self.record_custom_findings(findings, AttackType::QuantumResistance, progress)?;
        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_privacy_advanced_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{PrivacyAdvancedAttack, PrivacyAdvancedConfig};

        let section = config.get("privacy_advanced").unwrap_or(config);
        let leakage_samples = section
            .get("metadata_leakage")
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_else(|| section.get("sample_count").and_then(|v| v.as_u64()))
            .or_else(|| section.get("num_tests").and_then(|v| v.as_u64()));
        let timing_samples = section
            .get("metadata_leakage")
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .or_else(|| section.get("timing_samples").and_then(|v| v.as_u64()));

        let mut privacy_config = PrivacyAdvancedConfig::default();
        let sample_count = leakage_samples
            .unwrap_or(privacy_config.sample_count as u64)
            .max(timing_samples.unwrap_or(0));
        privacy_config.sample_count = self.bounded_attack_units(
            sample_count as usize,
            1,
            "privacy_advanced_sample_count_cap",
            "privacy_advanced.sample_count",
        );
        if let Some(v) = section
            .get("entropy_threshold_bits")
            .and_then(|v| v.as_f64())
        {
            privacy_config.entropy_threshold_bits = v;
        }
        if let Some(v) = section.get("timing_cv_threshold").and_then(|v| v.as_f64()) {
            privacy_config.timing_cv_threshold = v;
        }
        if let Some(v) = section
            .get("detect_metadata_leakage")
            .and_then(|v| v.as_bool())
        {
            privacy_config.detect_metadata_leakage = v;
        }
        if let Some(v) = section
            .get("detect_timing_leakage")
            .and_then(|v| v.as_bool())
        {
            privacy_config.detect_timing_leakage = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            privacy_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);
        let mut attack = PrivacyAdvancedAttack::new(privacy_config);
        let findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        self.record_custom_findings(findings, AttackType::PrivacyAdvanced, progress)?;

        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_defi_advanced_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{DefiAdvancedAttack, DefiAdvancedConfig};

        let section = config
            .get("defi_advanced")
            .or_else(|| config.get("defi"))
            .unwrap_or(config);

        let mev_section = section
            .get("mev_patterns")
            .or_else(|| section.get("mev"))
            .unwrap_or(section);
        let front_section = section
            .get("front_running_patterns")
            .or_else(|| section.get("front_running"))
            .unwrap_or(section);

        let mut defi_config = DefiAdvancedConfig::default();
        if let Some(v) = mev_section
            .get("ordering_permutations")
            .and_then(|v| v.as_u64())
        {
            defi_config.ordering_permutations = self.bounded_attack_units(
                v as usize,
                1,
                "defi_advanced_ordering_permutations_cap",
                "defi_advanced.ordering_permutations",
            );
        }
        if let Some(v) = mev_section.get("profit_threshold").and_then(|v| v.as_f64()) {
            defi_config.ordering_delta_threshold = v;
        }
        if let Some(v) = mev_section.get("detect_ordering").and_then(|v| v.as_bool()) {
            defi_config.detect_ordering = v;
        }

        if let Some(v) = front_section.get("leakage_tests").and_then(|v| v.as_u64()) {
            defi_config.leakage_samples = self.bounded_attack_units(
                v as usize,
                1,
                "defi_advanced_leakage_samples_cap",
                "defi_advanced.leakage_samples",
            );
        }
        if let Some(v) = front_section
            .get("entropy_threshold")
            .and_then(|v| v.as_f64())
        {
            defi_config.entropy_threshold_bits = v;
        }
        if let Some(v) = front_section
            .get("detect_leakage")
            .and_then(|v| v.as_bool())
        {
            defi_config.detect_front_running_signals = v;
        }
        if let Some(v) = section.get("seed").and_then(|v| v.as_u64()) {
            defi_config.seed = Some(v);
        }

        let base_inputs = self
            .collect_corpus_inputs(1)
            .into_iter()
            .next()
            .unwrap_or_else(|| self.generate_test_case().inputs);
        let mut attack = DefiAdvancedAttack::new(defi_config);
        let findings = attack.run(self.executor.as_ref(), &base_inputs)?;
        self.record_custom_findings(findings, AttackType::DefiAdvanced, progress)?;

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    pub(super) fn get_circuit_info(&self) -> zk_core::CircuitInfo {
        zk_core::CircuitInfo {
            name: self.config.campaign.target.main_component.clone(),
            num_constraints: self.executor.num_constraints(),
            num_private_inputs: self.executor.num_private_inputs(),
            num_public_inputs: self.executor.num_public_inputs(),
            num_outputs: 1,
        }
    }

    pub(super) fn hash_output(&self, output: &[FieldElement]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for fe in output {
            hasher.update(fe.0);
        }
        hasher.finalize().to_vec()
    }

    /// Check if witnesses have different inputs (Mode 3 optimized: takes references)
    pub(super) fn witnesses_are_different_refs(&self, witnesses: &[&TestCase]) -> bool {
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

    pub(super) fn get_field_modulus(&self) -> [u8; 32] {
        // Use executor's field modulus instead of hardcoded BN254
        self.executor.field_modulus()
    }

    pub(super) fn detect_overflow_indicator(
        &self,
        test_case: &TestCase,
        output: &[FieldElement],
    ) -> bool {
        // Keep this heuristic narrow: only evaluate the "small input" probes to
        // avoid noise from circuits that naturally emit high-entropy field values.
        let small_input_probe = test_case
            .inputs
            .iter()
            .all(|input| Self::fits_in_bytes(input, 2));
        if !small_input_probe {
            return false;
        }

        let modulus = self.get_field_modulus();
        output
            .iter()
            .any(|fe| Self::is_within_distance_to_modulus(fe, &modulus, 2))
    }

    fn fits_in_bytes(value: &FieldElement, bytes: usize) -> bool {
        let leading = 32usize.saturating_sub(bytes);
        value.0.iter().take(leading).all(|&byte| byte == 0)
    }

    /// Check whether `value` is within `threshold_bytes` of the field modulus.
    /// Uses byte-accurate big-endian subtraction to remain field-agnostic.
    fn is_within_distance_to_modulus(
        value: &FieldElement,
        modulus: &[u8; 32],
        threshold_bytes: usize,
    ) -> bool {
        match Self::cmp_be(&value.0, modulus) {
            // Non-canonical output (> modulus) is already suspicious.
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => true,
            std::cmp::Ordering::Less => {
                let diff = Self::sub_be(modulus, &value.0);
                let leading = 32usize.saturating_sub(threshold_bytes);
                diff.iter().take(leading).all(|&byte| byte == 0)
            }
        }
    }

    fn cmp_be(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
        for (left, right) in a.iter().zip(b.iter()) {
            if left < right {
                return std::cmp::Ordering::Less;
            }
            if left > right {
                return std::cmp::Ordering::Greater;
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Compute `a - b` for big-endian 256-bit integers with `a >= b`.
    fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0u16;

        for i in (0..32).rev() {
            let ai = a[i] as u16;
            let bi = b[i] as u16 + borrow;
            if ai >= bi {
                out[i] = (ai - bi) as u8;
                borrow = 0;
            } else {
                out[i] = (ai + 256 - bi) as u8;
                borrow = 1;
            }
        }

        out
    }

    // ========================================================================
    // Phase 4: Novel Oracle Attack Implementations
    // ========================================================================

    pub(super) async fn run_constraint_inference_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::config::v2::InvariantType;
        use crate::oracles::constraint_inference::{ConstraintInferenceEngine, InferenceContext};

        let confidence_threshold = config
            .get("confidence_threshold")
            .and_then(|v| v.as_f64())
            .or_value(0.7);

        let confirm_violations = config
            .get("confirm_violations")
            .and_then(|v| v.as_bool())
            .or_value(true);

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

        tracing::debug!("Analyzing constraints for inference...");
        let mut implied = if let Some(inspector) = self.executor.constraint_inspector() {
            let mut context = InferenceContext::from_inspector(inspector, num_wires);
            self.merge_config_input_labels(inspector, &mut context.wire_labels);
            self.merge_output_labels(inspector, &mut context.wire_labels);
            output_wires.extend(inspector.output_indices());

            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.analyze_with_context(&context)
            })) {
                Ok(result) => {
                    tracing::info!("Found {} implied constraints", result.len());
                    result
                }
                Err(e) => {
                    tracing::error!("FATAL: Constraint analysis panicked: {:?}", e);
                    anyhow::bail!("Constraint analysis panicked during execution");
                }
            }
        } else {
            tracing::error!("FATAL: No constraint inspector available for constraint inference");
            anyhow::bail!("Constraint inspector not available");
        };

        if confirm_violations && !implied.is_empty() {
            tracing::info!("Confirming {} inferred violations...", implied.len());
            let base_inputs = self.generate_test_case().inputs;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.confirm_violations(
                    self.executor.as_ref(),
                    &base_inputs,
                    &mut implied,
                    &output_wires,
                );
            })) {
                Ok(_) => {
                    tracing::info!("✓ Violation confirmation completed successfully");
                }
                Err(e) => {
                    tracing::error!("FATAL: Violation confirmation panicked: {:?}", e);
                    anyhow::bail!("Violation confirmation panicked during execution");
                }
            }
        }

        // Filter to only confirmed violations (eliminate false positives)
        use crate::oracles::constraint_inference::ViolationConfirmation;
        let before_filter = implied.len();
        implied.retain(|c| c.confirmation == ViolationConfirmation::Confirmed);
        tracing::info!(
            "Filtered {} -> {} violations (keeping only Confirmed, rejecting false positives)",
            before_filter,
            implied.len()
        );

        tracing::debug!("Converting implied constraints to findings...");
        let findings = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.to_findings(&implied)
        })) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("FATAL: Finding conversion panicked: {:?}", e);
                anyhow::bail!("Finding conversion panicked during execution");
            }
        };

        if !findings.is_empty() {
            let kept =
                self.record_custom_findings(findings, AttackType::ConstraintInference, progress)?;
            tracing::info!("Generated {} findings from constraint inference", kept);
        }

        // Enforce v2 invariants (constraint/range/uniqueness) by attempting violations.
        tracing::debug!("Enforcing v2 invariants...");
        let invariants: Vec<_> = self
            .config
            .get_invariants()
            .into_iter()
            .filter(|inv| inv.invariant_type != InvariantType::Metamorphic)
            .collect();

        let invariant_findings =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.enforce_invariants(&invariants)
            })) {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("FATAL: Invariant enforcement panicked: {:?}", e);
                    anyhow::bail!("Invariant enforcement panicked during execution");
                }
            };

        if !invariant_findings.is_empty() {
            let kept = self.record_custom_findings(
                invariant_findings,
                AttackType::ConstraintInference,
                progress,
            )?;
            tracing::info!("Generated {} findings from invariant enforcement", kept);
        }

        tracing::info!("Constraint inference attack completed");
        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    pub(super) async fn run_metamorphic_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::metamorphic::MetamorphicOracle;

        let configured_num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;
        let num_tests = self.bounded_attack_units(
            configured_num_tests,
            1,
            "metamorphic_num_tests_cap",
            "metamorphic.num_tests",
        );

        tracing::info!(
            "Running metamorphic testing with {} base witnesses",
            num_tests
        );

        let mut oracle = MetamorphicOracle::new().with_circuit_aware_relations();
        let invariant_relations = self.build_metamorphic_relations();
        for relation in invariant_relations {
            oracle = oracle.with_relation(relation);
        }

        // Generate base witnesses and test metamorphic relations
        for _ in 0..num_tests {
            if self.wall_clock_timeout_reached() {
                tracing::warn!("Stopping metamorphic attack early: wall-clock timeout reached");
                break;
            }
            let base_witness = self.generate_test_case();
            let results = oracle
                .test_all(self.executor.as_ref(), &base_witness.inputs)
                .await;

            let findings = oracle.to_findings(&results);
            if !findings.is_empty() {
                self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
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

    pub(super) async fn run_constraint_slice_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::constraint_slice::{ConstraintSliceOracle, OutputMapping};

        let configured_samples_per_cone = config
            .get("samples_per_cone")
            .and_then(|v| v.as_u64())
            .or_value(100) as usize;
        let configured_samples_per_cone = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_samples_per_cone,
            32,
            "constraint_slice.samples_per_cone",
        );
        let samples_per_cone = self.bounded_attack_units(
            configured_samples_per_cone,
            1,
            "constraint_slice_samples_per_cone_cap",
            "constraint_slice.samples_per_cone",
        );

        let configured_base_witness_attempts = config
            .get("base_witness_attempts")
            .and_then(|v| v.as_u64())
            .or_value(16) as usize;
        let configured_base_witness_attempts = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_base_witness_attempts,
            32,
            "constraint_slice.base_witness_attempts",
        );
        let base_witness_attempts = self.bounded_attack_units(
            configured_base_witness_attempts,
            1,
            "constraint_slice_base_witness_attempts_cap",
            "constraint_slice.base_witness_attempts",
        );

        tracing::info!(
            "Running constraint slice analysis ({} samples/cone)",
            samples_per_cone
        );

        let oracle = ConstraintSliceOracle::new().with_samples(samples_per_cone);

        // Generate a base witness that successfully executes.
        // Start with fresh generation, then fall back to corpus-derived witnesses.
        let mut base_witness_inputs: Option<Vec<FieldElement>> = None;
        let attempts = base_witness_attempts.max(1);
        for _ in 0..attempts {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping constraint-slice base witness search early: wall-clock timeout reached"
                );
                break;
            }
            let candidate = self.generate_test_case();
            let result = self.executor.execute_sync(&candidate.inputs);
            if result.success {
                base_witness_inputs = Some(candidate.inputs);
                break;
            }
        }

        if base_witness_inputs.is_none() {
            let corpus_probe_count = attempts.saturating_mul(4).max(16);
            for witness in self.collect_corpus_inputs(corpus_probe_count) {
                if self.wall_clock_timeout_reached() {
                    tracing::warn!(
                        "Stopping constraint-slice corpus witness fallback early: wall-clock timeout reached"
                    );
                    break;
                }
                let result = self.executor.execute_sync(&witness);
                if result.success {
                    tracing::info!(
                        "Constraint-slice base witness recovered via corpus fallback (probe_count={})",
                        corpus_probe_count
                    );
                    base_witness_inputs = Some(witness);
                    break;
                }
            }
        }

        let Some(base_witness_inputs) = base_witness_inputs else {
            tracing::warn!(
                "Skipping constraint slice attack: failed to find a valid base witness after {} generated attempts plus corpus fallback",
                attempts,
            );
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
            .run(self.executor.as_ref(), &base_witness_inputs, &outputs)
            .await;

        let _kept = self.record_custom_findings(findings, AttackType::ConstraintSlice, progress)?;

        if let Some(p) = progress {
            p.inc();
        }

        Ok(())
    }

    pub(super) async fn run_spec_inference_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
        phase_context: Option<(u64, u64, u64, u64)>,
    ) -> anyhow::Result<()> {
        use crate::oracles::spec_inference::SpecInferenceOracle;

        let configured_sample_count = config
            .get("sample_count")
            .and_then(|v| v.as_u64())
            .or_value(500) as usize;
        let configured_sample_count = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_sample_count,
            1000,
            "spec_inference.sample_count",
        );
        let sample_count = self.bounded_attack_units(
            configured_sample_count,
            1,
            "spec_inference_sample_count_cap",
            "spec_inference.sample_count",
        );
        let evidence_mode =
            Self::additional_bool(&self.config.campaign.parameters.additional, "evidence_mode")
                .unwrap_or_default();

        // Depth contract: SpecInference must run full depth in Mode 2.
        // Do not accept YAML knobs that would cap work or reduce attempt depth.
        if evidence_mode
            && (config.get("max_specs").is_some()
                || config.get("max_wall_clock_secs").is_some()
                || config.get("violation_attempts").is_some())
        {
            anyhow::bail!(
                "SpecInference depth-limiting knobs are not allowed in evidence mode: \
                 remove 'max_specs', 'max_wall_clock_secs', and 'violation_attempts' from the campaign YAML"
            );
        }

        tracing::info!("Running spec inference attack ({} samples)", sample_count);

        let oracle = SpecInferenceOracle::new()
            .with_sample_count(sample_count)
            .with_confidence_threshold(0.9)
            .with_wire_labels(self.input_labels());

        // Generate initial witnesses
        let mut initial_witnesses = Vec::with_capacity(sample_count.max(1));
        for _ in 0..sample_count.max(1) {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping spec-inference witness seeding early: wall-clock timeout reached"
                );
                break;
            }
            initial_witnesses.push(self.generate_test_case().inputs);
        }

        let mode_label = if evidence_mode { "evidence" } else { "run" };

        let findings = if let Some((phases_total, phases_completed, attack_idx, attacks_total)) =
            phase_context
        {
            let mut last_snapshot = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(60))
                .unwrap_or_else(std::time::Instant::now);
            oracle
                .run_with_progress(
                    self.executor.as_ref(),
                    &initial_witnesses,
                    |spec_idx, specs_total| {
                        let now = std::time::Instant::now();
                        let is_last = spec_idx.saturating_add(1) >= specs_total;
                        let should_emit = spec_idx == 0
                            || is_last
                            || now.duration_since(last_snapshot)
                                >= std::time::Duration::from_secs(15);
                        if !should_emit {
                            return;
                        }
                        last_snapshot = now;

                        let denom = specs_total.max(1) as f64;
                        let phase_progress =
                            ((spec_idx.saturating_add(1) as f64) / denom).clamp(0.0, 1.0);
                        self.write_progress_snapshot(
                            mode_label,
                            "attack_progress",
                            phases_total,
                            phases_completed,
                            Some(phase_progress),
                            serde_json::json!({
                                "attack_idx": attack_idx,
                                "attacks_total": attacks_total,
                                "attack_type": "SpecInference",
                                "specs_total": specs_total,
                                "specs_tested": spec_idx.saturating_add(1),
                            }),
                        );
                    },
                )
                .await
        } else {
            oracle.run(self.executor.as_ref(), &initial_witnesses).await
        };

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
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

    pub(super) async fn run_witness_collision_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::witness_collision::WitnessCollisionDetector;

        let configured_samples = config
            .get("samples")
            .and_then(|v| v.as_u64())
            .or_value(10000) as usize;
        let configured_samples = strict_attack_floor(
            &self.config.campaign.parameters.additional,
            configured_samples,
            2000,
            "witness_collision.samples",
        );
        let samples = self.bounded_attack_units(
            configured_samples,
            1,
            "witness_collision_samples_cap",
            "witness_collision.samples",
        );

        let scope_public_inputs = config
            .get("scope_public_inputs")
            .and_then(|v| v.as_bool())
            .or_value(true);

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
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping witness-collision sample generation early: wall-clock timeout reached"
                );
                break;
            }
            witnesses.push(self.generate_test_case().inputs);
        }

        let collisions = detector.run(self.executor.as_ref(), &witnesses).await;
        let findings = detector.to_findings(&collisions);

        if !findings.is_empty() {
            self.with_findings_write(|store| store.extend(findings.iter().cloned()))?;
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
}

#[cfg(test)]
#[path = "attack_runner_tests.rs"]
mod tests;
