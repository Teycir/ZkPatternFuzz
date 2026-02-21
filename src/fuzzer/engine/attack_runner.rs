use super::attack_runner_budget::strict_attack_floor;
use super::prelude::*;
use super::FuzzingEngine;

pub(super) trait OptionValueExt<T> {
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

impl FuzzingEngine {
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

}

#[cfg(test)]
#[path = "attack_runner_tests.rs"]
mod tests;
