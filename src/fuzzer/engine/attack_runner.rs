use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_underconstrained_attack(
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

        self.run_frozen_wire_detector(config, progress);

        Ok(())
    }

    pub(super) fn run_frozen_wire_detector(
        &self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) {
        use crate::attacks::FrozenWireDetector;
        use std::collections::HashSet;

        let section = config.get("frozen_wire");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return;
        }

        let min_samples = section
            .and_then(|v| v.get("min_samples"))
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;

        let mut constants = HashSet::new();
        if let Some(list) = section
            .and_then(|v| v.get("known_constants"))
            .and_then(|v| v.as_sequence())
        {
            for entry in list {
                let parsed = match entry {
                    serde_yaml::Value::Number(n) => n.as_u64().map(|v| v as usize),
                    serde_yaml::Value::String(s) => s.parse::<usize>().ok(),
                    _ => None,
                };
                if let Some(idx) = parsed {
                    constants.insert(idx);
                }
            }
        }

        let witnesses = self.collect_corpus_inputs(min_samples.max(1));
        if witnesses.is_empty() {
            tracing::warn!("Frozen wire detector skipped: no corpus witnesses available");
            return;
        }

        let detector = if constants.is_empty() {
            FrozenWireDetector::new().with_min_samples(min_samples)
        } else {
            FrozenWireDetector::new()
                .with_min_samples(min_samples)
                .with_known_constants(constants)
        };

        let findings = detector.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Underconstrained, progress);
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
        } else {
            for _ in 0..forge_attempts {
                let valid_case = self.generate_test_case();
                let valid_proof = match self.executor.prove(&valid_case.inputs) {
                    Ok(proof) => proof,
                    Err(err) => {
                        tracing::debug!(
                            "Skipping soundness attempt: failed to generate proof for witness: {}",
                            err
                        );
                        if let Some(p) = progress {
                            p.inc();
                        }
                        continue;
                    }
                };

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
                    if let Some(p) = progress {
                        p.inc();
                    }
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
                    // Always store the PoC finding with proof bytes so evidence
                    // is preserved regardless of oracle findings.
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
                        for of in &oracle_findings {
                            p.log_finding("CRITICAL", &of.description);
                        }
                    }
                }

                if let Some(p) = progress {
                    p.inc();
                }
            }
        }

        self.run_proof_malleability_attack(config, progress);
        self.run_determinism_check(config, progress);
        self.run_setup_poisoning_attack(config, progress);

        Ok(())
    }

    pub(super) fn run_proof_malleability_attack(
        &self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) {
        use crate::attacks::ProofMalleabilityScanner;

        let section = config.get("proof_malleability");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return;
        }

        let proof_samples = section
            .and_then(|v| v.get("proof_samples"))
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;
        let random_mutations = section
            .and_then(|v| v.get("random_mutations"))
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        let structured_mutations = section
            .and_then(|v| v.get("structured_mutations"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let witnesses = self.collect_corpus_inputs(proof_samples.max(1));
        if witnesses.is_empty() {
            tracing::warn!("Proof malleability scanner skipped: no corpus witnesses available");
            return;
        }

        let scanner = ProofMalleabilityScanner::new()
            .with_proof_samples(proof_samples)
            .with_random_mutations(random_mutations)
            .with_structured_mutations(structured_mutations);

        let findings = scanner.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Soundness, progress);
    }

    pub(super) fn run_determinism_check(
        &self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) {
        use crate::attacks::DeterminismOracle;

        let section = config.get("determinism");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return;
        }

        let repetitions = section
            .and_then(|v| v.get("repetitions"))
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as usize;
        let sample_count = section
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(50) as usize;

        let witnesses = self.collect_corpus_inputs(sample_count.max(1));
        if witnesses.is_empty() {
            tracing::warn!("Determinism oracle skipped: no corpus witnesses available");
            return;
        }

        let oracle = DeterminismOracle::new()
            .with_repetitions(repetitions)
            .with_sample_count(sample_count);

        let findings = oracle.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Soundness, progress);
    }

    pub(super) fn run_setup_poisoning_attack(
        &self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) {
        use crate::attacks::SetupPoisoningDetector;
        use std::path::PathBuf;

        let section = config.get("trusted_setup_test");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return;
        }

        let attempts = section
            .and_then(|v| v.get("attempts"))
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;
        if attempts == 0 {
            return;
        }

        let ptau_a = section.and_then(|v| v.get("ptau_file_a")).and_then(|v| v.as_str());
        let ptau_b = section.and_then(|v| v.get("ptau_file_b")).and_then(|v| v.as_str());

        let Some(ptau_a) = ptau_a else {
            tracing::warn!("Trusted setup test skipped: missing ptau_file_a");
            return;
        };
        let Some(ptau_b) = ptau_b else {
            tracing::warn!("Trusted setup test skipped: missing ptau_file_b");
            return;
        };
        if ptau_a == ptau_b {
            tracing::warn!("Trusted setup test skipped: ptau_file_a == ptau_file_b");
            return;
        }

        if !std::path::Path::new(ptau_a).exists() {
            tracing::warn!("Trusted setup test skipped: ptau_file_a not found ({})", ptau_a);
            return;
        }
        if !std::path::Path::new(ptau_b).exists() {
            tracing::warn!("Trusted setup test skipped: ptau_file_b not found ({})", ptau_b);
            return;
        }

        let circuit_path = self
            .config
            .campaign
            .target
            .circuit_path
            .to_str()
            .unwrap_or("");
        if circuit_path.is_empty() {
            tracing::warn!("Trusted setup test skipped: invalid circuit path");
            return;
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
                tracing::warn!("Trusted setup test skipped: failed to create executor A ({})", e);
                return;
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
                tracing::warn!("Trusted setup test skipped: failed to create executor B ({})", e);
                return;
            }
        };

        let witnesses = self.collect_corpus_inputs(attempts.max(1));
        if witnesses.is_empty() {
            tracing::warn!("Trusted setup test skipped: no corpus witnesses available");
            return;
        }

        let detector = SetupPoisoningDetector::new().with_attempts(attempts);
        let findings = detector.run(executor_a.as_ref(), executor_b.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Soundness, progress);
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

    pub(super) async fn run_collision_attack(
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

        self.run_nullifier_replay_attack(config, progress);

        Ok(())
    }

    pub(super) fn run_nullifier_replay_attack(
        &self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) {
        use crate::attacks::NullifierReplayScanner;

        let section = config.get("nullifier_replay");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return;
        }

        let replay_attempts = section
            .and_then(|v| v.get("replay_attempts"))
            .and_then(|v| v.as_u64())
            .unwrap_or(50) as usize;
        let base_samples = section
            .and_then(|v| v.get("base_samples"))
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;

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
                    serde_yaml::Value::String(s) => s.parse::<usize>().ok(),
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
            tracing::warn!("Nullifier replay scanner skipped: no corpus witnesses available");
            return;
        }

        let findings = scanner.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Collision, progress);
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

        self.run_canonicalization_attack(config, progress);

        Ok(())
    }

    pub(super) fn run_canonicalization_attack(
        &self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) {
        use crate::attacks::CanonicalizationChecker;

        let section = config.get("canonicalization");
        let enabled = section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return;
        }

        let sample_count = section
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(20) as usize;
        let test_field_wrap = section
            .and_then(|v| v.get("test_field_wrap"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let test_additive_inverse = section
            .and_then(|v| v.get("test_additive_inverse"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let test_negative_zero = section
            .and_then(|v| v.get("test_negative_zero"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let witnesses = self.collect_corpus_inputs(sample_count.max(1));
        if witnesses.is_empty() {
            tracing::warn!("Canonicalization checker skipped: no corpus witnesses available");
            return;
        }

        let checker = CanonicalizationChecker::new()
            .with_sample_count(sample_count)
            .with_field_wrap(test_field_wrap)
            .with_additive_inverse(test_additive_inverse)
            .with_negative_zero(test_negative_zero);

        let findings = checker.run(self.executor.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Boundary, progress);
    }

    pub(super) async fn run_verification_fuzzing_attack(
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

    pub(super) async fn run_witness_fuzzing_attack(
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

    pub(super) async fn run_differential_attack(
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

        let cross_backend_section = config.get("cross_backend");
        let cross_backend_enabled = cross_backend_section
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let cross_backend_samples = cross_backend_section
            .and_then(|v| v.get("sample_count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        let cross_backend_tolerance_bits = cross_backend_section
            .and_then(|v| v.get("tolerance_bits"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

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
        let mut cross_backend_execs: Vec<Arc<dyn CircuitExecutor>> = Vec::new();
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
                    if cross_backend_enabled && cross_backend_execs.len() < 2 {
                        cross_backend_execs.push(executor.clone());
                    }
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

        if cross_backend_enabled {
            if cross_backend_execs.len() >= 2 {
                self.run_cross_backend_differential(
                    cross_backend_execs[0].clone(),
                    cross_backend_execs[1].clone(),
                    cross_backend_samples,
                    cross_backend_tolerance_bits,
                    progress,
                );
            } else {
                tracing::warn!(
                    "Cross-backend differential skipped: fewer than two active executors"
                );
            }
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

    pub(super) fn run_cross_backend_differential(
        &self,
        executor_a: Arc<dyn CircuitExecutor>,
        executor_b: Arc<dyn CircuitExecutor>,
        sample_count: usize,
        tolerance_bits: usize,
        progress: Option<&ProgressReporter>,
    ) {
        use crate::attacks::CrossBackendDifferential;

        if sample_count == 0 {
            return;
        }

        let witnesses = self.collect_corpus_inputs(sample_count.max(1));
        if witnesses.is_empty() {
            tracing::warn!("Cross-backend differential skipped: no corpus witnesses available");
            return;
        }

        let oracle = CrossBackendDifferential::new()
            .with_sample_count(sample_count)
            .with_tolerance_bits(tolerance_bits);

        let findings = oracle.run(executor_a.as_ref(), executor_b.as_ref(), &witnesses);
        self.record_custom_findings(findings, AttackType::Differential, progress);
    }

    pub(super) async fn run_circuit_composition_attack(
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

    pub(super) async fn run_information_leakage_attack(
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

    pub(super) async fn run_timing_sidechannel_attack(
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

    pub(super) async fn run_recursive_proof_attack(
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

    pub(super) fn add_attack_findings(
        &self,
        attack: &dyn AttackTrait,
        samples: usize,
        progress: Option<&ProgressReporter>,
    ) -> usize {
        let context = AttackContext::new(
            self.get_circuit_info(),
            samples,
            self.config.campaign.parameters.timeout_seconds,
        )
        .with_executor(self.executor.clone())
        .with_input_ranges(self.input_index_ranges());
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

    pub(super) fn record_custom_findings(
        &self,
        mut findings: Vec<Finding>,
        attack_type: AttackType,
        progress: Option<&ProgressReporter>,
    ) -> usize {
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
                    attack_type
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

    pub(super) fn poc_is_empty(poc: &ProofOfConcept) -> bool {
        poc.witness_a.is_empty()
            && poc.witness_b.is_none()
            && poc.public_inputs.is_empty()
            && poc.proof.is_none()
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
                },
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
                },
                Err(e) => {
                    tracing::error!("FATAL: Violation confirmation panicked: {:?}", e);
                    anyhow::bail!("Violation confirmation panicked during execution");
                }
            }
        }

        // Filter to only confirmed violations (eliminate false positives)
        use crate::attacks::constraint_inference::ViolationConfirmation;
        let before_filter = implied.len();
        implied.retain(|c| c.confirmation == ViolationConfirmation::Confirmed);
        tracing::info!("Filtered {} -> {} violations (keeping only Confirmed, rejecting false positives)", 
            before_filter, implied.len());

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
            tracing::info!("Generated {} findings from constraint inference", findings.len());
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
        tracing::debug!("Enforcing v2 invariants...");
        let invariants: Vec<_> = self
            .config
            .get_invariants()
            .into_iter()
            .filter(|inv| inv.invariant_type != InvariantType::Metamorphic)
            .collect();
        
        let invariant_findings = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.enforce_invariants(&invariants)
        })) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("FATAL: Invariant enforcement panicked: {:?}", e);
                anyhow::bail!("Invariant enforcement panicked during execution");
            }
        };

        if !invariant_findings.is_empty() {
            tracing::info!("Generated {} findings from invariant enforcement", invariant_findings.len());
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
        use crate::attacks::metamorphic::MetamorphicOracle;

        let num_tests = config
            .get("num_tests")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;

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

    pub(super) async fn run_constraint_slice_attack(
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

    pub(super) async fn run_spec_inference_attack(
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

    pub(super) async fn run_witness_collision_attack(
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

}
