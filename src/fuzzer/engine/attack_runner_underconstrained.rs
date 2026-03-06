use super::attack_runner_option_ext::OptionValueExt;
use super::prelude::*;
use super::FuzzingEngine;

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
        let public_input_labels: Vec<String> = public_input_positions
            .iter()
            .filter_map(|&pos| self.config.inputs.get(pos).map(|input| input.name.clone()))
            .collect();
        tracing::info!(
            "Underconstrained public-input mapping: {:?}",
            public_input_labels
        );
        let path_probe_inputs =
            Self::underconstrained_path_probe_inputs(&self.config.inputs, &public_input_positions);
        if !path_probe_inputs.is_empty() {
            tracing::info!(
                "Underconstrained path-selector probe positions: {:?}",
                path_probe_inputs
                    .iter()
                    .map(|(idx, name)| format!("{}:{}", idx, name))
                    .collect::<Vec<_>>()
            );
        }

        if public_input_positions.is_empty() {
            tracing::warn!(
                "Skipping witness-collision underconstrained check: target exposes 0 public inputs, \
                 so output collisions across different private witnesses are expected."
            );
            self.run_frozen_wire_detector(config, progress)?;
            return Ok(());
        }

        let seed_inputs = self.collect_underconstrained_seed_inputs(witness_pairs.max(1))?;
        if seed_inputs.is_empty() {
            anyhow::bail!(
                "Underconstrained attack requires non-empty corpus seeds to avoid \
                 random invalid witness no-op behavior; provide seed inputs or run a \
                 seeding phase before underconstrained detection."
            );
        }

        // Generate fixed public inputs that will be shared across all test cases.
        // Prefer a corpus-derived base witness over raw random generation.
        let fixed_public = if public_input_positions.is_empty() {
            None
        } else if let Some(fixed) = Self::parse_fixed_public_inputs(config, &public_input_positions)
        {
            Some(fixed)
        } else {
            let base_inputs = seed_inputs
                .first()
                .cloned()
                .unwrap_or_else(|| self.generate_test_case().inputs);
            let fixed: Vec<(usize, FieldElement)> = public_input_positions
                .iter()
                .filter_map(|&pos| base_inputs.get(pos).map(|val| (pos, val.clone())))
                .collect();
            Some(fixed)
        };

        let mut test_cases = Vec::with_capacity(witness_pairs);
        let mut non_binary_generated = 0usize;
        let mut non_binary_generated_samples = Vec::new();
        for inputs in seed_inputs.into_iter().take(witness_pairs) {
            let mut tc = TestCase {
                inputs,
                expected_output: None,
                metadata: TestMetadata::default(),
            };
            if let Some(ref fixed) = fixed_public {
                for (pos, val) in fixed {
                    if *pos < tc.inputs.len() {
                        tc.inputs[*pos] = val.clone();
                    }
                }
            }
            if let Some(sample) = Self::first_non_binary_path_sample(&tc.inputs, &path_probe_inputs)
            {
                non_binary_generated = non_binary_generated.saturating_add(1);
                if non_binary_generated_samples.len() < 3 {
                    non_binary_generated_samples.push(sample);
                }
            }
            test_cases.push(tc);
        }

        let mut timed_out = false;
        while test_cases.len() < witness_pairs {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping underconstrained attack witness generation early: wall-clock timeout reached"
                );
                timed_out = true;
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
            if let Some(sample) = Self::first_non_binary_path_sample(&tc.inputs, &path_probe_inputs)
            {
                non_binary_generated = non_binary_generated.saturating_add(1);
                if non_binary_generated_samples.len() < 3 {
                    non_binary_generated_samples.push(sample);
                }
            }
            test_cases.push(tc);
        }

        // Execute in bounded chunks so wall-clock timeout can be enforced mid-attack.
        let executor = self.executor.clone();
        let execution_chunk_size = config
            .get("execution_chunk_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(32)
            .clamp(1, 256) as usize;

        // Group by output hash to find collisions
        // Mode 3: Pre-size HashMap to avoid rehashing
        // Use indices to reference test_cases, only clone when adding to collision set
        let num_pairs = test_cases.len();
        let mut output_map: std::collections::HashMap<Vec<u8>, Vec<usize>> =
            std::collections::HashMap::with_capacity(num_pairs / 2);
        let mut chunk_start = 0usize;
        let mut successful_executions = 0usize;
        let mut failed_executions = 0usize;
        let mut failed_execution_samples = Vec::new();
        let mut non_binary_successes = 0usize;
        let mut non_binary_success_samples = Vec::new();

        'execution_loop: while chunk_start < test_cases.len() {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping underconstrained attack execution early: wall-clock timeout reached"
                );
                timed_out = true;
                break;
            }

            let chunk_size = match self.wall_clock_remaining() {
                Some(remaining) if remaining <= Duration::from_secs(15) => 1usize,
                _ => execution_chunk_size,
            };
            let chunk_end = (chunk_start + chunk_size).min(test_cases.len());
            let chunk = &test_cases[chunk_start..chunk_end];

            let indexed_results: Vec<(usize, ExecutionResult, Duration)> =
                if let Some(ref pool) = self.thread_pool {
                    pool.install(|| {
                        chunk
                            .par_iter()
                            .enumerate()
                            .map(|(offset, tc)| {
                                let idx = chunk_start + offset;
                                let exec_start = Instant::now();
                                let result = executor.execute_sync(&tc.inputs);
                                (idx, result, exec_start.elapsed())
                            })
                            .collect()
                    })
                } else {
                    chunk
                        .iter()
                        .enumerate()
                        .map(|(offset, tc)| {
                            let idx = chunk_start + offset;
                            let exec_start = Instant::now();
                            let result = executor.execute_sync(&tc.inputs);
                            (idx, result, exec_start.elapsed())
                        })
                        .collect()
                };

            for (idx, result, exec_time) in indexed_results {
                self.observe_execution_result(&result, exec_time);

                if result.success {
                    successful_executions = successful_executions.saturating_add(1);
                    if let Some(sample) = Self::first_non_binary_path_sample(
                        &test_cases[idx].inputs,
                        &path_probe_inputs,
                    ) {
                        non_binary_successes = non_binary_successes.saturating_add(1);
                        if non_binary_success_samples.len() < 3 {
                            non_binary_success_samples.push(sample);
                        }
                    }
                    let output_hash = self.hash_output(&result.outputs);
                    output_map.entry(output_hash).or_default().push(idx);
                } else {
                    failed_executions = failed_executions.saturating_add(1);
                    if failed_execution_samples.len() < 3 {
                        let input_preview = test_cases[idx]
                            .inputs
                            .iter()
                            .enumerate()
                            .take(8)
                            .map(|(input_idx, value)| {
                                let label = self
                                    .config
                                    .inputs
                                    .get(input_idx)
                                    .map(|input| input.name.as_str())
                                    .unwrap_or("input");
                                format!("{}={}", label, value.to_decimal_string())
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        failed_execution_samples.push(format!(
                            "error={} input_preview=[{}]",
                            result
                                .error
                                .clone()
                                .unwrap_or_else(|| "<unknown>".to_string()),
                            input_preview
                        ));
                    }
                }

                if let Some(p) = progress {
                    p.inc();
                }

                if self.wall_clock_timeout_reached() {
                    tracing::warn!(
                        "Stopping underconstrained attack post-processing early: wall-clock timeout reached"
                    );
                    timed_out = true;
                    break 'execution_loop;
                }
            }

            chunk_start = chunk_end;
        }

        let collision_group_count = output_map
            .values()
            .filter(|indices| indices.len() > 1)
            .count();
        let max_collision_group_size = output_map
            .values()
            .map(|indices| indices.len())
            .max()
            .unwrap_or(0);
        tracing::info!(
            "Underconstrained execution summary: attempted={} successful={} failed={} collision_groups={} max_collision_group_size={} timed_out={}",
            test_cases.len(),
            successful_executions,
            failed_executions,
            collision_group_count,
            max_collision_group_size,
            timed_out
        );
        if !path_probe_inputs.is_empty() {
            tracing::info!(
                "Underconstrained path-selector summary: non_binary_generated={}/{} non_binary_successful={}/{} generated_samples={:?} successful_samples={:?}",
                non_binary_generated,
                test_cases.len(),
                non_binary_successes,
                successful_executions,
                non_binary_generated_samples,
                non_binary_success_samples
            );
        }
        if !failed_execution_samples.is_empty() {
            tracing::warn!(
                "Underconstrained failed execution samples: {:?}",
                failed_execution_samples
            );
        }

        if !timed_out && successful_executions == 0 {
            anyhow::bail!(
                "Underconstrained attack could not find any executable witness pairs \
                 (attempted={}, failed={}); seed corpus with valid witnesses for this target.",
                test_cases.len(),
                failed_executions
            );
        }

        // Check for collisions
        for (_hash, witness_indices) in output_map {
            if self.wall_clock_timeout_reached() {
                tracing::warn!(
                    "Stopping underconstrained collision scan early: wall-clock timeout reached"
                );
                timed_out = true;
                break;
            }
            // Collect TestCases for indices that produced same output
            let witnesses: Vec<&TestCase> = witness_indices
                .iter()
                .filter_map(|&idx| test_cases.get(idx))
                .collect();

            if witnesses.len() > 1 && self.witnesses_are_different_refs(&witnesses) {
                let Some((primary_witness, secondary_witness, non_binary_path_sample)) =
                    Self::select_collision_reporting_witnesses(&witnesses, &path_probe_inputs)
                else {
                    continue;
                };
                let public_inputs: Vec<FieldElement> = public_input_positions
                    .iter()
                    .filter_map(|&pos| primary_witness.inputs.get(pos).cloned())
                    .collect();
                let finding = Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: format!(
                        "Found {} different witnesses producing identical output",
                        witnesses.len()
                    ),
                    poc: super::ProofOfConcept {
                        witness_a: primary_witness.inputs.clone(),
                        witness_b: Some(secondary_witness.inputs.clone()),
                        public_inputs: public_inputs.clone(),
                        proof: None,
                    },
                    location: None,
                    class: None,
                };

                self.with_findings_write(|store| store.push(finding.clone()))?;

                if let Some(p) = progress {
                    p.log_finding("CRITICAL", &finding.description);
                }

                if let Some(path_sample) = non_binary_path_sample {
                    let boundary_finding = Finding {
                        attack_type: AttackType::Boundary,
                        severity: Severity::High,
                        description: format!(
                            "Circuit accepted non-binary path selector values under fixed public inputs while preserving identical output: {}",
                            path_sample
                        ),
                        poc: super::ProofOfConcept {
                            witness_a: primary_witness.inputs.clone(),
                            witness_b: Some(secondary_witness.inputs.clone()),
                            public_inputs,
                            proof: None,
                        },
                        location: None,
                        class: None,
                    };

                    self.with_findings_write(|store| store.push(boundary_finding.clone()))?;

                    if let Some(p) = progress {
                        p.log_finding("HIGH", &boundary_finding.description);
                    }
                }
            }
        }

        if timed_out {
            tracing::warn!(
                "Skipping frozen-wire follow-up: underconstrained attack already hit wall-clock timeout"
            );
            if path_probe_inputs.is_empty() {
                self.run_generic_underconstrained_detector(config, witness_pairs, progress)?;
            } else {
                tracing::warn!(
                    "Skipping generic underconstrained detector: targeted path-selector probe already consumed the wall-clock budget"
                );
            }
            return Ok(());
        }

        self.run_frozen_wire_detector(config, progress)?;
        self.run_generic_underconstrained_detector(config, witness_pairs, progress)?;

        Ok(())
    }

    fn run_generic_underconstrained_detector(
        &self,
        config: &serde_yaml::Value,
        witness_pairs: usize,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::UnderconstrainedDetector;

        let tolerance = config.get("tolerance").and_then(|v| v.as_f64());
        let detector = if let Some(tol) = tolerance {
            UnderconstrainedDetector::new(witness_pairs).with_tolerance(tol)
        } else {
            UnderconstrainedDetector::new(witness_pairs)
        };
        self.add_attack_findings(&detector, witness_pairs, progress)?;
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

    fn underconstrained_path_probe_inputs(
        inputs: &[Input],
        public_input_positions: &[usize],
    ) -> Vec<(usize, String)> {
        use std::collections::HashSet;

        let public_positions: HashSet<usize> = public_input_positions.iter().copied().collect();
        inputs
            .iter()
            .enumerate()
            .filter(|(idx, input)| {
                !public_positions.contains(idx) && Self::is_path_selector_input(&input.name)
            })
            .map(|(idx, input)| (idx, input.name.clone()))
            .collect()
    }

    fn is_path_selector_input(name: &str) -> bool {
        let normalized: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect();
        normalized.contains("pathindex") || normalized.contains("pathindices")
    }

    fn first_non_binary_path_sample(
        inputs: &[FieldElement],
        path_probe_inputs: &[(usize, String)],
    ) -> Option<String> {
        let mut values = Vec::new();
        for (idx, name) in path_probe_inputs {
            let value = inputs.get(*idx)?;
            if !Self::field_element_is_binary(value) {
                values.push(format!("{}={}", name, value.to_decimal_string()));
            }
        }

        if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        }
    }

    fn field_element_is_binary(value: &FieldElement) -> bool {
        value.is_zero() || value.is_one()
    }

    fn collect_underconstrained_seed_inputs(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<FieldElement>>> {
        use std::collections::HashSet;

        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut combined = Vec::new();
        let mut seen = HashSet::new();
        let mut external_loaded = 0usize;

        if let Some(path) = Self::additional_string(
            &self.config.campaign.parameters.additional,
            "seed_inputs_path",
        ) {
            let external = self.load_seed_inputs_from_path(&path)?;
            external_loaded = external.len();
            if external_loaded == 0 {
                tracing::warn!(
                    "Configured seed_inputs_path '{}' produced 0 usable witness seeds \
                     for underconstrained attack",
                    path
                );
            } else {
                tracing::info!(
                    "Loaded {} direct witness seeds from {} for underconstrained attack",
                    external_loaded,
                    path
                );
            }

            for inputs in external {
                if seen.insert(inputs.clone()) {
                    combined.push(inputs);
                    if combined.len() >= limit {
                        tracing::info!(
                            "Underconstrained seed candidates: external={} corpus=0 unique_used={}",
                            external_loaded,
                            combined.len()
                        );
                        return Ok(combined);
                    }
                }
            }
        }

        let mut corpus_loaded = 0usize;
        for inputs in self.collect_corpus_inputs(limit.max(1)) {
            corpus_loaded = corpus_loaded.saturating_add(1);
            if seen.insert(inputs.clone()) {
                combined.push(inputs);
                if combined.len() >= limit {
                    break;
                }
            }
        }

        tracing::info!(
            "Underconstrained seed candidates: external={} corpus={} unique_used={}",
            external_loaded,
            corpus_loaded,
            combined.len()
        );

        Ok(combined)
    }

    fn select_collision_reporting_witnesses<'a>(
        witnesses: &[&'a TestCase],
        path_probe_inputs: &[(usize, String)],
    ) -> Option<(&'a TestCase, &'a TestCase, Option<String>)> {
        let mut fallback_pair: Option<(&TestCase, &TestCase)> = None;

        for (idx, witness_a) in witnesses.iter().enumerate() {
            for witness_b in witnesses.iter().skip(idx + 1) {
                if witness_a.inputs == witness_b.inputs {
                    continue;
                }

                let witness_a_path_sample =
                    Self::first_non_binary_path_sample(&witness_a.inputs, path_probe_inputs);
                if witness_a_path_sample.is_some() {
                    return Some((witness_a, witness_b, witness_a_path_sample));
                }

                let witness_b_path_sample =
                    Self::first_non_binary_path_sample(&witness_b.inputs, path_probe_inputs);
                if witness_b_path_sample.is_some() {
                    return Some((witness_b, witness_a, witness_b_path_sample));
                }

                if fallback_pair.is_none() {
                    fallback_pair = Some((witness_a, witness_b));
                }
            }
        }

        fallback_pair.map(|(witness_a, witness_b)| (witness_a, witness_b, None))
    }
}
