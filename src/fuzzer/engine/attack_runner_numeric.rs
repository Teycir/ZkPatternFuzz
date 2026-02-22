use super::attack_runner_option_ext::OptionValueExt;
use super::prelude::*;
use super::FuzzingEngine;
use std::collections::HashMap;
use zk_constraints::{
    ExtendedConstraint, LinearCombination, R1CSConstraint, RangeConstraint, RangeMethod, WireRef,
};

impl FuzzingEngine {
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

    pub(super) fn run_non_native_field_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::NonNativeFieldOracle;

        let section = config.get("non_native_field").or_value(config);
        let enabled = section
            .get("enabled")
            .and_then(|v| v.as_bool())
            .or_value(true);
        if !enabled {
            return Ok(());
        }

        let sample_count = section
            .get("sample_count")
            .and_then(|v| v.as_u64())
            .or_value(16) as usize;
        let case_limit = section
            .get("case_limit")
            .and_then(|v| v.as_u64())
            .or_value(256) as usize;
        let finding_limit = section
            .get("finding_limit")
            .and_then(|v| v.as_u64())
            .or_value(32) as usize;

        let mut witnesses = self.collect_corpus_inputs(sample_count.max(1));
        if witnesses.is_empty() {
            tracing::warn!(
                "Non-native field oracle did not receive corpus witnesses; falling back to generated samples"
            );
            for _ in 0..sample_count.max(1) {
                if self.wall_clock_timeout_reached() {
                    tracing::warn!(
                        "Stopping non-native oracle witness generation early: wall-clock timeout reached"
                    );
                    break;
                }
                witnesses.push(self.generate_test_case().inputs);
            }
        }
        if witnesses.is_empty() {
            tracing::warn!(
                "Skipping non-native field oracle: no witness samples available after fallback generation"
            );
            return Ok(());
        }

        let Some(inspector) = self.executor.constraint_inspector() else {
            tracing::debug!("Skipping non-native field oracle: constraint inspector unavailable");
            return Ok(());
        };

        let equations = inspector.get_constraints();
        if equations.is_empty() {
            tracing::debug!("Skipping non-native field oracle: no constraints available");
            return Ok(());
        }

        let mut wire_labels = inspector.wire_labels();
        self.merge_config_input_labels(inspector, &mut wire_labels);
        self.merge_output_labels(inspector, &mut wire_labels);

        let constraints = equations
            .iter()
            .map(|equation| Self::constraint_equation_to_extended(equation, &wire_labels))
            .collect::<Vec<_>>();

        let oracle = NonNativeFieldOracle::new()
            .with_sample_count(sample_count)
            .with_case_limit(case_limit)
            .with_finding_limit(finding_limit);

        let findings = oracle.run(
            self.executor.as_ref(),
            &constraints,
            &wire_labels,
            &witnesses,
        );
        self.record_custom_findings(findings, AttackType::BitDecomposition, progress)?;
        Ok(())
    }

    fn constraint_equation_to_extended(
        equation: &zk_core::ConstraintEquation,
        wire_labels: &HashMap<usize, String>,
    ) -> ExtendedConstraint {
        let is_range = equation
            .description
            .as_deref()
            .map(|desc| {
                let lower = desc.to_ascii_lowercase();
                lower.contains("range") || lower.contains("bit")
            })
            .unwrap_or(false);

        if is_range {
            let wire_idx = equation
                .c_terms
                .first()
                .map(|(idx, _)| *idx)
                .or_else(|| equation.a_terms.first().map(|(idx, _)| *idx));

            if let Some(index) = wire_idx {
                let bits = Self::infer_range_bits(
                    equation.description.as_deref(),
                    wire_labels.get(&index).map(|s| s.as_str()),
                );
                if let Some(bits) = bits {
                    return ExtendedConstraint::Range(RangeConstraint {
                        wire: Self::wire_ref_with_label(index, wire_labels),
                        bits,
                        method: RangeMethod::Plookup,
                    });
                }
            }
        }

        ExtendedConstraint::R1CS(R1CSConstraint {
            a: Self::linear_combination_from_terms(&equation.a_terms, wire_labels),
            b: Self::linear_combination_from_terms(&equation.b_terms, wire_labels),
            c: Self::linear_combination_from_terms(&equation.c_terms, wire_labels),
        })
    }

    fn linear_combination_from_terms(
        terms: &[(usize, FieldElement)],
        wire_labels: &HashMap<usize, String>,
    ) -> LinearCombination {
        let mut lc = LinearCombination::new();
        for (index, coeff) in terms {
            lc.add_term(
                Self::wire_ref_with_label(*index, wire_labels),
                coeff.clone(),
            );
        }
        lc
    }

    fn wire_ref_with_label(index: usize, wire_labels: &HashMap<usize, String>) -> WireRef {
        if let Some(name) = wire_labels.get(&index) {
            WireRef::named(index, name)
        } else {
            WireRef::new(index)
        }
    }

    fn infer_range_bits(description: Option<&str>, wire_label: Option<&str>) -> Option<usize> {
        description
            .and_then(Self::extract_plausible_bit_width)
            .or_else(|| wire_label.and_then(Self::extract_plausible_bit_width))
    }

    fn extract_plausible_bit_width(raw: &str) -> Option<usize> {
        const PLAUSIBLE_WIDTHS: &[usize] = &[
            8, 16, 24, 31, 32, 48, 51, 52, 64, 80, 96, 104, 112, 120, 126, 127, 128, 160, 192, 224,
            252, 253, 254, 255, 256,
        ];

        let mut token = String::new();
        for ch in raw.chars() {
            if ch.is_ascii_digit() {
                token.push(ch);
                continue;
            }

            if !token.is_empty() {
                if let Ok(value) = token.parse::<usize>() {
                    if PLAUSIBLE_WIDTHS.contains(&value) {
                        return Some(value);
                    }
                }
                token.clear();
            }
        }

        if !token.is_empty() {
            if let Ok(value) = token.parse::<usize>() {
                if PLAUSIBLE_WIDTHS.contains(&value) {
                    return Some(value);
                }
            }
        }

        None
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
}
