use super::attack_runner_budget::strict_attack_floor;
use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
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
            .unwrap_or(100) as usize;
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
            .unwrap_or(100) as usize;
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
            .unwrap_or(16) as usize;
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
            .unwrap_or(500) as usize;
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
            .unwrap_or(10000) as usize;
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
