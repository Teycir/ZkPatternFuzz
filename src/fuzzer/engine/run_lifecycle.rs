use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    /// Parse power schedule strategy from configuration
    ///
    /// Power schedules determine how energy is assigned to test cases:
    /// - **FAST**: Favor fast-executing test cases
    /// - **COE**: Cut-Off Exponential - balance speed and coverage
    /// - **EXPLORE**: Prioritize unexplored paths
    /// - **MMOPT**: Min-Max Optimal - balanced approach (default)
    /// - **RARE**: Focus on rare edge cases
    /// - **SEEK**: Actively seek new coverage
    ///
    /// Specified in campaign YAML as:
    /// ```yaml
    /// campaign:
    ///   parameters:
    ///     power_schedule: "MMOPT"
    /// ```
    /// Execute the complete fuzzing campaign
    ///
    /// This is the main entry point that runs the entire fuzzing workflow:
    /// 1. Analyzes circuit complexity and structure
    /// 2. Performs static analysis (taint, source code patterns)
    /// 3. Seeds initial corpus with interesting values
    /// 4. Executes configured attacks (underconstrained, soundness, etc.)
    /// 5. Runs coverage-guided fuzzing loop
    /// 6. Generates comprehensive report
    ///
    /// # Arguments
    ///
    /// * `progress` - Optional progress reporter for interactive display
    ///
    /// # Returns
    ///
    /// Returns a `FuzzReport` containing:
    /// - All discovered vulnerabilities with severity ratings
    /// - Proof-of-concept test cases for reproduction
    /// - Coverage statistics and execution metrics
    /// - Recommendations for fixing issues
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use zk_fuzzer::config::FuzzConfig;
    /// use zk_fuzzer::fuzzer::FuzzingEngine;
    /// use zk_fuzzer::progress::ProgressReporter;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// # let config_yaml = r#"
    /// # campaign:
    /// #   name: "Doc Engine Run"
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
    /// let mut engine = FuzzingEngine::new(config, Some(12345), 1)?;
    ///
    /// let rt = tokio::runtime::Runtime::new()?;
    /// // Run with progress reporting
    /// let reporter = ProgressReporter::new("Doc Engine Run", 10, false);
    /// let _report = rt.block_on(async { engine.run(Some(&reporter)).await })?;
    ///
    /// // Run without progress (CI/CD mode)
    /// // let _report = rt.block_on(async { engine.run(None).await })?;
    /// # Ok(())
    /// # }
    /// ```
    pub(super) fn with_findings_write<R>(
        &self,
        apply: impl FnOnce(&mut Vec<Finding>) -> R,
    ) -> anyhow::Result<R> {
        let findings_store = self.core.findings();
        let mut store = findings_store.write();
        Ok(apply(&mut store))
    }

    pub(super) fn with_findings_read<R>(
        &self,
        apply: impl FnOnce(&Vec<Finding>) -> R,
    ) -> anyhow::Result<R> {
        let findings_store = self.core.findings();
        let store = findings_store.read();
        Ok(apply(&store))
    }

    fn configure_wall_clock_deadline(&mut self, start_time: Instant) -> Option<u64> {
        let timeout_seconds = self
            .config
            .campaign
            .parameters
            .additional
            .get("fuzzing_timeout_seconds")
            .and_then(|v| v.as_u64());

        self.wall_clock_deadline = timeout_seconds.and_then(|seconds| {
            let bounded = seconds.max(1);
            start_time.checked_add(Duration::from_secs(bounded))
        });

        if let Some(seconds) = timeout_seconds {
            if self.wall_clock_deadline.is_some() {
                tracing::info!(
                    "Global wall-clock timeout enabled for this run: {}s",
                    seconds.max(1)
                );
            } else {
                tracing::warn!(
                    "Failed to configure global wall-clock timeout from {}s (overflow)",
                    seconds
                );
            }
        }

        timeout_seconds
    }

    pub(super) fn wall_clock_timeout_reached(&self) -> bool {
        self.wall_clock_deadline
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(false)
    }

    pub(super) fn wall_clock_remaining(&self) -> Option<Duration> {
        self.wall_clock_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    pub async fn run(&mut self, progress: Option<&ProgressReporter>) -> anyhow::Result<FuzzReport> {
        let start_time = Instant::now();
        self.core.set_start_time(start_time);
        let _configured_wall_clock_timeout = self.configure_wall_clock_deadline(start_time);

        let additional = &self.config.campaign.parameters.additional;
        let evidence_mode = Self::additional_bool(additional, "evidence_mode").unwrap_or(false);
        // Engagement contract: in evidence mode, fail fast on misconfiguration that would cause
        // patterns/attacks to be silently skipped.
        let engagement_strict =
            Self::additional_bool(additional, "engagement_strict").unwrap_or(evidence_mode);
        let mode_label = if evidence_mode { "evidence" } else { "run" };
        let phases_total = 1u64
            .saturating_add(self.config.attacks.len() as u64)
            .saturating_add(1)
            .saturating_add(1); // seeded_corpus + attacks + continuous + reporting

        tracing::warn!(
            "MILESTONE start mode={} target={} circuit={} output_dir={}",
            mode_label,
            self.config.campaign.name,
            self.config.campaign.target.circuit_path.display(),
            self.config.reporting.output_dir.display()
        );
        self.write_progress_snapshot(
            mode_label,
            "start",
            phases_total,
            0,
            None,
            serde_json::json!({}),
        );

        tracing::info!("Starting fuzzing campaign: {}", self.config.campaign.name);
        tracing::info!(
            "Circuit: {} ({:?})",
            self.executor.name(),
            self.executor.framework()
        );
        tracing::info!("Workers: {}", self.workers);

        // Check for underconstrained circuit
        if self.executor.is_likely_underconstrained() {
            tracing::warn!(
                "Circuit appears underconstrained (DOF = {})",
                self.executor.circuit_info().degrees_of_freedom()
            );
        }

        // Run taint analysis before fuzzing
        if let Some(ref analyzer) = self.taint_analyzer {
            let taint_findings = analyzer.to_findings();
            if !taint_findings.is_empty() {
                tracing::info!(
                    "Taint analysis found {} potential issues",
                    taint_findings.len()
                );
                for finding in &taint_findings {
                    if let Some(p) = progress {
                        p.log_finding(&format!("{:?}", finding.severity), &finding.description);
                    }
                }
                self.with_findings_write(|store| store.extend(taint_findings))?;
            }
        }

        // Run source code analysis for vulnerability hints
        self.run_source_analysis(progress);

        // Seed corpus with external inputs if provided
        if let Err(err) = self.seed_external_inputs_from_config() {
            tracing::warn!("Failed to load external seed inputs: {}", err);
        }

        // Phase 0: Load resume corpus if --resume was specified
        match self.maybe_load_resume_corpus() {
            Ok(count) if count > 0 => {
                tracing::info!("Resumed from {} previous test cases", count);
            }
            Err(err) => {
                tracing::warn!("Failed to load resume corpus: {}", err);
            }
            _ => {}
        }

        // Seed corpus
        self.seed_corpus()?;
        tracing::info!(
            "Seeded corpus with {} initial test cases",
            self.core.corpus().len()
        );
        tracing::warn!(
            "MILESTONE seeded_corpus target={} count={}",
            self.config.campaign.name,
            self.core.corpus().len()
        );
        self.write_progress_snapshot(
            mode_label,
            "seeded_corpus",
            phases_total,
            1,
            None,
            serde_json::json!({
                "corpus_len": self.core.corpus().len(),
            }),
        );

        // Regex selector hits are static CVE-pattern evidence. Record them as findings
        // with executable witness context so they survive evidence-mode validation.
        let pattern_findings = self.record_scan_pattern_findings(progress, evidence_mode)?;
        if pattern_findings > 0 {
            tracing::warn!(
                "MILESTONE pattern_findings target={} count={}",
                self.config.campaign.name,
                pattern_findings
            );
        }

        // Initialize simple progress tracker for non-interactive environments
        self.simple_tracker = Some(SimpleProgressTracker::new());

        // Update power scheduler with initial global stats
        self.update_power_scheduler_globals();

        // Run attacks
        let attacks_total = self.config.attacks.len() as u64;
        let run_id_for_snapshots =
            Self::additional_string(&self.config.campaign.parameters.additional, "run_id");
        let command_for_snapshots = match Self::additional_string(
            &self.config.campaign.parameters.additional,
            "run_command",
        ) {
            Some(value) => value,
            None => {
                if mode_label == "evidence" {
                    "evidence".to_string()
                } else {
                    "run".to_string()
                }
            }
        };

        struct _StopAttackHeartbeat(tokio::sync::watch::Sender<bool>);
        impl Drop for _StopAttackHeartbeat {
            fn drop(&mut self) {
                if let Err(err) = self.0.send(true) {
                    tracing::warn!("Failed to stop attack progress heartbeat: {}", err);
                }
            }
        }

        let mut wall_clock_timed_out = false;
        for (attack_idx, attack_config) in self.config.attacks.clone().into_iter().enumerate() {
            if self.wall_clock_timeout_reached() {
                wall_clock_timed_out = true;
                let phases_completed = 1u64.saturating_add(attack_idx as u64);
                tracing::warn!(
                    "Global wall-clock timeout reached before attack {:?}; ending run early",
                    attack_config.attack_type
                );
                self.write_progress_snapshot(
                    mode_label,
                    "timeout_reached",
                    phases_total,
                    phases_completed,
                    Some(0.0),
                    serde_json::json!({
                        "reason": "wall_clock_timeout",
                        "elapsed_seconds": start_time.elapsed().as_secs_f64(),
                        "remaining_seconds": self.wall_clock_remaining().map(|d| d.as_secs_f64()),
                        "next_attack_type": format!("{:?}", attack_config.attack_type),
                    }),
                );
                break;
            }

            let phases_completed = 1u64.saturating_add(attack_idx as u64);
            self.write_progress_snapshot(
                mode_label,
                "attack_start",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "attack_idx": attack_idx,
                    "attacks_total": attacks_total,
                    "attack_type": format!("{:?}", attack_config.attack_type),
                }),
            );
            tracing::warn!(
                "MILESTONE attack_start target={} type={:?}",
                self.config.campaign.name,
                attack_config.attack_type
            );
            if let Some(p) = progress {
                p.log_attack_start(&format!("{:?}", attack_config.attack_type));
            }

            // Keep machine-readable progress alive for long-running attacks that do not
            // emit internal progress updates (e.g. non-SpecInference attacks).
            let _attack_heartbeat_guard =
                if !matches!(attack_config.attack_type, AttackType::SpecInference) {
                    let (hb_stop_tx, mut hb_stop_rx) = tokio::sync::watch::channel(false);
                    let output_dir = self.config.reporting.output_dir.clone();
                    let campaign_name = self.config.campaign.name.clone();
                    let mode_label_owned = mode_label.to_string();
                    let command_owned = command_for_snapshots.clone();
                    let run_id_owned = run_id_for_snapshots.clone();
                    let attack_idx_u64 = attack_idx as u64;
                    let attack_type_label = format!("{:?}", attack_config.attack_type);

                    tokio::spawn(async move {
                        let heartbeat_start = std::time::Instant::now();
                        let progress_path = output_dir.join("progress.json");
                        loop {
                            if *hb_stop_rx.borrow() {
                                break;
                            }

                            tokio::select! {
                                _ = hb_stop_rx.changed() => {},
                                _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {},
                            }

                            if *hb_stop_rx.borrow() {
                                break;
                            }

                            let now_epoch = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            let overall = if phases_total == 0 {
                                0.0
                            } else {
                                (phases_completed as f64 / phases_total as f64).clamp(0.0, 1.0)
                            };
                            let steps_total = phases_total.max(1);
                            let steps_done = phases_completed.min(steps_total);
                            let step_current = (steps_done.saturating_add(1)).min(steps_total);
                            let elapsed = heartbeat_start.elapsed().as_secs();

                            let snapshot = serde_json::json!({
                                "updated_unix_seconds": now_epoch,
                                "run_id": run_id_owned.clone(),
                                "command": command_owned.clone(),
                                "mode_label": mode_label_owned.clone(),
                                "campaign_name": campaign_name.clone(),
                                "output_dir": output_dir.display().to_string(),
                                "stage": "attack_progress",
                                "progress": {
                                    "steps_total": steps_total,
                                    "steps_done": steps_done,
                                    "step_current": step_current,
                                    "step_fraction": format!("{}/{}", step_current, steps_total),
                                    "overall_fraction": overall,
                                    "overall_percent": (overall * 100.0),
                                    "phase_progress": serde_json::Value::Null,
                                },
                                "details": {
                                    "attack_idx": attack_idx_u64,
                                    "attacks_total": attacks_total,
                                    "attack_type": attack_type_label,
                                    "heartbeat": true,
                                    "elapsed_seconds": elapsed,
                                },
                            });

                            if let Some(parent) = progress_path.parent() {
                                if let Err(err) = std::fs::create_dir_all(parent) {
                                    tracing::warn!(
                                        "Failed to create attack heartbeat progress dir '{}': {}",
                                        parent.display(),
                                        err
                                    );
                                    continue;
                                }
                            }
                            let data = match serde_json::to_vec_pretty(&snapshot) {
                                Ok(data) => data,
                                Err(err) => {
                                    tracing::warn!(
                                        "Failed serializing attack heartbeat snapshot: {}",
                                        err
                                    );
                                    continue;
                                }
                            };
                            if let Err(err) = crate::util::write_file_atomic(&progress_path, &data)
                            {
                                tracing::warn!(
                                    "Failed writing attack heartbeat progress '{}': {}",
                                    progress_path.display(),
                                    err
                                );
                            }
                        }
                    });

                    Some(_StopAttackHeartbeat(hb_stop_tx))
                } else {
                    None
                };

            let findings_before = self.with_findings_read(|store| store.len())?;
            let (plugin_name, plugin_explicit) = Self::resolve_attack_plugin(&attack_config);
            let mut plugin_ran = false;
            let mut attack_executed = false;

            if let Some(name) = plugin_name.as_deref() {
                let lookup = name.trim();
                let plugin = self
                    .attack_registry
                    .get(lookup)
                    .or_else(|| self.attack_registry.get(&lookup.to_lowercase()));

                if let Some(plugin) = plugin {
                    let samples = Self::attack_samples(&attack_config.config);
                    self.add_attack_findings(plugin, samples, progress)?;
                    plugin_ran = true;
                    attack_executed = true;
                } else {
                    if plugin_explicit && engagement_strict {
                        anyhow::bail!(
                            "Engagement contract violation: attack[{}] specifies plugin '{}' \
                             but it was not found in the registry. In strict evidence mode this \
                             is a hard error because it would silently skip intended patterns.",
                            attack_idx,
                            lookup
                        );
                    }
                    tracing::warn!("Attack plugin '{}' not found in registry", lookup);
                }
            }

            if !(plugin_ran && plugin_explicit) {
                match attack_config.attack_type {
                    AttackType::Underconstrained => {
                        self.run_underconstrained_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Soundness => {
                        self.run_soundness_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::TrustedSetup => {
                        self.run_setup_poisoning_attack(
                            &attack_config.config,
                            AttackType::TrustedSetup,
                            progress,
                        )?;
                        attack_executed = true;
                    }
                    AttackType::ArithmeticOverflow => {
                        self.run_arithmetic_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Collision => {
                        self.run_collision_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Boundary => {
                        self.run_boundary_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::ConstraintBypass => {
                        self.run_canonicalization_attack(
                            &attack_config.config,
                            AttackType::ConstraintBypass,
                            progress,
                        )?;
                        attack_executed = true;
                    }
                    AttackType::BitDecomposition => {
                        tracing::info!(
                            "Routing BitDecomposition attack to underconstrained runner"
                        );
                        self.run_underconstrained_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Malleability => {
                        self.run_proof_malleability_attack(
                            &attack_config.config,
                            AttackType::Malleability,
                            progress,
                        )?;
                        attack_executed = true;
                    }
                    AttackType::ReplayAttack => {
                        self.run_nullifier_replay_attack(
                            &attack_config.config,
                            AttackType::ReplayAttack,
                            progress,
                        )?;
                        attack_executed = true;
                    }
                    AttackType::VerificationFuzzing => {
                        self.run_verification_fuzzing_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::WitnessFuzzing => {
                        self.run_witness_fuzzing_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Differential => {
                        self.run_differential_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::InformationLeakage => {
                        self.run_information_leakage_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::WitnessLeakage => {
                        self.run_information_leakage_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::TimingSideChannel => {
                        self.run_timing_sidechannel_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::CircuitComposition => {
                        self.run_circuit_composition_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::RecursiveProof => {
                        self.run_recursive_proof_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::Mev => {
                        self.run_mev_attack(&attack_config.config, progress).await?;
                        attack_executed = true;
                    }
                    AttackType::FrontRunning => {
                        self.run_front_running_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::ZkEvm => {
                        self.run_zkevm_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::BatchVerification => {
                        self.run_batch_verification_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::SidechannelAdvanced => {
                        self.run_sidechannel_advanced_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::QuantumResistance => {
                        self.run_quantum_resistance_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::PrivacyAdvanced => {
                        self.run_privacy_advanced_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::DefiAdvanced => {
                        self.run_defi_advanced_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::CircomStaticLint => {
                        self.run_circom_static_lint_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    // Phase 4: Novel Oracle Attacks - Now Implemented!
                    AttackType::ConstraintInference => {
                        match self
                            .run_constraint_inference_attack(&attack_config.config, progress)
                            .await
                        {
                            Ok(_) => {
                                tracing::info!(
                                    "✓ Constraint inference attack completed successfully"
                                );
                            }
                            Err(e) => {
                                tracing::error!("✗ Constraint inference attack FAILED: {}", e);
                                tracing::error!("Error details: {:?}", e);
                                if let Some(p) = progress {
                                    p.log_finding(
                                        "ERROR",
                                        &format!("Constraint inference failed: {}", e),
                                    );
                                }
                                return Err(e);
                            }
                        }
                        attack_executed = true;
                    }
                    AttackType::Metamorphic => {
                        self.run_metamorphic_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::ConstraintSlice => {
                        self.run_constraint_slice_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                    AttackType::SpecInference => {
                        self.run_spec_inference_attack(
                            &attack_config.config,
                            progress,
                            Some((
                                phases_total,
                                phases_completed,
                                attack_idx as u64,
                                attacks_total,
                            )),
                        )
                        .await?;
                        attack_executed = true;
                    }
                    AttackType::WitnessCollision => {
                        self.run_witness_collision_attack(&attack_config.config, progress)
                            .await?;
                        attack_executed = true;
                    }
                }
            }

            if engagement_strict && !attack_executed {
                anyhow::bail!(
                    "Engagement contract violation: attack[{}] type {:?} is configured but did not execute \
                     (unimplemented or skipped). In strict evidence mode, this run is invalid because it \
                     would silently skip attack patterns.",
                    attack_idx,
                    attack_config.attack_type
                );
            }

            let findings_after = self.with_findings_read(|store| store.len())?;
            let new_findings = findings_after - findings_before;

            if let Some(p) = progress {
                p.log_attack_complete(&format!("{:?}", attack_config.attack_type), new_findings);
            }
            tracing::warn!(
                "MILESTONE attack_complete target={} type={:?} new_findings={} total_findings={}",
                self.config.campaign.name,
                attack_config.attack_type,
                new_findings,
                findings_after
            );
            let phases_completed = 1u64.saturating_add((attack_idx as u64).saturating_add(1));
            self.write_progress_snapshot(
                mode_label,
                "attack_complete",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "attack_idx": attack_idx,
                    "attacks_total": attacks_total,
                    "attack_type": format!("{:?}", attack_config.attack_type),
                    "new_findings": new_findings,
                    "total_findings": findings_after,
                }),
            );

            // Update power scheduler with current stats after each attack
            self.update_power_scheduler_globals();

            // Update simple tracker
            let current_stats = self.stats();
            if let Some(ref mut tracker) = self.simple_tracker {
                tracker.update(current_stats);
            }

            if self.wall_clock_timeout_reached() {
                wall_clock_timed_out = true;
                let phases_completed = 1u64.saturating_add((attack_idx as u64).saturating_add(1));
                tracing::warn!(
                    "Global wall-clock timeout reached after attack {:?}; ending run early",
                    attack_config.attack_type
                );
                self.write_progress_snapshot(
                    mode_label,
                    "timeout_reached",
                    phases_total,
                    phases_completed,
                    Some(0.0),
                    serde_json::json!({
                        "reason": "wall_clock_timeout",
                        "elapsed_seconds": start_time.elapsed().as_secs_f64(),
                        "remaining_seconds": self.wall_clock_remaining().map(|d| d.as_secs_f64()),
                        "last_attack_type": format!("{:?}", attack_config.attack_type),
                    }),
                );
                break;
            }
        }

        // Finish simple tracker
        if let Some(ref tracker) = self.simple_tracker {
            tracker.finish();
        }

        // Phase 0 Fix: Run continuous fuzzing phase after attacks
        let iterations = self
            .config
            .campaign
            .parameters
            .additional
            .get("max_iterations")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                self.config
                    .campaign
                    .parameters
                    .additional
                    .get("fuzzing_iterations")
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(1000);

        let timeout = self
            .config
            .campaign
            .parameters
            .additional
            .get("fuzzing_timeout_seconds")
            .and_then(|v| v.as_u64());

        if iterations > 0 && !wall_clock_timed_out && !self.wall_clock_timeout_reached() {
            let phases_completed = 1u64.saturating_add(attacks_total);
            self.write_progress_snapshot(
                mode_label,
                "continuous_start",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "iterations": iterations,
                    "timeout_seconds": timeout,
                }),
            );
            tracing::warn!(
                "MILESTONE continuous_start target={} iterations={} timeout={:?}",
                self.config.campaign.name,
                iterations,
                timeout
            );
            self.run_continuous_fuzzing_phase(
                iterations,
                timeout,
                progress,
                mode_label,
                phases_total,
                phases_completed,
            )
            .await?;
            tracing::warn!(
                "MILESTONE continuous_complete target={}",
                self.config.campaign.name
            );
            let phases_completed = phases_completed.saturating_add(1);
            self.write_progress_snapshot(
                mode_label,
                "continuous_complete",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({}),
            );
        } else if iterations > 0 {
            tracing::warn!(
                "Skipping continuous fuzzing phase: global wall-clock timeout already reached"
            );
            let phases_completed = 1u64.saturating_add(attacks_total);
            self.write_progress_snapshot(
                mode_label,
                "continuous_skipped_timeout",
                phases_total,
                phases_completed,
                Some(0.0),
                serde_json::json!({
                    "reason": "wall_clock_timeout",
                    "elapsed_seconds": start_time.elapsed().as_secs_f64(),
                }),
            );
        }

        self.finalize_run_report(start_time, mode_label, phases_total)
    }
}
