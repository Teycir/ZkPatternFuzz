use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_attack_phase(
        &mut self,
        progress: Option<&ProgressReporter>,
        mode_label: &str,
        phases_total: u64,
        start_time: Instant,
        engagement_strict: bool,
    ) -> anyhow::Result<(u64, bool)> {
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
            let attack_phase_index = 1u64.saturating_add(attack_idx as u64);
            if self.wall_clock_timeout_reached() {
                wall_clock_timed_out = true;
                tracing::warn!(
                    "Global wall-clock timeout reached before attack {:?}; ending run early",
                    attack_config.attack_type
                );
                self.write_progress_snapshot(
                    mode_label,
                    "timeout_reached",
                    phases_total,
                    attack_phase_index,
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

            self.write_progress_snapshot(
                mode_label,
                "attack_start",
                phases_total,
                attack_phase_index,
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
                                (attack_phase_index as f64 / phases_total as f64).clamp(0.0, 1.0)
                            };
                            let steps_total = phases_total.max(1);
                            let steps_done = attack_phase_index.min(steps_total);
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
                            "Running BitDecomposition attack with underconstrained + non-native field checks"
                        );
                        self.run_underconstrained_attack(&attack_config.config, progress)
                            .await?;
                        self.run_non_native_field_attack(&attack_config.config, progress)?;
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
                                attack_phase_index,
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
            self.write_progress_snapshot(
                mode_label,
                "attack_complete",
                phases_total,
                attack_phase_index,
                Some(1.0),
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
                tracing::warn!(
                    "Global wall-clock timeout reached after attack {:?}; ending run early",
                    attack_config.attack_type
                );
                self.write_progress_snapshot(
                    mode_label,
                    "timeout_reached",
                    phases_total,
                    attack_phase_index,
                    Some(1.0),
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

        Ok((attacks_total, wall_clock_timed_out))
    }
}
