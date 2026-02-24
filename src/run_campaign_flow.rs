use chrono::{Local, Utc};
use std::path::Path;

use crate::cli::{campaign_run_options_doc, CampaignRunOptions};
use crate::engagement_artifacts::{
    mode_folder_from_command, write_global_run_signal, write_run_artifacts,
};
use crate::run_bootstrap::{
    announce_report_dir_and_bind_log_context, load_campaign_config_with_optional_profile,
};
use crate::run_identity::make_run_id;
use crate::run_lifecycle::{
    initialize_campaign_run_lifecycle, require_evidence_readiness_or_emit_failure,
    run_backend_preflight_or_emit_failure, seed_running_run_artifact,
    write_failed_mode_run_artifact_with_error, write_failed_mode_run_artifact_with_reason,
    RunLifecycleContext, RunLifecycleMeta,
};
use crate::run_log_context::RunLogContextGuard;
use crate::run_outcome_docs::{
    completed_run_doc_with_window, running_run_doc_with_window, RunOutcomeDocContext,
};
use crate::run_paths::engagement_root_dir;
use crate::runtime_misc::{print_banner, print_run_window};
use zk_fuzzer::ai::{build_ai_circuit_context, redact_sensitive_text, AIAssistant};
use zk_fuzzer::formal::{
    export_formal_bridge_artifacts, import_formal_invariants_from_file, FormalBridgeOptions,
};
use zk_fuzzer::fuzzer::ZkFuzzer;
use zk_fuzzer::Framework;

fn maybe_write_ai_artifact(output_dir: &Path, file_name: &str, content: &str) {
    let path = output_dir.join("ai").join(file_name);
    if let Err(err) = zk_fuzzer::util::write_file_atomic(&path, content.as_bytes()) {
        tracing::warn!("Failed to write AI artifact '{}': {}", path.display(), err);
    }
}

struct CampaignPipeline;

impl CampaignPipeline {
    fn apply_resume_mode(config: &mut zk_fuzzer::config::FuzzConfig, options: &CampaignRunOptions) {
        if !options.resume {
            return;
        }

        let corpus_path = if let Some(ref dir) = options.corpus_dir {
            std::path::PathBuf::from(dir)
        } else {
            config.reporting.output_dir.join("corpus")
        };

        if corpus_path.exists() {
            tracing::info!("Resume mode: loading corpus from {:?}", corpus_path);
            config.campaign.parameters.additional.insert(
                "resume_corpus_dir".to_string(),
                serde_yaml::Value::String(corpus_path.display().to_string()),
            );
            println!("📂 Resuming from corpus: {}", corpus_path.display());
        } else {
            tracing::warn!(
                "Resume requested but corpus directory not found: {:?}",
                corpus_path
            );
            println!(
                "⚠️  Corpus directory not found, starting fresh: {}",
                corpus_path.display()
            );
        }
    }

    fn print_dry_run_summary(
        config: &zk_fuzzer::config::FuzzConfig,
        options: &CampaignRunOptions,
        ai_enabled: bool,
        ai_generated_invariant_count: usize,
        ai_generated_yaml: bool,
        formal_bridge_options: &FormalBridgeOptions,
        formal_bridge_invariant_count: usize,
        imported_formal_invariants: usize,
    ) {
        println!("\n✓ Configuration is valid");
        println!("  Campaign: {}", config.campaign.name);
        println!("  Target: {:?}", config.campaign.target.framework);
        println!("  Attacks: {}", config.attacks.len());
        println!("  Inputs: {}", config.inputs.len());
        if options.resume {
            println!("  Resume: enabled");
        }
        if ai_enabled {
            println!(
                "  AI: enabled (invariants: {}, config_suggestion: {})",
                ai_generated_invariant_count,
                if ai_generated_yaml {
                    "generated"
                } else {
                    "not_generated"
                }
            );
        }
        if formal_bridge_options.enabled {
            println!(
                "  Formal bridge: enabled (system: {:?}, invariants: {}, imported_now: {})",
                formal_bridge_options.system,
                formal_bridge_invariant_count,
                imported_formal_invariants
            );
        }
        if let Some(ref profile) = options.profile {
            println!("  Profile: {}", profile);
        }
    }
}

pub(crate) async fn run_campaign(
    config_path: &str,
    options: CampaignRunOptions,
) -> anyhow::Result<()> {
    let started_utc = Utc::now();
    let run_wall_clock_started = std::time::Instant::now();
    let command = options.command_label;
    let run_id = make_run_id(command, Some(config_path));
    let mut stage: &'static str;
    announce_report_dir_and_bind_log_context(
        options.dry_run,
        &run_id,
        command,
        config_path,
        &started_utc,
    );

    let mut config = load_campaign_config_with_optional_profile(
        "campaign",
        &run_id,
        command,
        config_path,
        &started_utc,
        options.profile.as_deref(),
    )?;

    let campaign_name = config.campaign.name.clone();
    let formal_bridge_options =
        FormalBridgeOptions::from_additional(&config.campaign.parameters.additional);
    let imported_formal_invariants =
        match import_formal_invariants_from_file(&mut config, config_path) {
            Ok(count) => count,
            Err(err) => {
                tracing::warn!("Failed to import formal invariants: {}", err);
                0
            }
        };
    if imported_formal_invariants > 0 {
        tracing::info!(
            "Imported {} formal invariants into fuzzing runtime",
            imported_formal_invariants
        );
    }
    let formal_bridge_invariants = config.get_invariants();

    let ai_assistant = config
        .get_ai_assistant_config()
        .filter(|cfg| cfg.enabled)
        .map(|cfg| {
            tracing::info!(
                "AI assistant enabled (model='{}', modes={:?})",
                cfg.model,
                cfg.modes
            );
            AIAssistant::new(cfg)
        });

    if options.real_only {
        tracing::info!("--real-only set (real backend mode is already enforced)");
    }

    // Soundness for Circom requires proving/verification keys. In strict live runs, ensure
    // prerequisites are satisfied by auto-running trusted setup when needed.
    let needs_soundness_keys = config
        .attacks
        .iter()
        .any(|attack| matches!(attack.attack_type, zk_fuzzer::config::AttackType::Soundness));
    if config.campaign.target.framework == Framework::Circom && needs_soundness_keys {
        config.campaign.parameters.additional.insert(
            "circom_auto_setup_keys".to_string(),
            serde_yaml::Value::Bool(true),
        );
        config.campaign.parameters.additional.insert(
            "circom_skip_compile_if_artifacts".to_string(),
            serde_yaml::Value::Bool(true),
        );
        tracing::info!(
            "Circom prerequisites: enabling automatic trusted setup/key generation for soundness"
        );
    }

    // Inject CLI fuzzing parameters into config
    config.campaign.parameters.additional.insert(
        "fuzzing_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.iterations)),
    );
    if let Some(t) = options.timeout {
        config.campaign.parameters.additional.insert(
            "fuzzing_timeout_seconds".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(t)),
        );

        // Align Circom external command timeout with the run timeout so backend setup/metadata
        // steps cannot silently run far beyond the requested wall-clock budget.
        if config.campaign.target.framework == Framework::Circom {
            let desired = t.max(1);
            let current = std::env::var("ZK_FUZZER_CIRCOM_EXTERNAL_TIMEOUT_SECS")
                .ok()
                .and_then(|raw| raw.trim().parse::<u64>().ok())
                .map(|secs| secs.max(1));
            let effective = current.map(|secs| secs.min(desired));
            tracing::info!(
                "Circom external command timeout {} (run timeout {}s)",
                match effective {
                    Some(value) => format!("derived from env: {}s", value),
                    None => "using backend default".to_string(),
                },
                desired
            );
        }
    }

    // Provide a stable identifier for the engine to emit progress snapshots into output_dir.
    // This allows the engagement report to group scan/chains activity consistently.
    config.campaign.parameters.additional.insert(
        "run_id".to_string(),
        serde_yaml::Value::String(run_id.clone()),
    );
    config.campaign.parameters.additional.insert(
        "run_command".to_string(),
        serde_yaml::Value::String(command.to_string()),
    );

    let run_lifecycle_meta = RunLifecycleMeta {
        command,
        run_id: &run_id,
        config_path,
        campaign_name: &campaign_name,
        started_utc: &started_utc,
        timeout_seconds: options.timeout,
    };
    let (output_dir, _output_lock) = initialize_campaign_run_lifecycle(
        options.dry_run,
        &mut config,
        run_lifecycle_meta,
        campaign_run_options_doc(&options),
    )?;
    let lifecycle_ctx = RunLifecycleContext::from_meta(&output_dir, run_lifecycle_meta);

    let _ctx_guard = RunLogContextGuard::new();

    // Evidence mode settings + preflight checks.
    if options.require_invariants {
        stage = "preflight_invariants";
        let invariants = config.get_invariants();
        if invariants.is_empty() {
            if !options.dry_run {
                write_failed_mode_run_artifact_with_reason(
                    &lifecycle_ctx,
                    stage,
                    "Evidence mode requires v2 invariants in the YAML (invariants: ...)."
                        .to_string(),
                    None,
                );
            }
            anyhow::bail!("Evidence mode requires v2 invariants in the YAML (invariants: ...).");
        }

        config
            .campaign
            .parameters
            .additional
            .insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));
        config.campaign.parameters.additional.insert(
            "engagement_strict".to_string(),
            serde_yaml::Value::Bool(true),
        );

        // Slight recall bias for evidence scans: prefer not missing true positives.
        // Keep YAML authority by only applying when user did not set explicit values.
        let additional = &mut config.campaign.parameters.additional;
        if additional.get("min_evidence_confidence").is_none() {
            additional.insert(
                "min_evidence_confidence".to_string(),
                serde_yaml::Value::String("low".to_string()),
            );
        }
        if let Ok(value) = std::env::var("ZKF_MIN_EVIDENCE_CONFIDENCE") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                additional.insert(
                    "min_evidence_confidence".to_string(),
                    serde_yaml::Value::String(trimmed.to_string()),
                );
            }
        }
        if additional
            .get("oracle_validation_min_agreement_ratio")
            .is_none()
        {
            additional.insert(
                "oracle_validation_min_agreement_ratio".to_string(),
                serde_yaml::Value::String("0.45".to_string()),
            );
        }
        if let Ok(value) = std::env::var("ZKF_ORACLE_VALIDATION_MIN_AGREEMENT_RATIO") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                additional.insert(
                    "oracle_validation_min_agreement_ratio".to_string(),
                    serde_yaml::Value::String(trimmed.to_string()),
                );
            }
        }
        if additional
            .get("oracle_validation_cross_attack_weight")
            .is_none()
        {
            additional.insert(
                "oracle_validation_cross_attack_weight".to_string(),
                serde_yaml::Value::String("0.65".to_string()),
            );
        }
        if let Ok(value) = std::env::var("ZKF_ORACLE_VALIDATION_CROSS_ATTACK_WEIGHT") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                additional.insert(
                    "oracle_validation_cross_attack_weight".to_string(),
                    serde_yaml::Value::String(trimmed.to_string()),
                );
            }
        }
        if additional
            .get("oracle_validation_mutation_test_count")
            .is_none()
        {
            additional.insert(
                "oracle_validation_mutation_test_count".to_string(),
                serde_yaml::Value::Number(serde_yaml::Number::from(8u64)),
            );
        }
        if std::env::var_os("ZKF_DISABLE_EVIDENCE_BUNDLES").is_some() {
            additional.insert(
                "generate_evidence_bundles".to_string(),
                serde_yaml::Value::Bool(false),
            );
            tracing::info!(
                "Evidence bundle generation disabled by environment (ZKF_DISABLE_EVIDENCE_BUNDLES)"
            );
        }
        let value_to_string = |key: &str| -> String {
            match additional.get(key) {
                Some(serde_yaml::Value::String(s)) => s.clone(),
                Some(serde_yaml::Value::Number(n)) => n.to_string(),
                Some(serde_yaml::Value::Bool(b)) => b.to_string(),
                Some(_) => "set".to_string(),
                None => "unset".to_string(),
            }
        };
        tracing::info!(
            "Evidence recall bias active (min_conf={}, agreement_ratio<={}, cross_attack_weight>={} unless overridden in YAML/env)",
            value_to_string("min_evidence_confidence"),
            value_to_string("oracle_validation_min_agreement_ratio"),
            value_to_string("oracle_validation_cross_attack_weight"),
        );

        // Pre-flight readiness check for strict evidence engagements.
        stage = "preflight_readiness";
        println!();
        let readiness = zk_fuzzer::config::check_0day_readiness(&config);
        print!("{}", readiness.format());
        require_evidence_readiness_or_emit_failure(
            options.dry_run,
            &lifecycle_ctx,
            stage,
            &readiness,
            "Campaign has critical issues; refusing to start strict evidence run",
        )?;
    }

    stage = "preflight_backend";
    run_backend_preflight_or_emit_failure(options.dry_run, &config, &lifecycle_ctx, stage)?;

    // Print banner
    print_banner(&config);
    let run_start = Local::now();
    print_run_window(run_start, options.timeout);

    if !options.dry_run {
        // Update run artifacts with a more informative stage than the initial lock acquisition.
        seed_running_run_artifact(
            &lifecycle_ctx,
            "starting_engine",
            campaign_run_options_doc(&options),
        );
    }

    CampaignPipeline::apply_resume_mode(&mut config, &options);

    let mut ai_generated_invariant_count = 0usize;
    let mut ai_generated_yaml = false;
    if let Some(ai) = ai_assistant.as_ref() {
        let ai_context = build_ai_circuit_context(&config);

        match ai.generate_invariants(&ai_context).await {
            Ok(invariants) if !invariants.is_empty() => {
                ai_generated_invariant_count = invariants.len();
                let mut artifact = String::from("# AI-generated candidate invariants\n\n");
                for invariant in invariants {
                    artifact.push_str("- ");
                    artifact.push_str(&invariant);
                    artifact.push('\n');
                }
                if !options.dry_run {
                    maybe_write_ai_artifact(&output_dir, "candidate_invariants.md", &artifact);
                }
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(
                "AI invariant generation failed: {}",
                redact_sensitive_text(&err.to_string())
            ),
        }

        match ai.suggest_yaml(&ai_context).await {
            Ok(suggested_yaml) if !suggested_yaml.trim().is_empty() => {
                ai_generated_yaml = true;
                if !options.dry_run {
                    maybe_write_ai_artifact(
                        &output_dir,
                        "suggested_campaign.yaml",
                        &suggested_yaml,
                    );
                }
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(
                "AI YAML suggestion failed: {}",
                redact_sensitive_text(&err.to_string())
            ),
        }
    }

    if options.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        CampaignPipeline::print_dry_run_summary(
            &config,
            &options,
            ai_assistant.is_some(),
            ai_generated_invariant_count,
            ai_generated_yaml,
            &formal_bridge_options,
            formal_bridge_invariants.len(),
            imported_formal_invariants,
        );
        return Ok(());
    }

    if let Some(total_timeout) = options.timeout {
        // Reserve a small tail budget for final report/save cleanup so the full
        // command respects the user wall-clock timeout.
        const RUN_TIMEOUT_TAIL_RESERVE_SECS: u64 = 2;
        let total_timeout = total_timeout.max(1);
        let elapsed = run_wall_clock_started.elapsed();
        let consumed_ceil = elapsed
            .as_secs()
            .saturating_add(u64::from(elapsed.subsec_nanos() > 0));
        let consumed_with_reserve = consumed_ceil.saturating_add(RUN_TIMEOUT_TAIL_RESERVE_SECS);

        if consumed_with_reserve >= total_timeout {
            stage = "preflight_timeout";
            let reason = format!(
                "Global wall-clock timeout exhausted before engine start (budget={}s, consumed~{}s, reserve={}s)",
                total_timeout, consumed_ceil, RUN_TIMEOUT_TAIL_RESERVE_SECS
            );
            write_failed_mode_run_artifact_with_reason(&lifecycle_ctx, stage, reason.clone(), None);
            anyhow::bail!("{}", reason);
        }

        let remaining = total_timeout.saturating_sub(consumed_with_reserve).max(1);
        config.campaign.parameters.additional.insert(
            "fuzzing_timeout_seconds".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(remaining)),
        );
        tracing::info!(
            "Adjusted engine wall-clock budget to {}s (consumed~{}s setup/preflight + {}s tail reserve, requested total {}s)",
            remaining,
            consumed_ceil,
            RUN_TIMEOUT_TAIL_RESERVE_SECS,
            total_timeout
        );
    }

    // While the engine is running, periodically mirror progress snapshots (progress.json) into
    // the engagement report folder so you can see "where we are at from total" without digging
    // into the app output_dir.
    let (progress_stop_tx, mut progress_stop_rx) = tokio::sync::watch::channel(false);
    struct _StopProgress(tokio::sync::watch::Sender<bool>);
    impl Drop for _StopProgress {
        fn drop(&mut self) {
            if let Err(err) = self.0.send(true) {
                tracing::warn!("Failed to stop progress monitor: {}", err);
            }
        }
    }
    let _progress_guard = _StopProgress(progress_stop_tx);

    {
        let output_dir_for_monitor = output_dir.clone();
        let run_id_for_monitor = run_id.clone();
        let command_for_monitor = command.to_string();
        let campaign_name_for_monitor = campaign_name.clone();
        let campaign_path_for_monitor = config_path.to_string();
        let started_utc_for_monitor = started_utc;
        let timeout_for_monitor = options.timeout;

        tokio::spawn(async move {
            let progress_path = output_dir_for_monitor.join("progress.json");
            loop {
                if *progress_stop_rx.borrow() {
                    break;
                }

                tokio::select! {
                    _ = progress_stop_rx.changed() => {},
                    _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {},
                }

                if *progress_stop_rx.borrow() {
                    break;
                }

                let progress_raw = match std::fs::read_to_string(&progress_path) {
                    Ok(s) => s,
                    Err(err) => {
                        if err.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(
                                "Failed reading progress snapshot '{}': {}",
                                progress_path.display(),
                                err
                            );
                        }
                        continue;
                    }
                };
                let progress_json: serde_json::Value = match serde_json::from_str(&progress_raw) {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::warn!(
                            "Failed parsing progress snapshot '{}': {}",
                            progress_path.display(),
                            err
                        );
                        continue;
                    }
                };

                let mut doc = running_run_doc_with_window(RunOutcomeDocContext {
                    command: &command_for_monitor,
                    run_id: &run_id_for_monitor,
                    stage: "engine_progress",
                    config_path: &campaign_path_for_monitor,
                    campaign_name: &campaign_name_for_monitor,
                    output_dir: &output_dir_for_monitor,
                    started_utc: &started_utc_for_monitor,
                    timeout_seconds: timeout_for_monitor,
                });
                doc["progress"] = progress_json;
                let run_id_for_signal = match doc.get("run_id").and_then(|v| v.as_str()) {
                    Some(run_id) => run_id,
                    None => {
                        tracing::warn!(
                            "Progress document missing run_id while writing global run signal"
                        );
                        continue;
                    }
                };
                write_global_run_signal(run_id_for_signal, &doc);

                // Convenience: if output_dir is outside the engagement report folder, mirror the
                // progress snapshot into the engagement folder. When output_dir already lives
                // under the engagement folder (our default), avoid redundant writes.
                let command_for_mode = match doc.get("command").and_then(|v| v.as_str()) {
                    Some(command) => command,
                    None => {
                        tracing::warn!(
                            "Progress document missing command while mirroring progress snapshot"
                        );
                        continue;
                    }
                };
                let report_dir = engagement_root_dir(run_id_for_signal);
                let mode = mode_folder_from_command(command_for_mode);
                let dst = report_dir.join(mode).join("progress.json");
                if dst != progress_path {
                    if let Some(parent) = dst.parent() {
                        if let Err(err) = std::fs::create_dir_all(parent) {
                            tracing::warn!(
                                "Failed to create mirrored progress dir '{}': {}",
                                parent.display(),
                                err
                            );
                            continue;
                        }
                    }
                    if let Err(err) =
                        zk_fuzzer::util::write_file_atomic(&dst, progress_raw.as_bytes())
                    {
                        tracing::warn!(
                            "Failed to write mirrored progress '{}': {}",
                            dst.display(),
                            err
                        );
                    }
                }
            }
        });
    }

    // Run with new engine if not using simple progress
    stage = "engine_run";
    if !options.dry_run {
        let doc = running_run_doc_with_window(RunOutcomeDocContext {
            command,
            run_id: &run_id,
            stage,
            config_path,
            campaign_name: &campaign_name,
            output_dir: &output_dir,
            started_utc: &started_utc,
            timeout_seconds: options.timeout,
        });
        write_run_artifacts(&output_dir, &run_id, &doc);
    }
    let report = match if options.simple_progress {
        let mut fuzzer = ZkFuzzer::new(config, options.seed);
        fuzzer.run_with_workers(options.workers).await
    } else {
        ZkFuzzer::run_with_progress(config, options.seed, options.workers, options.verbose).await
    } {
        Ok(r) => r,
        Err(err) => {
            write_failed_mode_run_artifact_with_error(&lifecycle_ctx, stage, format!("{:#}", err));
            return Err(err);
        }
    };

    // Output results
    stage = "save_report";
    report.print_summary();
    if let Err(err) = report.save_to_files() {
        write_failed_mode_run_artifact_with_error(&lifecycle_ctx, stage, format!("{:#}", err));
        return Err(err);
    }

    if let Some(ai) = ai_assistant.as_ref() {
        match serde_json::to_string_pretty(&report) {
            Ok(serialized_report) => match ai.analyze_results(&serialized_report).await {
                Ok(analysis) if !analysis.trim().is_empty() => {
                    maybe_write_ai_artifact(&output_dir, "result_analysis.md", &analysis);
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(
                    "AI result analysis failed: {}",
                    redact_sensitive_text(&err.to_string())
                ),
            },
            Err(err) => tracing::warn!("Failed to serialize report for AI analysis: {}", err),
        }

        if let Some(finding) = report.findings.first() {
            let vulnerability = format!("{:?}: {}", finding.attack_type, finding.description);
            match ai.explain_vulnerability(&vulnerability).await {
                Ok(explanation) if !explanation.trim().is_empty() => {
                    maybe_write_ai_artifact(
                        &output_dir,
                        "top_finding_explanation.md",
                        &explanation,
                    );
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(
                    "AI vulnerability explanation failed: {}",
                    redact_sensitive_text(&err.to_string())
                ),
            }
        }
    }

    if formal_bridge_options.enabled {
        match export_formal_bridge_artifacts(
            &output_dir,
            &campaign_name,
            &report,
            &formal_bridge_invariants,
            &formal_bridge_options,
        ) {
            Ok(artifacts) => {
                tracing::info!(
                    "Formal bridge artifacts generated: findings='{}' invariants='{}' module='{}' obligations={}",
                    artifacts.findings_export_path.display(),
                    artifacts.imported_oracles_path.display(),
                    artifacts.proof_module_path.display(),
                    artifacts.obligations_count
                );
            }
            Err(err) => {
                tracing::warn!("Formal bridge artifact generation failed: {}", err);
            }
        }
    }

    let critical = report.has_critical_findings();
    let mut doc = completed_run_doc_with_window(
        if critical {
            "completed_with_critical_findings"
        } else {
            "completed"
        },
        RunOutcomeDocContext {
            command,
            run_id: &run_id,
            stage: "completed",
            config_path,
            campaign_name: &campaign_name,
            output_dir: &output_dir,
            started_utc: &started_utc,
            timeout_seconds: options.timeout,
        },
    );
    doc["metrics"] = serde_json::json!({
        "findings_total": report.findings.len(),
        "critical_findings": critical,
        "total_executions": report.statistics.total_executions,
    });
    write_run_artifacts(&output_dir, &run_id, &doc);

    if critical {
        anyhow::bail!("Run completed with CRITICAL findings (see report.json/report.md)");
    }

    Ok(())
}
