use chrono::{Local, Utc};
use clap::Parser;
use std::path::PathBuf;
mod cli;
mod engagement_artifacts;
mod output_lock;
mod preflight_backend;
mod run_bootstrap;
mod run_chain_corpus;
mod run_chain_quality;
mod run_chain_reports;
mod run_chain_ui;
mod run_identity;
mod run_interrupts;
mod run_lifecycle;
mod run_log_context;
mod run_outcome_docs;
mod run_paths;
mod run_process_control;
mod runtime_misc;
mod scan_dispatch;
mod scan_output;
mod scan_progress;
mod scan_runner;
mod scan_selector;
mod toolchain_bootstrap;
use cli::{
    campaign_run_options_doc, chain_run_options_doc, BinsBootstrapRequest, CampaignRunOptions,
    ChainRunOptions, Cli, CommandRequest, ScanFamily, ScanRequest,
};
use engagement_artifacts::{
    mode_folder_from_command, write_global_run_signal, write_run_artifacts,
};
use preflight_backend::preflight_campaign;
use run_bootstrap::{
    announce_report_dir_and_bind_log_context, load_campaign_config_with_optional_profile,
};
use run_chain_corpus::{
    chain_completed_and_unique_cov_from_path, chain_unique_coverage_bits, load_chain_corpus,
    read_chain_execution_count, read_chain_meta,
};
use run_chain_quality::collect_chain_quality_failures;
use run_chain_reports::{
    build_chain_report_json, build_chain_report_markdown, write_chain_report_json,
    write_chain_report_markdown,
};
use run_chain_ui::{print_chain_mode_banner, print_chains_to_fuzz};
pub(crate) use run_identity::{make_run_id, sanitize_slug};
use run_interrupts::{install_panic_hook, start_signal_watchers};
use run_lifecycle::{
    initialize_campaign_run_lifecycle, require_evidence_readiness_or_emit_failure,
    run_backend_preflight_or_emit_failure, seed_running_run_artifact,
    write_failed_mode_run_artifact_with_error, write_failed_mode_run_artifact_with_reason,
};
pub(crate) use run_log_context::set_run_log_context_for_campaign;
use run_log_context::{DynamicLogWriter, RunLogContextGuard};
use run_outcome_docs::{completed_run_doc_with_window, running_run_doc_with_window};
#[cfg(test)]
pub(crate) use run_paths::{engagement_dir_name, run_id_epoch_dir};
pub(crate) use run_paths::{
    engagement_root_dir, normalize_build_paths, read_optional_env, run_signal_dir,
};
use run_process_control::kill_existing_instances;
use runtime_misc::{
    generate_sample_config, minimize_corpus, print_banner, print_run_window, truncate_str,
    validate_campaign,
};
use scan_runner::run_scan as run_scan_orchestrated;
#[cfg(test)]
use scan_selector::{
    evaluate_loaded_scan_regex_patterns, load_scan_regex_selector_config,
    validate_scan_regex_pattern_safety, ScanRegexPatternSummary,
};
use zk_fuzzer::fuzzer::ZkFuzzer;
use zk_fuzzer::Framework;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Only kill existing instances if explicitly requested
    if cli.kill_existing {
        kill_existing_instances().await;
    }

    // Run the command and ensure cleanup
    let result = run_cli_command(cli).await;

    result
}

async fn run_cli_command(cli: Cli) -> anyhow::Result<()> {
    // Initialize logging
    let log_level = if cli.quiet {
        tracing::Level::WARN
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_ansi(false)
        .with_writer(DynamicLogWriter)
        .init();

    // Ensure early-stop causes are captured to disk when possible (panic/signal).
    install_panic_hook();
    start_signal_watchers();

    let dry_run = cli.dry_run;
    let implicit_legacy_run = cli.command.is_none() && cli.config.is_some();
    let request = cli.into_request();

    match request {
        CommandRequest::Scan(ScanRequest {
            pattern,
            family,
            target_circuit,
            main_component,
            framework,
            output_suffix,
            mono_options,
            chain_options,
        }) => {
            run_scan(
                &pattern,
                family,
                &target_circuit,
                &main_component,
                &framework,
                output_suffix.as_deref(),
                mono_options,
                chain_options,
            )
            .await
        }
        CommandRequest::RunCampaign { campaign, options } => {
            if implicit_legacy_run {
                tracing::warn!(
                    "No subcommand provided; defaulting to legacy run mode for '{}'",
                    campaign
                );
            }
            run_campaign(&campaign, options).await
        }
        CommandRequest::RunChainCampaign { campaign, options } => {
            run_chain_campaign(&campaign, options).await
        }
        CommandRequest::Preflight {
            campaign,
            setup_keys,
        } => preflight_campaign(&campaign, setup_keys),
        CommandRequest::Validate { campaign } => validate_campaign(&campaign),
        CommandRequest::BinsBootstrap(BinsBootstrapRequest {
            bins_dir,
            circom_version,
            snarkjs_version,
            ptau_file,
            ptau_url,
            ptau_sha256,
            skip_circom,
            skip_snarkjs,
            skip_ptau,
            force,
        }) => toolchain_bootstrap::run_bins_bootstrap(&toolchain_bootstrap::BinsBootstrapOptions {
            bins_dir: PathBuf::from(bins_dir),
            circom_version,
            snarkjs_version,
            ptau_file_name: ptau_file,
            ptau_url,
            ptau_sha256,
            skip_circom,
            skip_snarkjs,
            skip_ptau,
            force,
            dry_run,
        }),
        CommandRequest::Minimize { corpus_dir, output } => {
            minimize_corpus(&corpus_dir, output.as_deref())
        }
        CommandRequest::Init { output, framework } => generate_sample_config(&output, &framework),
        CommandRequest::ExecWorker => zk_fuzzer::executor::run_exec_worker(),
        CommandRequest::MissingCommand => anyhow::bail!(
            "No command provided. Use `zk-fuzzer scan <pattern.yaml> --target-circuit <path> --main-component <name> --framework <fw>`."
        ),
    }
}

async fn run_scan(
    pattern_path: &str,
    family_hint: ScanFamily,
    target_circuit: &str,
    main_component: &str,
    framework: &str,
    output_suffix: Option<&str>,
    mono_options: CampaignRunOptions,
    chain_options: ChainRunOptions,
) -> anyhow::Result<()> {
    run_scan_orchestrated(
        pattern_path,
        family_hint,
        target_circuit,
        main_component,
        framework,
        output_suffix,
        mono_options,
        chain_options,
        |materialized, options| async move { run_campaign(&materialized, options).await },
        |materialized, options| async move { run_chain_campaign(&materialized, options).await },
    )
    .await
}

async fn run_campaign(config_path: &str, options: CampaignRunOptions) -> anyhow::Result<()> {
    let started_utc = Utc::now();
    let command = options.command_label;
    let run_id = make_run_id(command, Some(config_path));
    let mut stage: &str;
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

    if options.real_only {
        tracing::info!("--real-only set (real backend mode is already enforced)");
    }

    // Always enforce strict backend in this CLI.
    config
        .campaign
        .parameters
        .additional
        .insert("strict_backend".to_string(), serde_yaml::Value::Bool(true));
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

    let (output_dir, _output_lock) = initialize_campaign_run_lifecycle(
        options.dry_run,
        &mut config,
        command,
        &run_id,
        config_path,
        &campaign_name,
        started_utc,
        options.timeout,
        campaign_run_options_doc(&options),
    )?;

    let _ctx_guard = RunLogContextGuard::new();

    // Evidence mode settings + preflight checks.
    if options.require_invariants {
        stage = "preflight_invariants";
        let invariants = config.get_invariants();
        if invariants.is_empty() {
            if !options.dry_run {
                write_failed_mode_run_artifact_with_reason(
                    &output_dir,
                    command,
                    &run_id,
                    stage,
                    config_path,
                    &campaign_name,
                    started_utc,
                    options.timeout,
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
        config
            .campaign
            .parameters
            .additional
            .insert("strict_backend".to_string(), serde_yaml::Value::Bool(true));

        // Slight recall bias for evidence scans: prefer not missing true positives.
        // Keep YAML authority by only applying when user did not set explicit values.
        let additional = &mut config.campaign.parameters.additional;
        if additional.get("min_evidence_confidence").is_none() {
            additional.insert(
                "min_evidence_confidence".to_string(),
                serde_yaml::Value::String("low".to_string()),
            );
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
        if additional
            .get("oracle_validation_cross_attack_weight")
            .is_none()
        {
            additional.insert(
                "oracle_validation_cross_attack_weight".to_string(),
                serde_yaml::Value::String("0.65".to_string()),
            );
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
        tracing::info!(
            "Evidence recall bias active (min_conf=low, agreement_ratio<=0.45, cross_attack_weight>=0.65 unless overridden in YAML)"
        );

        // Pre-flight readiness check for strict evidence engagements.
        stage = "preflight_readiness";
        println!();
        let readiness = zk_fuzzer::config::check_0day_readiness(&config);
        print!("{}", readiness.format());
        require_evidence_readiness_or_emit_failure(
            options.dry_run,
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            options.timeout,
            &readiness,
            "Campaign has critical issues; refusing to start strict evidence run",
        )?;
    }

    stage = "preflight_backend";
    run_backend_preflight_or_emit_failure(
        options.dry_run,
        &config,
        &output_dir,
        command,
        &run_id,
        stage,
        config_path,
        &campaign_name,
        started_utc,
        options.timeout,
    )?;

    // Print banner
    print_banner(&config);
    let run_start = Local::now();
    print_run_window(run_start, options.timeout);

    if !options.dry_run {
        // Update run artifacts with a more informative stage than the initial lock acquisition.
        seed_running_run_artifact(
            &output_dir,
            command,
            &run_id,
            "starting_engine",
            config_path,
            &campaign_name,
            started_utc,
            options.timeout,
            campaign_run_options_doc(&options),
        );
    }

    // Handle resume mode
    if options.resume {
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

    if options.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Configuration is valid");
        println!("  Campaign: {}", config.campaign.name);
        println!("  Target: {:?}", config.campaign.target.framework);
        println!("  Attacks: {}", config.attacks.len());
        println!("  Inputs: {}", config.inputs.len());
        if options.resume {
            println!("  Resume: enabled");
        }
        if let Some(ref p) = options.profile {
            println!("  Profile: {}", p);
        }
        return Ok(());
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

                let mut doc = running_run_doc_with_window(
                    &command_for_monitor,
                    &run_id_for_monitor,
                    "engine_progress",
                    &campaign_path_for_monitor,
                    &campaign_name_for_monitor,
                    &output_dir_for_monitor,
                    started_utc_for_monitor,
                    timeout_for_monitor,
                );
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
        let doc = running_run_doc_with_window(
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            &output_dir,
            started_utc,
            options.timeout,
        );
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
            write_failed_mode_run_artifact_with_error(
                &output_dir,
                command,
                &run_id,
                stage,
                config_path,
                &campaign_name,
                started_utc,
                options.timeout,
                format!("{:#}", err),
            );
            return Err(err);
        }
    };

    // Output results
    stage = "save_report";
    report.print_summary();
    if let Err(err) = report.save_to_files() {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            options.timeout,
            format!("{:#}", err),
        );
        return Err(err);
    }

    let critical = report.has_critical_findings();
    let mut doc = completed_run_doc_with_window(
        command,
        &run_id,
        if critical {
            "completed_with_critical_findings"
        } else {
            "completed"
        },
        "completed",
        config_path,
        &campaign_name,
        &output_dir,
        started_utc,
        options.timeout,
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

/// Run a chain-focused fuzzing campaign (Mode 3: Deepest)
async fn run_chain_campaign(config_path: &str, options: ChainRunOptions) -> anyhow::Result<()> {
    use colored::*;
    use zk_fuzzer::chain_fuzzer::{ChainFinding, DepthMetrics};
    use zk_fuzzer::config::parse_chains;
    use zk_fuzzer::fuzzer::FuzzingEngine;
    use zk_fuzzer::reporting::FuzzReport;

    let started_utc = Utc::now();
    let command = "chains";
    let run_id = make_run_id(command, Some(config_path));
    let mut stage: &str;
    announce_report_dir_and_bind_log_context(
        options.dry_run,
        &run_id,
        command,
        config_path,
        &started_utc,
    );

    let mut config = load_campaign_config_with_optional_profile(
        "chain campaign",
        &run_id,
        command,
        config_path,
        &started_utc,
        None,
    )?;

    let campaign_name = config.campaign.name.clone();

    let (output_dir, _output_lock) = initialize_campaign_run_lifecycle(
        options.dry_run,
        &mut config,
        command,
        &run_id,
        config_path,
        &campaign_name,
        started_utc,
        Some(options.timeout),
        chain_run_options_doc(&options),
    )?;

    let _ctx_guard = RunLogContextGuard::new();

    // Get chains from config
    stage = "parse_chains";
    let chains = parse_chains(&config);
    if chains.is_empty() {
        if !options.dry_run {
            write_failed_mode_run_artifact_with_reason(
                &output_dir,
                command,
                &run_id,
                stage,
                config_path,
                &campaign_name,
                started_utc,
                Some(options.timeout),
                "Chain mode requires chains: definitions in the YAML.".to_string(),
                None,
            );
        }
        anyhow::bail!(
            "Chain mode requires chains: definitions in the YAML. \
             See campaigns/templates/deepest_multistep.yaml for examples."
        );
    }

    // Force evidence mode settings for chain fuzzing
    config
        .campaign
        .parameters
        .additional
        .insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));
    config.campaign.parameters.additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config
        .campaign
        .parameters
        .additional
        .insert("strict_backend".to_string(), serde_yaml::Value::Bool(true));
    config.campaign.parameters.additional.insert(
        "chain_budget_seconds".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.timeout)),
    );
    config.campaign.parameters.additional.insert(
        "chain_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.iterations)),
    );
    config.campaign.parameters.additional.insert(
        "chain_resume".to_string(),
        serde_yaml::Value::Bool(options.resume),
    );

    // Pre-flight readiness check (chains need assertions; strict mode blocks silent runs).
    stage = "preflight_readiness";
    println!();
    let readiness = zk_fuzzer::config::check_0day_readiness(&config);
    print!("{}", readiness.format());
    require_evidence_readiness_or_emit_failure(
        options.dry_run,
        &output_dir,
        command,
        &run_id,
        stage,
        config_path,
        &campaign_name,
        started_utc,
        Some(options.timeout),
        &readiness,
        "Campaign has critical issues; refusing to start strict chain run",
    )?;

    stage = "preflight_backend";
    run_backend_preflight_or_emit_failure(
        options.dry_run,
        &config,
        &output_dir,
        command,
        &run_id,
        stage,
        config_path,
        &campaign_name,
        started_utc,
        Some(options.timeout),
    )?;

    // Print chain-specific banner.
    print_chain_mode_banner(
        &config.campaign.name,
        chains.len(),
        options.timeout,
        options.resume,
    );
    let run_start = Local::now();
    print_run_window(run_start, Some(options.timeout));

    if !options.dry_run {
        seed_running_run_artifact(
            &output_dir,
            command,
            &run_id,
            "starting_engine",
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            chain_run_options_doc(&options),
        );
    }

    // List chains.
    print_chains_to_fuzz(&chains);

    if options.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Chain configuration is valid");
        return Ok(());
    }

    let corpus_path = output_dir.join("chain_corpus.json");
    let corpus_meta_path = output_dir.join("chain_corpus_meta.json");
    let baseline_execution_count = if options.resume {
        read_chain_execution_count(&corpus_path)?
    } else {
        0
    };

    let baseline_meta = if options.resume && corpus_meta_path.exists() {
        read_chain_meta(&corpus_meta_path)
    } else {
        None
    };
    let (baseline_total_entries, baseline_unique_coverage_bits): (usize, usize) = if !options.resume
    {
        (0, 0)
    } else if let Some(meta) = &baseline_meta {
        (meta.total_entries, meta.unique_coverage_bits)
    } else {
        let baseline_corpus = load_chain_corpus(&corpus_path)?;
        let baseline_total_entries = baseline_corpus.len();
        let baseline_unique_coverage_bits = chain_unique_coverage_bits(&baseline_corpus);
        (baseline_total_entries, baseline_unique_coverage_bits)
    };

    // Create engine directly
    stage = "engine_init";
    let mut engine = match FuzzingEngine::new(config.clone(), options.seed, options.workers) {
        Ok(e) => e,
        Err(err) => {
            write_failed_mode_run_artifact_with_error(
                &output_dir,
                command,
                &run_id,
                stage,
                config_path,
                &campaign_name,
                started_utc,
                Some(options.timeout),
                format!("{:#}", err),
            );
            return Err(err);
        }
    };

    // Run chain fuzzing
    let progress = if options.simple_progress {
        None
    } else {
        // Create a progress reporter for chain mode
        let total = (options.iterations as usize * chains.len()) as u64;
        Some(zk_fuzzer::progress::ProgressReporter::new(
            &format!("{} (chains)", config.campaign.name),
            total,
            options.verbose,
        ))
    };

    stage = "engine_run_chains";
    let chain_findings: Vec<ChainFinding> =
        match engine.run_chains(&chains, progress.as_ref()).await {
            Ok(findings) => findings,
            Err(err) => {
                write_failed_mode_run_artifact_with_error(
                    &output_dir,
                    command,
                    &run_id,
                    stage,
                    config_path,
                    &campaign_name,
                    started_utc,
                    Some(options.timeout),
                    format!("{:#}", err),
                );
                return Err(err);
            }
        };

    // Load chain corpus for quality/coverage metrics (persistent across runs).
    // Prefer meta sidecar to avoid parsing a large chain_corpus.json.
    let final_meta = if corpus_meta_path.exists() {
        read_chain_meta(&corpus_meta_path)
    } else {
        None
    };
    let (final_total_entries, final_unique_coverage_bits, final_max_depth): (usize, usize, usize) =
        if let Some(meta) = &final_meta {
            (
                meta.total_entries,
                meta.unique_coverage_bits,
                meta.max_depth,
            )
        } else {
            let final_corpus = load_chain_corpus(&corpus_path)?;
            let final_total_entries = final_corpus.len();
            let final_unique_coverage_bits = chain_unique_coverage_bits(&final_corpus);
            let final_max_depth = final_corpus.entries().iter().map(|e| e.depth_reached).max();
            let final_max_depth: usize = final_max_depth.unwrap_or_default();
            (
                final_total_entries,
                final_unique_coverage_bits,
                final_max_depth,
            )
        };
    let final_execution_count = read_chain_execution_count(&corpus_path)?;
    let run_execution_count = final_execution_count.saturating_sub(baseline_execution_count);

    // Engagement contract for Mode 3: refuse to report a "clean" run when exploration is too narrow.
    let engagement_strict = config
        .campaign
        .parameters
        .additional
        .get_bool("engagement_strict")
        .unwrap_or(true);
    let min_unique_coverage_bits = config
        .campaign
        .parameters
        .additional
        .get_usize("engagement_min_chain_unique_coverage_bits")
        .unwrap_or(2);
    let min_completed_per_chain = config
        .campaign
        .parameters
        .additional
        .get_usize("engagement_min_chain_completed_per_chain")
        .unwrap_or(1);

    let quality_failures = collect_chain_quality_failures(
        &chains,
        final_meta.as_ref(),
        &corpus_path,
        min_completed_per_chain,
        min_unique_coverage_bits,
    )?;
    let run_valid = quality_failures.is_empty();

    // Compute metrics
    let metrics = DepthMetrics::new(chain_findings.clone());
    let summary = metrics.summary();

    // Print results
    println!();
    println!("{}", "═".repeat(60).bright_magenta());
    println!("{}", "  CHAIN FUZZING RESULTS".bright_white().bold());
    println!("{}", "═".repeat(60).bright_magenta());

    println!("\n{}", "DEPTH METRICS".bright_yellow().bold());
    println!("  Total Chain Findings:  {}", summary.total_findings);
    println!("  Mean L_min (D):        {:.2}", summary.d_mean);
    println!("  P(L_min >= 2):         {:.1}%", summary.p_deep * 100.0);
    println!();
    println!("{}", "CORPUS / EXPLORATION METRICS".bright_yellow().bold());
    println!(
        "  Corpus entries:            {} (Δ {})",
        final_total_entries,
        final_total_entries.saturating_sub(baseline_total_entries)
    );
    println!(
        "  Unique coverage bits:      {} (Δ {})",
        final_unique_coverage_bits,
        final_unique_coverage_bits.saturating_sub(baseline_unique_coverage_bits)
    );
    println!("  Max depth reached:         {}", final_max_depth);

    if !summary.depth_distribution.is_empty() {
        println!("\n{}", "DEPTH DISTRIBUTION".bright_yellow().bold());
        let mut depths: Vec<_> = summary.depth_distribution.iter().collect();
        depths.sort_by_key(|(k, _)| *k);
        for (depth, count) in depths {
            let bar = "█".repeat((*count).min(30));
            println!("  L_min={}: {} ({})", depth, bar.bright_cyan(), count);
        }
    }

    if !chain_findings.is_empty() {
        println!("\n{}", "CHAIN FINDINGS".bright_yellow().bold());
        for (i, finding) in chain_findings.iter().enumerate() {
            let severity_str = match finding.finding.severity.to_uppercase().as_str() {
                "CRITICAL" => format!("[{}]", finding.finding.severity)
                    .bright_red()
                    .bold(),
                "HIGH" => format!("[{}]", finding.finding.severity).red(),
                "MEDIUM" => format!("[{}]", finding.finding.severity).yellow(),
                "LOW" => format!("[{}]", finding.finding.severity).bright_yellow(),
                _ => format!("[{}]", finding.finding.severity).white(),
            };

            println!(
                "\n  {}. {} Chain: {} (L_min: {})",
                i + 1,
                severity_str,
                finding.spec_name.cyan(),
                finding.l_min.to_string().bright_green()
            );
            println!("     {}", finding.finding.description);

            if let Some(ref assertion) = finding.violated_assertion {
                println!("     Violated: {}", assertion.bright_red());
            }

            // Print reproduction command
            println!("     {}", "Reproduction:".bright_yellow());
            println!(
                "       cargo run --release -- chains {} --seed {}",
                config_path,
                options.seed.unwrap_or(42)
            );
        }
    } else if run_valid {
        println!(
            "\n{}",
            "  ✓ No chain vulnerabilities found!".bright_green().bold()
        );
    } else {
        println!(
            "\n{}",
            "  ✗ Run invalid: exploration too narrow to treat as 'clean'"
                .bright_red()
                .bold()
        );
        for failure in &quality_failures {
            println!("     - {}", failure);
        }
    }

    println!("\n{}", "═".repeat(60).bright_magenta());

    // Save reports
    stage = "save_chain_reports";
    if let Err(err) = std::fs::create_dir_all(&output_dir) {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            format!("{:#}", err),
        );
        return Err(err.into());
    }

    let report_ctx = run_chain_reports::ChainReportContext {
        campaign_name: &config.campaign.name,
        engagement_strict,
        run_valid,
        quality_failures: &quality_failures,
        min_unique_coverage_bits,
        min_completed_per_chain,
        summary: &summary,
        final_total_entries,
        final_unique_coverage_bits,
        final_max_depth,
        baseline_total_entries,
        baseline_unique_coverage_bits,
        chain_findings: &chain_findings,
    };

    // Save chain findings as JSON.
    let chain_report_path = output_dir.join("chain_report.json");
    let chain_report = build_chain_report_json(&report_ctx);
    if let Err(err) = write_chain_report_json(&chain_report_path, &chain_report) {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            format!("{:#}", err),
        );
        return Err(err);
    }
    tracing::info!("Saved chain report to {:?}", chain_report_path);

    // Save chain findings as markdown.
    let chain_md_path = output_dir.join("chain_report.md");
    let chain_md = build_chain_report_markdown(&report_ctx, config_path, options.seed);
    if let Err(err) = write_chain_report_markdown(&chain_md_path, &chain_md) {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            format!("{:#}", err),
        );
        return Err(err.into());
    }
    tracing::info!("Saved chain markdown report to {:?}", chain_md_path);

    // Convert chain findings to regular findings for standard report
    let standard_findings: Vec<_> = chain_findings.iter().map(|cf| cf.to_finding()).collect();

    // Create standard report with chain findings merged in
    let mut report = FuzzReport::new(
        config.campaign.name.clone(),
        standard_findings,
        zk_core::CoverageMap::default(),
        config.reporting.clone(),
    );
    report.statistics.total_executions = run_execution_count;
    stage = "save_standard_report";
    if let Err(err) = report.save_to_files() {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            format!("{:#}", err),
        );
        return Err(err);
    }

    let critical = chain_findings
        .iter()
        .any(|f| f.finding.severity.to_lowercase() == "critical");
    let status = if critical {
        "completed_with_critical_findings"
    } else if engagement_strict && !run_valid {
        "failed_engagement_contract"
    } else {
        "completed"
    };

    stage = "completed";
    let mut doc = completed_run_doc_with_window(
        command,
        &run_id,
        status,
        stage,
        config_path,
        &campaign_name,
        &output_dir,
        started_utc,
        Some(options.timeout),
    );
    doc["metrics"] = serde_json::json!({
        "chain_findings_total": summary.total_findings,
        "critical_findings": critical,
        "corpus_entries": final_total_entries,
        "unique_coverage_bits": final_unique_coverage_bits,
        "max_depth": final_max_depth,
        "d_mean": summary.d_mean,
        "p_deep": summary.p_deep,
    });
    doc["engagement"] = serde_json::json!({
        "strict": engagement_strict,
        "valid_run": run_valid,
        "failures": quality_failures,
        "thresholds": {
            "min_unique_coverage_bits": min_unique_coverage_bits,
            "min_completed_per_chain": min_completed_per_chain,
        }
    });
    write_run_artifacts(&output_dir, &run_id, &doc);

    if critical {
        anyhow::bail!("Chain run produced CRITICAL findings (see chain_report.json/report.json)");
    }
    if engagement_strict && !run_valid {
        anyhow::bail!(
            "Strict chain run failed engagement contract; see chain_report.json for details"
        );
    }

    Ok(())
}

#[cfg(test)]
mod scan_selector_tests;
