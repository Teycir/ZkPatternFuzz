use anyhow::Context;
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
mod cli;
mod engagement_artifacts;
mod output_lock;
mod preflight_backend;
mod run_lifecycle;
mod run_outcome_docs;
mod runtime_misc;
mod scan_dispatch;
mod scan_output;
mod scan_progress;
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
use run_lifecycle::{
    initialize_campaign_run_lifecycle, require_evidence_readiness_or_emit_failure,
    run_backend_preflight_or_emit_failure, seed_running_run_artifact,
    write_failed_mode_run_artifact_with_error, write_failed_mode_run_artifact_with_reason,
    write_failed_run_artifact, write_failed_run_artifact_with_error,
};
use run_outcome_docs::{
    completed_run_doc_with_window, running_run_doc_with_window,
};
use runtime_misc::{
    generate_sample_config, minimize_corpus, print_banner, print_run_window, truncate_str,
    validate_campaign,
};
use scan_dispatch::prepare_scan_dispatch;
use scan_output::apply_scan_output_suffix_if_present;
use scan_progress::{
    dispatch_scan_family_run, scan_default_output_dir,
};
#[cfg(test)]
use scan_selector::{
    evaluate_loaded_scan_regex_patterns, load_scan_regex_selector_config,
    validate_scan_regex_pattern_safety, ScanRegexPatternSummary,
};
use zk_fuzzer::config::{apply_profile, FuzzConfig, ProfileName};
use zk_fuzzer::fuzzer::ZkFuzzer;
use zk_fuzzer::Framework;

#[derive(Debug, Clone)]
struct RunLogContext {
    run_id: String,
    command: String,
    campaign_path: Option<String>,
    campaign_name: Option<String>,
    output_dir: Option<PathBuf>,
    started_utc: String,
}

static RUN_LOG_CONTEXT: OnceLock<Mutex<Option<RunLogContext>>> = OnceLock::new();
static PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();
static SIGNAL_WATCHER_STARTED: OnceLock<()> = OnceLock::new();
static DYNAMIC_LOG_FILE: OnceLock<Mutex<Option<(PathBuf, std::fs::File)>>> = OnceLock::new();

struct DynamicLogWriter;

struct DynamicTeeWriter;

impl DynamicTeeWriter {
    fn desired_log_path() -> PathBuf {
        if let Some(ctx) = get_run_log_context() {
            // Engagement-local session log. This makes each `report_<timestamp>/` folder
            // self-contained and easy to manage when you have many engagements.
            engagement_root_dir(&ctx.run_id).join("session.log")
        } else {
            run_signal_dir().join("session.log")
        }
    }

    fn with_log_file<F, R>(f: F) -> io::Result<R>
    where
        F: FnOnce(&mut std::fs::File) -> io::Result<R>,
    {
        let path = Self::desired_log_path();
        let slot = DYNAMIC_LOG_FILE.get_or_init(|| Mutex::new(None));
        let mut guard = slot.lock().map_err(|_| io::ErrorKind::Other)?;

        let need_reopen = match guard.as_ref() {
            Some((p, _)) => *p != path,
            None => true,
        };

        if need_reopen {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    io::Error::other(format!(
                        "Failed to create log directory '{}': {err}",
                        parent.display()
                    ))
                })?;
            }
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                Ok(file) => {
                    *guard = Some((path.clone(), file));
                }
                Err(err) => {
                    // Fail opening file logger for this write attempt.
                    return Err(err);
                }
            }
        }

        if let Some((_, ref mut file)) = guard.as_mut() {
            f(file)
        } else {
            Err(io::Error::other("log file unavailable"))
        }
    }

    /// Best-effort synchronization hook used when run-log context changes.
    ///
    /// This pre-opens/rebinds the file target immediately so most subsequent log lines
    /// are routed to the new engagement log path without waiting for the next write call.
    fn sync_to_current_context() {
        if let Err(err) = Self::with_log_file(|_| Ok(())) {
            eprintln!(
                "[zk-fuzzer] WARN: failed to sync session log path to current context: {}",
                err
            );
        }
    }
}

impl io::Write for DynamicTeeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Console output (keep behavior similar to default fmt subscriber).
        if let Err(err) = io::stderr().write_all(buf) {
            eprintln!("[zk-fuzzer] WARN: failed writing to stderr: {}", err);
        }

        // Best-effort file output with non-blocking approach
        let _ = Self::with_log_file(|file| file.write_all(buf).map(|_| ()));

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Err(err) = io::stderr().flush() {
            eprintln!("[zk-fuzzer] WARN: failed flushing stderr: {}", err);
        }
        let _ = Self::with_log_file(|file| file.flush());
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DynamicLogWriter {
    type Writer = DynamicTeeWriter;

    fn make_writer(&'a self) -> Self::Writer {
        DynamicTeeWriter
    }
}

fn set_run_log_context(ctx: Option<RunLogContext>) {
    let slot = RUN_LOG_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut should_sync_file = false;
    match slot.lock() {
        Ok(mut guard) => {
            *guard = ctx;
            should_sync_file = true;
        }
        Err(err) => eprintln!("[zk-fuzzer] WARN: failed to lock run log context: {}", err),
    }
    if should_sync_file {
        DynamicTeeWriter::sync_to_current_context();
    }
}

fn get_run_log_context() -> Option<RunLogContext> {
    let slot = RUN_LOG_CONTEXT.get_or_init(|| Mutex::new(None));
    match slot.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => {
            tracing::warn!("Run log context mutex poisoned, recovering data");
            poisoned.into_inner().clone()
        }
    }
}

struct RunLogContextGuard;

impl RunLogContextGuard {
    fn new() -> Self {
        Self
    }
}

impl Drop for RunLogContextGuard {
    fn drop(&mut self) {
        set_run_log_context(None);
    }
}

pub(crate) fn set_run_log_context_for_campaign(
    dry_run: bool,
    run_id: &str,
    command: &str,
    config_path: &str,
    campaign_name: Option<&str>,
    output_dir: Option<&Path>,
    started_utc: &DateTime<Utc>,
) {
    if dry_run {
        return;
    }

    set_run_log_context(Some(RunLogContext {
        run_id: run_id.to_string(),
        command: command.to_string(),
        campaign_path: Some(config_path.to_string()),
        campaign_name: campaign_name.map(|name| name.to_string()),
        output_dir: output_dir.map(Path::to_path_buf),
        started_utc: started_utc.to_rfc3339(),
    }));
}

fn sanitize_slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed
    }
}

fn derive_campaign_slug(campaign_path: &str) -> String {
    let slug = Path::new(campaign_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(sanitize_slug);
    match slug {
        Some(value) => value,
        None => "campaign".to_string(),
    }
}

fn make_run_id(command: &str, campaign_path: Option<&str>) -> String {
    let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let pid = std::process::id();
    let campaign = match campaign_path {
        Some(path) => derive_campaign_slug(path),
        None => "no_campaign".to_string(),
    };
    format!("{}_{}_{}_pid{}", ts, sanitize_slug(command), campaign, pid)
}

fn read_optional_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => {
            eprintln!("[zk-fuzzer] ERROR: invalid {} value: {}", name, e);
            std::process::exit(2);
        }
    }
}

fn run_signal_dir() -> PathBuf {
    // Base folder where "easy to find" run folders are written.
    //
    // Default matches your requested structure:
    //   /home/<user>/ZkFuzz/report_<epoch>/
    //
    // Override with:
    //   ZKF_RUN_SIGNAL_DIR=/some/other/base
    //
    // If writing outside the repo is not allowed in your environment, set it back to:
    //   ZKF_RUN_SIGNAL_DIR=reports/_run_signals
    let path = if let Some(v) = read_optional_env("ZKF_RUN_SIGNAL_DIR") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            PathBuf::from(trimmed)
        } else {
            eprintln!("[zk-fuzzer] ERROR: ZKF_RUN_SIGNAL_DIR is set but empty");
            std::process::exit(2);
        }
    } else if let Some(home) = read_optional_env("HOME") {
        let home = home.trim();
        if !home.is_empty() {
            PathBuf::from(home).join("ZkFuzz")
        } else {
            eprintln!("[zk-fuzzer] ERROR: HOME is set but empty");
            std::process::exit(2);
        }
    } else {
        eprintln!("[zk-fuzzer] ERROR: neither ZKF_RUN_SIGNAL_DIR nor HOME is available");
        std::process::exit(2);
    };

    if let Err(err) = std::fs::create_dir_all(&path) {
        eprintln!(
            "[zk-fuzzer] ERROR: cannot create run-signal dir '{}': {}",
            path.display(),
            err
        );
        std::process::exit(2);
    }
    path
}

fn build_cache_dir() -> PathBuf {
    // Build artifacts are large and should not live inside engagement report folders.
    // Default:
    //   /home/<user>/ZkFuzz/_build_cache/
    //
    // Override with:
    //   ZKF_BUILD_CACHE_DIR=/some/other/path
    if let Some(v) = read_optional_env("ZKF_BUILD_CACHE_DIR") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if let Err(err) = std::fs::create_dir_all(&path) {
                eprintln!(
                    "[zk-fuzzer] ERROR: cannot create build cache dir '{}': {}",
                    path.display(),
                    err
                );
                std::process::exit(2);
            }
            return path;
        }
    }

    let path = run_signal_dir().join("_build_cache");
    if let Err(err) = std::fs::create_dir_all(&path) {
        eprintln!(
            "[zk-fuzzer] ERROR: cannot create build cache dir '{}': {}",
            path.display(),
            err
        );
        std::process::exit(2);
    }
    path
}

pub(crate) fn normalize_build_paths(config: &mut FuzzConfig, run_id: &str) {
    use std::path::PathBuf;

    let report_dir = engagement_root_dir(run_id);
    let cache = build_cache_dir();
    let additional = &mut config.campaign.parameters.additional;

    // Remove any explicit build paths that point inside the engagement folder, then force
    // build_dir_base to the cache root.
    let keys = [
        "build_dir_base",
        "build_dir",
        "circom_build_dir",
        "noir_build_dir",
        "halo2_build_dir",
        "cairo_build_dir",
    ];

    let mut had_in_report = false;
    for key in keys {
        if let Some(v) = additional.get(key).and_then(|v| v.as_str()) {
            let p = PathBuf::from(v);
            if p.starts_with(&report_dir) {
                had_in_report = true;
                additional.remove(key);
            }
        }
    }

    // If build_dir_base is missing, set it. If it existed but pointed into the report dir, replace it.
    if had_in_report || additional.get("build_dir_base").is_none() {
        additional.insert(
            "build_dir_base".to_string(),
            serde_yaml::Value::String(cache.display().to_string()),
        );
        if had_in_report {
            tracing::info!(
                "Build artifacts redirected to cache dir {:?} (were inside engagement folder {:?})",
                cache,
                report_dir
            );
        }
    }
}

fn run_id_epoch_dir(run_id: &str) -> Option<String> {
    // run_id prefix is make_run_id(): "%Y%m%d_%H%M%S_..."
    if run_id.len() < 15 {
        return None;
    }
    let ts = &run_id[..15];
    let naive = match chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%d_%H%M%S") {
        Ok(naive) => naive,
        Err(err) => {
            tracing::warn!("Invalid run_id timestamp prefix '{}': {}", ts, err);
            return None;
        }
    };
    let started_utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
    Some(format!("report_{}", started_utc.timestamp()))
}

fn engagement_dir_name(run_id: &str) -> String {
    // Allow grouping multiple processes (scan/chains/misc) into the same report folder.
    //
    // Example:
    //   export ZKF_ENGAGEMENT_EPOCH=176963063
    //   ... run scan and chains ...
    //   => /home/<user>/ZkFuzz/report_176963063/
    if let Some(epoch) = read_optional_env("ZKF_ENGAGEMENT_EPOCH") {
        let trimmed = epoch.trim();
        if !trimmed.is_empty() {
            return format!("report_{}", trimmed);
        }
    }

    if let Some(name) = read_optional_env("ZKF_ENGAGEMENT_NAME") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    match run_id_epoch_dir(run_id) {
        Some(dir_name) => dir_name,
        None => {
            let fallback = format!("report_{}", sanitize_slug(run_id));
            tracing::warn!(
                "Run id '{}' does not contain a valid timestamp prefix; using fallback engagement dir '{}'",
                run_id,
                fallback
            );
            fallback
        }
    }
}

fn engagement_root_dir(run_id: &str) -> PathBuf {
    // If ZKF_ENGAGEMENT_DIR is set, use it as the full report folder.
    if let Some(dir) = read_optional_env("ZKF_ENGAGEMENT_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    run_signal_dir().join(engagement_dir_name(run_id))
}

fn install_panic_hook() {
    if PANIC_HOOK_INSTALLED.set(()).is_err() {
        return;
    }

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let now = Utc::now().to_rfc3339();
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "panic payload (non-string)".to_string()
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        let backtrace = std::backtrace::Backtrace::force_capture().to_string();

        let ctx = get_run_log_context();
        let run_id = match ctx.as_ref().map(|c| c.run_id.clone()) {
            Some(id) => id,
            None => make_run_id("panic", None),
        };

        let doc = serde_json::json!({
            "status": "panic",
            "timestamp_utc": now,
            "run_id": run_id.clone(),
            "panic": {
                "message": payload,
                "location": location,
                "backtrace": backtrace,
            },
            "context": ctx.as_ref().map(|c| serde_json::json!({
                "command": c.command,
                "campaign_path": c.campaign_path,
                "campaign_name": c.campaign_name,
                "output_dir": c.output_dir.as_ref().map(|p| p.display().to_string()),
                "started_utc": c.started_utc,
                "pid": std::process::id(),
            })),
        });

        if let Some(ctx) = ctx {
            if let Some(output_dir) = ctx.output_dir.as_ref() {
                write_run_artifacts(output_dir, &run_id, &doc);
            } else {
                write_failed_run_artifact(&run_id, &doc);
            }
        } else {
            write_failed_run_artifact(&run_id, &doc);
        }

        default_hook(info);
    }));
}

fn start_signal_watchers() {
    if SIGNAL_WATCHER_STARTED.set(()).is_err() {
        return;
    }

    tokio::spawn(async move {
        let mut sigint = Box::pin(tokio::signal::ctrl_c());

        #[cfg(unix)]
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to install SIGTERM handler: {}", e);
                    return;
                }
            };

        #[cfg(not(unix))]
        let mut sigterm: Option<()> = None;

        let stop = async {
            #[cfg(unix)]
            {
                tokio::select! {
                    _ = &mut sigint => "SIGINT",
                    _ = sigterm.recv() => "SIGTERM",
                }
            }

            #[cfg(not(unix))]
            {
                let _ = sigint;
                "SIGINT"
            }
        };

        let signal_name = stop.await;
        let now = Utc::now().to_rfc3339();
        let ctx = get_run_log_context();
        let run_id = match ctx.as_ref().map(|c| c.run_id.clone()) {
            Some(id) => id,
            None => make_run_id("interrupted", None),
        };

        let doc = serde_json::json!({
            "status": "interrupted",
            "timestamp_utc": now,
            "run_id": run_id.clone(),
            "signal": signal_name,
            "context": ctx.as_ref().map(|c| serde_json::json!({
                "command": c.command,
                "campaign_path": c.campaign_path,
                "campaign_name": c.campaign_name,
                "output_dir": c.output_dir.as_ref().map(|p| p.display().to_string()),
                "started_utc": c.started_utc,
                "pid": std::process::id(),
            })),
        });

        if let Some(ctx) = ctx {
            if let Some(output_dir) = ctx.output_dir.as_ref() {
                write_run_artifacts(output_dir, &run_id, &doc);
            } else {
                write_failed_run_artifact(&run_id, &doc);
            }
        } else {
            write_failed_run_artifact(&run_id, &doc);
        }

        // Conventional shell exit codes: 130 (SIGINT), 143 (SIGTERM).
        let code = if signal_name == "SIGTERM" { 143 } else { 130 };
        std::process::exit(code);
    });
}

/// Kill existing zk-fuzzer instances with graceful shutdown
async fn kill_existing_instances() {
    let current_pid = std::process::id();

    let pgrep_output = std::process::Command::new("pgrep")
        .args(["-x", "zk-fuzzer"])
        .output();

    if let Ok(output) = pgrep_output {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        // Try graceful shutdown first (SIGTERM)
                        match std::process::Command::new("kill")
                            .args(["-15", &pid.to_string()])
                            .output()
                        {
                            Ok(output) if output.status.success() => {}
                            Ok(output) => tracing::warn!(
                                "Failed to send SIGTERM to {}: {}",
                                pid,
                                String::from_utf8_lossy(&output.stderr)
                            ),
                            Err(err) => {
                                tracing::warn!("Error sending SIGTERM to {}: {}", pid, err)
                            }
                        }
                    }
                }
            }

            // Wait for graceful shutdown
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Force kill any remaining processes (SIGKILL)
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        match std::process::Command::new("kill")
                            .args(["-9", &pid.to_string()])
                            .output()
                        {
                            Ok(output) if output.status.success() => {}
                            Ok(output) => tracing::warn!(
                                "Failed to send SIGKILL to {}: {}",
                                pid,
                                String::from_utf8_lossy(&output.stderr)
                            ),
                            Err(err) => {
                                tracing::warn!("Error sending SIGKILL to {}: {}", pid, err)
                            }
                        }
                    }
                }
            }

            eprintln!(
                "Terminated existing zk-fuzzer instances (excluding PID {})",
                current_pid
            );
        }
    }
}

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
    let prepared = prepare_scan_dispatch(
        pattern_path,
        family_hint,
        target_circuit,
        main_component,
        framework,
        output_suffix,
    )?;
    let materialized_str = prepared.materialized_campaign_path.to_string_lossy().to_string();

    let output_dir = scan_default_output_dir();
    let mono_has_explicit_corpus_dir = mono_options.corpus_dir.is_some();
    dispatch_scan_family_run(
        prepared.family,
        &output_dir,
        mono_has_explicit_corpus_dir,
        || run_campaign(&materialized_str, mono_options),
        || run_chain_campaign(&materialized_str, chain_options),
    )
    .await
}

async fn run_campaign(config_path: &str, options: CampaignRunOptions) -> anyhow::Result<()> {
    let started_utc = Utc::now();
    let command = options.command_label;
    let run_id = make_run_id(command, Some(config_path));
    let report_dir = engagement_root_dir(&run_id);
    let mut stage = "load_config";
    tracing::info!("Report directory: {}", report_dir.display());

    // Put `session.log` under the engagement folder from the very start (even if YAML parsing
    // fails). This avoids scattering logs across multiple locations.
    set_run_log_context_for_campaign(
        options.dry_run,
        &run_id,
        command,
        config_path,
        None,
        None,
        &started_utc,
    );

    tracing::info!("Loading campaign from: {}", config_path);
    let mut config = match FuzzConfig::from_yaml(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            let ended_utc = Utc::now();
            write_failed_run_artifact_with_error(
                &run_id,
                command,
                stage,
                config_path,
                &started_utc,
                &ended_utc,
                format!("{:#}", err),
                None,
            );
            return Err(err);
        }
    };

    // Apply profile if specified
    stage = "apply_profile";
    if let Some(profile_name) = options.profile.as_deref() {
        match profile_name.parse::<ProfileName>() {
            Ok(parsed_profile) => apply_profile(&mut config, parsed_profile),
            Err(e) => {
                let ended_utc = Utc::now();
                let parse_error = e.to_string();
                write_failed_run_artifact_with_error(
                    &run_id,
                    command,
                    stage,
                    config_path,
                    &started_utc,
                    &ended_utc,
                    parse_error.clone(),
                    Some(config.reporting.output_dir.as_path()),
                );
                return Err(anyhow::anyhow!(
                    "Invalid --profile '{}': {}",
                    profile_name,
                    parse_error
                ));
            }
        }
    }

    apply_scan_output_suffix_if_present(&mut config)?;

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
    use zk_fuzzer::chain_fuzzer::{ChainCorpus, ChainFinding, DepthMetrics};
    use zk_fuzzer::config::parse_chains;
    use zk_fuzzer::fuzzer::FuzzingEngine;
    use zk_fuzzer::reporting::FuzzReport;

    let started_utc = Utc::now();
    let command = "chains";
    let run_id = make_run_id(command, Some(config_path));
    let report_dir = engagement_root_dir(&run_id);
    let mut stage = "load_config";
    tracing::info!("Report directory: {}", report_dir.display());

    // Put `session.log` under the engagement folder from the very start (even if YAML parsing
    // fails). This avoids scattering logs across multiple locations.
    set_run_log_context_for_campaign(
        options.dry_run,
        &run_id,
        command,
        config_path,
        None,
        None,
        &started_utc,
    );

    tracing::info!("Loading chain campaign from: {}", config_path);
    let mut config = match FuzzConfig::from_yaml(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            let ended_utc = Utc::now();
            write_failed_run_artifact_with_error(
                &run_id,
                command,
                stage,
                config_path,
                &started_utc,
                &ended_utc,
                format!("{:#}", err),
                None,
            );
            return Err(err);
        }
    };

    apply_scan_output_suffix_if_present(&mut config)?;

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

    // Print chain-specific banner
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".bright_magenta()
    );
    println!(
        "{}",
        "║         ZK-FUZZER v0.1.0 — MODE 3: CHAIN FUZZING          ║".bright_magenta()
    );
    println!(
        "{}",
        "║               Multi-Step Deep Bug Discovery               ║".bright_magenta()
    );
    println!(
        "{}",
        "╠═══════════════════════════════════════════════════════════╣".bright_magenta()
    );
    println!(
        "{}  Campaign: {:<45} {}",
        "║".bright_magenta(),
        truncate_str(&config.campaign.name, 45).white(),
        "║".bright_magenta()
    );
    println!(
        "{}  Chains:   {:<45} {}",
        "║".bright_magenta(),
        format!("{} defined", chains.len()).cyan(),
        "║".bright_magenta()
    );
    println!(
        "{}  Budget:   {:<45} {}",
        "║".bright_magenta(),
        format!("{}s total", options.timeout).yellow(),
        "║".bright_magenta()
    );
    println!(
        "{}  Resume:   {:<45} {}",
        "║".bright_magenta(),
        if options.resume {
            "yes".green()
        } else {
            "no".white()
        },
        "║".bright_magenta()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".bright_magenta()
    );
    println!();
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

    // List chains
    println!("{}", "CHAINS TO FUZZ:".bright_yellow().bold());
    for chain in &chains {
        println!(
            "  {} {} ({} steps, {} assertions)",
            "→".bright_cyan(),
            chain.name.white(),
            chain.steps.len(),
            chain.assertions.len()
        );
    }
    println!();

    if options.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Chain configuration is valid");
        return Ok(());
    }

    let corpus_path = output_dir.join("chain_corpus.json");
    let corpus_meta_path = output_dir.join("chain_corpus_meta.json");
    let read_chain_meta =
        |p: &std::path::Path| -> Option<zk_fuzzer::chain_fuzzer::ChainCorpusMeta> {
            match std::fs::read_to_string(p) {
                Ok(raw) => {
                    match serde_json::from_str::<zk_fuzzer::chain_fuzzer::ChainCorpusMeta>(&raw) {
                        Ok(meta) => Some(meta),
                        Err(err) => {
                            tracing::warn!(
                                "Invalid chain corpus metadata '{}': {}",
                                p.display(),
                                err
                            );
                            None
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to read chain corpus metadata '{}': {}",
                        p.display(),
                        err
                    );
                    None
                }
            }
        };
    let load_chain_corpus =
        |p: &std::path::Path| -> anyhow::Result<zk_fuzzer::chain_fuzzer::ChainCorpus> {
            if p.exists() {
                ChainCorpus::load(p)
                    .with_context(|| format!("Failed to load chain corpus from '{}'", p.display()))
            } else {
                Ok(ChainCorpus::with_storage(p))
            }
        };
    let read_chain_execution_count = |p: &std::path::Path| -> anyhow::Result<u64> {
        if !p.exists() {
            return Ok(0);
        }
        let corpus = load_chain_corpus(p)?;
        let total = corpus
            .entries()
            .iter()
            .map(|entry| entry.execution_count as u64)
            .sum();
        Ok(total)
    };
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
        let baseline_unique_coverage_bits: usize = {
            use std::collections::HashSet;
            baseline_corpus
                .entries()
                .iter()
                .map(|e| e.coverage_bits)
                .collect::<HashSet<_>>()
                .len()
        };
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
            let final_unique_coverage_bits: usize = {
                use std::collections::HashSet;
                final_corpus
                    .entries()
                    .iter()
                    .map(|e| e.coverage_bits)
                    .collect::<HashSet<_>>()
                    .len()
            };
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

    let mut quality_failures: Vec<String> = Vec::new();
    for chain in &chains {
        let (completed, unique_cov): (usize, usize) = if let Some(meta) = &final_meta {
            match meta.per_chain.get(&chain.name) {
                Some(m) => (m.completed_traces, m.unique_coverage_bits),
                None => {
                    tracing::warn!(
                        "Chain corpus metadata missing per-chain entry for '{}'",
                        chain.name
                    );
                    (0, 0)
                }
            }
        } else {
            let final_corpus = load_chain_corpus(&corpus_path)?;
            let entries: Vec<_> = final_corpus
                .entries()
                .iter()
                .filter(|e| e.spec_name == chain.name)
                .collect();
            let completed = entries.len();
            let unique_cov: usize = {
                use std::collections::HashSet;
                entries
                    .iter()
                    .map(|e| e.coverage_bits)
                    .collect::<HashSet<_>>()
                    .len()
            };
            (completed, unique_cov)
        };
        if completed < min_completed_per_chain {
            quality_failures.push(format!(
                "chain '{}' completed_traces={} < min_completed_per_chain={}",
                chain.name, completed, min_completed_per_chain
            ));
        }
        if unique_cov < min_unique_coverage_bits {
            quality_failures.push(format!(
                "chain '{}' unique_coverage_bits={} < min_unique_coverage_bits={}",
                chain.name, unique_cov, min_unique_coverage_bits
            ));
        }
    }
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

    // Save chain findings as JSON
    let chain_report_path = output_dir.join("chain_report.json");
    let chain_report = serde_json::json!({
        "campaign_name": config.campaign.name,
        "mode": "chain_fuzzing",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "engagement": {
            "strict": engagement_strict,
            "valid_run": run_valid,
            "failures": quality_failures,
            "thresholds": {
                "min_unique_coverage_bits": min_unique_coverage_bits,
                "min_completed_per_chain": min_completed_per_chain,
            },
        },
        "metrics": {
            "total_findings": summary.total_findings,
            "d_mean": summary.d_mean,
            "p_deep": summary.p_deep,
            "depth_distribution": summary.depth_distribution,
        },
        "corpus_metrics": {
            "corpus_entries": final_total_entries,
            "unique_coverage_bits": final_unique_coverage_bits,
            "max_depth": final_max_depth,
            "baseline": {
                "corpus_entries": baseline_total_entries,
                "unique_coverage_bits": baseline_unique_coverage_bits,
            }
        },
        "chain_findings": chain_findings,
    });
    if let Err(err) = (|| -> anyhow::Result<()> {
        use std::io::{BufWriter, Write};
        let f = std::fs::File::create(&chain_report_path)?;
        let mut w = BufWriter::new(f);
        serde_json::to_writer_pretty(&mut w, &chain_report)?;
        w.flush()?;
        Ok(())
    })() {
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

    // Save chain findings as markdown
    let chain_md_path = output_dir.join("chain_report.md");
    let mut md = String::new();
    md.push_str(&format!(
        "# Chain Fuzzing Report: {}\n\n",
        config.campaign.name
    ));
    md.push_str("**Mode:** Multi-Step Chain Fuzzing (Mode 3)\n");
    md.push_str(&format!(
        "**Generated:** {}\n\n",
        chrono::Utc::now().to_rfc3339()
    ));

    md.push_str("## Engagement Validation\n\n");
    md.push_str(&format!("**Strict:** {}\n", engagement_strict));
    md.push_str(&format!(
        "**Valid Run:** {}\n",
        if run_valid { "yes" } else { "no" }
    ));
    md.push_str(&format!(
        "**Thresholds:** min_unique_coverage_bits={}, min_completed_per_chain={}\n\n",
        min_unique_coverage_bits, min_completed_per_chain
    ));

    md.push_str("### Corpus / Exploration Metrics\n\n");
    md.push_str(&format!(
        "- Corpus entries: {} (delta {})\n",
        final_total_entries,
        final_total_entries.saturating_sub(baseline_total_entries)
    ));
    md.push_str(&format!(
        "- Unique coverage bits: {} (delta {})\n",
        final_unique_coverage_bits,
        final_unique_coverage_bits.saturating_sub(baseline_unique_coverage_bits)
    ));
    md.push_str(&format!("- Max depth: {}\n\n", final_max_depth));

    if !quality_failures.is_empty() {
        md.push_str("### Failures\n\n");
        for failure in &quality_failures {
            md.push_str(&format!("- {}\n", failure));
        }
        md.push('\n');
    }

    md.push_str("## Depth Metrics\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Total Findings | {} |\n",
        summary.total_findings
    ));
    md.push_str(&format!("| Mean L_min (D) | {:.2} |\n", summary.d_mean));
    md.push_str(&format!(
        "| P(L_min >= 2) | {:.1}% |\n\n",
        summary.p_deep * 100.0
    ));

    if !chain_findings.is_empty() {
        md.push_str("## Chain Findings\n\n");
        for (i, finding) in chain_findings.iter().enumerate() {
            md.push_str(&format!(
                "### {}. [{}] Chain: {}\n\n",
                i + 1,
                finding.finding.severity.to_uppercase(),
                finding.spec_name
            ));
            md.push_str(&format!("**L_min:** {}\n\n", finding.l_min));
            md.push_str(&format!("{}\n\n", finding.finding.description));

            if let Some(ref assertion) = finding.violated_assertion {
                md.push_str(&format!("**Violated Assertion:** `{}`\n\n", assertion));
            }

            // Add trace summary
            md.push_str("**Trace:**\n\n");
            for (step_idx, step) in finding.trace.steps.iter().enumerate() {
                let status = if step.success { "✓" } else { "✗" };
                md.push_str(&format!(
                    "- Step {}: {} `{}` - {}\n",
                    step_idx,
                    status,
                    step.circuit_ref,
                    if step.success {
                        "success"
                    } else {
                        step.error.as_deref().unwrap_or("failed")
                    }
                ));
            }
            md.push('\n');

            // Add reproduction
            md.push_str("**Reproduction:**\n\n");
            md.push_str(&format!(
                "```bash\ncargo run --release -- chains {} --seed {}\n```\n\n",
                config_path,
                options.seed.unwrap_or(42)
            ));
        }
    }

    if let Err(err) = std::fs::write(&chain_md_path, md) {
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
