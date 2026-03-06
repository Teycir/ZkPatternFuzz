use clap::Parser;
use std::path::PathBuf;
use zk_fuzzer::cve::CveDatabase;
mod cli;
mod engagement_artifacts;
mod output_lock;
mod preflight_backend;
mod run_bootstrap;
mod run_campaign_flow;
mod run_chain_campaign_flow;
mod run_chain_config;
mod run_chain_context;
mod run_chain_corpus;
mod run_chain_engine;
mod run_chain_quality;
mod run_chain_reports;
mod run_chain_startup;
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
mod scan_selector_context;
mod toolchain_bootstrap;
use cli::{
    BinsBootstrapRequest, ChainRunOptions, Cli, CommandRequest, CompletionShell, ScanRequest,
};
use preflight_backend::preflight_campaign;
use run_campaign_flow::run_campaign;
pub(crate) use run_identity::{make_run_id, sanitize_slug};
use run_interrupts::{install_panic_hook, start_signal_watchers};
pub(crate) use run_log_context::set_run_log_context_for_campaign;
use run_log_context::DynamicLogWriter;
pub(crate) use run_paths::{
    engagement_root_dir, normalize_build_paths, read_optional_env, run_signal_dir,
};
use run_process_control::kill_existing_instances;
use runtime_misc::{generate_sample_config, minimize_corpus, validate_campaign};
use scan_runner::run_scan as run_scan_orchestrated;

const DEFAULT_CVE_DATABASE_PATH: &str = "templates/known_vulnerabilities.yaml";

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
    let log_level = if cli.quiet {
        tracing::Level::WARN
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    let dry_run = cli.dry_run;
    let implicit_legacy_run = cli.command.is_none() && cli.config.is_some();
    let request = cli.into_request();
    if let CommandRequest::ListPatterns = &request {
        return list_known_cve_patterns();
    }
    if let CommandRequest::GenerateCompletions { shell } = &request {
        return generate_shell_completions(*shell);
    }
    if let CommandRequest::ExecWorker = &request {
        return zk_fuzzer::executor::run_exec_worker();
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_ansi(false)
        .with_writer(DynamicLogWriter)
        .init();

    // Ensure early-stop causes are captured to disk when possible (panic/signal).
    install_panic_hook();
    start_signal_watchers();

    match request {
        CommandRequest::ListPatterns => list_known_cve_patterns(),
        CommandRequest::GenerateCompletions { shell } => generate_shell_completions(shell),
        CommandRequest::Scan(scan_request) => run_scan(scan_request).await,
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
        CommandRequest::ExecWorker => unreachable!("exec worker is handled before logging init"),
        CommandRequest::MissingCommand => anyhow::bail!(
            "No command provided. Use `zk-fuzzer scan <pattern.yaml> --target-circuit <path> --main-component <name> --framework <fw>`."
        ),
    }
}

async fn run_scan(scan_request: ScanRequest) -> anyhow::Result<()> {
    run_scan_orchestrated(
        scan_request,
        |materialized, options| async move { run_campaign(&materialized, options).await },
        |materialized, options| async move { run_chain_campaign(&materialized, options).await },
    )
    .await
}

/// Run a chain-focused fuzzing campaign (Mode 3: Deepest)
async fn run_chain_campaign(config_path: &str, options: ChainRunOptions) -> anyhow::Result<()> {
    run_chain_campaign_flow::run_chain_campaign(config_path, options).await
}

fn list_known_cve_patterns() -> anyhow::Result<()> {
    let database = CveDatabase::load(DEFAULT_CVE_DATABASE_PATH).map_err(|err| {
        anyhow::anyhow!(
            "Failed to load CVE pattern database '{}': {:#}",
            DEFAULT_CVE_DATABASE_PATH,
            err
        )
    })?;

    let mut patterns: Vec<_> = database.all_patterns().iter().collect();
    patterns.sort_by(|left, right| left.id.cmp(&right.id));

    println!(
        "Known CVE patterns: {} (version {}, updated {})",
        patterns.len(),
        database.version,
        database.last_updated
    );
    println!("ID | Severity | Name | Summary");
    println!("---|---|---|---");
    for pattern in patterns {
        let summary = pattern
            .description
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("-");
        println!(
            "{} | {} | {} | {}",
            pattern.id, pattern.severity, pattern.name, summary
        );
    }

    Ok(())
}

fn generate_shell_completions(shell: CompletionShell) -> anyhow::Result<()> {
    let script = match shell {
        CompletionShell::Bash => include_str!("../assets/completions/zk-fuzzer.bash"),
        CompletionShell::Zsh => include_str!("../assets/completions/_zk-fuzzer"),
        CompletionShell::Fish => include_str!("../assets/completions/zk-fuzzer.fish"),
    };
    print!("{}", script);
    Ok(())
}
