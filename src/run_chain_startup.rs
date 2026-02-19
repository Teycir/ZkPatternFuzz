use chrono::{DateTime, Local, Utc};
use zk_fuzzer::chain_fuzzer::ChainSpec;

use crate::cli::{chain_run_options_doc, ChainRunOptions};
use crate::run_chain_ui::{print_chain_mode_banner, print_chains_to_fuzz};
use crate::run_lifecycle::{
    require_evidence_readiness_or_emit_failure, run_backend_preflight_or_emit_failure,
    seed_running_run_artifact, write_failed_mode_run_artifact_with_reason,
};
use crate::runtime_misc::print_run_window;

pub(crate) fn startup_chain_run_or_exit_dry_run(
    config: &zk_fuzzer::config::FuzzConfig,
    chains: &[ChainSpec],
    options: &ChainRunOptions,
    output_dir: &std::path::Path,
    command: &str,
    run_id: &str,
    config_path: &str,
    campaign_name: &str,
    started_utc: DateTime<Utc>,
) -> anyhow::Result<bool> {
    if chains.is_empty() {
        if !options.dry_run {
            write_failed_mode_run_artifact_with_reason(
                output_dir,
                command,
                run_id,
                "parse_chains",
                config_path,
                campaign_name,
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

    println!();
    let readiness = zk_fuzzer::config::check_0day_readiness(config);
    print!("{}", readiness.format());
    require_evidence_readiness_or_emit_failure(
        options.dry_run,
        output_dir,
        command,
        run_id,
        "preflight_readiness",
        config_path,
        campaign_name,
        started_utc,
        Some(options.timeout),
        &readiness,
        "Campaign has critical issues; refusing to start strict chain run",
    )?;

    run_backend_preflight_or_emit_failure(
        options.dry_run,
        config,
        output_dir,
        command,
        run_id,
        "preflight_backend",
        config_path,
        campaign_name,
        started_utc,
        Some(options.timeout),
    )?;

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
            output_dir,
            command,
            run_id,
            "starting_engine",
            config_path,
            campaign_name,
            started_utc,
            Some(options.timeout),
            chain_run_options_doc(options),
        );
    }

    print_chains_to_fuzz(chains);

    if options.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Chain configuration is valid");
        return Ok(true);
    }

    Ok(false)
}
