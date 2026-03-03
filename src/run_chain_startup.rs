use chrono::Local;
use zk_fuzzer::chain_fuzzer::ChainSpec;

use crate::cli::{chain_run_options_doc, ChainRunOptions};
use crate::run_chain_context::ChainRunContext;
use crate::run_chain_ui::{print_chain_mode_banner, print_chains_to_fuzz};
use crate::run_lifecycle::{
    require_evidence_readiness_or_emit_failure, run_backend_preflight_or_emit_failure,
    seed_running_run_artifact, write_failed_mode_run_artifact_with_reason, RunLifecycleContext,
};
use crate::runtime_misc::print_run_window;

pub(crate) fn startup_chain_run_or_exit_dry_run(
    run_ctx: &ChainRunContext<'_>,
    config: &zk_fuzzer::config::FuzzConfig,
    chains: &[ChainSpec],
    options: &ChainRunOptions,
) -> anyhow::Result<bool> {
    let lifecycle_ctx = RunLifecycleContext::new(
        run_ctx.output_dir,
        run_ctx.command,
        run_ctx.run_id,
        run_ctx.config_path,
        run_ctx.campaign_name,
        &run_ctx.started_utc,
        run_ctx.timeout_seconds,
    );

    if chains.is_empty() {
        if !options.dry_run {
            write_failed_mode_run_artifact_with_reason(
                &lifecycle_ctx,
                "parse_chains",
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
    if !options.dry_run {
        seed_running_run_artifact(
            &lifecycle_ctx,
            "preflight_readiness",
            chain_run_options_doc(options),
        );
    }
    let readiness = zk_fuzzer::config::check_0day_readiness(config);
    print!("{}", readiness.format());
    require_evidence_readiness_or_emit_failure(
        options.dry_run,
        &lifecycle_ctx,
        "preflight_readiness",
        &readiness,
        "Campaign has critical issues; refusing to start strict chain run",
    )?;

    if !options.dry_run {
        seed_running_run_artifact(
            &lifecycle_ctx,
            "preflight_backend",
            chain_run_options_doc(options),
        );
    }
    run_backend_preflight_or_emit_failure(
        options.dry_run,
        config,
        &lifecycle_ctx,
        "preflight_backend",
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
            &lifecycle_ctx,
            "starting_engine",
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
