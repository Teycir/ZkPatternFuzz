use zk_fuzzer::chain_fuzzer::{ChainFinding, ChainSpec};
use zk_fuzzer::fuzzer::FuzzingEngine;

use crate::cli::ChainRunOptions;
use crate::run_chain_context::ChainRunContext;
use crate::run_lifecycle::{write_failed_mode_run_artifact_with_error, RunLifecycleContext};

pub(crate) async fn run_chain_engine(
    run_ctx: &ChainRunContext<'_>,
    config: &zk_fuzzer::config::FuzzConfig,
    chains: &[ChainSpec],
    options: &ChainRunOptions,
) -> anyhow::Result<Vec<ChainFinding>> {
    let lifecycle_ctx = RunLifecycleContext::new(
        run_ctx.output_dir,
        run_ctx.command,
        run_ctx.run_id,
        run_ctx.config_path,
        run_ctx.campaign_name,
        &run_ctx.started_utc,
        run_ctx.timeout_seconds,
    );

    let mut engine = match FuzzingEngine::new(config.clone(), options.seed, options.workers) {
        Ok(e) => e,
        Err(err) => {
            write_failed_mode_run_artifact_with_error(
                &lifecycle_ctx,
                "engine_init",
                format!("{:#}", err),
            );
            return Err(err);
        }
    };

    let progress = if options.simple_progress {
        None
    } else {
        let total = (options.iterations as usize * chains.len()) as u64;
        Some(zk_fuzzer::progress::ProgressReporter::new(
            &format!("{} (chains)", config.campaign.name),
            total,
            options.verbose,
        ))
    };

    match engine.run_chains(chains, progress.as_ref()).await {
        Ok(findings) => Ok(findings),
        Err(err) => {
            write_failed_mode_run_artifact_with_error(
                &lifecycle_ctx,
                "engine_run_chains",
                format!("{:#}", err),
            );
            Err(err)
        }
    }
}
