use chrono::{DateTime, Utc};
use zk_fuzzer::chain_fuzzer::{ChainFinding, ChainSpec};
use zk_fuzzer::fuzzer::FuzzingEngine;

use crate::cli::ChainRunOptions;
use crate::run_lifecycle::write_failed_mode_run_artifact_with_error;

pub(crate) async fn run_chain_engine(
    config: &zk_fuzzer::config::FuzzConfig,
    chains: &[ChainSpec],
    options: &ChainRunOptions,
    output_dir: &std::path::Path,
    command: &str,
    run_id: &str,
    config_path: &str,
    campaign_name: &str,
    started_utc: DateTime<Utc>,
) -> anyhow::Result<Vec<ChainFinding>> {
    let mut engine = match FuzzingEngine::new(config.clone(), options.seed, options.workers) {
        Ok(e) => e,
        Err(err) => {
            write_failed_mode_run_artifact_with_error(
                output_dir,
                command,
                run_id,
                "engine_init",
                config_path,
                campaign_name,
                started_utc,
                Some(options.timeout),
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
                output_dir,
                command,
                run_id,
                "engine_run_chains",
                config_path,
                campaign_name,
                started_utc,
                Some(options.timeout),
                format!("{:#}", err),
            );
            Err(err)
        }
    }
}
