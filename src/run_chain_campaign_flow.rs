use chrono::Utc;

use crate::cli::{chain_run_options_doc, ChainRunOptions};
use crate::run_bootstrap::{
    announce_report_dir_and_bind_log_context, load_campaign_config_with_optional_profile,
};
use crate::run_chain_config::apply_chain_mode_overrides;
use crate::run_chain_context::ChainRunContext;
use crate::run_chain_corpus::load_chain_run_corpus_metrics;
use crate::run_chain_engine::run_chain_engine;
use crate::run_chain_quality::assess_chain_quality;
use crate::run_chain_reports::{
    build_chain_completion_doc_context, build_chain_report_context, chain_completion_status,
    finalize_chain_run, save_chain_reports_and_standard_or_emit_failure, ChainFinalizeContext,
    ChainReportContextInput,
};
use crate::run_chain_startup::startup_chain_run_or_exit_dry_run;
use crate::run_chain_ui::print_chain_results_from_report;
use crate::run_identity::make_run_id;
use crate::run_lifecycle::{initialize_campaign_run_lifecycle, RunLifecycleMeta};
use crate::run_log_context::RunLogContextGuard;

pub(crate) async fn run_chain_campaign(
    config_path: &str,
    options: ChainRunOptions,
) -> anyhow::Result<()> {
    use zk_fuzzer::chain_fuzzer::ChainFinding;
    use zk_fuzzer::config::parse_chains;

    let started_utc = Utc::now();
    let command = "chains";
    let run_id = make_run_id(command, Some(config_path));
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
    let run_meta = RunLifecycleMeta {
        command,
        run_id: &run_id,
        config_path,
        campaign_name: &campaign_name,
        started_utc: &started_utc,
        timeout_seconds: Some(options.timeout),
    };

    let (output_dir, _output_lock) = initialize_campaign_run_lifecycle(
        options.dry_run,
        &mut config,
        run_meta,
        chain_run_options_doc(&options),
    )?;

    let run_ctx = ChainRunContext::from_options(
        &output_dir,
        command,
        &run_id,
        config_path,
        &campaign_name,
        started_utc,
        &options,
    );

    let _ctx_guard = RunLogContextGuard::new();

    let chains = parse_chains(&config);
    apply_chain_mode_overrides(&mut config, &options);

    if startup_chain_run_or_exit_dry_run(&run_ctx, &config, &chains, &options)? {
        return Ok(());
    }

    let corpus_path = output_dir.join("chain_corpus.json");
    let corpus_meta_path = output_dir.join("chain_corpus_meta.json");
    let chain_findings: Vec<ChainFinding> =
        run_chain_engine(&run_ctx, &config, &chains, &options).await?;

    let run_corpus_metrics =
        load_chain_run_corpus_metrics(&corpus_path, &corpus_meta_path, options.resume)?;
    let baseline_total_entries = run_corpus_metrics.baseline.total_entries;
    let baseline_unique_coverage_bits = run_corpus_metrics.baseline.unique_coverage_bits;
    let final_meta = run_corpus_metrics.final_metrics.meta;
    let final_total_entries = run_corpus_metrics.final_metrics.total_entries;
    let final_unique_coverage_bits = run_corpus_metrics.final_metrics.unique_coverage_bits;
    let final_max_depth = run_corpus_metrics.final_metrics.max_depth;
    let run_execution_count = run_corpus_metrics.run_execution_count;

    let assessment = assess_chain_quality(
        &config,
        &chains,
        final_meta.as_ref(),
        &corpus_path,
        &chain_findings,
    )?;

    let report_ctx = build_chain_report_context(ChainReportContextInput {
        campaign_name: &config.campaign.name,
        engagement_strict: assessment.engagement.strict,
        run_valid: assessment.run_valid,
        quality_failures: &assessment.quality_failures,
        min_unique_coverage_bits: assessment.engagement.min_unique_coverage_bits,
        min_completed_per_chain: assessment.engagement.min_completed_per_chain,
        summary: &assessment.summary,
        final_total_entries,
        final_unique_coverage_bits,
        final_max_depth,
        baseline_total_entries,
        baseline_unique_coverage_bits,
        chain_findings: &chain_findings,
    });

    print_chain_results_from_report(&report_ctx, config_path, options.seed);

    save_chain_reports_and_standard_or_emit_failure(
        &run_ctx,
        &report_ctx,
        options.seed,
        config.reporting.clone(),
        run_execution_count,
    )?;

    let (status, critical) = chain_completion_status(
        report_ctx.engagement_strict,
        report_ctx.run_valid,
        &chain_findings,
    );
    let completion_ctx =
        build_chain_completion_doc_context(&run_ctx, &report_ctx, status, critical);
    finalize_chain_run(ChainFinalizeContext {
        run_ctx: &run_ctx,
        report_ctx: &report_ctx,
        completion_ctx,
        critical,
    })
}
