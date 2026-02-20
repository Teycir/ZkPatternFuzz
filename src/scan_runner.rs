use crate::cli::ScanRequest;
use crate::scan_dispatch::prepare_scan_dispatch;
use crate::scan_progress::{dispatch_scan_family_run, scan_default_output_dir};

pub(crate) async fn run_scan<RunMono, RunMulti, MonoFut, MultiFut>(
    scan_request: ScanRequest,
    run_mono: RunMono,
    run_multi: RunMulti,
) -> anyhow::Result<()>
where
    RunMono: FnOnce(String, crate::cli::CampaignRunOptions) -> MonoFut,
    RunMulti: FnOnce(String, crate::cli::ChainRunOptions) -> MultiFut,
    MonoFut: std::future::Future<Output = anyhow::Result<()>>,
    MultiFut: std::future::Future<Output = anyhow::Result<()>>,
{
    let ScanRequest {
        pattern,
        family,
        target_circuit,
        main_component,
        framework,
        output_suffix,
        mono_options,
        chain_options,
    } = scan_request;

    let prepared = prepare_scan_dispatch(
        &pattern,
        family,
        &target_circuit,
        &main_component,
        &framework,
        output_suffix.as_deref(),
    )?;
    let materialized_mono = prepared
        .materialized_campaign_path
        .to_string_lossy()
        .to_string();
    let materialized_multi = materialized_mono.clone();

    let output_dir = scan_default_output_dir();
    let mono_has_explicit_corpus_dir = mono_options.corpus_dir.is_some();
    dispatch_scan_family_run(
        prepared.family,
        &output_dir,
        mono_has_explicit_corpus_dir,
        || run_mono(materialized_mono, mono_options),
        || run_multi(materialized_multi, chain_options),
    )
    .await
}
