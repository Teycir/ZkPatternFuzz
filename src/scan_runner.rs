use crate::cli::ScanRequest;
use crate::scan_dispatch::prepare_scan_dispatch;
use crate::scan_progress::{dispatch_scan_family_run, scan_default_output_dir};
use std::path::{Path, PathBuf};
use zk_fuzzer::target_overrides::{
    collect_target_override_env, resolve_target_run_overrides, DEFAULT_TARGET_OVERRIDES_INDEX_PATH,
};

fn apply_target_overrides_for_scan(
    target_circuit: &str,
    framework: &str,
    target_overrides_index: Option<&str>,
    disable_target_overrides: bool,
    mono_options: &mut crate::cli::CampaignRunOptions,
    chain_options: &mut crate::cli::ChainRunOptions,
) -> anyhow::Result<()> {
    if disable_target_overrides {
        return Ok(());
    }

    let index_path = target_overrides_index
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_TARGET_OVERRIDES_INDEX_PATH));
    if !index_path.exists() {
        if target_overrides_index.is_some() {
            anyhow::bail!(
                "Target overrides index not found: '{}'",
                index_path.display()
            );
        }
        return Ok(());
    }

    let target_path = Path::new(target_circuit);
    let Some(resolved) = resolve_target_run_overrides(&index_path, target_path, framework)? else {
        return Ok(());
    };

    if let Some(value) = resolved.overrides.workers {
        if value == 0 {
            anyhow::bail!(
                "Invalid workers=0 in target run overrides '{}'",
                resolved.overrides_path.display()
            );
        }
        mono_options.workers = value;
        chain_options.workers = value;
    }
    if let Some(value) = resolved.overrides.iterations {
        mono_options.iterations = value;
        chain_options.iterations = value;
    }
    if let Some(value) = resolved.overrides.timeout {
        if value == 0 {
            anyhow::bail!(
                "Invalid timeout=0 in target run overrides '{}'",
                resolved.overrides_path.display()
            );
        }
        mono_options.timeout = Some(value);
        chain_options.timeout = value;
    }

    let env_overrides = collect_target_override_env(&resolved.overrides)?;
    for (key, value) in &env_overrides {
        std::env::set_var(key, value);
    }

    tracing::info!(
        "Target overrides applied: target='{}' matrix_target='{}' file='{}' workers={} iterations={} timeout={} env_keys={}",
        resolved.target_name,
        resolved.target_circuit.display(),
        resolved.overrides_path.display(),
        mono_options.workers,
        mono_options.iterations,
        mono_options.timeout.unwrap_or(chain_options.timeout),
        if env_overrides.is_empty() {
            "<none>".to_string()
        } else {
            env_overrides.keys().cloned().collect::<Vec<String>>().join(",")
        }
    );

    Ok(())
}

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
        target_overrides_index,
        disable_target_overrides,
        output_suffix,
        mut mono_options,
        mut chain_options,
    } = scan_request;

    apply_target_overrides_for_scan(
        &target_circuit,
        &framework,
        target_overrides_index.as_deref(),
        disable_target_overrides,
        &mut mono_options,
        &mut chain_options,
    )?;

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
