use clap::Parser;
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::sync::atomic::Ordering;
use std::time::Instant;

#[path = "zkpatternfuzz/checkenv.rs"]
mod checkenv;
#[path = "zkpatternfuzz/run_log.rs"]
mod run_log;
#[path = "zkpatternfuzz/zkpatternfuzz_batch.rs"]
mod zkpatternfuzz_batch;
#[path = "zkpatternfuzz/zkpatternfuzz_bootstrap.rs"]
mod zkpatternfuzz_bootstrap;
#[path = "zkpatternfuzz/zkpatternfuzz_campaign.rs"]
mod zkpatternfuzz_campaign;
#[path = "zkpatternfuzz/zkpatternfuzz_config.rs"]
mod zkpatternfuzz_config;
#[path = "zkpatternfuzz/zkpatternfuzz_discovery.rs"]
mod zkpatternfuzz_discovery;
#[path = "zkpatternfuzz/zkpatternfuzz_env.rs"]
mod zkpatternfuzz_env;
#[path = "zkpatternfuzz/zkpatternfuzz_execution.rs"]
mod zkpatternfuzz_execution;
#[path = "zkpatternfuzz/zkpatternfuzz_pipeline.rs"]
mod zkpatternfuzz_pipeline;
#[path = "zkpatternfuzz/zkpatternfuzz_readiness.rs"]
mod zkpatternfuzz_readiness;
#[path = "zkpatternfuzz/zkpatternfuzz_reporting.rs"]
mod zkpatternfuzz_reporting;
#[path = "zkpatternfuzz/zkpatternfuzz_runtime.rs"]
mod zkpatternfuzz_runtime;
#[path = "zkpatternfuzz/zkpatternfuzz_selection.rs"]
mod zkpatternfuzz_selection;
#[path = "zkpatternfuzz/zkpatternfuzz_types.rs"]
mod zkpatternfuzz_types;

use checkenv::{is_set as env_is_set, var as env_var, CheckEnv};
#[allow(unused_imports)]
use run_log::{append_run_log, run_log_file_cache};
use run_log::{
    append_run_log_best_effort, step_failed, step_skipped, step_started, step_succeeded,
};
use zkpatternfuzz_batch::{
    apply_memory_parallelism_guardrails, format_stuck_step_warning_line, host_available_memory_mb,
    progress_stage_is_proof, read_template_progress_update, reserve_batch_scan_run_root,
    template_progress_path, validate_template_compatibility, BatchProgress,
};
#[allow(unused_imports)]
use zkpatternfuzz_batch::{
    apply_memory_parallelism_guardrails_with_available, estimated_batch_memory_mb,
    parse_mem_available_kib,
};
use zkpatternfuzz_bootstrap::{bootstrap_pre_execution, TOTAL_STEPS};
use zkpatternfuzz_campaign::{
    classify_run_reason_code, collect_observed_suffixes_for_roots,
    collect_template_outcome_reasons, list_scan_run_roots, print_reason_summary,
};
#[allow(unused_imports)]
use zkpatternfuzz_campaign::{parse_correlation_confidence, parse_correlation_oracle_count};
use zkpatternfuzz_config::{
    apply_file_config, effective_batch_timeout_secs, halo2_effective_external_timeout_secs,
    high_confidence_min_oracles_from_env, load_batch_file_config, load_memory_guard_config,
    load_stage_timeout_config, resolve_build_cache_dir, resolve_results_root,
};
use zkpatternfuzz_discovery::{
    build_template_index, dedupe_patterns_by_signature, discover_all_pattern_templates,
    print_catalog, resolve_explicit_pattern_selection, resolve_selection, split_csv,
    validate_pattern_only_yaml,
};
use zkpatternfuzz_env::{expand_env_placeholders, has_unresolved_env_placeholder};
#[allow(unused_imports)]
use zkpatternfuzz_execution::{
    finalize_pipe_capture, join_pipe_reader, run_scan, spawn_pipe_reader,
    write_stage_timeout_outcome, PipeCapture,
};
use zkpatternfuzz_execution::{
    proof_status_from_run_outcome_doc, run_template, scan_output_suffix,
};
use zkpatternfuzz_pipeline::{execute_templates_step, ExecuteStepInput};
use zkpatternfuzz_readiness::{ensure_local_runtime_requirements, preflight_template_paths};
use zkpatternfuzz_reporting::{
    create_timestamped_result_dir, is_error_reason, print_reason_tsv, proof_state_counts,
    write_error_log, write_report_json,
};
use zkpatternfuzz_runtime::{
    auto_halo2_toolchain_candidates, is_external_target, preflight_runtime_paths,
    prepare_target_for_framework, resolved_release_bin_path,
};
#[allow(unused_imports)]
use zkpatternfuzz_runtime::{parse_rustup_toolchain_names, push_unique_nonempty};
use zkpatternfuzz_selection::{
    ensure_positive_cli_values, parse_family, resolve_batch_selection, SelectionResolution,
};
use zkpatternfuzz_types::*;

fn main() -> anyhow::Result<()> {
    let _check_env = CheckEnv::new(
        Path::new(".env"),
        &[
            SCAN_OUTPUT_ROOT_ENV,
            RUN_SIGNAL_DIR_ENV,
            BUILD_CACHE_DIR_ENV,
            DEFAULT_BATCH_JOBS_ENV,
            DEFAULT_BATCH_WORKERS_ENV,
            DEFAULT_BATCH_ITERATIONS_ENV,
            DEFAULT_BATCH_TIMEOUT_ENV,
            MEMORY_GUARD_ENABLED_ENV,
            MEMORY_GUARD_RESERVED_MB_ENV,
            MEMORY_GUARD_MB_PER_TEMPLATE_ENV,
            MEMORY_GUARD_MB_PER_WORKER_ENV,
            MEMORY_GUARD_LAUNCH_FLOOR_MB_ENV,
            MEMORY_GUARD_WAIT_SECS_ENV,
            MEMORY_GUARD_POLL_MS_ENV,
            DETECTION_STAGE_TIMEOUT_ENV,
            PROOF_STAGE_TIMEOUT_ENV,
            STUCK_STEP_WARN_SECS_ENV,
        ],
    )?;

    let mut args = Args::parse();
    let effective_file_cfg = if let Some(path) = args.config_json.clone() {
        let cfg = load_batch_file_config(&path)?;
        apply_file_config(&mut args, cfg)?
    } else {
        EffectiveFileConfig::default()
    };
    let requested_timeout = args.timeout;
    args.timeout = effective_batch_timeout_secs(&args.framework, args.timeout);
    if args.timeout != requested_timeout {
        eprintln!(
            "Halo2 timeout default applied: {}s -> {}s (override with --timeout or {})",
            requested_timeout, args.timeout, HALO2_DEFAULT_BATCH_TIMEOUT_ENV
        );
    }
    ensure_positive_cli_values(&args)?;
    let memory_guard = load_memory_guard_config()?;
    let stage_timeouts = load_stage_timeout_config(args.timeout)?;
    apply_memory_parallelism_guardrails(&mut args, memory_guard)?;
    let family_override = parse_family(&args.family)?;

    let selection = match resolve_batch_selection(&mut args, family_override)? {
        SelectionResolution::ListedCatalog => return Ok(()),
        SelectionResolution::Selected(selection) => selection,
    };
    let target_circuit = selection.target_circuit;
    let target_circuit_path = selection.target_circuit_path;
    let selected_with_family = selection.selected_with_family;
    let expected_suffixes = selection.expected_suffixes;
    let expected_count = expected_suffixes.len();
    let batch_started_at = Instant::now();

    let template_paths: Vec<PathBuf> = selected_with_family
        .iter()
        .map(|(template, _)| template.path.clone())
        .collect();
    let bootstrap = bootstrap_pre_execution(
        &args,
        &target_circuit,
        &target_circuit_path,
        &template_paths,
        expected_count,
    )?;
    let total_steps = TOTAL_STEPS;
    let results_root = bootstrap.results_root;
    let timestamped_result_dir = bootstrap.timestamped_result_dir;
    let timestamped_report_path = bootstrap.timestamped_report_path;
    let timestamped_error_log = bootstrap.timestamped_error_log;
    let timestamped_run_log = bootstrap.timestamped_run_log;
    let run_signal_dir = bootstrap.run_signal_dir;
    let build_cache_dir = bootstrap.build_cache_dir;
    let bin_path = bootstrap.bin_path;
    let artifacts_root = bootstrap.artifacts_root;

    let run_cfg_base = ScanRunConfig {
        bin_path: &bin_path,
        target_circuit: &target_circuit,
        framework: &args.framework,
        main_component: &args.main_component,
        env_overrides: &effective_file_cfg.env,
        extra_args: &effective_file_cfg.extra_args,
        workers: args.workers,
        seed: args.seed,
        iterations: args.iterations,
        timeout: args.timeout,
        scan_run_root: None,
        results_root: &results_root,
        run_signal_dir: &run_signal_dir,
        build_cache_dir: &build_cache_dir,
        dry_run: args.dry_run,
        artifacts_root: &artifacts_root,
        memory_guard,
        stage_timeouts,
    };

    let execute_outcome = execute_templates_step(ExecuteStepInput {
        args: &args,
        selected_with_family: &selected_with_family,
        expected_suffixes: &expected_suffixes,
        expected_count,
        batch_started_at,
        run_cfg_base,
        artifacts_root: &artifacts_root,
        target_circuit: &target_circuit,
        timestamped_report_path: &timestamped_report_path,
        timestamped_error_log: &timestamped_error_log,
        timestamped_run_log: &timestamped_run_log,
        timestamped_result_dir: &timestamped_result_dir,
        results_root: &results_root,
        total_steps,
    })?;

    if !execute_outcome.gate2_ok || !execute_outcome.gate3_ok {
        std::process::exit(1);
    }

    Ok(())
}
