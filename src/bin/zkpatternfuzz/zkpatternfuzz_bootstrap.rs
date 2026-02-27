use anyhow::Context;
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{
    append_run_log_best_effort, create_timestamped_result_dir, ensure_local_runtime_requirements,
    preflight_runtime_paths, preflight_template_paths, prepare_target_for_framework,
    resolve_results_root, resolved_release_bin_path, step_failed, step_skipped, step_started,
    step_succeeded, validate_pattern_only_yaml, write_error_log, Args, SCAN_OUTPUT_ROOT_ENV,
};

pub(super) const TOTAL_STEPS: usize = 5;

pub(super) struct BootstrapState {
    pub(super) results_root: PathBuf,
    pub(super) timestamped_result_dir: PathBuf,
    pub(super) timestamped_report_path: PathBuf,
    pub(super) timestamped_error_log: PathBuf,
    pub(super) timestamped_run_log: PathBuf,
    pub(super) run_signal_dir: PathBuf,
    pub(super) build_cache_dir: PathBuf,
    pub(super) bin_path: PathBuf,
    pub(super) artifacts_root: PathBuf,
}

fn write_early_error_log(timestamped_error_log: &Path, dry_run: bool) {
    if let Err(log_err) = write_error_log(timestamped_error_log, &[], 1, false, false, dry_run) {
        eprintln!(
            "Failed to write early error log '{}': {:#}",
            timestamped_error_log.display(),
            log_err
        );
    }
}

pub(super) fn bootstrap_pre_execution(
    args: &Args,
    target_circuit: &str,
    target_circuit_path: &Path,
    template_paths: &[PathBuf],
    expected_count: usize,
) -> anyhow::Result<BootstrapState> {
    println!("Gate 1/3 (expected templates): {}", expected_count);
    let results_root = resolve_results_root().map_err(|err| {
        anyhow::anyhow!(
            "Output path configuration failed: {:#}\nHint: set {} to a writable directory (example: export {}=/home/teycir/zkfuzz)",
            err,
            SCAN_OUTPUT_ROOT_ENV,
            SCAN_OUTPUT_ROOT_ENV
        )
    })?;
    let timestamped_result_dir = create_timestamped_result_dir(&results_root).with_context(|| {
        format!(
            "Unable to create result directory under '{}'. Check that the path exists and is writable.",
            results_root.display()
        )
    })?;
    let timestamped_report_path = timestamped_result_dir.join("detected_patterns.json");
    let timestamped_error_log = timestamped_result_dir.join("errors.log");
    let timestamped_run_log = timestamped_result_dir.join("run.log");
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "start_utc={} step=gate1_expected_templates expected_patterns={}",
            Utc::now().to_rfc3339(),
            expected_count
        ),
    );

    let preflight_step_started =
        step_started(1, TOTAL_STEPS, "template preflight", &timestamped_run_log);
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=template_preflight status=started templates={}",
            template_paths.len()
        ),
    );
    if let Err(err) = preflight_template_paths(template_paths, validate_pattern_only_yaml) {
        step_failed(
            1,
            TOTAL_STEPS,
            "template preflight",
            preflight_step_started,
            &timestamped_run_log,
            &err,
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!("step=template_preflight status=failed error={}", err),
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "end_utc={} campaign_success=false dry_run={} termination_cause=template_preflight",
                Utc::now().to_rfc3339(),
                args.dry_run
            ),
        );
        write_early_error_log(&timestamped_error_log, args.dry_run);
        return Err(err);
    }
    append_run_log_best_effort(
        &timestamped_run_log,
        "step=template_preflight status=completed",
    );
    step_succeeded(
        1,
        TOTAL_STEPS,
        "template preflight",
        preflight_step_started,
        &timestamped_run_log,
    );

    let readiness_step_started =
        step_started(2, TOTAL_STEPS, "local readiness", &timestamped_run_log);
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=local_readiness status=started framework={} target_circuit={} results_root={}",
            args.framework,
            target_circuit,
            results_root.display()
        ),
    );
    if let Err(err) = ensure_local_runtime_requirements(
        &args.framework,
        target_circuit,
        target_circuit_path,
        &args.main_component,
    ) {
        step_failed(
            2,
            TOTAL_STEPS,
            "local readiness",
            readiness_step_started,
            &timestamped_run_log,
            &err,
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!("step=local_readiness status=failed error={}", err),
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "end_utc={} campaign_success=false dry_run={} termination_cause=local_readiness",
                Utc::now().to_rfc3339(),
                args.dry_run
            ),
        );
        write_early_error_log(&timestamped_error_log, args.dry_run);
        return Err(err);
    }
    let (run_signal_dir, build_cache_dir) = match preflight_runtime_paths(&results_root) {
        Ok(paths) => paths,
        Err(err) => {
            step_failed(
                2,
                TOTAL_STEPS,
                "local readiness",
                readiness_step_started,
                &timestamped_run_log,
                &err,
            );
            append_run_log_best_effort(
                &timestamped_run_log,
                format!("step=local_readiness status=failed error={}", err),
            );
            append_run_log_best_effort(
                &timestamped_run_log,
                format!(
                    "end_utc={} campaign_success=false dry_run={} termination_cause=runtime_paths",
                    Utc::now().to_rfc3339(),
                    args.dry_run
                ),
            );
            write_early_error_log(&timestamped_error_log, args.dry_run);
            return Err(anyhow::anyhow!(
                "Output path readiness check failed for '{}': {:#}\nHint: ensure this directory and its subdirectories are writable.",
                results_root.display(),
                err
            ));
        }
    };
    append_run_log_best_effort(
        &timestamped_run_log,
        format!(
            "step=local_readiness status=completed run_signal_dir={} build_cache_dir={}",
            run_signal_dir.display(),
            build_cache_dir.display()
        ),
    );
    append_run_log_best_effort(
        &timestamped_run_log,
        "step=local_readiness checks=framework_tools,target_shape,runtime_paths",
    );
    step_succeeded(
        2,
        TOTAL_STEPS,
        "local readiness",
        readiness_step_started,
        &timestamped_run_log,
    );

    let bin_path = resolved_release_bin_path("zk-fuzzer");
    let build_step_started = step_started(3, TOTAL_STEPS, "build zk-fuzzer", &timestamped_run_log);
    if args.build {
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "step=build_zk_fuzzer status=started bin={}",
                bin_path.display()
            ),
        );
        let status = match Command::new("cargo")
            .args(["build", "--release", "--bin", "zk-fuzzer"])
            .status()
        {
            Ok(status) => status,
            Err(err) => {
                let err = anyhow::anyhow!("Failed to execute cargo build for zk-fuzzer: {}", err);
                step_failed(
                    3,
                    TOTAL_STEPS,
                    "build zk-fuzzer",
                    build_step_started,
                    &timestamped_run_log,
                    &err,
                );
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!(
                        "step=build_zk_fuzzer status=failed error=cargo_command_failed detail={}",
                        err
                    ),
                );
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!(
                        "end_utc={} campaign_success=false dry_run={} termination_cause=build_zk_fuzzer_command",
                        Utc::now().to_rfc3339(),
                        args.dry_run
                    ),
                );
                write_early_error_log(&timestamped_error_log, args.dry_run);
                return Err(err);
            }
        };
        if !status.success() {
            let err = anyhow::anyhow!("cargo build --release --bin zk-fuzzer failed");
            step_failed(
                3,
                TOTAL_STEPS,
                "build zk-fuzzer",
                build_step_started,
                &timestamped_run_log,
                &err,
            );
            append_run_log_best_effort(&timestamped_run_log, "step=build_zk_fuzzer status=failed");
            append_run_log_best_effort(
                &timestamped_run_log,
                format!(
                    "end_utc={} campaign_success=false dry_run={} termination_cause=build_zk_fuzzer",
                    Utc::now().to_rfc3339(),
                    args.dry_run
                ),
            );
            write_early_error_log(&timestamped_error_log, args.dry_run);
            return Err(err);
        }
        append_run_log_best_effort(
            &timestamped_run_log,
            "step=build_zk_fuzzer status=completed",
        );
        step_succeeded(
            3,
            TOTAL_STEPS,
            "build zk-fuzzer",
            build_step_started,
            &timestamped_run_log,
        );
    } else if !bin_path.exists() {
        let err = anyhow::anyhow!(
            "zk-fuzzer binary not found at '{}' and --build=false",
            bin_path.display()
        );
        step_failed(
            3,
            TOTAL_STEPS,
            "build zk-fuzzer",
            build_step_started,
            &timestamped_run_log,
            &err,
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "step=build_zk_fuzzer status=missing_binary path={}",
                bin_path.display()
            ),
        );
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "end_utc={} campaign_success=false dry_run={} termination_cause=missing_binary",
                Utc::now().to_rfc3339(),
                args.dry_run
            ),
        );
        write_early_error_log(&timestamped_error_log, args.dry_run);
        return Err(err);
    } else {
        append_run_log_best_effort(
            &timestamped_run_log,
            format!(
                "step=build_zk_fuzzer status=skipped_existing_binary path={}",
                bin_path.display()
            ),
        );
        step_skipped(
            3,
            TOTAL_STEPS,
            "build zk-fuzzer",
            "existing binary (--build=false)",
            &timestamped_run_log,
        );
    }

    let prepare_step_started = step_started(4, TOTAL_STEPS, "target prepare", &timestamped_run_log);
    if args.dry_run {
        append_run_log_best_effort(
            &timestamped_run_log,
            "step=prepare_target status=skipped reason=dry_run",
        );
        step_skipped(
            4,
            TOTAL_STEPS,
            "target prepare",
            "dry run",
            &timestamped_run_log,
        );
    } else if args.prepare_target {
        match prepare_target_for_framework(&args.framework, target_circuit) {
            Ok(prepared) if prepared => {
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!(
                        "step=prepare_target status=completed framework={} target_circuit={}",
                        args.framework, target_circuit
                    ),
                );
                step_succeeded(
                    4,
                    TOTAL_STEPS,
                    "target prepare",
                    prepare_step_started,
                    &timestamped_run_log,
                );
            }
            Ok(_) => {
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!(
                        "step=prepare_target status=skipped framework={}",
                        args.framework
                    ),
                );
                step_skipped(
                    4,
                    TOTAL_STEPS,
                    "target prepare",
                    "framework has no explicit prepare phase",
                    &timestamped_run_log,
                );
            }
            Err(err) => {
                step_failed(
                    4,
                    TOTAL_STEPS,
                    "target prepare",
                    prepare_step_started,
                    &timestamped_run_log,
                    &err,
                );
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!("step=prepare_target status=failed error={}", err),
                );
                append_run_log_best_effort(
                    &timestamped_run_log,
                    format!(
                        "end_utc={} campaign_success=false dry_run={} termination_cause=prepare_target",
                        Utc::now().to_rfc3339(),
                        args.dry_run
                    ),
                );
                write_early_error_log(&timestamped_error_log, args.dry_run);
                return Err(err);
            }
        }
    } else {
        append_run_log_best_effort(
            &timestamped_run_log,
            "step=prepare_target status=skipped reason=disabled_by_flag",
        );
        step_skipped(
            4,
            TOTAL_STEPS,
            "target prepare",
            "disabled by --prepare-target=false",
            &timestamped_run_log,
        );
    }

    let artifacts_root = results_root.join(".scan_run_artifacts");
    Ok(BootstrapState {
        results_root,
        timestamped_result_dir,
        timestamped_report_path,
        timestamped_error_log,
        timestamped_run_log,
        run_signal_dir,
        build_cache_dir,
        bin_path,
        artifacts_root,
    })
}
