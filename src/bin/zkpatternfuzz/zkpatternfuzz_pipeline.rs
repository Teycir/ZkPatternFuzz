use chrono::Utc;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use super::{
    append_run_log_best_effort, collect_observed_suffixes_for_roots,
    collect_template_outcome_reasons, is_error_reason, list_scan_run_roots, print_reason_summary,
    print_reason_tsv, proof_state_counts, reserve_batch_scan_run_root, run_template,
    scan_output_suffix, step_failed, step_started, step_succeeded, write_error_log,
    write_report_json, Args, BatchProgress, Family, ScanRunConfig, TemplateInfo,
};

pub(super) struct ExecuteStepOutcome {
    pub(super) gate2_ok: bool,
    pub(super) gate3_ok: bool,
}

pub(super) struct ExecuteStepInput<'a> {
    pub(super) args: &'a Args,
    pub(super) selected_with_family: &'a [(TemplateInfo, Family)],
    pub(super) expected_suffixes: &'a BTreeSet<String>,
    pub(super) expected_count: usize,
    pub(super) batch_started_at: Instant,
    pub(super) run_cfg_base: ScanRunConfig<'a>,
    pub(super) artifacts_root: &'a Path,
    pub(super) target_circuit: &'a str,
    pub(super) timestamped_report_path: &'a Path,
    pub(super) timestamped_error_log: &'a Path,
    pub(super) timestamped_run_log: &'a Path,
    pub(super) timestamped_result_dir: &'a Path,
    pub(super) results_root: &'a Path,
    pub(super) total_steps: usize,
}

pub(super) fn execute_templates_step(
    input: ExecuteStepInput<'_>,
) -> anyhow::Result<ExecuteStepOutcome> {
    let ExecuteStepInput {
        args,
        selected_with_family,
        expected_suffixes,
        expected_count,
        batch_started_at,
        run_cfg_base,
        artifacts_root,
        target_circuit,
        timestamped_report_path,
        timestamped_error_log,
        timestamped_run_log,
        timestamped_result_dir,
        results_root,
        total_steps,
    } = input;

    let execute_step_started =
        step_started(5, total_steps, "execute templates", timestamped_run_log);
    let baseline_roots = if args.dry_run {
        BTreeSet::new()
    } else {
        match list_scan_run_roots(artifacts_root) {
            Ok(roots) => roots,
            Err(err) => {
                step_failed(
                    5,
                    total_steps,
                    "execute templates",
                    execute_step_started,
                    timestamped_run_log,
                    &err,
                );
                return Err(err);
            }
        }
    };

    // One batch command -> one collision-safe scan_run root.
    let batch_run_root = if args.dry_run {
        None
    } else {
        match reserve_batch_scan_run_root(artifacts_root) {
            Ok(run_root) => Some(run_root),
            Err(err) => {
                step_failed(
                    5,
                    total_steps,
                    "execute templates",
                    execute_step_started,
                    timestamped_run_log,
                    &err,
                );
                return Err(err);
            }
        }
    };
    let run_cfg = ScanRunConfig {
        scan_run_root: batch_run_root.as_deref(),
        ..run_cfg_base
    };

    let jobs = args.jobs.max(1);
    println!(
        "Running {} templates in parallel (jobs={})",
        selected_with_family.len(),
        jobs
    );
    println!(
        "Batch progress indicator: {}",
        if args.no_batch_progress {
            "disabled"
        } else {
            "enabled"
        }
    );
    println!(
        "Execution mode: detect patterns, then immediately resolve proof status from evidence artifacts."
    );
    println!(
        "Per-template hard timeouts: detection={}s proof={}s stuck_step_warn={}s",
        run_cfg.stage_timeouts.detection_timeout_secs,
        run_cfg.stage_timeouts.proof_timeout_secs,
        run_cfg.stage_timeouts.stuck_step_warn_secs
    );
    append_run_log_best_effort(
        timestamped_run_log,
        format!(
            "step=execute_templates status=started templates={} jobs={} dry_run={} detection_timeout_secs={} proof_timeout_secs={} stuck_step_warn_secs={}",
            selected_with_family.len(),
            jobs,
            args.dry_run,
            run_cfg.stage_timeouts.detection_timeout_secs,
            run_cfg.stage_timeouts.proof_timeout_secs,
            run_cfg.stage_timeouts.stuck_step_warn_secs
        ),
    );
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .map_err(|err| anyhow::anyhow!("Failed to build rayon thread pool: {}", err));
    let pool = match pool {
        Ok(pool) => pool,
        Err(err) => {
            step_failed(
                5,
                total_steps,
                "execute templates",
                execute_step_started,
                timestamped_run_log,
                &err,
            );
            return Err(err);
        }
    };
    let progress = if args.no_batch_progress {
        None
    } else {
        Some(Arc::new(BatchProgress::new(selected_with_family.len())))
    };

    let outcomes = pool.install(|| {
        selected_with_family
            .par_iter()
            .map(|(template, family)| {
                let suffix = scan_output_suffix(template, *family);
                println!(
                    "[TEMPLATE START] {} family={} output_suffix={}",
                    template.file_name,
                    family.as_str(),
                    suffix
                );
                let ok = match run_template(
                    run_cfg,
                    template,
                    *family,
                    args.skip_validate,
                    suffix.as_str(),
                ) {
                    Ok(ok) => ok,
                    Err(err) => {
                        eprintln!("Template '{}' failed: {}", template.file_name, err);
                        false
                    }
                };
                println!(
                    "[TEMPLATE END] {} result={}",
                    template.file_name,
                    if ok { "ok" } else { "template_error" }
                );
                if let Some(progress) = progress.as_ref() {
                    println!("{}", progress.record(&template.file_name, ok));
                }
                ok
            })
            .collect::<Vec<_>>()
    });

    let executed = outcomes.len();
    let template_errors = outcomes.iter().filter(|ok| !**ok).count();
    let duration_secs = batch_started_at.elapsed().as_secs_f64().max(0.001);
    let avg_rate = executed as f64 / duration_secs;

    println!(
        "Batch complete. Templates executed: {}, template_errors: {}, duration: {:.1}s, avg_rate: {:.2}/s",
        executed, template_errors, duration_secs, avg_rate
    );
    let gate2_ok = executed == expected_count && template_errors == 0;
    println!(
        "Gate 2/3 (completion line): {}",
        if gate2_ok {
            format!("PASS (executed={}, template_errors=0)", executed)
        } else {
            format!(
                "FAIL (expected={}, executed={}, template_errors={})",
                expected_count, executed, template_errors
            )
        }
    );

    let gate3_ok = if args.dry_run {
        println!("Gate 3/3 (artifact reconciliation): SKIP (dry run)");
        true
    } else {
        let after_roots = list_scan_run_roots(artifacts_root)?;
        let new_roots: BTreeSet<String> =
            after_roots.difference(&baseline_roots).cloned().collect();
        let observed_suffixes = collect_observed_suffixes_for_roots(artifacts_root, &new_roots)?;
        let missing: Vec<String> = expected_suffixes
            .difference(&observed_suffixes)
            .cloned()
            .collect();
        if missing.is_empty() {
            println!(
                "Gate 3/3 (artifact reconciliation): PASS (new run roots={}, observed={})",
                new_roots.len(),
                observed_suffixes.len()
            );
            true
        } else {
            eprintln!(
                "Gate 3/3 (artifact reconciliation): FAIL (missing={})",
                missing.len()
            );
            eprintln!("Missing suffixes: {}", missing.join(", "));
            false
        }
    };

    let mut reasons = Vec::new();
    if !args.dry_run {
        reasons = collect_template_outcome_reasons(
            artifacts_root,
            batch_run_root.as_deref(),
            selected_with_family,
        );
        print_reason_summary(&reasons);
        if args.emit_reason_tsv {
            print_reason_tsv(&reasons);
        }
        let (
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
        ) = proof_state_counts(&reasons);
        println!(
            "Proof totals: proven_exploitable={}, proven_not_exploitable_within_bounds={}, proof_failed={}, proof_skipped_by_policy={}",
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns
        );
    }
    let detected_patterns_total = reasons
        .iter()
        .map(|reason| reason.detected_pattern_count)
        .sum::<usize>();
    if !args.dry_run {
        let (
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
        ) = proof_state_counts(&reasons);
        println!(
            "Final totals: detected_patterns={} proven_exploitable={} proven_not_exploitable_within_bounds={} proof_failed={} proof_skipped_by_policy={} template_errors={}",
            detected_patterns_total,
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
            template_errors
        );
    }

    append_run_log_best_effort(
        timestamped_run_log,
        format!(
            "step=execute_templates status=completed executed={} template_errors={} duration_secs={:.3} avg_rate={:.3}",
            executed, template_errors, duration_secs, avg_rate
        ),
    );
    if !args.dry_run {
        let (
            exploitable_patterns,
            not_exploitable_within_bounds_patterns,
            proof_failed_patterns,
            proof_skipped_by_policy_patterns,
        ) = proof_state_counts(&reasons);
        append_run_log_best_effort(
            timestamped_run_log,
            format!(
                "proof_totals proven_exploitable={} proven_not_exploitable_within_bounds={} proof_failed={} proof_skipped_by_policy={}",
                exploitable_patterns,
                not_exploitable_within_bounds_patterns,
                proof_failed_patterns,
                proof_skipped_by_policy_patterns
            ),
        );
        append_run_log_best_effort(
            timestamped_run_log,
            format!(
                "final_totals detected_patterns={} template_errors={}",
                detected_patterns_total, template_errors
            ),
        );
    }
    append_run_log_best_effort(
        timestamped_run_log,
        format!(
            "step=gate2 status={}",
            if gate2_ok { "pass" } else { "fail" }
        ),
    );
    append_run_log_best_effort(
        timestamped_run_log,
        format!(
            "step=gate3 status={}",
            if gate3_ok { "pass" } else { "fail" }
        ),
    );
    for reason in reasons.iter().filter(|reason| is_error_reason(reason)) {
        append_run_log_best_effort(
            timestamped_run_log,
            format!(
                "error template={} suffix={} reason_code={} status={} stage={} proof_status={} detected_pattern_count={}",
                reason.template_file,
                reason.suffix,
                reason.reason_code,
                reason.status.as_deref().unwrap_or("unknown"),
                reason.stage.as_deref().unwrap_or("unknown"),
                reason.proof_status.as_deref().unwrap_or("unknown"),
                reason.detected_pattern_count
            ),
        );
    }

    write_error_log(
        timestamped_error_log,
        &reasons,
        template_errors,
        gate2_ok,
        gate3_ok,
        args.dry_run,
    )?;

    let has_reason_errors = reasons.iter().any(is_error_reason);
    let campaign_success = !args.dry_run && gate2_ok && gate3_ok && !has_reason_errors;
    if !args.dry_run {
        write_report_json(
            args,
            timestamped_report_path,
            target_circuit,
            &reasons,
            expected_count,
            executed,
            template_errors,
            results_root,
            gate2_ok,
            gate3_ok,
            campaign_success,
            timestamped_result_dir,
            timestamped_run_log,
            timestamped_error_log,
            batch_run_root.as_deref(),
        )?;
        println!(
            "Wrote detected-patterns report JSON: {}",
            timestamped_report_path.display()
        );
    } else {
        println!("Skipped detected-patterns JSON for dry run.");
    }
    println!(
        "Wrote timestamped result bundle: {}",
        timestamped_result_dir.display()
    );
    append_run_log_best_effort(
        timestamped_run_log,
        format!(
            "end_utc={} campaign_success={} dry_run={} gate2_ok={} gate3_ok={} template_errors={}",
            Utc::now().to_rfc3339(),
            campaign_success,
            args.dry_run,
            gate2_ok,
            gate3_ok,
            template_errors
        ),
    );

    if gate2_ok && gate3_ok {
        step_succeeded(
            5,
            total_steps,
            "execute templates",
            execute_step_started,
            timestamped_run_log,
        );
    } else {
        let err = anyhow::anyhow!(
            "execution gates failed (gate2_ok={}, gate3_ok={}, template_errors={})",
            gate2_ok,
            gate3_ok,
            template_errors
        );
        step_failed(
            5,
            total_steps,
            "execute templates",
            execute_step_started,
            timestamped_run_log,
            &err,
        );
    }

    Ok(ExecuteStepOutcome { gate2_ok, gate3_ok })
}
