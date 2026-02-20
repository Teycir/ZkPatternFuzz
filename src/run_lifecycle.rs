use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use zk_fuzzer::config::{FuzzConfig, ReadinessReport};

use crate::engagement_artifacts::{
    best_effort_write_json, write_global_run_signal, write_run_artifacts,
};
use crate::engagement_root_dir;
use crate::output_lock::acquire_output_dir_lock;
use crate::preflight_backend::run_backend_preflight;
use crate::run_outcome_docs::{
    failed_run_doc_with_window, log_run_reason_code, running_run_doc_with_window,
    RunOutcomeDocContext,
};
use crate::{normalize_build_paths, set_run_log_context_for_campaign};

fn run_doc_context<'a>(
    command: &'a str,
    run_id: &'a str,
    stage: &'a str,
    config_path: &'a str,
    campaign_name: &'a str,
    output_dir: &'a Path,
    started_utc: &'a DateTime<Utc>,
    timeout_seconds: Option<u64>,
) -> RunOutcomeDocContext<'a> {
    RunOutcomeDocContext {
        command,
        run_id,
        stage,
        config_path,
        campaign_name,
        output_dir,
        started_utc,
        timeout_seconds,
    }
}

fn readiness_report_to_json(readiness: &ReadinessReport) -> serde_json::Value {
    let warnings = readiness
        .warnings
        .iter()
        .map(|w| {
            serde_json::json!({
                "level": w.level.to_string(),
                "category": w.category,
                "message": w.message,
                "fix_hint": w.fix_hint,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "score": readiness.score,
        "ready_for_evidence": readiness.ready_for_evidence,
        "warnings": warnings,
    })
}

pub(crate) fn seed_running_run_artifact(
    output_dir: &Path,
    command: &str,
    run_id: &str,
    stage: &str,
    config_path: &str,
    campaign_name: &str,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
    options: serde_json::Value,
) {
    let mut doc = running_run_doc_with_window(run_doc_context(
        command,
        run_id,
        stage,
        config_path,
        campaign_name,
        output_dir,
        &started_utc,
        timeout_seconds,
    ));
    doc["options"] = options;
    write_run_artifacts(output_dir, run_id, &doc);
}

pub(crate) fn write_failed_mode_run_artifact_with_error(
    output_dir: &Path,
    command: &str,
    run_id: &str,
    stage: &str,
    config_path: &str,
    campaign_name: &str,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
    error: String,
) {
    let mut doc = failed_run_doc_with_window(run_doc_context(
        command,
        run_id,
        stage,
        config_path,
        campaign_name,
        output_dir,
        &started_utc,
        timeout_seconds,
    ));
    doc["error"] = serde_json::Value::String(error);
    write_run_artifacts(output_dir, run_id, &doc);
}

pub(crate) fn write_failed_mode_run_artifact_with_reason(
    output_dir: &Path,
    command: &str,
    run_id: &str,
    stage: &str,
    config_path: &str,
    campaign_name: &str,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
    reason: String,
    readiness: Option<serde_json::Value>,
) {
    let mut doc = failed_run_doc_with_window(run_doc_context(
        command,
        run_id,
        stage,
        config_path,
        campaign_name,
        output_dir,
        &started_utc,
        timeout_seconds,
    ));
    doc["reason"] = serde_json::Value::String(reason);
    if let Some(readiness) = readiness {
        doc["readiness"] = readiness;
    }
    write_run_artifacts(output_dir, run_id, &doc);
}

pub(crate) fn require_evidence_readiness_or_emit_failure(
    dry_run: bool,
    output_dir: &Path,
    command: &str,
    run_id: &str,
    stage: &str,
    config_path: &str,
    campaign_name: &str,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
    readiness: &ReadinessReport,
    failure_reason: &str,
) -> anyhow::Result<()> {
    if readiness.ready_for_evidence {
        return Ok(());
    }

    if !dry_run {
        write_failed_mode_run_artifact_with_reason(
            output_dir,
            command,
            run_id,
            stage,
            config_path,
            campaign_name,
            started_utc,
            timeout_seconds,
            failure_reason.to_string(),
            Some(readiness_report_to_json(readiness)),
        );
    }

    anyhow::bail!("{}", failure_reason);
}

pub(crate) fn run_backend_preflight_or_emit_failure(
    dry_run: bool,
    config: &FuzzConfig,
    output_dir: &Path,
    command: &str,
    run_id: &str,
    stage: &str,
    config_path: &str,
    campaign_name: &str,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
) -> anyhow::Result<()> {
    if dry_run {
        return Ok(());
    }

    if let Err(err) = run_backend_preflight(config) {
        write_failed_mode_run_artifact_with_error(
            output_dir,
            command,
            run_id,
            stage,
            config_path,
            campaign_name,
            started_utc,
            timeout_seconds,
            format!("{:#}", err),
        );
        return Err(err);
    }

    Ok(())
}

pub(crate) fn acquire_output_lock_or_write_failure(
    dry_run: bool,
    output_dir: &Path,
    command: &str,
    run_id: &str,
    stage: &str,
    config_path: &str,
    campaign_name: &str,
    started_utc: &DateTime<Utc>,
) -> anyhow::Result<Option<zk_fuzzer::util::file_lock::FileLock>> {
    if dry_run {
        return Ok(None);
    }

    match acquire_output_dir_lock(output_dir) {
        Ok(lock) => Ok(Some(lock)),
        Err(err) => {
            let err_text = format!("{:#}", err);
            let ended_utc = Utc::now();
            let doc = serde_json::json!({
                "status": "failed",
                "command": command,
                "run_id": run_id,
                "stage": stage,
                "pid": std::process::id(),
                "campaign_path": config_path,
                "campaign_name": campaign_name,
                "output_dir": output_dir.display().to_string(),
                "started_utc": started_utc.to_rfc3339(),
                "ended_utc": ended_utc.to_rfc3339(),
                "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                "error": err_text.clone(),
                "hint": "Output directory is already locked by another process. Choose a different reporting.output_dir or wait for the other run to finish.",
            });
            write_failed_run_artifact(run_id, &doc);
            Err(anyhow::anyhow!(
                "Output directory is already in use (locked): {}. Error: {}",
                output_dir.display(),
                err_text
            ))
        }
    }
}

pub(crate) fn initialize_campaign_run_lifecycle(
    dry_run: bool,
    config: &mut FuzzConfig,
    command: &str,
    run_id: &str,
    config_path: &str,
    campaign_name: &str,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
    options_doc: serde_json::Value,
) -> anyhow::Result<(PathBuf, Option<zk_fuzzer::util::file_lock::FileLock>)> {
    // Prevent multi-process collisions on the same output dir.
    // Skip locking/writes in --dry-run since no files are written.
    let stage = "acquire_output_lock";
    let output_dir = config.reporting.output_dir.clone();
    let output_lock = acquire_output_lock_or_write_failure(
        dry_run,
        &output_dir,
        command,
        run_id,
        stage,
        config_path,
        campaign_name,
        &started_utc,
    )?;

    if !dry_run {
        // If a previous run died without updating run_outcome.json, mark it as stale so it does
        // not look like "still running forever".
        mark_stale_previous_run_if_any(&output_dir, std::process::id());

        set_run_log_context_for_campaign(
            dry_run,
            run_id,
            command,
            config_path,
            Some(campaign_name),
            Some(&output_dir),
            &started_utc,
        );

        // Seed a persistent status file early so interrupted runs still leave artifacts.
        seed_running_run_artifact(
            &output_dir,
            command,
            run_id,
            stage,
            config_path,
            campaign_name,
            started_utc,
            timeout_seconds,
            options_doc,
        );
    }

    // Ensure build artifacts never land inside the engagement report folder.
    normalize_build_paths(config, run_id);

    Ok((output_dir, output_lock))
}

pub(crate) fn write_failed_run_artifact(run_id: &str, value: &serde_json::Value) {
    log_run_reason_code(value);

    // Keep failure artifacts within the engagement folder to avoid scattering files.
    let report_dir = engagement_root_dir(run_id);
    let failed_dir = report_dir.join("_failed_runs");
    best_effort_write_json(&failed_dir.join(format!("{}.json", run_id)), value);
    write_global_run_signal(run_id, value);
}

pub(crate) struct FailedRunArtifactErrorContext<'a> {
    pub run_id: &'a str,
    pub command: &'a str,
    pub stage: &'a str,
    pub config_path: &'a str,
    pub started_utc: &'a DateTime<Utc>,
    pub ended_utc: &'a DateTime<Utc>,
    pub error: String,
    pub output_dir: Option<&'a Path>,
}

pub(crate) fn write_failed_run_artifact_with_error(ctx: FailedRunArtifactErrorContext<'_>) {
    let mut doc = serde_json::json!({
        "status": "failed",
        "command": ctx.command,
        "run_id": ctx.run_id,
        "stage": ctx.stage,
        "pid": std::process::id(),
        "campaign_path": ctx.config_path,
        "started_utc": ctx.started_utc.to_rfc3339(),
        "ended_utc": ctx.ended_utc.to_rfc3339(),
        "duration_seconds": (*ctx.ended_utc - *ctx.started_utc).num_seconds().max(0),
        "error": ctx.error,
    });
    if let Some(path) = ctx.output_dir {
        doc["output_dir"] = serde_json::Value::String(path.display().to_string());
    }
    write_failed_run_artifact(ctx.run_id, &doc);
}

fn pid_is_alive(pid: u32) -> Option<bool> {
    if pid == 0 {
        return Some(false);
    }
    #[cfg(unix)]
    {
        Some(std::path::Path::new(&format!("/proc/{}", pid)).exists())
    }
    #[cfg(not(unix))]
    {
        let _pid = pid;
        None
    }
}

pub(crate) fn mark_stale_previous_run_if_any(output_dir: &Path, current_pid: u32) {
    let path = output_dir.join("run_outcome.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    "Failed to read prior run outcome '{}': {}",
                    path.display(),
                    err
                );
            }
            return;
        }
    };
    let mut doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                "Invalid run outcome JSON while checking stale run '{}': {}",
                path.display(),
                err
            );
            return;
        }
    };

    let status = match doc.get("status").and_then(|v| v.as_str()) {
        Some(status) => status,
        None => {
            tracing::warn!(
                "Missing status in run outcome JSON while checking stale run '{}'",
                path.display()
            );
            return;
        }
    };
    if status != "running" {
        return;
    }

    let prev_pid = match doc.get("pid").and_then(|v| v.as_u64()) {
        Some(pid) if pid > 0 => pid as u32,
        Some(_) => return,
        None => {
            tracing::warn!(
                "Missing pid in run outcome JSON while checking stale run '{}'",
                path.display()
            );
            return;
        }
    };
    if prev_pid == current_pid {
        return;
    }
    match pid_is_alive(prev_pid) {
        Some(true) => return,
        Some(false) => {}
        None => {
            tracing::warn!(
                "Skipping stale-run detection for prior PID {}: process liveness checks are not supported on this platform",
                prev_pid
            );
            return;
        }
    }
    let prev_run_id = match doc.get("run_id").and_then(|v| v.as_str()) {
        Some(run_id) => run_id.to_string(),
        None => {
            tracing::warn!(
                "Missing run_id in run outcome JSON while checking stale run '{}'",
                path.display()
            );
            return;
        }
    };

    let ended_utc = Utc::now();
    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "status".to_string(),
            serde_json::Value::String("stale_interrupted".to_string()),
        );
        obj.insert(
            "stage".to_string(),
            serde_json::Value::String("detected_stale_run".to_string()),
        );
        obj.insert(
            "ended_utc".to_string(),
            serde_json::Value::String(ended_utc.to_rfc3339()),
        );
        obj.insert(
            "reason".to_string(),
            serde_json::Value::String(
                "Previous run_outcome.json said status=running but its PID is no longer alive. The run likely died via SIGKILL/OOM or external termination before it could write completion artifacts."
                    .to_string(),
            ),
        );
        obj.insert(
            "previous_pid".to_string(),
            serde_json::Value::Number(serde_json::Number::from(prev_pid)),
        );
        obj.insert(
            "current_pid".to_string(),
            serde_json::Value::Number(serde_json::Number::from(current_pid)),
        );
    }

    // Preserve an explicit stale marker in the output dir.
    best_effort_write_json(&output_dir.join("stale_run.json"), &doc);

    // Also emit it into the engagement report/log stream.
    write_global_run_signal(&prev_run_id, &doc);
}
