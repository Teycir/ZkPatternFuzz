use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RunOutcomeDocContext<'a> {
    pub command: &'a str,
    pub run_id: &'a str,
    pub stage: &'a str,
    pub config_path: &'a str,
    pub campaign_name: &'a str,
    pub output_dir: &'a Path,
    pub started_utc: &'a DateTime<Utc>,
    pub timeout_seconds: Option<u64>,
}

pub(crate) fn add_run_window_fields(
    doc: &mut serde_json::Value,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
    timeout_semantics: &'static str,
) {
    let started_local = started_utc.with_timezone(&Local);
    let expected_end_utc = timeout_seconds
        .and_then(|s| match i64::try_from(s) {
            Ok(seconds) => Some(seconds),
            Err(err) => {
                tracing::warn!("Timeout seconds value '{}' exceeds i64: {}", s, err);
                None
            }
        })
        .map(|s| started_utc + ChronoDuration::seconds(s));
    let expected_end_local = expected_end_utc.map(|dt| dt.with_timezone(&Local));

    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "run_window".to_string(),
            serde_json::json!({
                "started_utc": started_utc.to_rfc3339(),
                "started_local": started_local.to_rfc3339(),
                "timeout_seconds": timeout_seconds,
                "timeout_semantics": timeout_semantics,
                "expected_latest_end_utc": expected_end_utc.map(|dt| dt.to_rfc3339()),
                "expected_latest_end_local": expected_end_local.map(|dt| dt.to_rfc3339()),
                "note": match timeout_semantics {
                    "wall_clock" => "For this command, --timeout is enforced as a total wall-clock budget for the run.",
                    _ => "",
                },
            }),
        );
    }
}

pub(crate) fn classify_run_reason_code(doc: &serde_json::Value) -> Option<&'static str> {
    let obj = doc.as_object()?;
    let status = obj
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let stage = obj
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let error_lc = obj
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reason_lc = obj
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if status == "completed_with_critical_findings" {
        return Some("critical_findings_detected");
    }
    if status == "completed" {
        return Some("completed");
    }
    if status == "failed_engagement_contract" {
        return Some("engagement_contract_failed");
    }
    if status == "stale_interrupted" {
        return Some("stale_interrupted");
    }
    if status == "running" {
        return None;
    }
    if error_lc.contains("permission denied") {
        return Some("filesystem_permission_denied");
    }
    if stage == "preflight_backend"
        && (error_lc.contains("backend required but not available")
            || error_lc.contains("not found in path")
            || error_lc.contains("snarkjs not found")
            || error_lc.contains("circom not found")
            || error_lc.contains("install circom"))
    {
        return Some("backend_tooling_missing");
    }
    if error_lc.contains("circom compilation failed") {
        return Some("circom_compilation_failed");
    }
    if error_lc.contains("key generation failed")
        || error_lc.contains("key setup failed")
        || error_lc.contains("proving key")
    {
        return Some("key_generation_failed");
    }
    if error_lc.contains("wall-clock timeout") || reason_lc.contains("wall-clock timeout") {
        return Some("wall_clock_timeout");
    }
    if stage == "acquire_output_lock" {
        return Some("output_dir_locked");
    }
    if stage == "preflight_backend" {
        return Some("backend_preflight_failed");
    }
    if stage == "preflight_invariants" {
        return Some("missing_invariants");
    }
    if stage == "preflight_readiness" {
        return Some("readiness_failed");
    }
    if stage == "parse_chains" && reason_lc.contains("requires chains") {
        return Some("missing_chains_definition");
    }
    if status == "failed" {
        return Some("runtime_error");
    }
    None
}

pub(crate) fn log_run_reason_code(doc: &serde_json::Value) {
    if doc
        .get("status")
        .and_then(|v| v.as_str())
        .map(|s| s == "running")
        .unwrap_or(false)
    {
        return;
    }
    let Some(code) = classify_run_reason_code(doc) else {
        return;
    };
    let status = doc
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let stage = doc
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    tracing::info!(
        "run_outcome_classified: reason_code={} status={} stage={}",
        code,
        status,
        stage
    );
}

pub(crate) fn running_run_doc_with_window(ctx: RunOutcomeDocContext<'_>) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "status": "running",
        "command": ctx.command,
        "run_id": ctx.run_id,
        "stage": ctx.stage,
        "pid": std::process::id(),
        "campaign_path": ctx.config_path,
        "campaign_name": ctx.campaign_name,
        "output_dir": ctx.output_dir.display().to_string(),
        "started_utc": ctx.started_utc.to_rfc3339(),
    });
    add_run_window_fields(
        &mut doc,
        ctx.started_utc.to_owned(),
        ctx.timeout_seconds,
        "wall_clock",
    );
    doc
}

pub(crate) fn completed_run_doc_with_window(
    status: &str,
    ctx: RunOutcomeDocContext<'_>,
) -> serde_json::Value {
    let ended_utc = Utc::now();
    let mut doc = serde_json::json!({
        "status": status,
        "command": ctx.command,
        "run_id": ctx.run_id,
        "stage": ctx.stage,
        "pid": std::process::id(),
        "campaign_path": ctx.config_path,
        "campaign_name": ctx.campaign_name,
        "output_dir": ctx.output_dir.display().to_string(),
        "started_utc": ctx.started_utc.to_rfc3339(),
        "ended_utc": ended_utc.to_rfc3339(),
        "duration_seconds": (ended_utc - ctx.started_utc.to_owned()).num_seconds().max(0),
    });
    add_run_window_fields(
        &mut doc,
        ctx.started_utc.to_owned(),
        ctx.timeout_seconds,
        "wall_clock",
    );
    doc
}

pub(crate) fn failed_run_doc_with_window(ctx: RunOutcomeDocContext<'_>) -> serde_json::Value {
    let ended_utc = Utc::now();
    let mut doc = serde_json::json!({
        "status": "failed",
        "command": ctx.command,
        "run_id": ctx.run_id,
        "stage": ctx.stage,
        "pid": std::process::id(),
        "campaign_path": ctx.config_path,
        "campaign_name": ctx.campaign_name,
        "output_dir": ctx.output_dir.display().to_string(),
        "started_utc": ctx.started_utc.to_rfc3339(),
        "ended_utc": ended_utc.to_rfc3339(),
        "duration_seconds": (ended_utc - ctx.started_utc.to_owned()).num_seconds().max(0),
    });
    add_run_window_fields(
        &mut doc,
        ctx.started_utc.to_owned(),
        ctx.timeout_seconds,
        "wall_clock",
    );
    doc
}
