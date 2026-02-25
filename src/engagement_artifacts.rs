use chrono::Utc;
use std::path::{Path, PathBuf};

use super::run_outcome_docs::{log_run_reason_code, standardize_run_outcome_doc};
use super::{engagement_root_dir, run_signal_dir};

pub(crate) fn best_effort_write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "Failed to create parent directory for '{}': {}",
                path.display(),
                err
            );
            return;
        }
    }
    let data = match serde_json::to_string_pretty(value) {
        Ok(data) => data,
        Err(err) => {
            tracing::warn!("Failed to serialize JSON for '{}': {}", path.display(), err);
            return;
        }
    };
    if let Err(err) = zk_fuzzer::util::write_file_atomic(path, data.as_bytes()) {
        tracing::warn!("Failed to write JSON '{}': {}", path.display(), err);
    }
}

pub(crate) fn best_effort_append_jsonl(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "Failed to create parent directory for '{}': {}",
                path.display(),
                err
            );
            return;
        }
    }
    let mut line = match serde_json::to_string(value) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(
                "Failed to serialize JSONL for '{}': {}",
                path.display(),
                err
            );
            return;
        }
    };
    line.push('\n');
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(mut file) => {
            use std::io::Write as _;
            if let Err(err) = file.write_all(line.as_bytes()) {
                tracing::warn!("Failed to append JSONL '{}': {}", path.display(), err);
            }
        }
        Err(err) => {
            tracing::warn!("Failed to open JSONL '{}': {}", path.display(), err);
        }
    }
}

pub(crate) fn mode_folder_from_command(command: &str) -> &'static str {
    match command {
        "scan" => "scan",
        "chains" => "chains",
        _ => "misc",
    }
}

pub(crate) fn ensure_engagement_layout(report_dir: &Path) {
    for dir in [
        report_dir.to_path_buf(),
        report_dir.join("log"),
        report_dir.join("scan"),
        report_dir.join("chains"),
        report_dir.join("misc"),
    ] {
        if let Err(err) = std::fs::create_dir_all(&dir) {
            tracing::warn!(
                "Failed to create engagement directory '{}': {}",
                dir.display(),
                err
            );
        }
    }
}

pub(crate) fn get_command_from_doc(value: &serde_json::Value) -> String {
    if let Some(command) = value.get("command").and_then(|v| v.as_str()) {
        return command.to_string();
    }
    if let Some(command) = value
        .get("context")
        .and_then(|ctx| ctx.get("command"))
        .and_then(|v| v.as_str())
    {
        return command.to_string();
    }
    tracing::warn!("Run document missing 'command' field; routing as misc");
    "unknown".to_string()
}

pub(crate) fn mirror_mode_output_snapshot(
    output_dir: &Path,
    run_id: &str,
    value: &serde_json::Value,
) {
    let command = get_command_from_doc(value);
    let mode = mode_folder_from_command(&command);
    let report_dir = engagement_root_dir(run_id);
    let mode_dir = report_dir.join(mode);
    if let Err(err) = std::fs::create_dir_all(&mode_dir) {
        tracing::warn!(
            "Failed to create mode output directory '{}': {}",
            mode_dir.display(),
            err
        );
        return;
    }

    let files = [
        "report.json",
        "report.md",
        "findings.json",
        "progress.json",
        "chain_report.json",
        "chain_report.md",
        "run_outcome.json",
    ];
    for name in files {
        let src = output_dir.join(name);
        if !src.is_file() {
            continue;
        }
        let data = match std::fs::read(&src) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!(
                    "Failed to read output snapshot file '{}': {}",
                    src.display(),
                    err
                );
                continue;
            }
        };
        let dst = mode_dir.join(name);
        if let Err(err) = zk_fuzzer::util::write_file_atomic(&dst, &data) {
            tracing::warn!(
                "Failed to mirror output snapshot '{}' -> '{}': {}",
                src.display(),
                dst.display(),
                err
            );
        }
    }

    let extra_files = [
        ("evidence/summary.md", "evidence_summary.md"),
        ("evidence/summary.json", "evidence_summary.json"),
    ];
    for (src_rel, dst_name) in extra_files {
        let src = output_dir.join(src_rel);
        if !src.is_file() {
            continue;
        }
        let data = match std::fs::read(&src) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!("Failed to read extra snapshot '{}': {}", src.display(), err);
                continue;
            }
        };
        let dst = mode_dir.join(dst_name);
        if let Err(err) = zk_fuzzer::util::write_file_atomic(&dst, &data) {
            tracing::warn!(
                "Failed to mirror extra snapshot '{}' -> '{}': {}",
                src.display(),
                dst.display(),
                err
            );
        }
    }
}

pub(crate) fn update_engagement_summary(report_dir: &Path, value: &serde_json::Value) {
    let value = standardize_run_outcome_doc(value);
    let now = Utc::now().to_rfc3339();
    let command = get_command_from_doc(&value);
    let mode = mode_folder_from_command(&command).to_string();

    let summary_path = report_dir.join("summary.json");
    let mut summary: serde_json::Value = match std::fs::read_to_string(&summary_path) {
        Ok(raw) => match serde_json::from_str(&raw) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!(
                    "Invalid existing summary JSON '{}': {}; recreating",
                    summary_path.display(),
                    err
                );
                serde_json::json!({
                    "updated_utc": now,
                    "modes": {},
                })
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => serde_json::json!({
            "updated_utc": now,
            "modes": {},
        }),
        Err(err) => {
            tracing::warn!(
                "Failed to read existing summary '{}': {}; recreating",
                summary_path.display(),
                err
            );
            serde_json::json!({
                "updated_utc": now,
                "modes": {},
            })
        }
    };

    if let Some(obj) = summary.as_object_mut() {
        obj.insert(
            "updated_utc".to_string(),
            serde_json::Value::String(now.clone()),
        );
        obj.insert(
            "report_dir".to_string(),
            serde_json::Value::String(report_dir.display().to_string()),
        );
        let modes = obj
            .entry("modes".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if let Some(modes_obj) = modes.as_object_mut() {
            modes_obj.insert(mode.clone(), value.clone());
        }
    }

    recompute_summary_totals(&mut summary);
    best_effort_write_json(&summary_path, &summary);

    // Markdown summary (human-friendly).
    let mut md = String::new();
    md.push_str("# ZkFuzz Engagement Summary\n\n");
    md.push_str(&format!("Updated (UTC): `{}`\n\n", now));

    if let Some(modes) = summary.get("modes").and_then(|m| m.as_object()) {
        let sections: [(&str, &[&str]); 3] = [
            ("scan", &["scan"]),
            ("chains", &["chains"]),
            ("misc", &["misc"]),
        ];
        for (section_name, aliases) in sections {
            let v = aliases.iter().find_map(|key| modes.get(*key));
            md.push_str(&format!("## {}\n\n", section_name));
            if let Some(v) = v {
                let status = v
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                let run_id = v
                    .get("run_id")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                let campaign = v
                    .get("campaign_name")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                let started = v
                    .get("started_utc")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                let ended: &str = v
                    .get("ended_utc")
                    .and_then(|s| s.as_str())
                    .unwrap_or_default();
                md.push_str(&format!("- Status: `{}`\n", status));
                if let Some(status_family) = v.get("status_family").and_then(|s| s.as_str()) {
                    md.push_str(&format!("- Status family: `{}`\n", status_family));
                }
                if let Some(reason_code) = v.get("reason_code").and_then(|s| s.as_str()) {
                    md.push_str(&format!("- Reason code: `{}`\n", reason_code));
                }
                md.push_str(&format!("- Run ID: `{}`\n", run_id));
                md.push_str(&format!("- Campaign: `{}`\n", campaign));
                md.push_str(&format!("- Started (UTC): `{}`\n", started));
                if !ended.is_empty() {
                    md.push_str(&format!("- Ended (UTC): `{}`\n", ended));
                }
                if let Some(qualification) = v.get("discovery_qualification") {
                    if let Some(state) = qualification
                        .get("discovery_state")
                        .and_then(|state| state.as_str())
                    {
                        md.push_str(&format!("- Discovery state: `{}`\n", state));
                    }
                    if let Some(proof) = qualification
                        .get("proof_status")
                        .and_then(|status| status.as_str())
                    {
                        md.push_str(&format!("- Proof status: `{}`\n", proof));
                    }
                    if let Some(priority) = qualification
                        .get("analysis_priority")
                        .and_then(|priority| priority.as_str())
                    {
                        md.push_str(&format!("- Analysis priority: `{}`\n", priority));
                    }
                    if let Some(next_step) = qualification
                        .get("next_step")
                        .and_then(|step| step.as_str())
                    {
                        md.push_str(&format!("- Next step: `{}`\n", next_step));
                    }
                }

                if let Some(window) = v.get("run_window") {
                    if let Some(exp) = window
                        .get("expected_latest_end_utc")
                        .and_then(|s| s.as_str())
                    {
                        md.push_str(&format!("- Expected latest end (UTC): `{}`\n", exp));
                    }
                    if let Some(sem) = window.get("timeout_semantics").and_then(|s| s.as_str()) {
                        md.push_str(&format!("- Timeout semantics: `{}`\n", sem));
                    }
                }

                if let Some(metrics) = v.get("metrics") {
                    if let Some(total) = metrics.get("findings_total").and_then(|n| n.as_u64()) {
                        md.push_str(&format!("- Findings: `{}`\n", total));
                    } else if let Some(total) =
                        metrics.get("chain_findings_total").and_then(|n| n.as_u64())
                    {
                        md.push_str(&format!("- Findings: `{}`\n", total));
                    }
                    if let Some(crit) = metrics.get("critical_findings").and_then(|b| b.as_bool()) {
                        md.push_str(&format!("- Critical: `{}`\n", crit));
                    }
                }
            } else {
                md.push_str("- Not run in this engagement yet.\n");
            }
            md.push('\n');
        }
    }

    let md_path = report_dir.join("summary.md");
    if let Some(parent) = md_path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "Failed to create summary directory '{}': {}",
                parent.display(),
                err
            );
            return;
        }
    }
    if let Err(err) = std::fs::write(&md_path, md) {
        tracing::warn!(
            "Failed to write engagement summary markdown '{}': {}",
            md_path.display(),
            err
        );
    }
}

fn recompute_summary_totals(summary: &mut serde_json::Value) {
    let Some(modes) = summary.get("modes").and_then(|m| m.as_object()) else {
        return;
    };
    let modes_len = modes.len();

    let mut running = 0u64;
    let mut completed = 0u64;
    let mut failed = 0u64;
    let mut unknown = 0u64;
    let mut pending_proof = 0u64;
    let mut candidate_vulnerabilities = 0u64;
    let mut critical_modes = 0u64;

    for mode_doc in modes.values() {
        let status_family = mode_doc
            .get("status_family")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                match mode_doc
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                {
                    "running" => "running",
                    "completed" | "completed_with_critical_findings" => "completed",
                    "failed" | "failed_engagement_contract" | "stale_interrupted" | "panic" => {
                        "failed"
                    }
                    _ => "unknown",
                }
            });
        match status_family {
            "running" => running += 1,
            "completed" => completed += 1,
            "failed" => failed += 1,
            _ => unknown += 1,
        }

        if mode_doc
            .get("discovery_qualification")
            .and_then(|q| q.get("proof_status"))
            .and_then(|v| v.as_str())
            .map(|v| v == "pending_proof")
            .unwrap_or(false)
        {
            pending_proof += 1;
        }

        if mode_doc
            .get("discovery_qualification")
            .and_then(|q| q.get("discovery_state"))
            .and_then(|v| v.as_str())
            .map(|v| v == "candidate_vulnerability")
            .unwrap_or(false)
        {
            candidate_vulnerabilities += 1;
        }

        if mode_doc
            .get("metrics")
            .and_then(|metrics| metrics.get("critical_findings"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || mode_doc
                .get("status")
                .and_then(|v| v.as_str())
                .map(|status| status == "completed_with_critical_findings")
                .unwrap_or(false)
        {
            critical_modes += 1;
        }
    }

    if let Some(obj) = summary.as_object_mut() {
        obj.insert(
            "totals".to_string(),
            serde_json::json!({
                "modes_total": modes_len,
                "running": running,
                "completed": completed,
                "failed": failed,
                "unknown": unknown,
                "pending_proof": pending_proof,
                "candidate_vulnerabilities": candidate_vulnerabilities,
                "critical_modes": critical_modes,
            }),
        );
    }
}

pub(crate) fn scan_public_root_from_output_dir(output_dir: &Path) -> Option<PathBuf> {
    let run_root_dir = output_dir.parent()?;
    let artifacts_dir = run_root_dir.parent()?;
    if artifacts_dir.file_name()?.to_str()? != ".scan_run_artifacts" {
        return None;
    }
    Some(run_root_dir.join("scan"))
}

pub(crate) fn write_scan_timestamp_totals_if_applicable(
    output_dir: &Path,
    value: &serde_json::Value,
) {
    let Some(scan_root) = scan_public_root_from_output_dir(output_dir) else {
        return;
    };
    let total_log_path = scan_root.join("total_results.jsonl");
    best_effort_append_jsonl(&total_log_path, value);
}

pub(crate) fn write_global_run_signal(run_id: &str, value: &serde_json::Value) {
    let value = standardize_run_outcome_doc(value);
    write_global_run_signal_standardized(run_id, &value);
}

fn write_global_run_signal_standardized(run_id: &str, value: &serde_json::Value) {
    let base = run_signal_dir();
    let report_dir = engagement_root_dir(run_id);
    ensure_engagement_layout(&report_dir);
    let command = get_command_from_doc(value);
    let mode = mode_folder_from_command(&command);
    let mode_dir = report_dir.join(mode);

    // Log/event stream (engagement-wide). Each line includes run_id, so per-run
    // splitting is redundant and creates unnecessary files.
    let log_dir = report_dir.join("log");
    best_effort_append_jsonl(&log_dir.join("events.jsonl"), value);
    // SCPF-style incremental feed: one engagement-wide file plus one per mode.
    best_effort_append_jsonl(&report_dir.join("incremental_results.jsonl"), value);
    best_effort_append_jsonl(&mode_dir.join("events.jsonl"), value);
    best_effort_append_jsonl(&mode_dir.join("incremental_results.jsonl"), value);

    // Latest pointers.
    best_effort_write_json(&report_dir.join("latest.json"), value);
    best_effort_write_json(&mode_dir.join("latest.json"), value);
    best_effort_write_json(&base.join("latest.json"), value);

    update_engagement_summary(&report_dir, value);
}

pub(crate) fn write_run_artifacts(output_dir: &Path, run_id: &str, value: &serde_json::Value) {
    let value = standardize_run_outcome_doc(value);
    log_run_reason_code(&value);

    // Minimal artifacts contract: avoid redundant run history + mirrored reports.
    // - `run_outcome.json` is the single authoritative per-mode status file (also used for resume).
    // - engagement-wide `log/events.jsonl` is the run history (includes run_id).
    best_effort_write_json(&output_dir.join("run_outcome.json"), &value);
    write_scan_timestamp_totals_if_applicable(output_dir, &value);
    mirror_mode_output_snapshot(output_dir, run_id, &value);
    write_global_run_signal_standardized(run_id, &value);
}
