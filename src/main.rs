use anyhow::Context;
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use regex::RegexBuilder;
use serde::Deserialize;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};
mod toolchain_bootstrap;
use zk_fuzzer::config::{apply_profile, FuzzConfig, ProfileName, ReadinessReport};
use zk_fuzzer::fuzzer::ZkFuzzer;
use zk_fuzzer::Framework;

#[derive(Debug, Clone)]
struct RunLogContext {
    run_id: String,
    command: String,
    campaign_path: Option<String>,
    campaign_name: Option<String>,
    output_dir: Option<PathBuf>,
    started_utc: String,
}

#[derive(Debug, Clone)]
struct ScanTarget {
    framework: Framework,
    circuit_path: PathBuf,
    main_component: String,
}

static RUN_LOG_CONTEXT: OnceLock<Mutex<Option<RunLogContext>>> = OnceLock::new();
static PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();
static SIGNAL_WATCHER_STARTED: OnceLock<()> = OnceLock::new();
static DYNAMIC_LOG_FILE: OnceLock<Mutex<Option<(PathBuf, std::fs::File)>>> = OnceLock::new();

struct DynamicLogWriter;

struct DynamicTeeWriter;

impl DynamicTeeWriter {
    fn desired_log_path() -> PathBuf {
        if let Some(ctx) = get_run_log_context() {
            // Engagement-local session log. This makes each `report_<timestamp>/` folder
            // self-contained and easy to manage when you have many engagements.
            engagement_root_dir(&ctx.run_id).join("session.log")
        } else {
            run_signal_dir().join("session.log")
        }
    }

    fn with_log_file<F, R>(f: F) -> io::Result<R>
    where
        F: FnOnce(&mut std::fs::File) -> io::Result<R>,
    {
        let path = Self::desired_log_path();
        let slot = DYNAMIC_LOG_FILE.get_or_init(|| Mutex::new(None));
        let mut guard = slot.lock().map_err(|_| io::ErrorKind::Other)?;

        let need_reopen = match guard.as_ref() {
            Some((p, _)) => *p != path,
            None => true,
        };

        if need_reopen {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    io::Error::other(format!(
                        "Failed to create log directory '{}': {err}",
                        parent.display()
                    ))
                })?;
            }
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                Ok(file) => {
                    *guard = Some((path.clone(), file));
                }
                Err(err) => {
                    // Fail opening file logger for this write attempt.
                    return Err(err);
                }
            }
        }

        if let Some((_, ref mut file)) = guard.as_mut() {
            f(file)
        } else {
            Err(io::Error::other("log file unavailable"))
        }
    }

    /// Best-effort synchronization hook used when run-log context changes.
    ///
    /// This pre-opens/rebinds the file target immediately so most subsequent log lines
    /// are routed to the new engagement log path without waiting for the next write call.
    fn sync_to_current_context() {
        if let Err(err) = Self::with_log_file(|_| Ok(())) {
            eprintln!(
                "[zk-fuzzer] WARN: failed to sync session log path to current context: {}",
                err
            );
        }
    }
}

impl io::Write for DynamicTeeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Console output (keep behavior similar to default fmt subscriber).
        if let Err(err) = io::stderr().write_all(buf) {
            eprintln!("[zk-fuzzer] WARN: failed writing to stderr: {}", err);
        }

        // Best-effort file output.
        if let Err(err) = Self::with_log_file(|file| file.write_all(buf).map(|_| ())) {
            eprintln!("[zk-fuzzer] WARN: failed writing session log: {}", err);
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Err(err) = io::stderr().flush() {
            eprintln!("[zk-fuzzer] WARN: failed flushing stderr: {}", err);
        }
        if let Err(err) = Self::with_log_file(|file| file.flush()) {
            eprintln!("[zk-fuzzer] WARN: failed flushing session log: {}", err);
        }
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DynamicLogWriter {
    type Writer = DynamicTeeWriter;

    fn make_writer(&'a self) -> Self::Writer {
        DynamicTeeWriter
    }
}

fn set_run_log_context(ctx: Option<RunLogContext>) {
    let slot = RUN_LOG_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut should_sync_file = false;
    match slot.lock() {
        Ok(mut guard) => {
            *guard = ctx;
            should_sync_file = true;
        }
        Err(err) => eprintln!("[zk-fuzzer] WARN: failed to lock run log context: {}", err),
    }
    if should_sync_file {
        DynamicTeeWriter::sync_to_current_context();
    }
}

fn get_run_log_context() -> Option<RunLogContext> {
    let slot = RUN_LOG_CONTEXT.get_or_init(|| Mutex::new(None));
    match slot.lock() {
        Ok(guard) => guard.clone(),
        Err(err) => {
            eprintln!("[zk-fuzzer] WARN: failed to lock run log context: {}", err);
            None
        }
    }
}

struct RunLogContextGuard;

impl RunLogContextGuard {
    fn new() -> Self {
        Self
    }
}

impl Drop for RunLogContextGuard {
    fn drop(&mut self) {
        set_run_log_context(None);
    }
}

fn set_run_log_context_for_campaign(
    dry_run: bool,
    run_id: &str,
    command: &str,
    config_path: &str,
    campaign_name: Option<&str>,
    output_dir: Option<&Path>,
    started_utc: &DateTime<Utc>,
) {
    if dry_run {
        return;
    }

    set_run_log_context(Some(RunLogContext {
        run_id: run_id.to_string(),
        command: command.to_string(),
        campaign_path: Some(config_path.to_string()),
        campaign_name: campaign_name.map(|name| name.to_string()),
        output_dir: output_dir.map(Path::to_path_buf),
        started_utc: started_utc.to_rfc3339(),
    }));
}

fn sanitize_slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed
    }
}

fn derive_campaign_slug(campaign_path: &str) -> String {
    let slug = Path::new(campaign_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(sanitize_slug);
    match slug {
        Some(value) => value,
        None => "campaign".to_string(),
    }
}

fn make_run_id(command: &str, campaign_path: Option<&str>) -> String {
    let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let pid = std::process::id();
    let campaign = match campaign_path {
        Some(path) => derive_campaign_slug(path),
        None => "no_campaign".to_string(),
    };
    format!("{}_{}_{}_pid{}", ts, sanitize_slug(command), campaign, pid)
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

fn best_effort_write_json(path: &Path, value: &serde_json::Value) {
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

fn read_optional_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => {
            eprintln!("[zk-fuzzer] ERROR: invalid {} value: {}", name, e);
            std::process::exit(2);
        }
    }
}

fn run_signal_dir() -> PathBuf {
    // Base folder where "easy to find" run folders are written.
    //
    // Default matches your requested structure:
    //   /home/<user>/ZkFuzz/report_<epoch>/
    //
    // Override with:
    //   ZKF_RUN_SIGNAL_DIR=/some/other/base
    //
    // If writing outside the repo is not allowed in your environment, set it back to:
    //   ZKF_RUN_SIGNAL_DIR=reports/_run_signals
    let path = if let Some(v) = read_optional_env("ZKF_RUN_SIGNAL_DIR") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            PathBuf::from(trimmed)
        } else {
            eprintln!("[zk-fuzzer] ERROR: ZKF_RUN_SIGNAL_DIR is set but empty");
            std::process::exit(2);
        }
    } else if let Some(home) = read_optional_env("HOME") {
        let home = home.trim();
        if !home.is_empty() {
            PathBuf::from(home).join("ZkFuzz")
        } else {
            eprintln!("[zk-fuzzer] ERROR: HOME is set but empty");
            std::process::exit(2);
        }
    } else {
        eprintln!("[zk-fuzzer] ERROR: neither ZKF_RUN_SIGNAL_DIR nor HOME is available");
        std::process::exit(2);
    };

    if let Err(err) = std::fs::create_dir_all(&path) {
        eprintln!(
            "[zk-fuzzer] ERROR: cannot create run-signal dir '{}': {}",
            path.display(),
            err
        );
        std::process::exit(2);
    }
    path
}

fn build_cache_dir() -> PathBuf {
    // Build artifacts are large and should not live inside engagement report folders.
    // Default:
    //   /home/<user>/ZkFuzz/_build_cache/
    //
    // Override with:
    //   ZKF_BUILD_CACHE_DIR=/some/other/path
    if let Some(v) = read_optional_env("ZKF_BUILD_CACHE_DIR") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if let Err(err) = std::fs::create_dir_all(&path) {
                eprintln!(
                    "[zk-fuzzer] ERROR: cannot create build cache dir '{}': {}",
                    path.display(),
                    err
                );
                std::process::exit(2);
            }
            return path;
        }
    }

    let path = run_signal_dir().join("_build_cache");
    if let Err(err) = std::fs::create_dir_all(&path) {
        eprintln!(
            "[zk-fuzzer] ERROR: cannot create build cache dir '{}': {}",
            path.display(),
            err
        );
        std::process::exit(2);
    }
    path
}

fn normalize_build_paths(config: &mut FuzzConfig, run_id: &str) {
    use std::path::PathBuf;

    let report_dir = engagement_root_dir(run_id);
    let cache = build_cache_dir();
    let additional = &mut config.campaign.parameters.additional;

    // Remove any explicit build paths that point inside the engagement folder, then force
    // build_dir_base to the cache root.
    let keys = [
        "build_dir_base",
        "build_dir",
        "circom_build_dir",
        "noir_build_dir",
        "halo2_build_dir",
        "cairo_build_dir",
    ];

    let mut had_in_report = false;
    for key in keys {
        if let Some(v) = additional.get(key).and_then(|v| v.as_str()) {
            let p = PathBuf::from(v);
            if p.starts_with(&report_dir) {
                had_in_report = true;
                additional.remove(key);
            }
        }
    }

    // If build_dir_base is missing, set it. If it existed but pointed into the report dir, replace it.
    if had_in_report || additional.get("build_dir_base").is_none() {
        additional.insert(
            "build_dir_base".to_string(),
            serde_yaml::Value::String(cache.display().to_string()),
        );
        if had_in_report {
            tracing::info!(
                "Build artifacts redirected to cache dir {:?} (were inside engagement folder {:?})",
                cache,
                report_dir
            );
        }
    }
}

fn best_effort_append_jsonl(path: &Path, value: &serde_json::Value) {
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
    let line = match serde_json::to_string(value) {
        Ok(line) => line,
        Err(err) => {
            tracing::warn!(
                "Failed to serialize JSONL record '{}': {}",
                path.display(),
                err
            );
            return;
        }
    };
    let mut f = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(file) => file,
        Err(err) => {
            tracing::warn!("Failed to open JSONL file '{}': {}", path.display(), err);
            return;
        }
    };
    if let Err(err) = writeln!(f, "{}", line) {
        tracing::warn!(
            "Failed to append JSONL record '{}': {}",
            path.display(),
            err
        );
    }
}

fn run_id_epoch_dir(run_id: &str) -> Option<String> {
    // run_id prefix is make_run_id(): "%Y%m%d_%H%M%S_..."
    if run_id.len() < 15 {
        return None;
    }
    let ts = &run_id[..15];
    let naive = match chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%d_%H%M%S") {
        Ok(naive) => naive,
        Err(err) => {
            tracing::warn!("Invalid run_id timestamp prefix '{}': {}", ts, err);
            return None;
        }
    };
    let started_utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
    Some(format!("report_{}", started_utc.timestamp()))
}

fn engagement_dir_name(run_id: &str) -> String {
    // Allow grouping multiple processes (mode1 + mode2 + mode3) into the same report folder.
    //
    // Example:
    //   export ZKF_ENGAGEMENT_EPOCH=176963063
    //   ... run mode1, mode2, mode3 ...
    //   => /home/<user>/ZkFuzz/report_176963063/
    if let Some(epoch) = read_optional_env("ZKF_ENGAGEMENT_EPOCH") {
        let trimmed = epoch.trim();
        if !trimmed.is_empty() {
            return format!("report_{}", trimmed);
        }
    }

    if let Some(name) = read_optional_env("ZKF_ENGAGEMENT_NAME") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    match run_id_epoch_dir(run_id) {
        Some(dir_name) => dir_name,
        None => {
            let fallback = format!("report_{}", sanitize_slug(run_id));
            tracing::warn!(
                "Run id '{}' does not contain a valid timestamp prefix; using fallback engagement dir '{}'",
                run_id,
                fallback
            );
            fallback
        }
    }
}

fn engagement_root_dir(run_id: &str) -> PathBuf {
    // If ZKF_ENGAGEMENT_DIR is set, use it as the full report folder.
    if let Some(dir) = read_optional_env("ZKF_ENGAGEMENT_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    run_signal_dir().join(engagement_dir_name(run_id))
}

fn mode_folder_from_command(command: &str) -> &'static str {
    match command {
        "run" => "mode1",
        "evidence" => "mode2",
        "chains" => "mode3",
        _ => "misc",
    }
}

fn ensure_engagement_layout(report_dir: &Path) {
    for dir in [
        report_dir.to_path_buf(),
        report_dir.join("log"),
        report_dir.join("mode1"),
        report_dir.join("mode2"),
        report_dir.join("mode3"),
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

fn get_command_from_doc(value: &serde_json::Value) -> String {
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

fn mirror_mode_output_snapshot(output_dir: &Path, run_id: &str, value: &serde_json::Value) {
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

fn update_engagement_summary(report_dir: &Path, value: &serde_json::Value) {
    let now = Utc::now().to_rfc3339();
    let command = get_command_from_doc(value);
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

    best_effort_write_json(&summary_path, &summary);

    // Markdown summary (human-friendly).
    let mut md = String::new();
    md.push_str("# ZkFuzz Engagement Summary\n\n");
    md.push_str(&format!("Updated (UTC): `{}`\n\n", now));

    if let Some(modes) = summary.get("modes").and_then(|m| m.as_object()) {
        for key in ["mode1", "mode2", "mode3"] {
            let v = modes.get(key);
            md.push_str(&format!("## {}\n\n", key));
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
                md.push_str(&format!("- Run ID: `{}`\n", run_id));
                md.push_str(&format!("- Campaign: `{}`\n", campaign));
                md.push_str(&format!("- Started (UTC): `{}`\n", started));
                if !ended.is_empty() {
                    md.push_str(&format!("- Ended (UTC): `{}`\n", ended));
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

fn add_run_window_fields(
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

fn classify_run_reason_code(doc: &serde_json::Value) -> Option<&'static str> {
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

fn log_run_reason_code(doc: &serde_json::Value) {
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

fn output_lock_wait_seconds() -> u64 {
    let default_wait_secs = 2u64;
    let Some(raw) = read_optional_env("ZKF_OUTPUT_LOCK_WAIT_SECS") else {
        return default_wait_secs;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return default_wait_secs;
    }
    match trimmed.parse::<u64>() {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(
                "Invalid ZKF_OUTPUT_LOCK_WAIT_SECS='{}' ({}); using default {}",
                trimmed,
                err,
                default_wait_secs
            );
            default_wait_secs
        }
    }
}

fn acquire_output_dir_lock(
    output_dir: &Path,
) -> anyhow::Result<zk_fuzzer::util::file_lock::FileLock> {
    let max_wait = Duration::from_secs(output_lock_wait_seconds());
    let started = Instant::now();
    let mut attempts: u32 = 0;

    loop {
        attempts += 1;
        match zk_fuzzer::util::file_lock::lock_dir_exclusive(
            output_dir,
            ".zkfuzz.lock",
            zk_fuzzer::util::file_lock::LockMode::NonBlocking,
        ) {
            Ok(lock) => {
                if attempts > 1 {
                    tracing::info!(
                        "Acquired output lock after {} attempts (waited {:.2}s): {}",
                        attempts,
                        started.elapsed().as_secs_f64(),
                        output_dir.display()
                    );
                }
                return Ok(lock);
            }
            Err(err) => {
                let err_lc = format!("{:#}", err).to_ascii_lowercase();
                if max_wait.is_zero()
                    || started.elapsed() >= max_wait
                    || err_lc.contains("permission denied")
                {
                    return Err(err.context(format!(
                        "Output lock acquisition exhausted after {} attempt(s), waited {:.2}s",
                        attempts,
                        started.elapsed().as_secs_f64()
                    )));
                }

                let backoff_ms = 100u64.saturating_mul(u64::from(attempts.min(20)));
                std::thread::sleep(Duration::from_millis(backoff_ms));
            }
        }
    }
}

fn acquire_output_lock_or_write_failure(
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

fn parse_preflight_executor_options(
    config: &FuzzConfig,
) -> anyhow::Result<zk_fuzzer::executor::ExecutorFactoryOptions> {
    let additional = &config.campaign.parameters.additional;
    let mut options = zk_fuzzer::executor::ExecutorFactoryOptions {
        build_dir_base: additional
            .get_path("build_dir_base")
            .or_else(|| additional.get_path("build_dir")),
        circom_build_dir: additional.get_path("circom_build_dir"),
        noir_build_dir: additional.get_path("noir_build_dir"),
        halo2_build_dir: additional.get_path("halo2_build_dir"),
        cairo_build_dir: additional.get_path("cairo_build_dir"),
        strict_backend: true,
        ..Default::default()
    };

    if let Some(auto_setup) = additional.get_bool("circom_auto_setup_keys") {
        options.circom_auto_setup_keys = auto_setup;
    }
    if let Some(require_setup) = additional.get_bool("circom_require_setup_keys") {
        options.circom_require_setup_keys = require_setup;
        if require_setup {
            options.circom_auto_setup_keys = true;
        }
    }
    options.circom_ptau_path = additional.get_path("circom_ptau_path");
    options.circom_snarkjs_path = additional.get_path("circom_snarkjs_path");
    if let Some(skip_compile) = additional.get_bool("circom_skip_compile_if_artifacts") {
        options.circom_skip_compile_if_artifacts = skip_compile;
    }
    if let Some(skip_check) = additional.get_bool("circom_skip_constraint_check") {
        if skip_check {
            anyhow::bail!(
                "Invalid config: circom_skip_constraint_check=true is disallowed. \
                 Mode 2/3 require real constraint coverage. Set circom_skip_constraint_check: false."
            );
        }
        options.circom_skip_constraint_check = false;
    }
    if let Some(sanity_check) = additional.get_bool("circom_witness_sanity_check") {
        options.circom_witness_sanity_check = sanity_check;
    }

    if let Some(value) = additional.get("include_paths") {
        let mut paths = Vec::new();
        match value {
            serde_yaml::Value::Sequence(items) => {
                for item in items {
                    if let Some(raw) = item.as_str() {
                        let trimmed = raw.trim();
                        if !trimmed.is_empty() {
                            paths.push(PathBuf::from(trimmed));
                        }
                    }
                }
            }
            serde_yaml::Value::String(s) => {
                for part in s.split(',') {
                    let trimmed = part.trim();
                    if !trimmed.is_empty() {
                        paths.push(PathBuf::from(trimmed));
                    }
                }
            }
            _ => {}
        }
        if !paths.is_empty() {
            options.circom_include_paths = paths;
        }
    }

    Ok(options)
}

fn run_backend_preflight(config: &FuzzConfig) -> anyhow::Result<()> {
    let framework = config.campaign.target.framework;
    let circuit_path = config
        .campaign
        .target
        .circuit_path
        .to_string_lossy()
        .to_string();
    let main_component = config.campaign.target.main_component.clone();
    let options = parse_preflight_executor_options(config)?;

    tracing::info!(
        "Backend preflight: framework={:?}, target='{}', component='{}'",
        framework,
        circuit_path,
        main_component
    );

    let _executor = zk_fuzzer::executor::ExecutorFactory::create_with_options(
        framework,
        &circuit_path,
        &main_component,
        &options,
    )
    .context("Backend preflight failed while initializing executor")?;

    tracing::info!("Backend preflight passed");
    Ok(())
}

fn preflight_campaign(config_path: &str, setup_keys: bool) -> anyhow::Result<()> {
    tracing::info!("Running backend preflight for campaign: {}", config_path);
    let mut config = FuzzConfig::from_yaml(config_path)?;

    if setup_keys {
        config.campaign.parameters.additional.insert(
            "circom_auto_setup_keys".to_string(),
            serde_yaml::Value::Bool(true),
        );
        config.campaign.parameters.additional.insert(
            "circom_require_setup_keys".to_string(),
            serde_yaml::Value::Bool(true),
        );
    }

    run_backend_preflight(&config)?;

    println!("✓ Backend preflight passed");
    if setup_keys {
        println!("✓ Circom key-setup preflight passed");
    }

    Ok(())
}

fn write_global_run_signal(run_id: &str, value: &serde_json::Value) {
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

fn write_run_artifacts(output_dir: &Path, run_id: &str, value: &serde_json::Value) {
    log_run_reason_code(value);

    // Minimal artifacts contract: avoid redundant run history + mirrored reports.
    // - `run_outcome.json` is the single authoritative per-mode status file (also used for resume).
    // - engagement-wide `log/events.jsonl` is the run history (includes run_id).
    best_effort_write_json(&output_dir.join("run_outcome.json"), value);
    write_scan_timestamp_totals_if_applicable(output_dir, value);
    mirror_mode_output_snapshot(output_dir, run_id, value);
    write_global_run_signal(run_id, value);
}

fn running_run_doc_with_window(
    command: &str,
    run_id: &str,
    stage: &str,
    config_path: &str,
    campaign_name: &str,
    output_dir: &Path,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "status": "running",
        "command": command,
        "run_id": run_id,
        "stage": stage,
        "pid": std::process::id(),
        "campaign_path": config_path,
        "campaign_name": campaign_name,
        "output_dir": output_dir.display().to_string(),
        "started_utc": started_utc.to_rfc3339(),
    });
    add_run_window_fields(&mut doc, started_utc, timeout_seconds, "wall_clock");
    doc
}

fn seed_running_run_artifact(
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
    let mut doc = running_run_doc_with_window(
        command,
        run_id,
        stage,
        config_path,
        campaign_name,
        output_dir,
        started_utc,
        timeout_seconds,
    );
    doc["options"] = options;
    write_run_artifacts(output_dir, run_id, &doc);
}

fn completed_run_doc_with_window(
    command: &str,
    run_id: &str,
    status: &str,
    stage: &str,
    config_path: &str,
    campaign_name: &str,
    output_dir: &Path,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
) -> serde_json::Value {
    let ended_utc = Utc::now();
    let mut doc = serde_json::json!({
        "status": status,
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
    });
    add_run_window_fields(&mut doc, started_utc, timeout_seconds, "wall_clock");
    doc
}

fn failed_run_doc_with_window(
    command: &str,
    run_id: &str,
    stage: &str,
    config_path: &str,
    campaign_name: &str,
    output_dir: &Path,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
) -> serde_json::Value {
    let ended_utc = Utc::now();
    let mut doc = serde_json::json!({
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
    });
    add_run_window_fields(&mut doc, started_utc, timeout_seconds, "wall_clock");
    doc
}

fn write_failed_mode_run_artifact_with_error(
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
    let mut doc = failed_run_doc_with_window(
        command,
        run_id,
        stage,
        config_path,
        campaign_name,
        output_dir,
        started_utc,
        timeout_seconds,
    );
    doc["error"] = serde_json::Value::String(error);
    write_run_artifacts(output_dir, run_id, &doc);
}

fn write_failed_mode_run_artifact_with_reason(
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
    let mut doc = failed_run_doc_with_window(
        command,
        run_id,
        stage,
        config_path,
        campaign_name,
        output_dir,
        started_utc,
        timeout_seconds,
    );
    doc["reason"] = serde_json::Value::String(reason);
    if let Some(readiness) = readiness {
        doc["readiness"] = readiness;
    }
    write_run_artifacts(output_dir, run_id, &doc);
}

fn require_evidence_readiness_or_emit_failure(
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

fn run_backend_preflight_or_emit_failure(
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

fn initialize_campaign_run_lifecycle(
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

fn scan_public_root_from_output_dir(output_dir: &Path) -> Option<PathBuf> {
    let run_root_dir = output_dir.parent()?;
    let artifacts_dir = run_root_dir.parent()?;
    if artifacts_dir.file_name().and_then(|s| s.to_str()) != Some(".scan_run_artifacts") {
        return None;
    }
    let base = artifacts_dir.parent()?;
    let run_root_name = run_root_dir.file_name()?.to_owned();
    Some(base.join(run_root_name))
}

fn write_scan_timestamp_totals_if_applicable(output_dir: &Path, value: &serde_json::Value) {
    let Some(scan_root) = scan_public_root_from_output_dir(output_dir) else {
        return;
    };

    let total_log_path = scan_root.join("log.jsonl");
    best_effort_append_jsonl(&total_log_path, value);
}

fn best_effort_append_text_line(path: &Path, line: &str) {
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
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(mut file) => {
            if let Err(err) = writeln!(file, "{}", line) {
                tracing::warn!(
                    "Failed to append text line to '{}': {}",
                    path.display(),
                    err
                );
            }
        }
        Err(err) => {
            tracing::warn!("Failed to open '{}' for append: {}", path.display(), err);
        }
    }
}

fn write_failed_run_artifact(run_id: &str, value: &serde_json::Value) {
    log_run_reason_code(value);

    // Keep failure artifacts within the engagement folder to avoid scattering files.
    let report_dir = engagement_root_dir(run_id);
    let failed_dir = report_dir.join("_failed_runs");
    best_effort_write_json(&failed_dir.join(format!("{}.json", run_id)), value);
    write_global_run_signal(run_id, value);
}

fn write_failed_run_artifact_with_error(
    run_id: &str,
    command: &str,
    stage: &str,
    config_path: &str,
    started_utc: &DateTime<Utc>,
    ended_utc: &DateTime<Utc>,
    error: String,
    output_dir: Option<&Path>,
) {
    let mut doc = serde_json::json!({
        "status": "failed",
        "command": command,
        "run_id": run_id,
        "stage": stage,
        "pid": std::process::id(),
        "campaign_path": config_path,
        "started_utc": started_utc.to_rfc3339(),
        "ended_utc": ended_utc.to_rfc3339(),
        "duration_seconds": (*ended_utc - *started_utc).num_seconds().max(0),
        "error": error,
    });
    if let Some(path) = output_dir {
        doc["output_dir"] = serde_json::Value::String(path.display().to_string());
    }
    write_failed_run_artifact(run_id, &doc);
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

fn mark_stale_previous_run_if_any(output_dir: &Path, current_pid: u32) {
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

fn install_panic_hook() {
    if PANIC_HOOK_INSTALLED.set(()).is_err() {
        return;
    }

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let now = Utc::now().to_rfc3339();
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "panic payload (non-string)".to_string()
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        let backtrace = std::backtrace::Backtrace::force_capture().to_string();

        let ctx = get_run_log_context();
        let run_id = match ctx.as_ref().map(|c| c.run_id.clone()) {
            Some(id) => id,
            None => make_run_id("panic", None),
        };

        let doc = serde_json::json!({
            "status": "panic",
            "timestamp_utc": now,
            "run_id": run_id.clone(),
            "panic": {
                "message": payload,
                "location": location,
                "backtrace": backtrace,
            },
            "context": ctx.as_ref().map(|c| serde_json::json!({
                "command": c.command,
                "campaign_path": c.campaign_path,
                "campaign_name": c.campaign_name,
                "output_dir": c.output_dir.as_ref().map(|p| p.display().to_string()),
                "started_utc": c.started_utc,
                "pid": std::process::id(),
            })),
        });

        if let Some(ctx) = ctx {
            if let Some(output_dir) = ctx.output_dir.as_ref() {
                write_run_artifacts(output_dir, &run_id, &doc);
            } else {
                write_failed_run_artifact(&run_id, &doc);
            }
        } else {
            write_failed_run_artifact(&run_id, &doc);
        }

        default_hook(info);
    }));
}

fn start_signal_watchers() {
    if SIGNAL_WATCHER_STARTED.set(()).is_err() {
        return;
    }

    tokio::spawn(async move {
        let mut sigint = Box::pin(tokio::signal::ctrl_c());

        #[cfg(unix)]
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => Some(s),
                Err(err) => panic!("Failed to install SIGTERM handler: {}", err),
            };

        #[cfg(not(unix))]
        let mut sigterm: Option<()> = None;

        let stop = async {
            #[cfg(unix)]
            {
                tokio::select! {
                    _ = &mut sigint => "SIGINT",
                    _ = async {
                        if let Some(s) = sigterm.as_mut() {
                            if s.recv().await.is_none() {
                                tracing::warn!("SIGTERM stream ended unexpectedly");
                                std::future::pending::<()>().await;
                            }
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => "SIGTERM",
                }
            }

            #[cfg(not(unix))]
            {
                if let Err(err) = sigint.await {
                    tracing::warn!("Failed waiting for SIGINT: {}", err);
                }
                "SIGINT"
            }
        };

        let signal_name = stop.await;
        let now = Utc::now().to_rfc3339();
        let ctx = get_run_log_context();
        let run_id = match ctx.as_ref().map(|c| c.run_id.clone()) {
            Some(id) => id,
            None => make_run_id("interrupted", None),
        };

        let doc = serde_json::json!({
            "status": "interrupted",
            "timestamp_utc": now,
            "run_id": run_id.clone(),
            "signal": signal_name,
            "context": ctx.as_ref().map(|c| serde_json::json!({
                "command": c.command,
                "campaign_path": c.campaign_path,
                "campaign_name": c.campaign_name,
                "output_dir": c.output_dir.as_ref().map(|p| p.display().to_string()),
                "started_utc": c.started_utc,
                "pid": std::process::id(),
            })),
        });

        if let Some(ctx) = ctx {
            if let Some(output_dir) = ctx.output_dir.as_ref() {
                write_run_artifacts(output_dir, &run_id, &doc);
            } else {
                write_failed_run_artifact(&run_id, &doc);
            }
        } else {
            write_failed_run_artifact(&run_id, &doc);
        }

        // Conventional shell exit codes: 130 (SIGINT), 143 (SIGTERM).
        let code = if signal_name == "SIGTERM" { 143 } else { 130 };
        std::process::exit(code);
    });
}

#[derive(Parser)]
#[command(name = "zk-fuzzer")]
#[command(version = "0.1.0")]
#[command(about = "Zero-Knowledge Proof Security Testing Framework")]
#[command(
    long_about = "A comprehensive fuzzing framework for detecting vulnerabilities in ZK circuits.\n\nSupports Circom, Noir, Halo2, and Cairo backends with coverage-guided fuzzing,\nmultiple attack vectors, and detailed vulnerability reporting."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to YAML campaign configuration
    #[arg(short, long, global = true)]
    config: Option<String>,

    /// Number of parallel workers
    #[arg(short, long, default_value = "4", global = true)]
    workers: usize,

    /// Seed for reproducibility
    #[arg(short, long, global = true)]
    seed: Option<u64>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Quiet mode - minimal output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Dry run - validate config without executing
    #[arg(long, global = true)]
    dry_run: bool,

    /// Use simple progress (no fancy terminal UI)
    #[arg(long, global = true)]
    simple_progress: bool,

    /// Require strict backend availability checks.
    #[arg(long, global = true)]
    real_only: bool,

    /// Configuration profile (quick, standard, deep, perf)
    /// Quick: 10K iterations, fast exploration
    /// Standard: 100K iterations, balanced fuzzing (default for evidence)
    /// Deep: 1M iterations, thorough analysis
    #[arg(long, global = true)]
    profile: Option<String>,

    /// Kill other zk-fuzzer instances on startup (use with caution)
    #[arg(long, global = true)]
    kill_existing: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Unified scan command: auto-dispatch mono/multi pattern YAML
    Scan {
        /// Path to pattern YAML (pattern-only schema)
        pattern: String,

        /// Pattern family hint (auto/mono/multi)
        #[arg(long, default_value = "auto")]
        family: ScanFamily,

        /// Target circuit path used to materialize runtime campaign metadata
        #[arg(long)]
        target_circuit: String,

        /// Main component name for target circuit
        #[arg(long, default_value = "main")]
        main_component: String,

        /// Framework for target circuit (circom, noir, halo2, cairo)
        #[arg(long, default_value = "circom")]
        framework: String,

        /// Number of iterations
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Timeout in seconds (mono: optional, multi: defaults to 600 if omitted)
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Resume from existing corpus
        #[arg(long)]
        resume: bool,

        /// Custom corpus directory (mono only)
        #[arg(long)]
        corpus_dir: Option<String>,

        /// Optional output suffix for scan isolation (used by batch parallel runs)
        #[arg(long)]
        output_suffix: Option<String>,
    },
    /// Run backend/key-setup preflight for a campaign and exit
    Preflight {
        /// Path to campaign YAML file
        campaign: String,
        /// Require Circom key setup to pass during preflight
        #[arg(long, default_value_t = false)]
        setup_keys: bool,
    },
    /// Validate a campaign configuration
    Validate {
        /// Path to campaign YAML file
        campaign: String,
    },
    /// Local toolchain bootstrap utilities
    Bins {
        #[command(subcommand)]
        command: BinsCommands,
    },
    /// Minimize a corpus
    Minimize {
        /// Path to corpus directory
        corpus_dir: String,
        /// Output directory for minimized corpus
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Generate a sample campaign configuration
    Init {
        /// Output file path
        #[arg(short, long, default_value = "campaign.yaml")]
        output: String,
        /// Target framework (circom, noir, halo2)
        #[arg(short, long, default_value = "circom")]
        framework: String,
    },
    #[command(hide = true)]
    ExecWorker,
}

#[derive(Subcommand)]
enum BinsCommands {
    /// Install/update local circom/snarkjs/ptau assets under bins/
    Bootstrap {
        /// Local bins directory root
        #[arg(long, default_value = "bins")]
        bins_dir: String,
        /// Circom release version (tag or semver, e.g. v2.2.3 or 2.2.3)
        #[arg(long, default_value = "v2.2.3")]
        circom_version: String,
        /// snarkjs npm version
        #[arg(long, default_value = "0.7.5")]
        snarkjs_version: String,
        /// Output filename under <bins_dir>/ptau/
        #[arg(long, default_value = "pot12_final.ptau")]
        ptau_file: String,
        /// Optional ptau download URL (when omitted, uses local fixture)
        #[arg(long)]
        ptau_url: Option<String>,
        /// Expected SHA-256 for ptau file (required when --ptau-url is used)
        #[arg(long)]
        ptau_sha256: Option<String>,
        /// Skip circom bootstrap
        #[arg(long, default_value_t = false)]
        skip_circom: bool,
        /// Skip snarkjs bootstrap
        #[arg(long, default_value_t = false)]
        skip_snarkjs: bool,
        /// Skip ptau bootstrap
        #[arg(long, default_value_t = false)]
        skip_ptau: bool,
        /// Force re-download/reinstall even when local artifacts already exist
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Hash)]
enum ScanFamily {
    Auto,
    Mono,
    Multi,
}

#[derive(Debug, Clone)]
struct CampaignRunOptions {
    workers: usize,
    seed: Option<u64>,
    verbose: bool,
    dry_run: bool,
    simple_progress: bool,
    real_only: bool,
    iterations: u64,
    timeout: Option<u64>,
    require_invariants: bool,
    resume: bool,
    corpus_dir: Option<String>,
    profile: Option<String>,
}

#[derive(Debug, Clone)]
struct ChainRunOptions {
    workers: usize,
    seed: Option<u64>,
    verbose: bool,
    dry_run: bool,
    simple_progress: bool,
    iterations: u64,
    timeout: u64,
    resume: bool,
}

/// Kill existing zk-fuzzer instances with graceful shutdown
async fn kill_existing_instances() {
    let current_pid = std::process::id();

    let pgrep_output = std::process::Command::new("pgrep")
        .args(["-x", "zk-fuzzer"])
        .output();

    if let Ok(output) = pgrep_output {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        // Try graceful shutdown first (SIGTERM)
                        match std::process::Command::new("kill")
                            .args(["-15", &pid.to_string()])
                            .output()
                        {
                            Ok(output) if output.status.success() => {}
                            Ok(output) => tracing::warn!(
                                "Failed to send SIGTERM to {}: {}",
                                pid,
                                String::from_utf8_lossy(&output.stderr)
                            ),
                            Err(err) => {
                                tracing::warn!("Error sending SIGTERM to {}: {}", pid, err)
                            }
                        }
                    }
                }
            }

            // Wait for graceful shutdown
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Force kill any remaining processes (SIGKILL)
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        match std::process::Command::new("kill")
                            .args(["-9", &pid.to_string()])
                            .output()
                        {
                            Ok(output) if output.status.success() => {}
                            Ok(output) => tracing::warn!(
                                "Failed to send SIGKILL to {}: {}",
                                pid,
                                String::from_utf8_lossy(&output.stderr)
                            ),
                            Err(err) => {
                                tracing::warn!("Error sending SIGKILL to {}: {}", pid, err)
                            }
                        }
                    }
                }
            }

            eprintln!(
                "Terminated existing zk-fuzzer instances (excluding PID {})",
                current_pid
            );
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Only kill existing instances if explicitly requested
    if cli.kill_existing {
        kill_existing_instances().await;
    }

    // Run the command and ensure cleanup
    let result = run_cli_command(cli).await;

    result
}

async fn run_cli_command(cli: Cli) -> anyhow::Result<()> {
    // Initialize logging
    let log_level = if cli.quiet {
        tracing::Level::WARN
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_ansi(false)
        .with_writer(DynamicLogWriter)
        .init();

    // Ensure early-stop causes are captured to disk when possible (panic/signal).
    install_panic_hook();
    start_signal_watchers();

    match cli.command {
        Some(Commands::Scan {
            pattern,
            family,
            target_circuit,
            main_component,
            framework,
            iterations,
            timeout,
            resume,
            corpus_dir,
            output_suffix,
        }) => {
            run_scan(
                &pattern,
                family,
                &target_circuit,
                &main_component,
                &framework,
                output_suffix.as_deref(),
                CampaignRunOptions {
                    workers: cli.workers,
                    seed: cli.seed,
                    verbose: cli.verbose,
                    dry_run: cli.dry_run,
                    simple_progress: cli.simple_progress,
                    real_only: true,
                    iterations,
                    timeout,
                    require_invariants: true,
                    resume,
                    corpus_dir: corpus_dir.clone(),
                    profile: cli.profile.clone(),
                },
                ChainRunOptions {
                    workers: cli.workers,
                    seed: cli.seed,
                    verbose: cli.verbose,
                    dry_run: cli.dry_run,
                    simple_progress: cli.simple_progress,
                    iterations,
                    timeout: timeout.unwrap_or(600),
                    resume,
                },
            )
            .await
        }
        Some(Commands::Preflight {
            campaign,
            setup_keys,
        }) => preflight_campaign(&campaign, setup_keys),
        Some(Commands::Validate { campaign }) => validate_campaign(&campaign),
        Some(Commands::Bins { command }) => match command {
            BinsCommands::Bootstrap {
                bins_dir,
                circom_version,
                snarkjs_version,
                ptau_file,
                ptau_url,
                ptau_sha256,
                skip_circom,
                skip_snarkjs,
                skip_ptau,
                force,
            } => toolchain_bootstrap::run_bins_bootstrap(
                &toolchain_bootstrap::BinsBootstrapOptions {
                    bins_dir: PathBuf::from(bins_dir),
                    circom_version,
                    snarkjs_version,
                    ptau_file_name: ptau_file,
                    ptau_url,
                    ptau_sha256,
                    skip_circom,
                    skip_snarkjs,
                    skip_ptau,
                    force,
                    dry_run: cli.dry_run,
                },
            ),
        },
        Some(Commands::Minimize { corpus_dir, output }) => {
            minimize_corpus(&corpus_dir, output.as_deref())
        }
        Some(Commands::Init { output, framework }) => generate_sample_config(&output, &framework),
        Some(Commands::ExecWorker) => zk_fuzzer::executor::run_exec_worker(),
        None => {
            anyhow::bail!(
                "No command provided. Use `zk-fuzzer scan <pattern.yaml> --target-circuit <path> --main-component <name> --framework <fw>`."
            );
        }
    }
}

fn parse_framework_arg(value: &str) -> anyhow::Result<Framework> {
    match value.trim().to_ascii_lowercase().as_str() {
        "circom" => Ok(Framework::Circom),
        "noir" => Ok(Framework::Noir),
        "halo2" => Ok(Framework::Halo2),
        "cairo" => Ok(Framework::Cairo),
        other => anyhow::bail!(
            "Unsupported --framework '{}'. Expected one of: circom, noir, halo2, cairo",
            other
        ),
    }
}

fn yaml_key(name: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(name.to_string())
}

fn detect_pattern_has_chains(path: &str) -> anyhow::Result<bool> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", path))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", path))?;
    let root = doc
        .as_mapping()
        .context("Pattern YAML root must be a mapping")?;
    let chains_key = yaml_key("chains");
    let chains = match root.get(&chains_key) {
        Some(v) => v,
        None => return Ok(false),
    };
    let seq = chains
        .as_sequence()
        .context("'chains' must be a YAML sequence when present")?;
    Ok(!seq.is_empty())
}

fn validate_scan_pattern_complexity(path: &str, family: ScanFamily) -> anyhow::Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", path))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", path))?;
    let root = doc
        .as_mapping()
        .context("Pattern YAML root must be a mapping")?;

    match family {
        ScanFamily::Mono => {}
        ScanFamily::Multi => {
            let chains = root
                .get(yaml_key("chains"))
                .and_then(|v| v.as_sequence())
                .context("Mode 3 (multi deep) requires non-empty `chains` in pattern YAML")?;
            if chains.is_empty() {
                anyhow::bail!("Mode 3 (multi deep) requires non-empty `chains` in pattern YAML");
            }

            let mut has_multistage_chain = false;
            let mut has_multi_circuit_chain = false;
            for chain in chains {
                let Some(chain_map) = chain.as_mapping() else {
                    anyhow::bail!("Each `chains` entry must be a mapping");
                };
                let steps_len = chain_map
                    .get(yaml_key("steps"))
                    .and_then(|v| v.as_sequence())
                    .map(|s| s.len())
                    .unwrap_or(0);
                if steps_len >= 2 {
                    has_multistage_chain = true;
                }

                let mut distinct_refs = std::collections::BTreeSet::new();
                if let Some(steps) = chain_map
                    .get(yaml_key("steps"))
                    .and_then(|v| v.as_sequence())
                {
                    for step in steps {
                        if let Some(step_map) = step.as_mapping() {
                            if let Some(circuit_ref) = step_map
                                .get(yaml_key("circuit_ref"))
                                .and_then(|v| v.as_str())
                            {
                                distinct_refs.insert(circuit_ref.to_string());
                            }
                        }
                    }
                }
                if distinct_refs.len() >= 2 {
                    has_multi_circuit_chain = true;
                }

                if has_multistage_chain && has_multi_circuit_chain {
                    break;
                }
            }
            if !has_multistage_chain {
                anyhow::bail!(
                    "Mode 3 (multi deep) requires multi-stage chains (at least one chain with 2+ steps)"
                );
            }
            if !has_multi_circuit_chain {
                anyhow::bail!(
                    "Mode 3 (multi deep) requires at least two distinct circuit refs in a chain. Mono-circuit targets cannot run multi."
                );
            }
        }
        ScanFamily::Auto => {}
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ScanRegexPatternKind {
    #[default]
    Regex,
}

fn default_scan_regex_pattern_weight() -> f64 {
    1.0
}

#[derive(Debug, Clone, Deserialize)]
struct ScanRegexPatternSpec {
    id: String,
    pattern: String,
    #[serde(default)]
    kind: ScanRegexPatternKind,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default = "default_scan_regex_pattern_weight")]
    weight: f64,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct ScanRegexSelectorPolicySpec {
    k_of_n: Option<usize>,
    min_score: Option<f64>,
    groups: Vec<ScanRegexSelectorGroupPolicySpec>,
}

fn default_selector_synonym_flexible_separators() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct ScanRegexSelectorNormalizationSpec {
    synonym_flexible_separators: bool,
}

impl Default for ScanRegexSelectorNormalizationSpec {
    fn default() -> Self {
        Self {
            synonym_flexible_separators: default_selector_synonym_flexible_separators(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct ScanRegexSelectorGroupPolicySpec {
    #[serde(alias = "group")]
    name: String,
    k_of_n: Option<usize>,
    min_score: Option<f64>,
}

#[derive(Debug, Clone)]
struct ScanRegexSelectorConfig {
    patterns: Vec<ScanRegexPatternSpec>,
    policy: ScanRegexSelectorPolicySpec,
}

#[derive(Debug, Clone)]
struct ScanRegexPatternMatch {
    id: String,
    lines: Vec<usize>,
    occurrences: usize,
}

#[derive(Debug, Clone)]
struct ScanRegexPatternGroupMatch {
    name: String,
    total_patterns: usize,
    matched_patterns: usize,
    matched_score: f64,
    required_k_of_n: usize,
    required_min_score: f64,
    passed: bool,
}

#[derive(Debug, Clone, Default)]
struct ScanRegexPatternSummary {
    total_patterns: usize,
    matched_patterns: usize,
    total_occurrences: usize,
    matched_score: f64,
    required_k_of_n: usize,
    required_min_score: f64,
    selector_passed: bool,
    matched_ids: Vec<String>,
    matches: Vec<ScanRegexPatternMatch>,
    group_matches: Vec<ScanRegexPatternGroupMatch>,
}

fn validate_scan_regex_pattern_safety(pattern: &str) -> anyhow::Result<()> {
    const MAX_PATTERN_LENGTH: usize = 1000;
    const MAX_ALTERNATIONS: usize = 50;
    const MAX_GROUPS: usize = 20;

    if pattern.len() > MAX_PATTERN_LENGTH {
        anyhow::bail!(
            "Regex pattern too long ({} chars). Maximum allowed: {}",
            pattern.len(),
            MAX_PATTERN_LENGTH
        );
    }

    let alternation_count = pattern.matches('|').count();
    if alternation_count > MAX_ALTERNATIONS {
        anyhow::bail!(
            "Regex pattern has too many alternations ({}). Maximum allowed: {}",
            alternation_count,
            MAX_ALTERNATIONS
        );
    }

    // Escape-aware scan for group count and nested quantifiers such as (a+)+.
    let bytes = pattern.as_bytes();
    let mut i = 0usize;
    let mut group_count = 0usize;
    let mut paren_stack: Vec<bool> = Vec::new(); // bool = has quantifier inside this group

    while i < bytes.len() {
        let ch = bytes[i];

        if ch == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }

        if ch == b'(' {
            group_count += 1;
            if group_count > MAX_GROUPS {
                anyhow::bail!(
                    "Regex pattern has too many groups ({}). Maximum allowed: {}",
                    group_count,
                    MAX_GROUPS
                );
            }
            paren_stack.push(false);
            i += 1;
            continue;
        }

        if ch == b')' {
            if let Some(has_quant_inside) = paren_stack.pop() {
                if i + 1 < bytes.len() {
                    let next = bytes[i + 1];
                    let has_outer_quant = next == b'*' || next == b'+' || next == b'{';
                    if has_outer_quant && has_quant_inside {
                        anyhow::bail!(
                            "Potentially dangerous nested quantifier detected in regex pattern: {}",
                            pattern
                        );
                    }
                }
                if has_quant_inside && !paren_stack.is_empty() {
                    if let Some(parent) = paren_stack.last_mut() {
                        *parent = true;
                    }
                }
            }
            i += 1;
            continue;
        }

        let is_quantifier = ch == b'*' || ch == b'+' || ch == b'{';
        if is_quantifier && !paren_stack.is_empty() {
            if let Some(last) = paren_stack.last_mut() {
                *last = true;
            }
        }

        i += 1;
    }

    Ok(())
}

fn normalize_synonym_term_to_regex(
    term: &str,
    normalization: &ScanRegexSelectorNormalizationSpec,
) -> String {
    if !normalization.synonym_flexible_separators {
        return regex::escape(term.trim());
    }

    let mut tokens: Vec<String> = Vec::new();
    for raw_chunk in term
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let mut current = String::new();
        let mut prev: Option<char> = None;
        for ch in raw_chunk.chars() {
            let boundary = match prev {
                Some(prev_ch) => {
                    (prev_ch.is_ascii_lowercase() && ch.is_ascii_uppercase())
                        || (prev_ch.is_ascii_alphabetic() && ch.is_ascii_digit())
                        || (prev_ch.is_ascii_digit() && ch.is_ascii_alphabetic())
                }
                None => false,
            };
            if boundary && !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            current.push(ch);
            prev = Some(ch);
        }
        if !current.is_empty() {
            tokens.push(current);
        }
    }
    let tokens: Vec<String> = tokens
        .into_iter()
        .map(|token| regex::escape(&token))
        .collect();
    if tokens.len() >= 2 {
        return tokens.join(r"(?:[\s_\-./]*)");
    }

    regex::escape(term.trim())
}

fn validate_scan_regex_synonym_bundles(
    pattern_path: &str,
    bundles: &BTreeMap<String, Vec<String>>,
) -> anyhow::Result<()> {
    for (bundle_name, variants) in bundles {
        let bundle_name = bundle_name.trim();
        if bundle_name.is_empty() {
            anyhow::bail!(
                "Invalid `selector_synonyms` in '{}': bundle names must be non-empty",
                pattern_path
            );
        }
        if variants.is_empty() {
            anyhow::bail!(
                "Invalid `selector_synonyms.{}` in '{}': bundle must contain at least one synonym",
                bundle_name,
                pattern_path
            );
        }
        for (idx, variant) in variants.iter().enumerate() {
            if variant.trim().is_empty() {
                anyhow::bail!(
                    "Invalid `selector_synonyms.{}[{}]` in '{}': synonym values must be non-empty",
                    bundle_name,
                    idx,
                    pattern_path
                );
            }
        }
    }

    Ok(())
}

fn build_scan_regex_synonym_regexes(
    pattern_path: &str,
    bundles: &BTreeMap<String, Vec<String>>,
    normalization: &ScanRegexSelectorNormalizationSpec,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut regexes: BTreeMap<String, String> = BTreeMap::new();
    for (bundle_name, variants) in bundles {
        let mut bundle_variants: Vec<String> = Vec::with_capacity(variants.len());
        for variant in variants {
            bundle_variants.push(normalize_synonym_term_to_regex(variant, normalization));
        }
        if bundle_variants.is_empty() {
            anyhow::bail!(
                "Invalid `selector_synonyms.{}` in '{}': bundle must contain at least one synonym",
                bundle_name,
                pattern_path
            );
        }
        regexes.insert(
            bundle_name.trim().to_string(),
            format!("(?:{})", bundle_variants.join("|")),
        );
    }

    Ok(regexes)
}

fn expand_scan_regex_synonym_placeholders(
    pattern_path: &str,
    pattern_id: &str,
    raw_pattern: &str,
    synonym_regexes: &BTreeMap<String, String>,
) -> anyhow::Result<String> {
    if !raw_pattern.contains("{{") {
        return Ok(raw_pattern.to_string());
    }

    let mut expanded = String::new();
    let mut cursor = 0usize;
    while let Some(start_rel) = raw_pattern[cursor..].find("{{") {
        let start = cursor + start_rel;
        expanded.push_str(&raw_pattern[cursor..start]);

        let tail = &raw_pattern[start + 2..];
        let Some(end_rel) = tail.find("}}") else {
            anyhow::bail!(
                "Invalid synonym placeholder in pattern '{}' from '{}': missing closing '}}'",
                pattern_id,
                pattern_path
            );
        };

        let bundle_name = tail[..end_rel].trim();
        if bundle_name.is_empty() {
            anyhow::bail!(
                "Invalid synonym placeholder in pattern '{}' from '{}': empty bundle name",
                pattern_id,
                pattern_path
            );
        }
        let Some(bundle_regex) = synonym_regexes.get(bundle_name) else {
            anyhow::bail!(
                "Unknown synonym bundle '{}' referenced by pattern '{}' in '{}'",
                bundle_name,
                pattern_id,
                pattern_path
            );
        };
        expanded.push_str(bundle_regex);
        cursor = start + 2 + end_rel + 2;
    }
    expanded.push_str(&raw_pattern[cursor..]);

    Ok(expanded)
}

fn validate_scan_regex_selector_config(
    pattern_path: &str,
    patterns: &[ScanRegexPatternSpec],
    policy: &ScanRegexSelectorPolicySpec,
) -> anyhow::Result<()> {
    if patterns.is_empty() {
        return Ok(());
    }

    let global_k = policy.k_of_n.unwrap_or(1);
    if global_k == 0 {
        anyhow::bail!(
            "Invalid `selector_policy.k_of_n` in '{}': value must be >= 1",
            pattern_path
        );
    }
    if global_k > patterns.len() {
        anyhow::bail!(
            "Invalid `selector_policy.k_of_n` in '{}': value {} exceeds total patterns {}",
            pattern_path,
            global_k,
            patterns.len()
        );
    }

    if let Some(min_score) = policy.min_score {
        if !min_score.is_finite() || min_score < 0.0 {
            anyhow::bail!(
                "Invalid `selector_policy.min_score` in '{}': expected a non-negative finite number",
                pattern_path
            );
        }
    }

    let mut patterns_by_group: BTreeMap<String, usize> = BTreeMap::new();
    for pattern in patterns {
        if let Some(group) = pattern.group.as_ref() {
            *patterns_by_group.entry(group.clone()).or_insert(0usize) += 1;
        }
    }

    let mut seen_groups = BTreeSet::new();
    for (idx, group_rule) in policy.groups.iter().enumerate() {
        let group_name = group_rule.name.trim();
        if group_name.is_empty() {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}]` in '{}': `name` must be non-empty",
                idx,
                pattern_path
            );
        }
        if !seen_groups.insert(group_name.to_string()) {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}]` in '{}': duplicate group '{}'",
                idx,
                pattern_path,
                group_name
            );
        }

        let Some(total_patterns) = patterns_by_group.get(group_name).copied() else {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}]` in '{}': group '{}' has no matching patterns",
                idx,
                pattern_path,
                group_name
            );
        };

        let group_k = group_rule.k_of_n.unwrap_or(1);
        if group_k == 0 {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}].k_of_n` in '{}': value must be >= 1",
                idx,
                pattern_path
            );
        }
        if group_k > total_patterns {
            anyhow::bail!(
                "Invalid `selector_policy.groups[{}].k_of_n` in '{}': value {} exceeds group pattern count {} for '{}'",
                idx,
                pattern_path,
                group_k,
                total_patterns,
                group_name
            );
        }

        if let Some(min_score) = group_rule.min_score {
            if !min_score.is_finite() || min_score < 0.0 {
                anyhow::bail!(
                    "Invalid `selector_policy.groups[{}].min_score` in '{}': expected a non-negative finite number",
                    idx,
                    pattern_path
                );
            }
        }
    }

    Ok(())
}

fn load_scan_regex_selector_config(
    pattern_path: &str,
) -> anyhow::Result<Option<ScanRegexSelectorConfig>> {
    let raw = fs::read_to_string(pattern_path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", pattern_path))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", pattern_path))?;
    let root = doc
        .as_mapping()
        .context("Pattern YAML root must be a mapping")?;

    let Some(patterns_value) = root.get(yaml_key("patterns")) else {
        return Ok(None);
    };

    let sequence = patterns_value
        .as_sequence()
        .context("'patterns' must be a YAML sequence when present")?;

    let normalization = match root.get(yaml_key("selector_normalization")) {
        Some(value) => serde_yaml::from_value(value.clone()).with_context(|| {
            format!(
                "Invalid `selector_normalization` in '{}': expected key `synonym_flexible_separators`",
                pattern_path
            )
        })?,
        None => ScanRegexSelectorNormalizationSpec::default(),
    };

    let synonyms: BTreeMap<String, Vec<String>> = match root
        .get(yaml_key("selector_synonyms"))
        .or_else(|| root.get(yaml_key("synonym_bundles")))
    {
        Some(value) => serde_yaml::from_value(value.clone()).with_context(|| {
            format!(
                "Invalid `selector_synonyms` in '{}': expected mapping of bundle -> list of strings",
                pattern_path
            )
        })?,
        None => BTreeMap::new(),
    };
    validate_scan_regex_synonym_bundles(pattern_path, &synonyms)?;
    let synonym_regexes =
        build_scan_regex_synonym_regexes(pattern_path, &synonyms, &normalization)?;

    let mut patterns: Vec<ScanRegexPatternSpec> = Vec::with_capacity(sequence.len());
    for (idx, item) in sequence.iter().enumerate() {
        let mut pattern: ScanRegexPatternSpec =
            serde_yaml::from_value(item.clone()).with_context(|| {
                format!(
                    "Invalid `patterns[{}]` entry in '{}': expected keys {{id, kind, pattern, message, group, weight}}",
                    idx, pattern_path
                )
            })?;

        pattern.id = pattern.id.trim().to_string();
        if pattern.id.is_empty() {
            anyhow::bail!(
                "Invalid `patterns[{}]` in '{}': `id` must be non-empty",
                idx,
                pattern_path
            );
        }
        pattern.pattern = pattern.pattern.trim().to_string();
        if pattern.pattern.is_empty() {
            anyhow::bail!(
                "Invalid `patterns[{}]` in '{}': `pattern` must be non-empty",
                idx,
                pattern_path
            );
        }
        if pattern.kind != ScanRegexPatternKind::Regex {
            anyhow::bail!(
                "Invalid `patterns[{}]` in '{}': only `kind: regex` is supported",
                idx,
                pattern_path
            );
        }

        if !pattern.weight.is_finite() || pattern.weight <= 0.0 {
            anyhow::bail!(
                "Invalid `patterns[{}]` in '{}': `weight` must be a positive finite number",
                idx,
                pattern_path
            );
        }

        pattern.group = pattern
            .group
            .map(|group| group.trim().to_string())
            .filter(|group| !group.is_empty());

        pattern.pattern = expand_scan_regex_synonym_placeholders(
            pattern_path,
            &pattern.id,
            &pattern.pattern,
            &synonym_regexes,
        )?;

        validate_scan_regex_pattern_safety(&pattern.pattern)
            .with_context(|| format!("Unsafe regex for pattern '{}'", pattern.id))?;
        RegexBuilder::new(&pattern.pattern)
            .case_insensitive(true)
            .size_limit(2 * 1024 * 1024)
            .dfa_size_limit(2 * 1024 * 1024)
            .build()
            .with_context(|| {
                format!("Invalid regex in `patterns[{}]` (id='{}')", idx, pattern.id)
            })?;

        patterns.push(pattern);
    }

    let policy = match root.get(yaml_key("selector_policy")) {
        Some(value) => serde_yaml::from_value(value.clone()).with_context(|| {
            format!(
                "Invalid `selector_policy` in '{}': expected keys {{k_of_n, min_score, groups}}",
                pattern_path
            )
        })?,
        None => ScanRegexSelectorPolicySpec::default(),
    };

    validate_scan_regex_selector_config(pattern_path, &patterns, &policy)?;

    Ok(Some(ScanRegexSelectorConfig { patterns, policy }))
}

fn evaluate_loaded_scan_regex_patterns(
    selector_config: &ScanRegexSelectorConfig,
    target_circuit: &Path,
) -> anyhow::Result<ScanRegexPatternSummary> {
    let patterns = &selector_config.patterns;
    if patterns.is_empty() {
        return Ok(ScanRegexPatternSummary::default());
    }

    let source = fs::read_to_string(target_circuit).with_context(|| {
        format!(
            "Failed to read target circuit '{}' for regex pattern evaluation",
            target_circuit.display()
        )
    })?;

    let mut line_starts = vec![0usize];
    for (idx, ch) in source.char_indices() {
        if ch == '\n' {
            line_starts.push(idx + 1);
        }
    }

    println!("PATTERN FILTER START");
    let mut summary = ScanRegexPatternSummary {
        total_patterns: patterns.len(),
        required_k_of_n: selector_config.policy.k_of_n.unwrap_or(1),
        required_min_score: selector_config.policy.min_score.unwrap_or(0.0),
        ..Default::default()
    };
    let mut matched_pattern_ids: BTreeSet<String> = BTreeSet::new();
    for (idx, pattern) in patterns.iter().enumerate() {
        println!(
            "pattern filter {}/{} {}",
            idx + 1,
            patterns.len(),
            pattern.id
        );

        let regex = RegexBuilder::new(&pattern.pattern)
            .case_insensitive(true)
            .size_limit(2 * 1024 * 1024)
            .dfa_size_limit(2 * 1024 * 1024)
            .build()
            .with_context(|| {
                format!(
                    "Invalid regex in pattern '{}' while scanning target '{}'",
                    pattern.id,
                    target_circuit.display()
                )
            })?;

        if regex.is_match(&source) {
            let mut lines: Vec<usize> = Vec::new();
            let mut occurrences = 0usize;
            for m in regex.find_iter(&source) {
                occurrences += 1;
                let line = match line_starts.binary_search(&m.start()) {
                    Ok(pos) => pos + 1,
                    Err(pos) => pos,
                };
                if lines.last().copied() != Some(line) {
                    lines.push(line);
                }
            }
            summary.matched_patterns += 1;
            summary.total_occurrences += occurrences;
            summary.matched_score += pattern.weight;
            summary.matched_ids.push(pattern.id.clone());
            matched_pattern_ids.insert(pattern.id.clone());
            summary.matches.push(ScanRegexPatternMatch {
                id: pattern.id.clone(),
                lines: lines.clone(),
                occurrences,
            });
            if let Some(message) = pattern
                .message
                .as_ref()
                .map(|m| m.trim())
                .filter(|m| !m.is_empty())
            {
                println!(
                    "pattern hit {}: {} (matches: {}, weight: {:.2}, lines: {:?})",
                    pattern.id, message, occurrences, pattern.weight, lines
                );
            } else {
                println!(
                    "pattern hit {} (matches: {}, weight: {:.2}, lines: {:?})",
                    pattern.id, occurrences, pattern.weight, lines
                );
            }
        }
    }

    let mut grouped_stats: BTreeMap<String, (usize, usize, f64)> = BTreeMap::new();
    for pattern in patterns {
        let Some(group_name) = pattern.group.as_ref() else {
            continue;
        };
        let entry = grouped_stats
            .entry(group_name.clone())
            .or_insert((0usize, 0usize, 0.0f64));
        entry.0 += 1;
        if matched_pattern_ids.contains(&pattern.id) {
            entry.1 += 1;
            entry.2 += pattern.weight;
        }
    }

    for group_rule in &selector_config.policy.groups {
        let group_name = group_rule.name.trim();
        if group_name.is_empty() {
            continue;
        }
        let (total_patterns, matched_patterns, matched_score) = grouped_stats
            .get(group_name)
            .copied()
            .unwrap_or((0usize, 0usize, 0.0f64));
        let required_k_of_n = group_rule.k_of_n.unwrap_or(1);
        let required_min_score = group_rule.min_score.unwrap_or(0.0);
        let passed = matched_patterns >= required_k_of_n
            && matched_score + f64::EPSILON >= required_min_score;
        summary.group_matches.push(ScanRegexPatternGroupMatch {
            name: group_name.to_string(),
            total_patterns,
            matched_patterns,
            matched_score,
            required_k_of_n,
            required_min_score,
            passed,
        });
    }

    let global_k_pass = summary.matched_patterns >= summary.required_k_of_n;
    let global_score_pass = summary.matched_score + f64::EPSILON >= summary.required_min_score;
    let groups_pass = summary.group_matches.iter().all(|group| group.passed);
    summary.selector_passed = global_k_pass && global_score_pass && groups_pass;

    println!("PATTERN FILTER END");
    let match_ratio = if summary.total_patterns == 0 {
        0.0
    } else {
        (summary.matched_patterns as f64 / summary.total_patterns as f64) * 100.0
    };
    println!(
        "pattern summary: matched {}/{} ({:.1}%), total regex hits: {}",
        summary.matched_patterns, summary.total_patterns, match_ratio, summary.total_occurrences
    );
    println!(
        "pattern gate: k_of_n {}/{} (required {}), score {:.2}/{:.2} => {}",
        summary.matched_patterns,
        summary.total_patterns,
        summary.required_k_of_n,
        summary.matched_score,
        summary.required_min_score,
        if global_k_pass && global_score_pass {
            "PASS"
        } else {
            "FAIL"
        }
    );
    for group in &summary.group_matches {
        println!(
            "pattern group {}: k_of_n {}/{} (required {}), score {:.2}/{:.2} => {}",
            group.name,
            group.matched_patterns,
            group.total_patterns,
            group.required_k_of_n,
            group.matched_score,
            group.required_min_score,
            if group.passed { "PASS" } else { "FAIL" }
        );
    }
    for hit in &summary.matches {
        let frequency = if summary.total_occurrences == 0 {
            0.0
        } else {
            (hit.occurrences as f64 / summary.total_occurrences as f64) * 100.0
        };
        println!(
            "pattern frequency {}: {} hits ({:.1}%)",
            hit.id, hit.occurrences, frequency
        );
    }
    println!(
        "pattern selector verdict: {}",
        if summary.selector_passed {
            "PASS"
        } else {
            "FAIL"
        }
    );

    Ok(summary)
}

#[derive(Debug, Clone, Copy, Default)]
struct ScanFindingsSummary {
    findings_total: u64,
}

fn scan_default_output_dir() -> PathBuf {
    match dirs::home_dir() {
        Some(home) => home.join("ZkFuzz"),
        None => PathBuf::from("./ZkFuzz"),
    }
}

fn read_scan_progress_step_fraction(progress_path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(progress_path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
    doc.get("progress")
        .and_then(|v| v.get("step_fraction"))
        .and_then(|v| v.as_str())
        .map(|value| value.to_string())
}

fn read_scan_findings_summary_since(
    output_dir: &Path,
    phase_started_at: std::time::SystemTime,
) -> Option<ScanFindingsSummary> {
    let run_outcome_path = output_dir.join("run_outcome.json");
    let modified = std::fs::metadata(&run_outcome_path).ok()?.modified().ok()?;
    if modified < phase_started_at {
        return None;
    }
    let raw = std::fs::read_to_string(run_outcome_path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let metrics = doc.get("metrics")?;

    let findings_total = metrics
        .get("findings_total")
        .and_then(|v| v.as_u64())
        .or_else(|| metrics.get("chain_findings_total").and_then(|v| v.as_u64()))
        .or_else(|| metrics.get("total_findings").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    Some(ScanFindingsSummary { findings_total })
}

async fn run_scan_phase_with_progress<F>(
    phase_label: &str,
    output_dir: &Path,
    phase_future: F,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    let progress_path = output_dir.join("progress.json");
    let mut last_fraction: Option<String> = read_scan_progress_step_fraction(&progress_path);
    let mut phase_future = std::pin::pin!(phase_future);

    loop {
        tokio::select! {
            result = &mut phase_future => return result,
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                let fraction = read_scan_progress_step_fraction(&progress_path);
                if let Some(fraction) = fraction {
                    let changed = match &last_fraction {
                        Some(prev) => prev != &fraction,
                        None => true,
                    };
                    if changed {
                        println!("{} {}", phase_label, fraction);
                        last_fraction = Some(fraction);
                    }
                }
            }
        }
    }
}

fn materialize_scan_pattern_campaign(
    pattern_path: &str,
    family: ScanFamily,
    target: &ScanTarget,
    output_suffix: Option<&str>,
    scan_regex_summary: Option<&ScanRegexPatternSummary>,
) -> anyhow::Result<PathBuf> {
    use std::hash::{Hash, Hasher};

    let raw = fs::read_to_string(pattern_path)
        .with_context(|| format!("Failed to read pattern YAML '{}'", pattern_path))?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse pattern YAML '{}'", pattern_path))?;
    let root = doc
        .as_mapping_mut()
        .context("Pattern YAML root must be a mapping")?;

    // Regex selector metadata is scan-time only. Remove it from the materialized
    // campaign so the runtime parser only sees executable fuzzing configuration.
    root.remove(yaml_key("patterns"));
    root.remove(yaml_key("selector_policy"));
    root.remove(yaml_key("selector_synonyms"));
    root.remove(yaml_key("synonym_bundles"));
    root.remove(yaml_key("selector_normalization"));

    // Keep includes valid after writing a materialized temp campaign.
    if let Some(includes) = root.get_mut(yaml_key("includes")) {
        let seq = includes
            .as_sequence_mut()
            .context("'includes' must be a YAML sequence")?;
        let pattern_dir = Path::new(pattern_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        for item in seq.iter_mut() {
            let include = match item.as_str() {
                Some(v) => v,
                None => continue,
            };
            if include.starts_with("${") {
                continue;
            }
            let include_path = Path::new(include);
            if include_path.is_absolute() {
                continue;
            }
            let rewritten = pattern_dir.join(include_path);
            *item = serde_yaml::Value::String(rewritten.to_string_lossy().to_string());
        }
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    pattern_path.hash(&mut hasher);
    target.framework.hash(&mut hasher);
    target.circuit_path.to_string_lossy().hash(&mut hasher);
    target.main_component.hash(&mut hasher);
    family.hash(&mut hasher);
    let digest = hasher.finish();

    let stem = Path::new(pattern_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(sanitize_slug)
        .unwrap_or_else(|| "pattern".to_string());
    let mut campaign = serde_yaml::Mapping::new();
    campaign.insert(
        yaml_key("name"),
        serde_yaml::Value::String(format!("scan_{}", stem)),
    );
    campaign.insert(
        yaml_key("version"),
        serde_yaml::Value::String("2.0".to_string()),
    );

    let mut campaign_target = serde_yaml::Mapping::new();
    campaign_target.insert(
        yaml_key("framework"),
        serde_yaml::to_value(target.framework).context("Failed to serialize framework")?,
    );
    campaign_target.insert(
        yaml_key("circuit_path"),
        serde_yaml::Value::String(target.circuit_path.to_string_lossy().to_string()),
    );
    campaign_target.insert(
        yaml_key("main_component"),
        serde_yaml::Value::String(target.main_component.clone()),
    );
    campaign.insert(
        yaml_key("target"),
        serde_yaml::Value::Mapping(campaign_target),
    );

    let mut parameters = serde_yaml::Mapping::new();
    parameters.insert(
        yaml_key("field"),
        serde_yaml::Value::String("bn254".to_string()),
    );
    parameters.insert(
        yaml_key("max_constraints"),
        serde_yaml::Value::Number(serde_yaml::Number::from(120000u64)),
    );
    parameters.insert(
        yaml_key("timeout_seconds"),
        serde_yaml::Value::Number(serde_yaml::Number::from(600u64)),
    );
    if matches!(target.framework, Framework::Circom) {
        // Scan stability hardening: ensure backend preflight validates not just tool presence
        // but also proving/verification key setup readiness for Circom targets.
        parameters.insert(
            yaml_key("circom_auto_setup_keys"),
            serde_yaml::Value::Bool(true),
        );
        parameters.insert(
            yaml_key("circom_require_setup_keys"),
            serde_yaml::Value::Bool(true),
        );
    }
    if let Some(raw_suffix) = output_suffix.map(str::trim).filter(|s| !s.is_empty()) {
        parameters.insert(
            yaml_key("scan_output_suffix"),
            serde_yaml::Value::String(sanitize_slug(raw_suffix)),
        );
    }
    if let Some(summary) = scan_regex_summary {
        let mut lines: Vec<String> = Vec::new();
        for hit in &summary.matches {
            if hit.lines.is_empty() {
                lines.push(format!(
                    "pattern {} found ({} matches)",
                    hit.id, hit.occurrences
                ));
            } else {
                lines.push(format!(
                    "pattern {} found ({} matches) in lines {:?}",
                    hit.id, hit.occurrences, hit.lines
                ));
            }
        }
        if !lines.is_empty() {
            parameters.insert(
                yaml_key("scan_pattern_summary_text"),
                serde_yaml::Value::String(lines.join("\n")),
            );
            // Regex selector scans intentionally preserve static findings as scan evidence.
            // Without this, strict evidence-mode filtering can hide valid selector hits.
            parameters.insert(
                yaml_key("min_evidence_confidence"),
                serde_yaml::Value::String("low".to_string()),
            );
        }
    }
    campaign.insert(
        yaml_key("parameters"),
        serde_yaml::Value::Mapping(parameters),
    );

    root.insert(yaml_key("campaign"), serde_yaml::Value::Mapping(campaign));

    let out = std::env::temp_dir()
        .join("zkfuzz_scan")
        .join(format!("{}__{:016x}.yaml", stem, digest));
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create temp scan materialization directory '{}'",
                parent.display()
            )
        })?;
    }
    let yaml = serde_yaml::to_string(&doc)?;
    fs::write(&out, yaml).with_context(|| {
        format!(
            "Failed to write materialized scan campaign '{}'",
            out.display()
        )
    })?;
    Ok(out)
}

async fn run_scan(
    pattern_path: &str,
    family_hint: ScanFamily,
    target_circuit: &str,
    main_component: &str,
    framework: &str,
    output_suffix: Option<&str>,
    mono_options: CampaignRunOptions,
    chain_options: ChainRunOptions,
) -> anyhow::Result<()> {
    validate_pattern_only_yaml(pattern_path, "Scan")?;
    let regex_selector_config = load_scan_regex_selector_config(pattern_path)?;
    let regex_mode = regex_selector_config.is_some();

    let has_chains = detect_pattern_has_chains(pattern_path)?;
    let family = if regex_mode {
        if has_chains {
            tracing::info!(
                "Regex-focused scan: forcing mono execution and ignoring `chains` in '{}'",
                pattern_path
            );
        }
        ScanFamily::Mono
    } else {
        match family_hint {
            ScanFamily::Auto => {
                if has_chains {
                    ScanFamily::Multi
                } else {
                    ScanFamily::Mono
                }
            }
            ScanFamily::Mono => {
                if has_chains {
                    anyhow::bail!(
                        "Scan family set to mono but pattern '{}' contains non-empty `chains`.",
                        pattern_path
                    );
                }
                ScanFamily::Mono
            }
            ScanFamily::Multi => {
                if !has_chains {
                    anyhow::bail!(
                        "Scan family set to multi but pattern '{}' has no `chains`.",
                        pattern_path
                    );
                }
                ScanFamily::Multi
            }
        }
    };
    if !regex_mode {
        validate_scan_pattern_complexity(pattern_path, family)?;
    } else {
        tracing::info!(
            "Regex selectors active: skipping multi-chain complexity checks for '{}'",
            pattern_path
        );
    }

    let target = ScanTarget {
        framework: parse_framework_arg(framework)?,
        circuit_path: PathBuf::from(target_circuit),
        main_component: main_component.to_string(),
    };
    let mut scan_regex_summary: Option<ScanRegexPatternSummary> = None;
    if let Some(selector_config) = regex_selector_config.as_ref() {
        let summary = evaluate_loaded_scan_regex_patterns(selector_config, &target.circuit_path)?;
        if !summary.selector_passed {
            let mut reasons: Vec<String> = Vec::new();
            if summary.matched_patterns < summary.required_k_of_n {
                reasons.push(format!(
                    "k_of_n not met (matched {} of {}, required >= {})",
                    summary.matched_patterns, summary.total_patterns, summary.required_k_of_n
                ));
            }
            if summary.matched_score + f64::EPSILON < summary.required_min_score {
                reasons.push(format!(
                    "score threshold not met (matched {:.2}, required >= {:.2})",
                    summary.matched_score, summary.required_min_score
                ));
            }
            for group in &summary.group_matches {
                if !group.passed {
                    reasons.push(format!(
                        "group '{}' unmet (k_of_n {}/{}, required >= {}; score {:.2}, required >= {:.2})",
                        group.name,
                        group.matched_patterns,
                        group.total_patterns,
                        group.required_k_of_n,
                        group.matched_score,
                        group.required_min_score
                    ));
                }
            }
            let detail = if reasons.is_empty() {
                "selector policy thresholds not satisfied".to_string()
            } else {
                reasons.join("; ")
            };
            anyhow::bail!(
                "Pattern '{}' selectors did not match target circuit '{}': {}. \
                 Refine `patterns`/`selector_policy` or choose a matching pattern YAML.",
                pattern_path,
                target.circuit_path.display(),
                detail
            );
        }
        tracing::info!(
            "Pattern selectors matched {}/{} (score {:.2}, required {:.2}): [{}]",
            summary.matched_patterns,
            summary.total_patterns,
            summary.matched_score,
            summary.required_min_score,
            summary.matched_ids.join(", ")
        );
        scan_regex_summary = Some(summary);
    }

    let materialized = materialize_scan_pattern_campaign(
        pattern_path,
        family,
        &target,
        output_suffix,
        scan_regex_summary.as_ref(),
    )?;
    let materialized_str = materialized.to_string_lossy().to_string();

    tracing::info!(
        "Scan dispatch: pattern='{}' family={:?} materialized='{}'",
        pattern_path,
        family,
        materialized.display()
    );

    let output_dir = scan_default_output_dir();

    match family {
        ScanFamily::Mono => {
            tracing::info!("Scan (yaml mono run)");
            println!("\nSCAN START");
            let started_at = std::time::SystemTime::now();
            let run_result = run_scan_phase_with_progress(
                "scan",
                &output_dir,
                run_campaign(&materialized_str, mono_options),
            )
            .await;
            let summary =
                read_scan_findings_summary_since(&output_dir, started_at).unwrap_or_default();
            println!("SCAN END");
            println!("scan findings: {}", summary.findings_total);
            run_result
        }
        ScanFamily::Multi => {
            if mono_options.corpus_dir.is_some() {
                anyhow::bail!(
                    "--corpus-dir is mono-only. Multi/chain scans use chain corpus under ~/ZkFuzz."
                );
            }

            tracing::info!("Scan (yaml multi run)");
            println!("\nSCAN START");
            let started_at = std::time::SystemTime::now();
            let run_result = run_scan_phase_with_progress(
                "scan",
                &output_dir,
                run_chain_campaign(&materialized_str, chain_options),
            )
            .await;
            let summary =
                read_scan_findings_summary_since(&output_dir, started_at).unwrap_or_default();
            println!("SCAN END");
            println!("scan findings: {}", summary.findings_total);
            run_result
        }
        ScanFamily::Auto => unreachable!("auto resolved above"),
    }
}

fn validate_pattern_only_yaml(path: &str, mode_name: &str) -> anyhow::Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {} pattern YAML '{}'", mode_name, path))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse {} pattern YAML '{}'", mode_name, path))?;
    let root = doc
        .as_mapping()
        .context("Pattern YAML root must be a mapping")?;

    let allowed: BTreeSet<&'static str> = BTreeSet::from([
        "includes",
        "profiles",
        "active_profile",
        "patterns",
        "selector_policy",
        "selector_synonyms",
        "synonym_bundles",
        "selector_normalization",
        "target_traits",
        "invariants",
        "schedule",
        "attacks",
        "inputs",
        "mutations",
        "oracles",
        "chains",
    ]);

    let mut unexpected = Vec::new();
    for key in root.keys() {
        let key = key
            .as_str()
            .context("Pattern YAML contains a non-string top-level key")?;
        if !allowed.contains(key) {
            unexpected.push(key.to_string());
        }
    }
    if !unexpected.is_empty() {
        unexpected.sort();
        anyhow::bail!(
            "{} YAML must be pattern-only. Unsupported top-level keys: [{}]. Allowed keys: [{}].",
            mode_name,
            unexpected.join(", "),
            allowed.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

fn apply_scan_output_suffix_if_present(config: &mut FuzzConfig) -> anyhow::Result<()> {
    let Some(raw_suffix) = config
        .campaign
        .parameters
        .additional
        .get_string("scan_output_suffix")
    else {
        return Ok(());
    };

    let trimmed = raw_suffix.trim();
    if trimmed.is_empty() {
        anyhow::bail!("`campaign.parameters.scan_output_suffix` cannot be empty");
    }

    let slug = sanitize_slug(trimmed);
    let run_root = if let Some(v) = read_optional_env("ZKF_SCAN_RUN_ROOT") {
        let candidate = v.trim();
        if candidate.is_empty() {
            anyhow::bail!("ZKF_SCAN_RUN_ROOT is set but empty");
        }
        if !candidate.starts_with("scan_run") {
            anyhow::bail!(
                "ZKF_SCAN_RUN_ROOT must start with 'scan_run' (got '{}')",
                candidate
            );
        }
        if !candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            anyhow::bail!(
                "ZKF_SCAN_RUN_ROOT contains invalid characters: '{}'",
                candidate
            );
        }
        candidate.to_string()
    } else {
        reserve_scan_run_root(&config.reporting.output_dir)?
    };
    let public_root = config.reporting.output_dir.join(&run_root);
    let artifacts_root = config
        .reporting
        .output_dir
        .join(".scan_run_artifacts")
        .join(&run_root);
    config.reporting.output_dir = config
        .reporting
        .output_dir
        .join(".scan_run_artifacts")
        .join(&run_root)
        .join(&slug);
    let _ = std::fs::create_dir_all(&public_root);
    let _ = std::fs::create_dir_all(artifacts_root);
    write_scan_pattern_summary_if_present(config, &public_root, &slug);
    tracing::info!(
        "Scan output isolation enabled: {}",
        config.reporting.output_dir.display()
    );
    Ok(())
}

fn reserve_scan_run_root(output_root: &Path) -> anyhow::Result<String> {
    let artifacts_base = output_root.join(".scan_run_artifacts");
    std::fs::create_dir_all(&artifacts_base).with_context(|| {
        format!(
            "Failed to create scan artifacts base '{}'",
            artifacts_base.display()
        )
    })?;

    // Keep the existing run-root format (`scan_runYYYYmmdd_HHMMSS`) for compatibility
    // while making allocation collision-safe across concurrent scan processes.
    for _ in 0..120 {
        let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let candidate = format!("scan_run{}", ts);
        let reservation = artifacts_base.join(&candidate);
        match std::fs::create_dir(&reservation) {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                std::thread::sleep(Duration::from_millis(1100));
                continue;
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Failed to reserve scan run root '{}' under '{}': {}",
                    candidate,
                    artifacts_base.display(),
                    err
                ));
            }
        }
    }

    anyhow::bail!(
        "Failed to allocate unique scan run root after repeated collisions under '{}'",
        artifacts_base.display()
    )
}

fn write_scan_pattern_summary_if_present(config: &FuzzConfig, public_root: &Path, slug: &str) {
    let summary_text = config
        .campaign
        .parameters
        .additional
        .get_string("scan_pattern_summary_text");

    let summary_path = public_root.join("summary.txt");
    if let Some(summary_text) = summary_text {
        for line in summary_text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            best_effort_append_text_line(&summary_path, &format!("{}: {}", slug, trimmed));
        }
    } else {
        best_effort_append_text_line(
            &summary_path,
            &format!("{}: pattern {} found in lines []", slug, slug),
        );
    }
}

async fn run_campaign(config_path: &str, options: CampaignRunOptions) -> anyhow::Result<()> {
    let started_utc = Utc::now();
    let command = if options.require_invariants {
        "evidence"
    } else {
        "run"
    };
    let run_id = make_run_id(command, Some(config_path));
    let report_dir = engagement_root_dir(&run_id);
    let mut stage = "load_config";
    tracing::info!("Report directory: {}", report_dir.display());

    // Put `session.log` under the engagement folder from the very start (even if YAML parsing
    // fails). This avoids scattering logs across multiple locations.
    set_run_log_context_for_campaign(
        options.dry_run,
        &run_id,
        command,
        config_path,
        None,
        None,
        &started_utc,
    );

    tracing::info!("Loading campaign from: {}", config_path);
    let mut config = match FuzzConfig::from_yaml(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            let ended_utc = Utc::now();
            write_failed_run_artifact_with_error(
                &run_id,
                command,
                stage,
                config_path,
                &started_utc,
                &ended_utc,
                format!("{:#}", err),
                None,
            );
            return Err(err);
        }
    };

    // Apply profile if specified
    stage = "apply_profile";
    if let Some(profile_name) = options.profile.as_deref() {
        match profile_name.parse::<ProfileName>() {
            Ok(parsed_profile) => apply_profile(&mut config, parsed_profile),
            Err(e) => {
                let ended_utc = Utc::now();
                let parse_error = e.to_string();
                write_failed_run_artifact_with_error(
                    &run_id,
                    command,
                    stage,
                    config_path,
                    &started_utc,
                    &ended_utc,
                    parse_error.clone(),
                    Some(config.reporting.output_dir.as_path()),
                );
                return Err(anyhow::anyhow!(
                    "Invalid --profile '{}': {}",
                    profile_name,
                    parse_error
                ));
            }
        }
    }

    apply_scan_output_suffix_if_present(&mut config)?;

    let campaign_name = config.campaign.name.clone();

    if options.real_only {
        tracing::info!("--real-only set (real backend mode is already enforced)");
    }

    // Always enforce strict backend in this CLI.
    config
        .campaign
        .parameters
        .additional
        .insert("strict_backend".to_string(), serde_yaml::Value::Bool(true));
    // Soundness for Circom requires proving/verification keys. In strict live runs, ensure
    // prerequisites are satisfied by auto-running trusted setup when needed.
    let needs_soundness_keys = config
        .attacks
        .iter()
        .any(|attack| matches!(attack.attack_type, zk_fuzzer::config::AttackType::Soundness));
    if config.campaign.target.framework == Framework::Circom && needs_soundness_keys {
        config.campaign.parameters.additional.insert(
            "circom_auto_setup_keys".to_string(),
            serde_yaml::Value::Bool(true),
        );
        config.campaign.parameters.additional.insert(
            "circom_skip_compile_if_artifacts".to_string(),
            serde_yaml::Value::Bool(true),
        );
        tracing::info!(
            "Circom prerequisites: enabling automatic trusted setup/key generation for soundness"
        );
    }

    // Inject CLI fuzzing parameters into config
    config.campaign.parameters.additional.insert(
        "fuzzing_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.iterations)),
    );
    if let Some(t) = options.timeout {
        config.campaign.parameters.additional.insert(
            "fuzzing_timeout_seconds".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(t)),
        );

        // Align Circom external command timeout with the run timeout so backend setup/metadata
        // steps cannot silently run far beyond the requested wall-clock budget.
        if config.campaign.target.framework == Framework::Circom {
            let desired = t.max(1);
            let current = std::env::var("ZK_FUZZER_CIRCOM_EXTERNAL_TIMEOUT_SECS")
                .ok()
                .and_then(|raw| raw.trim().parse::<u64>().ok())
                .map(|secs| secs.max(1));
            let effective = current.map(|secs| secs.min(desired));
            tracing::info!(
                "Circom external command timeout {} (run timeout {}s)",
                match effective {
                    Some(value) => format!("derived from env: {}s", value),
                    None => "using backend default".to_string(),
                },
                desired
            );
        }
    }

    // Provide a stable identifier for the engine to emit progress snapshots into output_dir.
    // This also allows the "engagement report" to group mode1/mode2/mode3 runs together.
    config.campaign.parameters.additional.insert(
        "run_id".to_string(),
        serde_yaml::Value::String(run_id.clone()),
    );
    config.campaign.parameters.additional.insert(
        "run_command".to_string(),
        serde_yaml::Value::String(command.to_string()),
    );

    let (output_dir, _output_lock) = initialize_campaign_run_lifecycle(
        options.dry_run,
        &mut config,
        command,
        &run_id,
        config_path,
        &campaign_name,
        started_utc,
        options.timeout,
        serde_json::json!({
            "workers": options.workers,
            "seed": options.seed,
            "iterations": options.iterations,
            "timeout_seconds": options.timeout,
            "resume": options.resume,
            "corpus_dir": options.corpus_dir.clone(),
            "profile": options.profile.clone(),
            "simple_progress": options.simple_progress,
            "dry_run": options.dry_run,
        }),
    )?;

    let _ctx_guard = RunLogContextGuard::new();

    // Evidence mode settings + preflight checks.
    if options.require_invariants {
        stage = "preflight_invariants";
        let invariants = config.get_invariants();
        if invariants.is_empty() {
            if !options.dry_run {
                write_failed_mode_run_artifact_with_reason(
                    &output_dir,
                    command,
                    &run_id,
                    stage,
                    config_path,
                    &campaign_name,
                    started_utc,
                    options.timeout,
                    "Evidence mode requires v2 invariants in the YAML (invariants: ...).".to_string(),
                    None,
                );
            }
            anyhow::bail!("Evidence mode requires v2 invariants in the YAML (invariants: ...).");
        }

        config
            .campaign
            .parameters
            .additional
            .insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));
        config.campaign.parameters.additional.insert(
            "engagement_strict".to_string(),
            serde_yaml::Value::Bool(true),
        );
        config
            .campaign
            .parameters
            .additional
            .insert("strict_backend".to_string(), serde_yaml::Value::Bool(true));

        // Slight recall bias for evidence scans: prefer not missing true positives.
        // Keep YAML authority by only applying when user did not set explicit values.
        let additional = &mut config.campaign.parameters.additional;
        if additional.get("min_evidence_confidence").is_none() {
            additional.insert(
                "min_evidence_confidence".to_string(),
                serde_yaml::Value::String("low".to_string()),
            );
        }
        if additional
            .get("oracle_validation_min_agreement_ratio")
            .is_none()
        {
            additional.insert(
                "oracle_validation_min_agreement_ratio".to_string(),
                serde_yaml::Value::String("0.45".to_string()),
            );
        }
        if additional
            .get("oracle_validation_cross_attack_weight")
            .is_none()
        {
            additional.insert(
                "oracle_validation_cross_attack_weight".to_string(),
                serde_yaml::Value::String("0.65".to_string()),
            );
        }
        if additional
            .get("oracle_validation_mutation_test_count")
            .is_none()
        {
            additional.insert(
                "oracle_validation_mutation_test_count".to_string(),
                serde_yaml::Value::Number(serde_yaml::Number::from(8u64)),
            );
        }
        tracing::info!(
            "Evidence recall bias active (min_conf=low, agreement_ratio<=0.45, cross_attack_weight>=0.65 unless overridden in YAML)"
        );

        // Pre-flight readiness check for strict evidence engagements.
        stage = "preflight_readiness";
        println!();
        let readiness = zk_fuzzer::config::check_0day_readiness(&config);
        print!("{}", readiness.format());
        require_evidence_readiness_or_emit_failure(
            options.dry_run,
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            options.timeout,
            &readiness,
            "Campaign has critical issues; refusing to start strict evidence run",
        )?;
    }

    stage = "preflight_backend";
    run_backend_preflight_or_emit_failure(
        options.dry_run,
        &config,
        &output_dir,
        command,
        &run_id,
        stage,
        config_path,
        &campaign_name,
        started_utc,
        options.timeout,
    )?;

    // Print banner
    print_banner(&config);
    let run_start = Local::now();
    print_run_window(run_start, options.timeout);

    if !options.dry_run {
        // Update run artifacts with a more informative stage than the initial lock acquisition.
        seed_running_run_artifact(
            &output_dir,
            command,
            &run_id,
            "starting_engine",
            config_path,
            &campaign_name,
            started_utc,
            options.timeout,
            serde_json::json!({
                "workers": options.workers,
                "seed": options.seed,
                "iterations": options.iterations,
                "timeout_seconds": options.timeout,
                "resume": options.resume,
                "corpus_dir": options.corpus_dir.clone(),
                "profile": options.profile.clone(),
                "simple_progress": options.simple_progress,
                "dry_run": options.dry_run,
            }),
        );
    }

    // Handle resume mode
    if options.resume {
        let corpus_path = if let Some(ref dir) = options.corpus_dir {
            std::path::PathBuf::from(dir)
        } else {
            config.reporting.output_dir.join("corpus")
        };

        if corpus_path.exists() {
            tracing::info!("Resume mode: loading corpus from {:?}", corpus_path);
            config.campaign.parameters.additional.insert(
                "resume_corpus_dir".to_string(),
                serde_yaml::Value::String(corpus_path.display().to_string()),
            );
            println!("📂 Resuming from corpus: {}", corpus_path.display());
        } else {
            tracing::warn!(
                "Resume requested but corpus directory not found: {:?}",
                corpus_path
            );
            println!(
                "⚠️  Corpus directory not found, starting fresh: {}",
                corpus_path.display()
            );
        }
    }

    if options.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Configuration is valid");
        println!("  Campaign: {}", config.campaign.name);
        println!("  Target: {:?}", config.campaign.target.framework);
        println!("  Attacks: {}", config.attacks.len());
        println!("  Inputs: {}", config.inputs.len());
        if options.resume {
            println!("  Resume: enabled");
        }
        if let Some(ref p) = options.profile {
            println!("  Profile: {}", p);
        }
        return Ok(());
    }

    // While the engine is running, periodically mirror progress snapshots (progress.json) into
    // the engagement report folder so you can see "where we are at from total" without digging
    // into the app output_dir.
    let (progress_stop_tx, mut progress_stop_rx) = tokio::sync::watch::channel(false);
    struct _StopProgress(tokio::sync::watch::Sender<bool>);
    impl Drop for _StopProgress {
        fn drop(&mut self) {
            if let Err(err) = self.0.send(true) {
                tracing::warn!("Failed to stop progress monitor: {}", err);
            }
        }
    }
    let _progress_guard = _StopProgress(progress_stop_tx);

    {
        let output_dir_for_monitor = output_dir.clone();
        let run_id_for_monitor = run_id.clone();
        let command_for_monitor = command.to_string();
        let campaign_name_for_monitor = campaign_name.clone();
        let campaign_path_for_monitor = config_path.to_string();
        let started_utc_for_monitor = started_utc;
        let timeout_for_monitor = options.timeout;

        tokio::spawn(async move {
            let progress_path = output_dir_for_monitor.join("progress.json");
            loop {
                if *progress_stop_rx.borrow() {
                    break;
                }

                tokio::select! {
                    _ = progress_stop_rx.changed() => {},
                    _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {},
                }

                if *progress_stop_rx.borrow() {
                    break;
                }

                let progress_raw = match std::fs::read_to_string(&progress_path) {
                    Ok(s) => s,
                    Err(err) => {
                        if err.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(
                                "Failed reading progress snapshot '{}': {}",
                                progress_path.display(),
                                err
                            );
                        }
                        continue;
                    }
                };
                let progress_json: serde_json::Value = match serde_json::from_str(&progress_raw) {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::warn!(
                            "Failed parsing progress snapshot '{}': {}",
                            progress_path.display(),
                            err
                        );
                        continue;
                    }
                };

                let mut doc = running_run_doc_with_window(
                    &command_for_monitor,
                    &run_id_for_monitor,
                    "engine_progress",
                    &campaign_path_for_monitor,
                    &campaign_name_for_monitor,
                    &output_dir_for_monitor,
                    started_utc_for_monitor,
                    timeout_for_monitor,
                );
                doc["progress"] = progress_json;
                let run_id_for_signal = match doc.get("run_id").and_then(|v| v.as_str()) {
                    Some(run_id) => run_id,
                    None => {
                        tracing::warn!(
                            "Progress document missing run_id while writing global run signal"
                        );
                        continue;
                    }
                };
                write_global_run_signal(run_id_for_signal, &doc);

                // Convenience: if output_dir is outside the engagement report folder, mirror the
                // progress snapshot into the engagement folder. When output_dir already lives
                // under the engagement folder (our default), avoid redundant writes.
                let command_for_mode = match doc.get("command").and_then(|v| v.as_str()) {
                    Some(command) => command,
                    None => {
                        tracing::warn!(
                            "Progress document missing command while mirroring progress snapshot"
                        );
                        continue;
                    }
                };
                let report_dir = engagement_root_dir(run_id_for_signal);
                let mode = mode_folder_from_command(command_for_mode);
                let dst = report_dir.join(mode).join("progress.json");
                if dst != progress_path {
                    if let Some(parent) = dst.parent() {
                        if let Err(err) = std::fs::create_dir_all(parent) {
                            tracing::warn!(
                                "Failed to create mirrored progress dir '{}': {}",
                                parent.display(),
                                err
                            );
                            continue;
                        }
                    }
                    if let Err(err) =
                        zk_fuzzer::util::write_file_atomic(&dst, progress_raw.as_bytes())
                    {
                        tracing::warn!(
                            "Failed to write mirrored progress '{}': {}",
                            dst.display(),
                            err
                        );
                    }
                }
            }
        });
    }

    // Run with new engine if not using simple progress
    stage = "engine_run";
    if !options.dry_run {
        let doc = running_run_doc_with_window(
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            &output_dir,
            started_utc,
            options.timeout,
        );
        write_run_artifacts(&output_dir, &run_id, &doc);
    }
    let report = match if options.simple_progress {
        let mut fuzzer = ZkFuzzer::new(config, options.seed);
        fuzzer.run_with_workers(options.workers).await
    } else {
        ZkFuzzer::run_with_progress(config, options.seed, options.workers, options.verbose).await
    } {
        Ok(r) => r,
        Err(err) => {
            write_failed_mode_run_artifact_with_error(
                &output_dir,
                command,
                &run_id,
                stage,
                config_path,
                &campaign_name,
                started_utc,
                options.timeout,
                format!("{:#}", err),
            );
            return Err(err);
        }
    };

    // Output results
    stage = "save_report";
    report.print_summary();
    if let Err(err) = report.save_to_files() {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            options.timeout,
            format!("{:#}", err),
        );
        return Err(err);
    }

    let critical = report.has_critical_findings();
    let mut doc = completed_run_doc_with_window(
        command,
        &run_id,
        if critical {
            "completed_with_critical_findings"
        } else {
            "completed"
        },
        "completed",
        config_path,
        &campaign_name,
        &output_dir,
        started_utc,
        options.timeout,
    );
    doc["metrics"] = serde_json::json!({
        "findings_total": report.findings.len(),
        "critical_findings": critical,
        "total_executions": report.statistics.total_executions,
    });
    write_run_artifacts(&output_dir, &run_id, &doc);

    if critical {
        anyhow::bail!("Run completed with CRITICAL findings (see report.json/report.md)");
    }

    Ok(())
}

fn validate_campaign(config_path: &str) -> anyhow::Result<()> {
    tracing::info!("Validating campaign: {}", config_path);
    let mut config = FuzzConfig::from_yaml(config_path)?;

    // The validate subcommand should reflect the CLI defaults used by `run/evidence/chains`.
    // Otherwise the readiness report emits noisy iteration warnings for configs that intentionally
    // omit max_iterations and rely on CLI defaults.
    {
        let additional = &mut config.campaign.parameters.additional;
        if !config.chains.is_empty() {
            // Match `chains` defaults: iterations=100000, timeout=600.
            additional
                .entry("chain_iterations".to_string())
                .or_insert_with(|| serde_yaml::Value::Number(serde_yaml::Number::from(100_000u64)));
            additional
                .entry("chain_budget_seconds".to_string())
                .or_insert_with(|| serde_yaml::Value::Number(serde_yaml::Number::from(600u64)));

            // Match `chains` run behavior (strict evidence semantics for findings).
            additional
                .entry("evidence_mode".to_string())
                .or_insert_with(|| serde_yaml::Value::Bool(true));
            additional
                .entry("engagement_strict".to_string())
                .or_insert_with(|| serde_yaml::Value::Bool(true));
            additional
                .entry("strict_backend".to_string())
                .or_insert_with(|| serde_yaml::Value::Bool(true));
        } else {
            // Match `run/evidence` defaults: iterations=100000.
            additional
                .entry("fuzzing_iterations".to_string())
                .or_insert_with(|| serde_yaml::Value::Number(serde_yaml::Number::from(100_000u64)));
        }
    }

    println!("✓ Configuration is valid");
    println!();
    println!("Campaign Details:");
    println!("  Name: {}", config.campaign.name);
    println!("  Version: {}", config.campaign.version);
    println!("  Framework: {:?}", config.campaign.target.framework);
    println!("  Circuit: {:?}", config.campaign.target.circuit_path);
    println!(
        "  Main Component: {}",
        config.campaign.target.main_component
    );
    println!();
    println!("Attacks ({}):", config.attacks.len());
    for attack in &config.attacks {
        println!("  - {:?}: {}", attack.attack_type, attack.description);
    }
    println!();
    println!("Inputs ({}):", config.inputs.len());
    for input in &config.inputs {
        println!(
            "  - {}: {} ({:?})",
            input.name, input.input_type, input.fuzz_strategy
        );
    }

    // Phase 4C: 0-day readiness check
    println!();
    let readiness = zk_fuzzer::config::check_0day_readiness(&config);
    print!("{}", readiness.format());

    if !readiness.ready_for_evidence {
        anyhow::bail!("Campaign has critical issues - not ready for evidence mode");
    }

    Ok(())
}

fn minimize_corpus(corpus_dir: &str, output: Option<&str>) -> anyhow::Result<()> {
    use std::path::Path;
    use zk_fuzzer::corpus::{minimizer, storage};

    tracing::info!("Loading corpus from: {}", corpus_dir);

    let entries = storage::load_corpus_from_dir(Path::new(corpus_dir))?;
    tracing::info!("Loaded {} entries", entries.len());

    let minimized = minimizer::minimize_corpus(&entries);
    let stats = minimizer::MinimizationStats::compute(entries.len(), minimized.len());

    println!("Corpus minimization:");
    println!("  Original size: {}", stats.original_size);
    println!("  Minimized size: {}", stats.minimized_size);
    println!("  Reduction: {:.1}%", stats.reduction_percentage);

    if let Some(output_dir) = output {
        let output_path = Path::new(output_dir);
        std::fs::create_dir_all(output_path)?;

        for (i, entry) in minimized.iter().enumerate() {
            storage::save_test_case(entry, output_path, i)?;
        }

        println!("Saved minimized corpus to: {}", output_dir);
    }

    Ok(())
}

fn generate_sample_config(output: &str, framework: &str) -> anyhow::Result<()> {
    let (circuit_path, main_component) = match framework {
        "circom" => ("./circuits/example.circom", "Main"),
        "noir" => ("./circuits/example", "main"),
        "halo2" => ("./circuits/example.rs", "ExampleCircuit"),
        "cairo" => ("./circuits/example.cairo", "main"),
        _ => ("./circuits/example.circom", "Main"),
    };

    let sample = format!(
        r#"# ZK-Fuzzer Pattern Configuration
# Generated sample for {} framework.
# This file is pattern-only and is used with `zk-fuzzer scan`.

patterns:
  - id: "contains_main_component"
    kind: regex
    pattern: "template\\s+Main|fn\\s+main|struct\\s+ExampleCircuit"
    message: "Target source has an expected main entrypoint pattern"

attacks:
  - type: underconstrained
    description: "Find inputs that satisfy constraints but produce wrong outputs"
    config:
      witness_pairs: 1000
      # Optional: fix public inputs for consistent checks
      # public_input_names: ["input1"]
      # fixed_public_inputs: ["0x01"]

  - type: soundness
    description: "Attempt to create valid proofs for false statements"
    config:
      forge_attempts: 1000
      mutation_rate: 0.1

  - type: arithmetic_overflow
    description: "Test field arithmetic edge cases"
    config:
      test_values:
        - "0"
        - "1"
        - "p-1"
        - "p"

  - type: collision
    description: "Detect hash collisions or output collisions"
    config:
      samples: 10000

inputs:
  - name: "input1"
    type: "field"
    fuzz_strategy: random
    constraints:
      - "nonzero"

  - name: "input2"
    type: "field"
    fuzz_strategy: interesting_values
    interesting:
      - "0x0"
      - "0x1"
      - "0xdead"

invariants:
  - name: "input1_nonzero"
    invariant_type: "constraint"
    relation: "input1 != 0"
    severity: "medium"
"#,
        framework
    );

    std::fs::write(output, sample)?;
    println!("Generated sample pattern: {}", output);
    println!(
        "Run with: zk-fuzzer scan {} --target-circuit {} --main-component {} --framework {}",
        output, circuit_path, main_component, framework
    );

    Ok(())
}

fn print_banner(config: &FuzzConfig) {
    use colored::*;

    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".bright_cyan()
    );
    println!(
        "{}",
        "║              ZK-FUZZER v0.1.0                             ║".bright_cyan()
    );
    println!(
        "{}",
        "║       Zero-Knowledge Proof Security Tester                ║".bright_cyan()
    );
    println!(
        "{}",
        "╠═══════════════════════════════════════════════════════════╣".bright_cyan()
    );
    println!(
        "{}  Campaign: {:<45} {}",
        "║".bright_cyan(),
        truncate_str(&config.campaign.name, 45).white(),
        "║".bright_cyan()
    );
    println!(
        "{}  Target:   {:<45} {}",
        "║".bright_cyan(),
        format!("{:?}", config.campaign.target.framework).yellow(),
        "║".bright_cyan()
    );
    println!(
        "{}  Attacks:  {:<45} {}",
        "║".bright_cyan(),
        format!("{} configured", config.attacks.len()).green(),
        "║".bright_cyan()
    );
    println!(
        "{}  Inputs:   {:<45} {}",
        "║".bright_cyan(),
        format!("{} defined", config.inputs.len()).green(),
        "║".bright_cyan()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".bright_cyan()
    );
    println!();
}

fn print_run_window(start: DateTime<Local>, timeout_seconds: Option<u64>) {
    println!("RUN WINDOW");
    println!("  Start: {}", start.format("%Y-%m-%d %H:%M:%S %Z"));

    match timeout_seconds.and_then(|s| match i64::try_from(s) {
        Ok(seconds) => Some(seconds),
        Err(err) => {
            tracing::warn!("Timeout seconds value '{}' exceeds i64: {}", s, err);
            None
        }
    }) {
        Some(seconds) => {
            let expected_end = start + ChronoDuration::seconds(seconds);
            println!(
                "  Expected latest end: {} (timeout {}s)",
                expected_end.format("%Y-%m-%d %H:%M:%S %Z"),
                seconds
            );
            tracing::info!(
                "RUN_WINDOW start={} expected_latest_end={} timeout_seconds={}",
                start.to_rfc3339(),
                expected_end.to_rfc3339(),
                seconds
            );
        }
        None => {
            println!("  Expected latest end: unbounded (no --timeout)");
            tracing::info!(
                "RUN_WINDOW start={} expected_latest_end=unbounded",
                start.to_rfc3339()
            );
        }
    }
    println!();
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Run a chain-focused fuzzing campaign (Mode 3: Deepest)
async fn run_chain_campaign(config_path: &str, options: ChainRunOptions) -> anyhow::Result<()> {
    use colored::*;
    use zk_fuzzer::chain_fuzzer::{ChainCorpus, ChainFinding, DepthMetrics};
    use zk_fuzzer::config::parse_chains;
    use zk_fuzzer::fuzzer::FuzzingEngine;
    use zk_fuzzer::reporting::FuzzReport;

    let started_utc = Utc::now();
    let command = "chains";
    let run_id = make_run_id(command, Some(config_path));
    let report_dir = engagement_root_dir(&run_id);
    let mut stage = "load_config";
    tracing::info!("Report directory: {}", report_dir.display());

    // Put `session.log` under the engagement folder from the very start (even if YAML parsing
    // fails). This avoids scattering logs across multiple locations.
    set_run_log_context_for_campaign(
        options.dry_run,
        &run_id,
        command,
        config_path,
        None,
        None,
        &started_utc,
    );

    tracing::info!("Loading chain campaign from: {}", config_path);
    let mut config = match FuzzConfig::from_yaml(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            let ended_utc = Utc::now();
            write_failed_run_artifact_with_error(
                &run_id,
                command,
                stage,
                config_path,
                &started_utc,
                &ended_utc,
                format!("{:#}", err),
                None,
            );
            return Err(err);
        }
    };

    apply_scan_output_suffix_if_present(&mut config)?;

    let campaign_name = config.campaign.name.clone();

    let (output_dir, _output_lock) = initialize_campaign_run_lifecycle(
        options.dry_run,
        &mut config,
        command,
        &run_id,
        config_path,
        &campaign_name,
        started_utc,
        Some(options.timeout),
        serde_json::json!({
            "workers": options.workers,
            "seed": options.seed,
            "iterations": options.iterations,
            "timeout_seconds": options.timeout,
            "resume": options.resume,
            "simple_progress": options.simple_progress,
            "dry_run": options.dry_run,
        }),
    )?;

    let _ctx_guard = RunLogContextGuard::new();

    // Get chains from config
    stage = "parse_chains";
    let chains = parse_chains(&config);
    if chains.is_empty() {
        if !options.dry_run {
            write_failed_mode_run_artifact_with_reason(
                &output_dir,
                command,
                &run_id,
                stage,
                config_path,
                &campaign_name,
                started_utc,
                Some(options.timeout),
                "Chain mode requires chains: definitions in the YAML.".to_string(),
                None,
            );
        }
        anyhow::bail!(
            "Chain mode requires chains: definitions in the YAML. \
             See campaigns/templates/deepest_multistep.yaml for examples."
        );
    }

    // Force evidence mode settings for chain fuzzing
    config
        .campaign
        .parameters
        .additional
        .insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));
    config.campaign.parameters.additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config
        .campaign
        .parameters
        .additional
        .insert("strict_backend".to_string(), serde_yaml::Value::Bool(true));
    config.campaign.parameters.additional.insert(
        "chain_budget_seconds".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.timeout)),
    );
    config.campaign.parameters.additional.insert(
        "chain_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.iterations)),
    );
    config.campaign.parameters.additional.insert(
        "chain_resume".to_string(),
        serde_yaml::Value::Bool(options.resume),
    );

    // Pre-flight readiness check (chains need assertions; strict mode blocks silent runs).
    stage = "preflight_readiness";
    println!();
    let readiness = zk_fuzzer::config::check_0day_readiness(&config);
    print!("{}", readiness.format());
    require_evidence_readiness_or_emit_failure(
        options.dry_run,
        &output_dir,
        command,
        &run_id,
        stage,
        config_path,
        &campaign_name,
        started_utc,
        Some(options.timeout),
        &readiness,
        "Campaign has critical issues; refusing to start strict chain run",
    )?;

    stage = "preflight_backend";
    run_backend_preflight_or_emit_failure(
        options.dry_run,
        &config,
        &output_dir,
        command,
        &run_id,
        stage,
        config_path,
        &campaign_name,
        started_utc,
        Some(options.timeout),
    )?;

    // Print chain-specific banner
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".bright_magenta()
    );
    println!(
        "{}",
        "║         ZK-FUZZER v0.1.0 — MODE 3: CHAIN FUZZING          ║".bright_magenta()
    );
    println!(
        "{}",
        "║               Multi-Step Deep Bug Discovery               ║".bright_magenta()
    );
    println!(
        "{}",
        "╠═══════════════════════════════════════════════════════════╣".bright_magenta()
    );
    println!(
        "{}  Campaign: {:<45} {}",
        "║".bright_magenta(),
        truncate_str(&config.campaign.name, 45).white(),
        "║".bright_magenta()
    );
    println!(
        "{}  Chains:   {:<45} {}",
        "║".bright_magenta(),
        format!("{} defined", chains.len()).cyan(),
        "║".bright_magenta()
    );
    println!(
        "{}  Budget:   {:<45} {}",
        "║".bright_magenta(),
        format!("{}s total", options.timeout).yellow(),
        "║".bright_magenta()
    );
    println!(
        "{}  Resume:   {:<45} {}",
        "║".bright_magenta(),
        if options.resume {
            "yes".green()
        } else {
            "no".white()
        },
        "║".bright_magenta()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".bright_magenta()
    );
    println!();
    let run_start = Local::now();
    print_run_window(run_start, Some(options.timeout));

    if !options.dry_run {
        seed_running_run_artifact(
            &output_dir,
            command,
            &run_id,
            "starting_engine",
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            serde_json::json!({
                "workers": options.workers,
                "seed": options.seed,
                "iterations": options.iterations,
                "timeout_seconds": options.timeout,
                "resume": options.resume,
                "simple_progress": options.simple_progress,
                "dry_run": options.dry_run,
            }),
        );
    }

    // List chains
    println!("{}", "CHAINS TO FUZZ:".bright_yellow().bold());
    for chain in &chains {
        println!(
            "  {} {} ({} steps, {} assertions)",
            "→".bright_cyan(),
            chain.name.white(),
            chain.steps.len(),
            chain.assertions.len()
        );
    }
    println!();

    if options.dry_run {
        tracing::info!("Dry run mode - configuration validated successfully");
        println!("\n✓ Chain configuration is valid");
        return Ok(());
    }

    let corpus_path = output_dir.join("chain_corpus.json");
    let corpus_meta_path = output_dir.join("chain_corpus_meta.json");
    let read_chain_meta =
        |p: &std::path::Path| -> Option<zk_fuzzer::chain_fuzzer::ChainCorpusMeta> {
            match std::fs::read_to_string(p) {
                Ok(raw) => {
                    match serde_json::from_str::<zk_fuzzer::chain_fuzzer::ChainCorpusMeta>(&raw) {
                        Ok(meta) => Some(meta),
                        Err(err) => {
                            tracing::warn!(
                                "Invalid chain corpus metadata '{}': {}",
                                p.display(),
                                err
                            );
                            None
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to read chain corpus metadata '{}': {}",
                        p.display(),
                        err
                    );
                    None
                }
            }
        };
    let load_chain_corpus =
        |p: &std::path::Path| -> anyhow::Result<zk_fuzzer::chain_fuzzer::ChainCorpus> {
            if p.exists() {
                ChainCorpus::load(p)
                    .with_context(|| format!("Failed to load chain corpus from '{}'", p.display()))
            } else {
                Ok(ChainCorpus::with_storage(p))
            }
        };
    let read_chain_execution_count = |p: &std::path::Path| -> anyhow::Result<u64> {
        if !p.exists() {
            return Ok(0);
        }
        let corpus = load_chain_corpus(p)?;
        let total = corpus
            .entries()
            .iter()
            .map(|entry| entry.execution_count as u64)
            .sum();
        Ok(total)
    };
    let baseline_execution_count = if options.resume {
        read_chain_execution_count(&corpus_path)?
    } else {
        0
    };

    let baseline_meta = if options.resume && corpus_meta_path.exists() {
        read_chain_meta(&corpus_meta_path)
    } else {
        None
    };
    let (baseline_total_entries, baseline_unique_coverage_bits): (usize, usize) = if !options.resume
    {
        (0, 0)
    } else if let Some(meta) = &baseline_meta {
        (meta.total_entries, meta.unique_coverage_bits)
    } else {
        let baseline_corpus = load_chain_corpus(&corpus_path)?;
        let baseline_total_entries = baseline_corpus.len();
        let baseline_unique_coverage_bits: usize = {
            use std::collections::HashSet;
            baseline_corpus
                .entries()
                .iter()
                .map(|e| e.coverage_bits)
                .collect::<HashSet<_>>()
                .len()
        };
        (baseline_total_entries, baseline_unique_coverage_bits)
    };

    // Create engine directly
    stage = "engine_init";
    let mut engine = match FuzzingEngine::new(config.clone(), options.seed, options.workers) {
        Ok(e) => e,
        Err(err) => {
            write_failed_mode_run_artifact_with_error(
                &output_dir,
                command,
                &run_id,
                stage,
                config_path,
                &campaign_name,
                started_utc,
                Some(options.timeout),
                format!("{:#}", err),
            );
            return Err(err);
        }
    };

    // Run chain fuzzing
    let progress = if options.simple_progress {
        None
    } else {
        // Create a progress reporter for chain mode
        let total = (options.iterations as usize * chains.len()) as u64;
        Some(zk_fuzzer::progress::ProgressReporter::new(
            &format!("{} (chains)", config.campaign.name),
            total,
            options.verbose,
        ))
    };

    stage = "engine_run_chains";
    let chain_findings: Vec<ChainFinding> =
        match engine.run_chains(&chains, progress.as_ref()).await {
            Ok(findings) => findings,
            Err(err) => {
                write_failed_mode_run_artifact_with_error(
                    &output_dir,
                    command,
                    &run_id,
                    stage,
                    config_path,
                    &campaign_name,
                    started_utc,
                    Some(options.timeout),
                    format!("{:#}", err),
                );
                return Err(err);
            }
        };

    // Load chain corpus for quality/coverage metrics (persistent across runs).
    // Prefer meta sidecar to avoid parsing a large chain_corpus.json.
    let final_meta = if corpus_meta_path.exists() {
        read_chain_meta(&corpus_meta_path)
    } else {
        None
    };
    let (final_total_entries, final_unique_coverage_bits, final_max_depth): (usize, usize, usize) =
        if let Some(meta) = &final_meta {
            (
                meta.total_entries,
                meta.unique_coverage_bits,
                meta.max_depth,
            )
        } else {
            let final_corpus = load_chain_corpus(&corpus_path)?;
            let final_total_entries = final_corpus.len();
            let final_unique_coverage_bits: usize = {
                use std::collections::HashSet;
                final_corpus
                    .entries()
                    .iter()
                    .map(|e| e.coverage_bits)
                    .collect::<HashSet<_>>()
                    .len()
            };
            let final_max_depth = final_corpus.entries().iter().map(|e| e.depth_reached).max();
            let final_max_depth: usize = final_max_depth.unwrap_or_default();
            (
                final_total_entries,
                final_unique_coverage_bits,
                final_max_depth,
            )
        };
    let final_execution_count = read_chain_execution_count(&corpus_path)?;
    let run_execution_count = final_execution_count.saturating_sub(baseline_execution_count);

    // Engagement contract for Mode 3: refuse to report a "clean" run when exploration is too narrow.
    let engagement_strict = config
        .campaign
        .parameters
        .additional
        .get_bool("engagement_strict")
        .unwrap_or(true);
    let min_unique_coverage_bits = config
        .campaign
        .parameters
        .additional
        .get_usize("engagement_min_chain_unique_coverage_bits")
        .unwrap_or(2);
    let min_completed_per_chain = config
        .campaign
        .parameters
        .additional
        .get_usize("engagement_min_chain_completed_per_chain")
        .unwrap_or(1);

    let mut quality_failures: Vec<String> = Vec::new();
    for chain in &chains {
        let (completed, unique_cov): (usize, usize) = if let Some(meta) = &final_meta {
            match meta.per_chain.get(&chain.name) {
                Some(m) => (m.completed_traces, m.unique_coverage_bits),
                None => {
                    tracing::warn!(
                        "Chain corpus metadata missing per-chain entry for '{}'",
                        chain.name
                    );
                    (0, 0)
                }
            }
        } else {
            let final_corpus = load_chain_corpus(&corpus_path)?;
            let entries: Vec<_> = final_corpus
                .entries()
                .iter()
                .filter(|e| e.spec_name == chain.name)
                .collect();
            let completed = entries.len();
            let unique_cov: usize = {
                use std::collections::HashSet;
                entries
                    .iter()
                    .map(|e| e.coverage_bits)
                    .collect::<HashSet<_>>()
                    .len()
            };
            (completed, unique_cov)
        };
        if completed < min_completed_per_chain {
            quality_failures.push(format!(
                "chain '{}' completed_traces={} < min_completed_per_chain={}",
                chain.name, completed, min_completed_per_chain
            ));
        }
        if unique_cov < min_unique_coverage_bits {
            quality_failures.push(format!(
                "chain '{}' unique_coverage_bits={} < min_unique_coverage_bits={}",
                chain.name, unique_cov, min_unique_coverage_bits
            ));
        }
    }
    let run_valid = quality_failures.is_empty();

    // Compute metrics
    let metrics = DepthMetrics::new(chain_findings.clone());
    let summary = metrics.summary();

    // Print results
    println!();
    println!("{}", "═".repeat(60).bright_magenta());
    println!("{}", "  CHAIN FUZZING RESULTS".bright_white().bold());
    println!("{}", "═".repeat(60).bright_magenta());

    println!("\n{}", "DEPTH METRICS".bright_yellow().bold());
    println!("  Total Chain Findings:  {}", summary.total_findings);
    println!("  Mean L_min (D):        {:.2}", summary.d_mean);
    println!("  P(L_min >= 2):         {:.1}%", summary.p_deep * 100.0);
    println!();
    println!("{}", "CORPUS / EXPLORATION METRICS".bright_yellow().bold());
    println!(
        "  Corpus entries:            {} (Δ {})",
        final_total_entries,
        final_total_entries.saturating_sub(baseline_total_entries)
    );
    println!(
        "  Unique coverage bits:      {} (Δ {})",
        final_unique_coverage_bits,
        final_unique_coverage_bits.saturating_sub(baseline_unique_coverage_bits)
    );
    println!("  Max depth reached:         {}", final_max_depth);

    if !summary.depth_distribution.is_empty() {
        println!("\n{}", "DEPTH DISTRIBUTION".bright_yellow().bold());
        let mut depths: Vec<_> = summary.depth_distribution.iter().collect();
        depths.sort_by_key(|(k, _)| *k);
        for (depth, count) in depths {
            let bar = "█".repeat((*count).min(30));
            println!("  L_min={}: {} ({})", depth, bar.bright_cyan(), count);
        }
    }

    if !chain_findings.is_empty() {
        println!("\n{}", "CHAIN FINDINGS".bright_yellow().bold());
        for (i, finding) in chain_findings.iter().enumerate() {
            let severity_str = match finding.finding.severity.to_uppercase().as_str() {
                "CRITICAL" => format!("[{}]", finding.finding.severity)
                    .bright_red()
                    .bold(),
                "HIGH" => format!("[{}]", finding.finding.severity).red(),
                "MEDIUM" => format!("[{}]", finding.finding.severity).yellow(),
                "LOW" => format!("[{}]", finding.finding.severity).bright_yellow(),
                _ => format!("[{}]", finding.finding.severity).white(),
            };

            println!(
                "\n  {}. {} Chain: {} (L_min: {})",
                i + 1,
                severity_str,
                finding.spec_name.cyan(),
                finding.l_min.to_string().bright_green()
            );
            println!("     {}", finding.finding.description);

            if let Some(ref assertion) = finding.violated_assertion {
                println!("     Violated: {}", assertion.bright_red());
            }

            // Print reproduction command
            println!("     {}", "Reproduction:".bright_yellow());
            println!(
                "       cargo run --release -- chains {} --seed {}",
                config_path,
                options.seed.unwrap_or(42)
            );
        }
    } else if run_valid {
        println!(
            "\n{}",
            "  ✓ No chain vulnerabilities found!".bright_green().bold()
        );
    } else {
        println!(
            "\n{}",
            "  ✗ Run invalid: exploration too narrow to treat as 'clean'"
                .bright_red()
                .bold()
        );
        for failure in &quality_failures {
            println!("     - {}", failure);
        }
    }

    println!("\n{}", "═".repeat(60).bright_magenta());

    // Save reports
    stage = "save_chain_reports";
    if let Err(err) = std::fs::create_dir_all(&output_dir) {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            format!("{:#}", err),
        );
        return Err(err.into());
    }

    // Save chain findings as JSON
    let chain_report_path = output_dir.join("chain_report.json");
    let chain_report = serde_json::json!({
        "campaign_name": config.campaign.name,
        "mode": "chain_fuzzing",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "engagement": {
            "strict": engagement_strict,
            "valid_run": run_valid,
            "failures": quality_failures,
            "thresholds": {
                "min_unique_coverage_bits": min_unique_coverage_bits,
                "min_completed_per_chain": min_completed_per_chain,
            },
        },
        "metrics": {
            "total_findings": summary.total_findings,
            "d_mean": summary.d_mean,
            "p_deep": summary.p_deep,
            "depth_distribution": summary.depth_distribution,
        },
        "corpus_metrics": {
            "corpus_entries": final_total_entries,
            "unique_coverage_bits": final_unique_coverage_bits,
            "max_depth": final_max_depth,
            "baseline": {
                "corpus_entries": baseline_total_entries,
                "unique_coverage_bits": baseline_unique_coverage_bits,
            }
        },
        "chain_findings": chain_findings,
    });
    if let Err(err) = (|| -> anyhow::Result<()> {
        use std::io::{BufWriter, Write};
        let f = std::fs::File::create(&chain_report_path)?;
        let mut w = BufWriter::new(f);
        serde_json::to_writer_pretty(&mut w, &chain_report)?;
        w.flush()?;
        Ok(())
    })() {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            format!("{:#}", err),
        );
        return Err(err);
    }
    tracing::info!("Saved chain report to {:?}", chain_report_path);

    // Save chain findings as markdown
    let chain_md_path = output_dir.join("chain_report.md");
    let mut md = String::new();
    md.push_str(&format!(
        "# Chain Fuzzing Report: {}\n\n",
        config.campaign.name
    ));
    md.push_str("**Mode:** Multi-Step Chain Fuzzing (Mode 3)\n");
    md.push_str(&format!(
        "**Generated:** {}\n\n",
        chrono::Utc::now().to_rfc3339()
    ));

    md.push_str("## Engagement Validation\n\n");
    md.push_str(&format!("**Strict:** {}\n", engagement_strict));
    md.push_str(&format!(
        "**Valid Run:** {}\n",
        if run_valid { "yes" } else { "no" }
    ));
    md.push_str(&format!(
        "**Thresholds:** min_unique_coverage_bits={}, min_completed_per_chain={}\n\n",
        min_unique_coverage_bits, min_completed_per_chain
    ));

    md.push_str("### Corpus / Exploration Metrics\n\n");
    md.push_str(&format!(
        "- Corpus entries: {} (delta {})\n",
        final_total_entries,
        final_total_entries.saturating_sub(baseline_total_entries)
    ));
    md.push_str(&format!(
        "- Unique coverage bits: {} (delta {})\n",
        final_unique_coverage_bits,
        final_unique_coverage_bits.saturating_sub(baseline_unique_coverage_bits)
    ));
    md.push_str(&format!("- Max depth: {}\n\n", final_max_depth));

    if !quality_failures.is_empty() {
        md.push_str("### Failures\n\n");
        for failure in &quality_failures {
            md.push_str(&format!("- {}\n", failure));
        }
        md.push('\n');
    }

    md.push_str("## Depth Metrics\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Total Findings | {} |\n",
        summary.total_findings
    ));
    md.push_str(&format!("| Mean L_min (D) | {:.2} |\n", summary.d_mean));
    md.push_str(&format!(
        "| P(L_min >= 2) | {:.1}% |\n\n",
        summary.p_deep * 100.0
    ));

    if !chain_findings.is_empty() {
        md.push_str("## Chain Findings\n\n");
        for (i, finding) in chain_findings.iter().enumerate() {
            md.push_str(&format!(
                "### {}. [{}] Chain: {}\n\n",
                i + 1,
                finding.finding.severity.to_uppercase(),
                finding.spec_name
            ));
            md.push_str(&format!("**L_min:** {}\n\n", finding.l_min));
            md.push_str(&format!("{}\n\n", finding.finding.description));

            if let Some(ref assertion) = finding.violated_assertion {
                md.push_str(&format!("**Violated Assertion:** `{}`\n\n", assertion));
            }

            // Add trace summary
            md.push_str("**Trace:**\n\n");
            for (step_idx, step) in finding.trace.steps.iter().enumerate() {
                let status = if step.success { "✓" } else { "✗" };
                md.push_str(&format!(
                    "- Step {}: {} `{}` - {}\n",
                    step_idx,
                    status,
                    step.circuit_ref,
                    if step.success {
                        "success"
                    } else {
                        step.error.as_deref().unwrap_or("failed")
                    }
                ));
            }
            md.push('\n');

            // Add reproduction
            md.push_str("**Reproduction:**\n\n");
            md.push_str(&format!(
                "```bash\ncargo run --release -- chains {} --seed {}\n```\n\n",
                config_path,
                options.seed.unwrap_or(42)
            ));
        }
    }

    if let Err(err) = std::fs::write(&chain_md_path, md) {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            format!("{:#}", err),
        );
        return Err(err.into());
    }
    tracing::info!("Saved chain markdown report to {:?}", chain_md_path);

    // Convert chain findings to regular findings for standard report
    let standard_findings: Vec<_> = chain_findings.iter().map(|cf| cf.to_finding()).collect();

    // Create standard report with chain findings merged in
    let mut report = FuzzReport::new(
        config.campaign.name.clone(),
        standard_findings,
        zk_core::CoverageMap::default(),
        config.reporting.clone(),
    );
    report.statistics.total_executions = run_execution_count;
    stage = "save_standard_report";
    if let Err(err) = report.save_to_files() {
        write_failed_mode_run_artifact_with_error(
            &output_dir,
            command,
            &run_id,
            stage,
            config_path,
            &campaign_name,
            started_utc,
            Some(options.timeout),
            format!("{:#}", err),
        );
        return Err(err);
    }

    let critical = chain_findings
        .iter()
        .any(|f| f.finding.severity.to_lowercase() == "critical");
    let status = if critical {
        "completed_with_critical_findings"
    } else if engagement_strict && !run_valid {
        "failed_engagement_contract"
    } else {
        "completed"
    };

    stage = "completed";
    let mut doc = completed_run_doc_with_window(
        command,
        &run_id,
        status,
        stage,
        config_path,
        &campaign_name,
        &output_dir,
        started_utc,
        Some(options.timeout),
    );
    doc["metrics"] = serde_json::json!({
        "chain_findings_total": summary.total_findings,
        "critical_findings": critical,
        "corpus_entries": final_total_entries,
        "unique_coverage_bits": final_unique_coverage_bits,
        "max_depth": final_max_depth,
        "d_mean": summary.d_mean,
        "p_deep": summary.p_deep,
    });
    doc["engagement"] = serde_json::json!({
        "strict": engagement_strict,
        "valid_run": run_valid,
        "failures": quality_failures,
        "thresholds": {
            "min_unique_coverage_bits": min_unique_coverage_bits,
            "min_completed_per_chain": min_completed_per_chain,
        }
    });
    write_run_artifacts(&output_dir, &run_id, &doc);

    if critical {
        anyhow::bail!("Chain run produced CRITICAL findings (see chain_report.json/report.json)");
    }
    if engagement_strict && !run_valid {
        anyhow::bail!(
            "Strict chain run failed engagement contract; see chain_report.json for details"
        );
    }

    Ok(())
}

#[cfg(test)]
mod scan_selector_tests;
