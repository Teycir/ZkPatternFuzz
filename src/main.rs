use clap::{Parser, Subcommand};
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use zk_fuzzer::config::{FuzzConfig, ProfileName, ReadinessReport, apply_profile};
use zk_fuzzer::fuzzer::ZkFuzzer;

#[derive(Debug, Clone)]
struct RunLogContext {
    run_id: String,
    command: String,
    campaign_path: Option<String>,
    campaign_name: Option<String>,
    output_dir: Option<PathBuf>,
    started_utc: String,
}

static RUN_LOG_CONTEXT: OnceLock<Mutex<Option<RunLogContext>>> = OnceLock::new();
static PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();
static SIGNAL_WATCHER_STARTED: OnceLock<()> = OnceLock::new();

fn set_run_log_context(ctx: Option<RunLogContext>) {
    let slot = RUN_LOG_CONTEXT.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = slot.lock() {
        *guard = ctx;
    }
}

fn get_run_log_context() -> Option<RunLogContext> {
    let slot = RUN_LOG_CONTEXT.get_or_init(|| Mutex::new(None));
    slot.lock().ok().and_then(|g| g.clone())
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
    out.trim_matches('_').to_string()
}

fn derive_campaign_slug(campaign_path: &str) -> String {
    Path::new(campaign_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(sanitize_slug)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown_campaign".to_string())
}

fn make_run_id(command: &str, campaign_path: Option<&str>) -> String {
    let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let pid = std::process::id();
    let campaign = campaign_path
        .map(derive_campaign_slug)
        .unwrap_or_else(|| "unknown_campaign".to_string());
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
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(data) = serde_json::to_string_pretty(value) {
        let _ = std::fs::write(path, data);
    }
}

fn run_signal_dir() -> PathBuf {
    // Base folder where "easy to find" run folders are written.
    //
    // Default matches your requested structure:
    //   /home/teycir/ZkFuzzReports/report_<epoch>/
    //
    // Override with:
    //   ZKF_RUN_SIGNAL_DIR=/some/other/base
    //
    // If writing outside the repo is not allowed in your environment, set it back to:
    //   ZKF_RUN_SIGNAL_DIR=reports/_run_signals
    if let Ok(v) = std::env::var("ZKF_RUN_SIGNAL_DIR") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        let home = home.trim();
        if !home.is_empty() {
            return PathBuf::from(home).join("ZkFuzzReports");
        }
    }

    PathBuf::from("reports/_run_signals")
}

fn best_effort_append_jsonl(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(line) = serde_json::to_string(value) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

fn run_id_epoch_dir(run_id: &str) -> Option<String> {
    // run_id prefix is make_run_id(): "%Y%m%d_%H%M%S_..."
    if run_id.len() < 15 {
        return None;
    }
    let ts = &run_id[..15];
    let naive = chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%d_%H%M%S").ok()?;
    let started_utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
    Some(format!("report_{}", started_utc.timestamp()))
}

fn engagement_dir_name(run_id: &str) -> String {
    // Allow grouping multiple processes (mode1 + mode2 + mode3) into the same report folder.
    //
    // Example:
    //   export ZKF_ENGAGEMENT_EPOCH=176963063
    //   ... run mode1, mode2, mode3 ...
    //   => /home/teycir/ZkFuzzReports/report_176963063/
    if let Ok(epoch) = std::env::var("ZKF_ENGAGEMENT_EPOCH") {
        let trimmed = epoch.trim();
        if !trimmed.is_empty() {
            return format!("report_{}", trimmed);
        }
    }

    if let Ok(name) = std::env::var("ZKF_ENGAGEMENT_NAME") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    run_id_epoch_dir(run_id).unwrap_or_else(|| "report_unknown".to_string())
}

fn engagement_root_dir(run_id: &str) -> PathBuf {
    // If ZKF_ENGAGEMENT_DIR is set, use it as the full report folder.
    if let Ok(dir) = std::env::var("ZKF_ENGAGEMENT_DIR") {
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

fn get_command_from_doc(value: &serde_json::Value) -> String {
    value
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string()
}

fn update_engagement_summary(report_dir: &Path, value: &serde_json::Value) {
    let now = Utc::now().to_rfc3339();
    let command = get_command_from_doc(value);
    let mode = mode_folder_from_command(&command).to_string();

    let summary_path = report_dir.join("summary.json");
    let mut summary: serde_json::Value = std::fs::read_to_string(&summary_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| {
            serde_json::json!({
                "updated_utc": now,
                "modes": {},
            })
        });

    if let Some(obj) = summary.as_object_mut() {
        obj.insert("updated_utc".to_string(), serde_json::Value::String(now.clone()));
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
                let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");
                let run_id = v.get("run_id").and_then(|s| s.as_str()).unwrap_or("unknown");
                let campaign = v.get("campaign_name").and_then(|s| s.as_str()).unwrap_or("unknown");
                let started = v.get("started_utc").and_then(|s| s.as_str()).unwrap_or("unknown");
                let ended = v.get("ended_utc").and_then(|s| s.as_str()).unwrap_or("");
                md.push_str(&format!("- Status: `{}`\n", status));
                md.push_str(&format!("- Run ID: `{}`\n", run_id));
                md.push_str(&format!("- Campaign: `{}`\n", campaign));
                md.push_str(&format!("- Started (UTC): `{}`\n", started));
                if !ended.is_empty() {
                    md.push_str(&format!("- Ended (UTC): `{}`\n", ended));
                }

                if let Some(window) = v.get("run_window") {
                    if let Some(exp) = window.get("expected_latest_end_utc").and_then(|s| s.as_str()) {
                        md.push_str(&format!("- Expected latest end (UTC): `{}`\n", exp));
                    }
                    if let Some(sem) = window.get("timeout_semantics").and_then(|s| s.as_str()) {
                        md.push_str(&format!("- Timeout semantics: `{}`\n", sem));
                    }
                }

                if let Some(metrics) = v.get("metrics") {
                    if let Some(total) = metrics.get("findings_total").and_then(|n| n.as_u64()) {
                        md.push_str(&format!("- Findings: `{}`\n", total));
                    } else if let Some(total) = metrics.get("chain_findings_total").and_then(|n| n.as_u64()) {
                        md.push_str(&format!("- Findings: `{}`\n", total));
                    }
                    if let Some(crit) = metrics.get("critical_findings").and_then(|b| b.as_bool()) {
                        md.push_str(&format!("- Critical: `{}`\n", crit));
                    }
                }
            } else {
                md.push_str("- Not run in this engagement yet.\n");
            }
            md.push_str("\n");
        }
    }

    let md_path = report_dir.join("summary.md");
    if let Some(parent) = md_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(md_path, md);
}

fn add_run_window_fields(
    doc: &mut serde_json::Value,
    started_utc: DateTime<Utc>,
    timeout_seconds: Option<u64>,
    timeout_semantics: &'static str,
) {
    let started_local = started_utc.with_timezone(&Local);
    let expected_end_utc = timeout_seconds
        .and_then(|s| i64::try_from(s).ok())
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
                    "continuous_phase_only" => "In run/evidence modes, --timeout applies to the continuous fuzzing phase only; setup + attacks may extend wall time.",
                    "wall_clock" => "In chains mode, --timeout is the total wall-clock budget for the chain fuzzing run.",
                    _ => "",
                },
            }),
        );
    }
}

fn write_global_run_signal(run_id: &str, value: &serde_json::Value) {
    let base = run_signal_dir();
    let report_dir = engagement_root_dir(run_id);
    let command = get_command_from_doc(value);
    let mode = mode_folder_from_command(&command);

    // Log/event stream (engagement-wide + per-run).
    let log_dir = report_dir.join("log");
    best_effort_append_jsonl(&log_dir.join("events.jsonl"), value);
    best_effort_append_jsonl(&log_dir.join(format!("events_{}.jsonl", run_id)), value);

    // Latest pointers.
    best_effort_write_json(&report_dir.join("latest.json"), value);
    best_effort_write_json(&report_dir.join(mode).join("latest.json"), value);
    best_effort_write_json(&base.join("latest.json"), value);

    // Per-run snapshot (stored under its mode).
    best_effort_write_json(
        &report_dir
            .join(mode)
            .join("runs")
            .join(run_id)
            .join("run_event.json"),
        value,
    );

    update_engagement_summary(&report_dir, value);
}

fn write_run_artifacts(output_dir: &Path, run_id: &str, value: &serde_json::Value) {
    best_effort_write_json(&output_dir.join("run_outcome.json"), value);
    let runs_dir = output_dir.join("_runs");
    best_effort_write_json(&runs_dir.join(format!("{}.json", run_id)), value);
    best_effort_write_json(&output_dir.join("run_status.json"), value);
    write_global_run_signal(run_id, value);

    // Best-effort mirror of the "human-facing" reports into the engagement folder, so you can
    // find mode1/mode2/mode3 outputs in one place.
    let report_dir = engagement_root_dir(run_id);
    let command = get_command_from_doc(value);
    let mode = mode_folder_from_command(&command);
    let dst_dir = report_dir.join(mode).join("runs").join(run_id);
    let _ = std::fs::create_dir_all(&dst_dir);

    for name in [
        "report.json",
        "report.md",
        "progress.json",
        "chain_report.json",
        "chain_report.md",
        "run_outcome.json",
        "run_status.json",
    ] {
        let src = output_dir.join(name);
        if src.exists() {
            let _ = std::fs::copy(&src, dst_dir.join(name));
        }
    }
}

fn write_failed_run_artifact(run_id: &str, value: &serde_json::Value) {
    let failed_dir = PathBuf::from("reports/_failed_runs");
    best_effort_write_json(&failed_dir.join(format!("{}.json", run_id)), value);
    write_global_run_signal(run_id, value);
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
        let run_id = ctx
            .as_ref()
            .map(|c| c.run_id.clone())
            .unwrap_or_else(|| make_run_id("panic", None));

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
        let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            Ok(s) => Some(s),
            Err(_) => None,
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
                            let _ = s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => "SIGTERM",
                }
            }

            #[cfg(not(unix))]
            {
                sigint.await.ok();
                "SIGINT"
            }
        };

        let signal_name = stop.await;
        let now = Utc::now().to_rfc3339();
        let ctx = get_run_log_context();
        let run_id = ctx
            .as_ref()
            .map(|c| c.run_id.clone())
            .unwrap_or_else(|| make_run_id("interrupted", None));

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
#[command(long_about = "A comprehensive fuzzing framework for detecting vulnerabilities in ZK circuits.\n\nSupports Circom, Noir, Halo2, and Cairo backends with coverage-guided fuzzing,\nmultiple attack vectors, and detailed vulnerability reporting.")]
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
    /// Run a fuzzing campaign
    Run {
        /// Path to campaign YAML file
        campaign: String,
        
        /// Number of continuous fuzzing iterations (Phase 0)
        #[arg(short, long, default_value = "100000")]
        iterations: u64,
        
        /// Timeout in seconds for continuous fuzzing phase
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Resume from existing corpus (loads from reports/<campaign>/corpus/)
        #[arg(long)]
        resume: bool,

        /// Custom corpus directory for resume (default: reports/<campaign>/corpus/)
        #[arg(long)]
        corpus_dir: Option<String>,
    },
    /// Run an evidence-focused campaign (requires invariants)
    Evidence {
        /// Path to campaign YAML file
        campaign: String,

        /// Number of continuous fuzzing iterations (Phase 0)
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Timeout in seconds for continuous fuzzing phase
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Resume from existing corpus (loads from reports/<campaign>/corpus/)
        #[arg(long)]
        resume: bool,

        /// Custom corpus directory for resume (default: reports/<campaign>/corpus/)
        #[arg(long)]
        corpus_dir: Option<String>,
    },
    /// Run multi-step chain fuzzing (Mode 3: Deepest)
    Chains {
        /// Path to campaign YAML file with chain definitions
        campaign: String,

        /// Number of chain fuzzing iterations
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Timeout in seconds for chain fuzzing
        #[arg(short, long, default_value = "600")]
        timeout: u64,

        /// Resume from existing chain corpus
        #[arg(long)]
        resume: bool,
    },
    /// Validate a campaign configuration
    Validate {
        /// Path to campaign YAML file
        campaign: String,
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
        .args(["-f", "zk-fuzzer"])
        .output();
    
    if let Ok(output) = pgrep_output {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        // Try graceful shutdown first (SIGTERM)
                        let _ = std::process::Command::new("kill")
                            .args(["-15", &pid.to_string()])
                            .output();
                    }
                }
            }
            
            // Wait for graceful shutdown
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // Force kill any remaining processes (SIGKILL)
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        let _ = std::process::Command::new("kill")
                            .args(["-9", &pid.to_string()])
                            .output();
                    }
                }
            }
            
            eprintln!("Terminated existing zk-fuzzer instances (excluding PID {})", current_pid);
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
        .init();

    // Ensure early-stop causes are captured to disk when possible (panic/signal).
    install_panic_hook();
    start_signal_watchers();

    match cli.command {
        Some(Commands::Run { campaign, iterations, timeout, resume, corpus_dir }) => {
            run_campaign(
                &campaign,
                CampaignRunOptions {
                    workers: cli.workers,
                    seed: cli.seed,
                    verbose: cli.verbose,
                    dry_run: cli.dry_run,
                    simple_progress: cli.simple_progress,
                    real_only: cli.real_only,
                    iterations,
                    timeout,
                    require_invariants: false,
                    resume,
                    corpus_dir,
                    profile: cli.profile.clone(),
                },
            )
            .await
        }
        Some(Commands::Evidence { campaign, iterations, timeout, resume, corpus_dir }) => {
            run_campaign(
                &campaign,
                CampaignRunOptions {
                    workers: cli.workers,
                    seed: cli.seed,
                    verbose: cli.verbose,
                    dry_run: cli.dry_run,
                    simple_progress: cli.simple_progress,
                    real_only: true, // Evidence mode always requires real backend
                    iterations,
                    timeout,
                    require_invariants: true,
                    resume,
                    corpus_dir,
                    profile: cli.profile.clone(),
                },
            )
            .await
        }
        Some(Commands::Chains { campaign, iterations, timeout, resume }) => {
            run_chain_campaign(
                &campaign,
                ChainRunOptions {
                    workers: cli.workers,
                    seed: cli.seed,
                    verbose: cli.verbose,
                    dry_run: cli.dry_run,
                    simple_progress: cli.simple_progress,
                    iterations,
                    timeout,
                    resume,
                },
            )
            .await
        }
        Some(Commands::Validate { campaign }) => {
            validate_campaign(&campaign)
        }
        Some(Commands::Minimize { corpus_dir, output }) => {
            minimize_corpus(&corpus_dir, output.as_deref())
        }
        Some(Commands::Init { output, framework }) => {
            generate_sample_config(&output, &framework)
        }
        Some(Commands::ExecWorker) => {
            zk_fuzzer::executor::run_exec_worker()
        }
        None => {
            // Default behavior: run with config if provided
            if let Some(config_path) = cli.config {
                // Use default values for iterations and timeout
                run_campaign(
                    &config_path,
                    CampaignRunOptions {
                        workers: cli.workers,
                        seed: cli.seed,
                        verbose: cli.verbose,
                        dry_run: cli.dry_run,
                        simple_progress: cli.simple_progress,
                        real_only: cli.real_only,
                        iterations: 1000,
                        timeout: None,
                        require_invariants: false,
                        resume: false, // resume
                        corpus_dir: None,
                        profile: cli.profile.clone(),
                    },
                )
                .await
            } else {
                anyhow::bail!(
                    "No campaign configuration provided. Use `zk-fuzzer --config <path>` or `zk-fuzzer run <path>`."
                );
            }
        }
    }
}

async fn run_campaign(config_path: &str, options: CampaignRunOptions) -> anyhow::Result<()> {
    let started_utc = Utc::now();
    let command = if options.require_invariants { "evidence" } else { "run" };
    let run_id = make_run_id(command, Some(config_path));
    let mut stage = "load_config";

    tracing::info!("Loading campaign from: {}", config_path);
    let mut config = match FuzzConfig::from_yaml(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            let ended_utc = Utc::now();
            let doc = serde_json::json!({
                "status": "failed",
                "command": command,
                "run_id": run_id.clone(),
                "stage": stage,
                "pid": std::process::id(),
                "campaign_path": config_path,
                "started_utc": started_utc.to_rfc3339(),
                "ended_utc": ended_utc.to_rfc3339(),
                "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                "error": format!("{:#}", err),
            });
            write_failed_run_artifact(&run_id, &doc);
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
                let doc = serde_json::json!({
                    "status": "failed",
                    "command": command,
                    "run_id": run_id.clone(),
                    "stage": stage,
                    "pid": std::process::id(),
                    "campaign_path": config_path,
                    "output_dir": config.reporting.output_dir.display().to_string(),
                    "started_utc": started_utc.to_rfc3339(),
                    "ended_utc": ended_utc.to_rfc3339(),
                    "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                    "error": e,
                });
                write_failed_run_artifact(&run_id, &doc);
                return Err(anyhow::anyhow!(
                    "Invalid --profile '{}': {}",
                    profile_name,
                    doc["error"].as_str().unwrap_or("parse error")
                ));
            }
        }
    }

    let campaign_name = config.campaign.name.clone();

    if options.real_only {
        tracing::info!("--real-only set (real backend mode is already enforced)");
    }

    // Always enforce strict backend in this CLI.
    config.campaign.parameters.additional.insert(
        "strict_backend".to_string(),
        serde_yaml::Value::Bool(true),
    );

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

    // Prevent multi-process collisions on the same output dir (reports/corpus/report.json, etc.).
    // Skip in --dry-run since no files are written.
    stage = "acquire_output_lock";
    let output_dir = config.reporting.output_dir.clone();
    let _output_lock = if options.dry_run {
        None
    } else {
        Some(match zk_fuzzer::util::file_lock::lock_dir_exclusive(
            &output_dir,
            ".zkfuzz.lock",
            zk_fuzzer::util::file_lock::LockMode::NonBlocking,
        ) {
            Ok(lock) => lock,
            Err(err) => {
                let ended_utc = Utc::now();
                let doc = serde_json::json!({
                    "status": "failed",
                    "command": command,
                    "run_id": run_id.clone(),
                    "stage": stage,
                    "pid": std::process::id(),
                    "campaign_path": config_path,
                    "campaign_name": campaign_name.clone(),
                    "output_dir": output_dir.display().to_string(),
                    "started_utc": started_utc.to_rfc3339(),
                    "ended_utc": ended_utc.to_rfc3339(),
                    "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                    "error": format!("{:#}", err),
                    "hint": "Output directory is already locked by another process. Choose a different reporting.output_dir or wait for the other run to finish.",
                });
                write_failed_run_artifact(&run_id, &doc);
                return Err(anyhow::anyhow!(
                    "Output directory is already in use (locked): {}. Error: {:#}",
                    output_dir.display(),
                    err
                ));
            }
        })
    };

    if !options.dry_run {
        set_run_log_context(Some(RunLogContext {
            run_id: run_id.clone(),
            command: command.to_string(),
            campaign_path: Some(config_path.to_string()),
            campaign_name: Some(config.campaign.name.clone()),
            output_dir: Some(output_dir.clone()),
            started_utc: started_utc.to_rfc3339(),
        }));

        // Seed a persistent status file early so "it stopped" cases always leave artifacts.
        let mut doc = serde_json::json!({
            "status": "running",
            "command": command,
            "run_id": run_id.clone(),
            "stage": stage,
            "pid": std::process::id(),
            "campaign_path": config_path,
            "campaign_name": campaign_name.clone(),
            "output_dir": output_dir.display().to_string(),
            "started_utc": started_utc.to_rfc3339(),
            "options": {
                "workers": options.workers,
                "seed": options.seed,
                "iterations": options.iterations,
                "timeout_seconds": options.timeout,
                "resume": options.resume,
                "corpus_dir": options.corpus_dir.clone(),
                "profile": options.profile.clone(),
                "simple_progress": options.simple_progress,
                "dry_run": options.dry_run,
            }
        });
        add_run_window_fields(&mut doc, started_utc, options.timeout, "continuous_phase_only");
        write_run_artifacts(&output_dir, &run_id, &doc);
    }

    struct _ClearRunContext;
    impl Drop for _ClearRunContext {
        fn drop(&mut self) {
            set_run_log_context(None);
        }
    }
    let _ctx_guard = _ClearRunContext;

    // Evidence mode settings + preflight checks.
    if options.require_invariants {
        stage = "preflight_invariants";
        let invariants = config.get_invariants();
        if invariants.is_empty() {
            let ended_utc = Utc::now();
            let mut doc = serde_json::json!({
                "status": "failed",
                "command": command,
                "run_id": run_id.clone(),
                "stage": stage,
                "pid": std::process::id(),
                "campaign_path": config_path,
                "campaign_name": campaign_name.clone(),
                "output_dir": output_dir.display().to_string(),
                "started_utc": started_utc.to_rfc3339(),
                "ended_utc": ended_utc.to_rfc3339(),
                "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                "reason": "Evidence mode requires v2 invariants in the YAML (invariants: ...).",
            });
            add_run_window_fields(&mut doc, started_utc, options.timeout, "continuous_phase_only");
            if !options.dry_run {
                write_run_artifacts(&output_dir, &run_id, &doc);
            }
            anyhow::bail!("Evidence mode requires v2 invariants in the YAML (invariants: ...).");
        }

        config.campaign.parameters.additional.insert(
            "evidence_mode".to_string(),
            serde_yaml::Value::Bool(true),
        );
        config.campaign.parameters.additional.insert(
            "engagement_strict".to_string(),
            serde_yaml::Value::Bool(true),
        );
        config.campaign.parameters.additional.insert(
            "strict_backend".to_string(),
            serde_yaml::Value::Bool(true),
        );

        // Pre-flight readiness check for strict evidence engagements.
        stage = "preflight_readiness";
        println!();
        let readiness = zk_fuzzer::config::check_0day_readiness(&config);
        print!("{}", readiness.format());
        if !readiness.ready_for_evidence {
            let ended_utc = Utc::now();
            let mut doc = serde_json::json!({
                "status": "failed",
                "command": command,
                "run_id": run_id.clone(),
                "stage": stage,
                "pid": std::process::id(),
                "campaign_path": config_path,
                "campaign_name": campaign_name.clone(),
                "output_dir": output_dir.display().to_string(),
                "started_utc": started_utc.to_rfc3339(),
                "ended_utc": ended_utc.to_rfc3339(),
                "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                "reason": "Campaign has critical issues; refusing to start strict evidence run",
                "readiness": readiness_report_to_json(&readiness),
            });
            add_run_window_fields(&mut doc, started_utc, options.timeout, "continuous_phase_only");
            if !options.dry_run {
                write_run_artifacts(&output_dir, &run_id, &doc);
            }
            anyhow::bail!("Campaign has critical issues; refusing to start strict evidence run");
        }
    }

    // Print banner
    print_banner(&config);
    let run_start = Local::now();
    print_run_window(run_start, options.timeout);

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
            tracing::warn!("Resume requested but corpus directory not found: {:?}", corpus_path);
            println!("⚠️  Corpus directory not found, starting fresh: {}", corpus_path.display());
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
            let _ = self.0.send(true);
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
        let pid = std::process::id();

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
                    Err(_) => continue,
                };
                let progress_json: serde_json::Value = match serde_json::from_str(&progress_raw) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let mut doc = serde_json::json!({
                    "status": "running",
                    "command": command_for_monitor,
                    "run_id": run_id_for_monitor,
                    "stage": "engine_progress",
                    "pid": pid,
                    "campaign_path": campaign_path_for_monitor,
                    "campaign_name": campaign_name_for_monitor,
                    "output_dir": output_dir_for_monitor.display().to_string(),
                    "started_utc": started_utc_for_monitor.to_rfc3339(),
                    "progress": progress_json,
                });
                add_run_window_fields(&mut doc, started_utc_for_monitor, timeout_for_monitor, "continuous_phase_only");
                write_global_run_signal(doc["run_id"].as_str().unwrap_or("unknown"), &doc);

                // Convenience: copy the raw progress.json into the engagement folder.
                let report_dir = engagement_root_dir(doc["run_id"].as_str().unwrap_or("unknown"));
                let mode = mode_folder_from_command(doc["command"].as_str().unwrap_or("unknown"));
                let dst = report_dir.join(mode).join("progress.json");
                if let Some(parent) = dst.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(dst, progress_raw);
            }
        });
    }

    // Run with new engine if not using simple progress
    stage = "engine_run";
    let report = match if options.simple_progress {
        let mut fuzzer = ZkFuzzer::new(config, options.seed);
        fuzzer.run_with_workers(options.workers).await
    } else {
        ZkFuzzer::run_with_progress(config, options.seed, options.workers, options.verbose).await
    } {
        Ok(r) => r,
        Err(err) => {
            let ended_utc = Utc::now();
            let mut doc = serde_json::json!({
                "status": "failed",
                "command": command,
                "run_id": run_id.clone(),
                "stage": stage,
                "pid": std::process::id(),
                "campaign_path": config_path,
                "campaign_name": campaign_name.clone(),
                "output_dir": output_dir.display().to_string(),
                "started_utc": started_utc.to_rfc3339(),
                "ended_utc": ended_utc.to_rfc3339(),
                "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                "error": format!("{:#}", err),
            });
            add_run_window_fields(&mut doc, started_utc, options.timeout, "continuous_phase_only");
            write_run_artifacts(&output_dir, &run_id, &doc);
            return Err(err);
        }
    };

    // Output results
    stage = "save_report";
    report.print_summary();
    if let Err(err) = report.save_to_files() {
        let ended_utc = Utc::now();
        let mut doc = serde_json::json!({
            "status": "failed",
            "command": command,
            "run_id": run_id.clone(),
            "stage": stage,
            "pid": std::process::id(),
            "campaign_path": config_path,
            "campaign_name": campaign_name.clone(),
            "output_dir": output_dir.display().to_string(),
            "started_utc": started_utc.to_rfc3339(),
            "ended_utc": ended_utc.to_rfc3339(),
            "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
            "error": format!("{:#}", err),
        });
        add_run_window_fields(&mut doc, started_utc, options.timeout, "continuous_phase_only");
        write_run_artifacts(&output_dir, &run_id, &doc);
        return Err(err);
    }

    let ended_utc = Utc::now();
    let critical = report.has_critical_findings();
    let mut doc = serde_json::json!({
        "status": if critical { "completed_with_critical_findings" } else { "completed" },
        "command": command,
        "run_id": run_id.clone(),
        "stage": "completed",
        "pid": std::process::id(),
        "campaign_path": config_path,
        "campaign_name": campaign_name.clone(),
        "output_dir": output_dir.display().to_string(),
        "started_utc": started_utc.to_rfc3339(),
        "ended_utc": ended_utc.to_rfc3339(),
        "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
        "metrics": {
            "findings_total": report.findings.len(),
            "critical_findings": critical,
            "total_executions": report.statistics.total_executions,
        },
    });
    add_run_window_fields(&mut doc, started_utc, options.timeout, "continuous_phase_only");
    write_run_artifacts(&output_dir, &run_id, &doc);

    if critical {
        anyhow::bail!("Run completed with CRITICAL findings (see report.json/report.md)");
    }

    Ok(())
}

fn validate_campaign(config_path: &str) -> anyhow::Result<()> {
    tracing::info!("Validating campaign: {}", config_path);
    let config = FuzzConfig::from_yaml(config_path)?;

    println!("✓ Configuration is valid");
    println!();
    println!("Campaign Details:");
    println!("  Name: {}", config.campaign.name);
    println!("  Version: {}", config.campaign.version);
    println!("  Framework: {:?}", config.campaign.target.framework);
    println!("  Circuit: {:?}", config.campaign.target.circuit_path);
    println!("  Main Component: {}", config.campaign.target.main_component);
    println!();
    println!("Attacks ({}):", config.attacks.len());
    for attack in &config.attacks {
        println!("  - {:?}: {}", attack.attack_type, attack.description);
    }
    println!();
    println!("Inputs ({}):", config.inputs.len());
    for input in &config.inputs {
        println!("  - {}: {} ({:?})", input.name, input.input_type, input.fuzz_strategy);
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
    use zk_fuzzer::corpus::{minimizer, storage};
    use std::path::Path;

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
    
    let sample = format!(r#"# ZK-Fuzzer Campaign Configuration
# Generated sample for {} framework

campaign:
  name: "Sample {} Audit"
  version: "1.0"
  target:
    framework: "{}"
    circuit_path: "{}"
    main_component: "{}"

  parameters:
    field: "bn254"
    max_constraints: 100000
    timeout_seconds: 300
    # NOTE: campaign.parameters is a flattened key/value map.
    # Do NOT nest under `additional:` (legacy templates used that shape).
    strict_backend: true
    mark_fallback: true

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

reporting:
  output_dir: "./reports"
  formats:
    - json
    - markdown
  include_poc: true
  crash_reproduction: true
"#, framework, framework, framework, circuit_path, main_component);

    std::fs::write(output, sample)?;
    println!("Generated sample configuration: {}", output);
    println!("Edit this file and run: zk-fuzzer run {}", output);

    Ok(())
}

fn print_banner(config: &FuzzConfig) {
    use colored::*;

    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║              ZK-FUZZER v0.1.0                             ║".bright_cyan());
    println!("{}", "║       Zero-Knowledge Proof Security Tester                ║".bright_cyan());
    println!("{}", "╠═══════════════════════════════════════════════════════════╣".bright_cyan());
    println!("{}  Campaign: {:<45} {}", "║".bright_cyan(), truncate_str(&config.campaign.name, 45).white(), "║".bright_cyan());
    println!("{}  Target:   {:<45} {}", "║".bright_cyan(), format!("{:?}", config.campaign.target.framework).yellow(), "║".bright_cyan());
    println!("{}  Attacks:  {:<45} {}", "║".bright_cyan(), format!("{} configured", config.attacks.len()).green(), "║".bright_cyan());
    println!("{}  Inputs:   {:<45} {}", "║".bright_cyan(), format!("{} defined", config.inputs.len()).green(), "║".bright_cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

fn print_run_window(start: DateTime<Local>, timeout_seconds: Option<u64>) {
    println!("RUN WINDOW");
    println!(
        "  Start: {}",
        start.format("%Y-%m-%d %H:%M:%S %Z")
    );

    match timeout_seconds.and_then(|s| i64::try_from(s).ok()) {
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
    let mut stage = "load_config";

    tracing::info!("Loading chain campaign from: {}", config_path);
    let mut config = match FuzzConfig::from_yaml(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            let ended_utc = Utc::now();
            let doc = serde_json::json!({
                "status": "failed",
                "command": command,
                "run_id": run_id.clone(),
                "stage": stage,
                "pid": std::process::id(),
                "campaign_path": config_path,
                "started_utc": started_utc.to_rfc3339(),
                "ended_utc": ended_utc.to_rfc3339(),
                "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                "error": format!("{:#}", err),
            });
            write_failed_run_artifact(&run_id, &doc);
            return Err(err);
        }
    };

    let campaign_name = config.campaign.name.clone();

    // Prevent multi-process collisions on the same output dir (chain_corpus.json, reports, etc.).
    // Skip in --dry-run since no files are written.
    stage = "acquire_output_lock";
    let output_dir = config.reporting.output_dir.clone();
    let _output_lock = if options.dry_run {
        None
    } else {
        Some(match zk_fuzzer::util::file_lock::lock_dir_exclusive(
            &output_dir,
            ".zkfuzz.lock",
            zk_fuzzer::util::file_lock::LockMode::NonBlocking,
        ) {
            Ok(lock) => lock,
            Err(err) => {
                let ended_utc = Utc::now();
                let doc = serde_json::json!({
                    "status": "failed",
                    "command": command,
                    "run_id": run_id.clone(),
                    "stage": stage,
                    "pid": std::process::id(),
                    "campaign_path": config_path,
                    "campaign_name": campaign_name.clone(),
                    "output_dir": output_dir.display().to_string(),
                    "started_utc": started_utc.to_rfc3339(),
                    "ended_utc": ended_utc.to_rfc3339(),
                    "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                    "error": format!("{:#}", err),
                    "hint": "Output directory is already locked by another process. Choose a different reporting.output_dir or wait for the other run to finish.",
                });
                write_failed_run_artifact(&run_id, &doc);
                return Err(anyhow::anyhow!(
                    "Output directory is already in use (locked): {}. Error: {:#}",
                    output_dir.display(),
                    err
                ));
            }
        })
    };

    if !options.dry_run {
        set_run_log_context(Some(RunLogContext {
            run_id: run_id.clone(),
            command: command.to_string(),
            campaign_path: Some(config_path.to_string()),
            campaign_name: Some(campaign_name.clone()),
            output_dir: Some(output_dir.clone()),
            started_utc: started_utc.to_rfc3339(),
        }));

        let mut doc = serde_json::json!({
            "status": "running",
            "command": command,
            "run_id": run_id.clone(),
            "stage": stage,
            "pid": std::process::id(),
            "campaign_path": config_path,
            "campaign_name": campaign_name.clone(),
            "output_dir": output_dir.display().to_string(),
            "started_utc": started_utc.to_rfc3339(),
            "options": {
                "workers": options.workers,
                "seed": options.seed,
                "iterations": options.iterations,
                "timeout_seconds": options.timeout,
                "resume": options.resume,
                "simple_progress": options.simple_progress,
                "dry_run": options.dry_run,
            }
        });
        add_run_window_fields(&mut doc, started_utc, Some(options.timeout), "wall_clock");
        write_run_artifacts(&output_dir, &run_id, &doc);
    }

    struct _ClearRunContext;
    impl Drop for _ClearRunContext {
        fn drop(&mut self) {
            set_run_log_context(None);
        }
    }
    let _ctx_guard = _ClearRunContext;

    // Get chains from config
    stage = "parse_chains";
    let chains = parse_chains(&config);
    if chains.is_empty() {
        let ended_utc = Utc::now();
        let doc = serde_json::json!({
            "status": "failed",
            "command": command,
            "run_id": run_id.clone(),
            "stage": stage,
            "pid": std::process::id(),
            "campaign_path": config_path,
            "campaign_name": campaign_name.clone(),
            "output_dir": output_dir.display().to_string(),
            "started_utc": started_utc.to_rfc3339(),
            "ended_utc": ended_utc.to_rfc3339(),
            "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
            "reason": "Chain mode requires chains: definitions in the YAML.",
        });
        if !options.dry_run {
            write_run_artifacts(&output_dir, &run_id, &doc);
        }
        anyhow::bail!(
            "Chain mode requires chains: definitions in the YAML. \
             See campaigns/templates/deepest_multistep.yaml for examples."
        );
    }

    // Force evidence mode settings for chain fuzzing
    config.campaign.parameters.additional.insert(
        "evidence_mode".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "strict_backend".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config.campaign.parameters.additional.insert(
        "chain_budget_seconds".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.timeout)),
    );
    config.campaign.parameters.additional.insert(
        "chain_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.iterations)),
    );

    // Pre-flight readiness check (chains need assertions; strict mode blocks silent runs).
    stage = "preflight_readiness";
    println!();
    let readiness = zk_fuzzer::config::check_0day_readiness(&config);
    print!("{}", readiness.format());
    if !readiness.ready_for_evidence {
        let ended_utc = Utc::now();
        let doc = serde_json::json!({
            "status": "failed",
            "command": command,
            "run_id": run_id.clone(),
            "stage": stage,
            "pid": std::process::id(),
            "campaign_path": config_path,
            "campaign_name": campaign_name.clone(),
            "output_dir": output_dir.display().to_string(),
            "started_utc": started_utc.to_rfc3339(),
            "ended_utc": ended_utc.to_rfc3339(),
            "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
            "reason": "Campaign has critical issues; refusing to start strict chain run",
            "readiness": readiness_report_to_json(&readiness),
        });
        if !options.dry_run {
            write_run_artifacts(&output_dir, &run_id, &doc);
        }
        anyhow::bail!("Campaign has critical issues; refusing to start strict chain run");
    }

    // Print chain-specific banner
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".bright_magenta());
    println!("{}", "║         ZK-FUZZER v0.1.0 — MODE 3: CHAIN FUZZING          ║".bright_magenta());
    println!("{}", "║               Multi-Step Deep Bug Discovery               ║".bright_magenta());
    println!("{}", "╠═══════════════════════════════════════════════════════════╣".bright_magenta());
    println!("{}  Campaign: {:<45} {}", "║".bright_magenta(), truncate_str(&config.campaign.name, 45).white(), "║".bright_magenta());
    println!("{}  Chains:   {:<45} {}", "║".bright_magenta(), format!("{} defined", chains.len()).cyan(), "║".bright_magenta());
    println!("{}  Budget:   {:<45} {}", "║".bright_magenta(), format!("{}s total", options.timeout).yellow(), "║".bright_magenta());
    println!("{}  Resume:   {:<45} {}", "║".bright_magenta(), if options.resume { "yes".green() } else { "no".white() }, "║".bright_magenta());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".bright_magenta());
    println!();
    let run_start = Local::now();
    print_run_window(run_start, Some(options.timeout));

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
    let baseline_corpus = ChainCorpus::load(&corpus_path).unwrap_or_else(|_| ChainCorpus::with_storage(&corpus_path));
    let baseline_total_entries = baseline_corpus.len();
    let baseline_unique_coverage_bits: usize = {
        use std::collections::HashSet;
        baseline_corpus.entries().iter().map(|e| e.coverage_bits).collect::<HashSet<_>>().len()
    };

    // Create engine directly
    stage = "engine_init";
    let mut engine = match FuzzingEngine::new(config.clone(), options.seed, options.workers) {
        Ok(e) => e,
        Err(err) => {
            let ended_utc = Utc::now();
            let doc = serde_json::json!({
                "status": "failed",
                "command": command,
                "run_id": run_id.clone(),
                "stage": stage,
                "pid": std::process::id(),
                "campaign_path": config_path,
                "campaign_name": campaign_name.clone(),
                "output_dir": output_dir.display().to_string(),
                "started_utc": started_utc.to_rfc3339(),
                "ended_utc": ended_utc.to_rfc3339(),
                "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                "error": format!("{:#}", err),
            });
            write_run_artifacts(&output_dir, &run_id, &doc);
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

    let chain_findings: Vec<ChainFinding> = engine.run_chains(&chains, progress.as_ref()).await;

    // Load chain corpus for quality/coverage metrics (persistent across runs).
    let final_corpus = ChainCorpus::load(&corpus_path).unwrap_or_else(|_| ChainCorpus::with_storage(&corpus_path));
    let final_total_entries = final_corpus.len();
    let final_unique_coverage_bits: usize = {
        use std::collections::HashSet;
        final_corpus.entries().iter().map(|e| e.coverage_bits).collect::<HashSet<_>>().len()
    };
    let final_max_depth = final_corpus
        .entries()
        .iter()
        .map(|e| e.depth_reached)
        .max()
        .unwrap_or(0);

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
        let entries: Vec<_> = final_corpus
            .entries()
            .iter()
            .filter(|e| e.spec_name == chain.name)
            .collect();
        let completed = entries.len();
        let unique_cov: usize = {
            use std::collections::HashSet;
            entries.iter().map(|e| e.coverage_bits).collect::<HashSet<_>>().len()
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
    println!("  Corpus entries:            {} (Δ {})", final_total_entries, final_total_entries.saturating_sub(baseline_total_entries));
    println!("  Unique coverage bits:      {} (Δ {})", final_unique_coverage_bits, final_unique_coverage_bits.saturating_sub(baseline_unique_coverage_bits));
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
                "CRITICAL" => format!("[{}]", finding.finding.severity).bright_red().bold(),
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
            println!("       cargo run --release -- chains {} --seed {}", 
                config_path, options.seed.unwrap_or(42));
        }
    } else {
        if run_valid {
            println!("\n{}", "  ✓ No chain vulnerabilities found!".bright_green().bold());
        } else {
            println!(
                "\n{}",
                "  ✗ Run invalid: exploration too narrow to treat as 'clean'".bright_red().bold()
            );
            for failure in &quality_failures {
                println!("     - {}", failure);
            }
        }
    }

    println!("\n{}", "═".repeat(60).bright_magenta());

    // Save reports
    stage = "save_chain_reports";
    if let Err(err) = std::fs::create_dir_all(&output_dir) {
        let ended_utc = Utc::now();
        let doc = serde_json::json!({
            "status": "failed",
            "command": command,
            "run_id": run_id.clone(),
            "stage": stage,
            "pid": std::process::id(),
            "campaign_path": config_path,
            "campaign_name": campaign_name.clone(),
            "output_dir": output_dir.display().to_string(),
            "started_utc": started_utc.to_rfc3339(),
            "ended_utc": ended_utc.to_rfc3339(),
            "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
            "error": format!("{:#}", err),
        });
        write_run_artifacts(&output_dir, &run_id, &doc);
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
    let chain_report_json = match serde_json::to_string_pretty(&chain_report) {
        Ok(s) => s,
        Err(err) => {
            let ended_utc = Utc::now();
            let doc = serde_json::json!({
                "status": "failed",
                "command": command,
                "run_id": run_id.clone(),
                "stage": stage,
                "pid": std::process::id(),
                "campaign_path": config_path,
                "campaign_name": campaign_name.clone(),
                "output_dir": output_dir.display().to_string(),
                "started_utc": started_utc.to_rfc3339(),
                "ended_utc": ended_utc.to_rfc3339(),
                "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
                "error": format!("{:#}", err),
            });
            write_run_artifacts(&output_dir, &run_id, &doc);
            return Err(err.into());
        }
    };
    if let Err(err) = std::fs::write(&chain_report_path, chain_report_json) {
        let ended_utc = Utc::now();
        let doc = serde_json::json!({
            "status": "failed",
            "command": command,
            "run_id": run_id.clone(),
            "stage": stage,
            "pid": std::process::id(),
            "campaign_path": config_path,
            "campaign_name": campaign_name.clone(),
            "output_dir": output_dir.display().to_string(),
            "started_utc": started_utc.to_rfc3339(),
            "ended_utc": ended_utc.to_rfc3339(),
            "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
            "error": format!("{:#}", err),
        });
        write_run_artifacts(&output_dir, &run_id, &doc);
        return Err(err.into());
    }
    tracing::info!("Saved chain report to {:?}", chain_report_path);

    // Save chain findings as markdown
    let chain_md_path = output_dir.join("chain_report.md");
    let mut md = String::new();
    md.push_str(&format!("# Chain Fuzzing Report: {}\n\n", config.campaign.name));
    md.push_str("**Mode:** Multi-Step Chain Fuzzing (Mode 3)\n");
    md.push_str(&format!("**Generated:** {}\n\n", chrono::Utc::now().to_rfc3339()));

    md.push_str("## Engagement Validation\n\n");
    md.push_str(&format!("**Strict:** {}\n", engagement_strict));
    md.push_str(&format!("**Valid Run:** {}\n", if run_valid { "yes" } else { "no" }));
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
    md.push_str(&format!("| Total Findings | {} |\n", summary.total_findings));
    md.push_str(&format!("| Mean L_min (D) | {:.2} |\n", summary.d_mean));
    md.push_str(&format!("| P(L_min >= 2) | {:.1}% |\n\n", summary.p_deep * 100.0));

    if !chain_findings.is_empty() {
        md.push_str("## Chain Findings\n\n");
        for (i, finding) in chain_findings.iter().enumerate() {
            md.push_str(&format!("### {}. [{}] Chain: {}\n\n", i + 1, finding.finding.severity.to_uppercase(), finding.spec_name));
            md.push_str(&format!("**L_min:** {}\n\n", finding.l_min));
            md.push_str(&format!("{}\n\n", finding.finding.description));
            
            if let Some(ref assertion) = finding.violated_assertion {
                md.push_str(&format!("**Violated Assertion:** `{}`\n\n", assertion));
            }

            // Add trace summary
            md.push_str("**Trace:**\n\n");
            for (step_idx, step) in finding.trace.steps.iter().enumerate() {
                let status = if step.success { "✓" } else { "✗" };
                md.push_str(&format!("- Step {}: {} `{}` - {}\n", 
                    step_idx, status, step.circuit_ref,
                    if step.success { "success" } else { step.error.as_deref().unwrap_or("failed") }
                ));
            }
            md.push('\n');

            // Add reproduction
            md.push_str("**Reproduction:**\n\n");
            md.push_str(&format!("```bash\ncargo run --release -- chains {} --seed {}\n```\n\n", 
                config_path, options.seed.unwrap_or(42)));
        }
    }

    if let Err(err) = std::fs::write(&chain_md_path, md) {
        let ended_utc = Utc::now();
        let doc = serde_json::json!({
            "status": "failed",
            "command": command,
            "run_id": run_id.clone(),
            "stage": stage,
            "pid": std::process::id(),
            "campaign_path": config_path,
            "campaign_name": campaign_name.clone(),
            "output_dir": output_dir.display().to_string(),
            "started_utc": started_utc.to_rfc3339(),
            "ended_utc": ended_utc.to_rfc3339(),
            "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
            "error": format!("{:#}", err),
        });
        write_run_artifacts(&output_dir, &run_id, &doc);
        return Err(err.into());
    }
    tracing::info!("Saved chain markdown report to {:?}", chain_md_path);

    // Convert chain findings to regular findings for standard report
    let standard_findings: Vec<_> = chain_findings.iter()
        .map(|cf| cf.to_finding())
        .collect();

    // Create standard report with chain findings merged in
    let mut report = FuzzReport::new(
        config.campaign.name.clone(),
        standard_findings,
        zk_core::CoverageMap::default(),
        config.reporting.clone(),
    );
    report.statistics.total_executions = options.iterations * chains.len() as u64;
    stage = "save_standard_report";
    if let Err(err) = report.save_to_files() {
        let ended_utc = Utc::now();
        let doc = serde_json::json!({
            "status": "failed",
            "command": command,
            "run_id": run_id.clone(),
            "stage": stage,
            "pid": std::process::id(),
            "campaign_path": config_path,
            "campaign_name": campaign_name.clone(),
            "output_dir": output_dir.display().to_string(),
            "started_utc": started_utc.to_rfc3339(),
            "ended_utc": ended_utc.to_rfc3339(),
            "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
            "error": format!("{:#}", err),
        });
        write_run_artifacts(&output_dir, &run_id, &doc);
        return Err(err);
    }

    let critical = chain_findings
        .iter()
        .any(|f| f.finding.severity.to_lowercase() == "critical");
    let ended_utc = Utc::now();
    let status = if critical {
        "completed_with_critical_findings"
    } else if engagement_strict && !run_valid {
        "failed_engagement_contract"
    } else {
        "completed"
    };

    stage = "completed";
    let mut doc = serde_json::json!({
        "status": status,
        "command": command,
        "run_id": run_id.clone(),
        "stage": stage,
        "pid": std::process::id(),
        "campaign_path": config_path,
        "campaign_name": campaign_name.clone(),
        "output_dir": output_dir.display().to_string(),
        "started_utc": started_utc.to_rfc3339(),
        "ended_utc": ended_utc.to_rfc3339(),
        "duration_seconds": (ended_utc - started_utc).num_seconds().max(0),
        "metrics": {
            "chain_findings_total": summary.total_findings,
            "critical_findings": critical,
            "corpus_entries": final_total_entries,
            "unique_coverage_bits": final_unique_coverage_bits,
            "max_depth": final_max_depth,
            "d_mean": summary.d_mean,
            "p_deep": summary.p_deep,
        },
        "engagement": {
            "strict": engagement_strict,
            "valid_run": run_valid,
            "failures": quality_failures,
            "thresholds": {
                "min_unique_coverage_bits": min_unique_coverage_bits,
                "min_completed_per_chain": min_completed_per_chain,
            }
        }
    });
    add_run_window_fields(&mut doc, started_utc, Some(options.timeout), "wall_clock");
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
