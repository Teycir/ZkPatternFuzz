use chrono::Utc;
use std::sync::OnceLock;

use crate::engagement_artifacts::write_run_artifacts;
use crate::make_run_id;
use crate::run_lifecycle::write_failed_run_artifact;
use crate::run_log_context::get_run_log_context;

static PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();
static SIGNAL_WATCHER_STARTED: OnceLock<()> = OnceLock::new();

pub(crate) fn install_panic_hook() {
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

pub(crate) fn start_signal_watchers() {
    if SIGNAL_WATCHER_STARTED.set(()).is_err() {
        return;
    }

    tokio::spawn(async move {
        let mut sigint = Box::pin(tokio::signal::ctrl_c());

        #[cfg(unix)]
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to install SIGTERM handler: {}", e);
                    return;
                }
            };

        #[cfg(not(unix))]
        let mut sigterm: Option<()> = None;

        let stop = async {
            #[cfg(unix)]
            {
                tokio::select! {
                    _ = &mut sigint => "SIGINT",
                    _ = sigterm.recv() => "SIGTERM",
                }
            }

            #[cfg(not(unix))]
            {
                let _ = sigint;
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
