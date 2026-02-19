use chrono::{DateTime, Utc};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::{engagement_root_dir, run_signal_dir};

#[derive(Debug, Clone)]
pub(crate) struct RunLogContext {
    pub(crate) run_id: String,
    pub(crate) command: String,
    pub(crate) campaign_path: Option<String>,
    pub(crate) campaign_name: Option<String>,
    pub(crate) output_dir: Option<PathBuf>,
    pub(crate) started_utc: String,
}

static RUN_LOG_CONTEXT: OnceLock<Mutex<Option<RunLogContext>>> = OnceLock::new();
static DYNAMIC_LOG_FILE: OnceLock<Mutex<Option<(PathBuf, std::fs::File)>>> = OnceLock::new();

pub(crate) struct DynamicLogWriter;

pub(crate) struct DynamicTeeWriter;

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

        // Best-effort file output with non-blocking approach
        let _ = Self::with_log_file(|file| file.write_all(buf).map(|_| ()));

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Err(err) = io::stderr().flush() {
            eprintln!("[zk-fuzzer] WARN: failed flushing stderr: {}", err);
        }
        let _ = Self::with_log_file(|file| file.flush());
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

pub(crate) fn get_run_log_context() -> Option<RunLogContext> {
    let slot = RUN_LOG_CONTEXT.get_or_init(|| Mutex::new(None));
    match slot.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => {
            tracing::warn!("Run log context mutex poisoned, recovering data");
            poisoned.into_inner().clone()
        }
    }
}

pub(crate) struct RunLogContextGuard;

impl RunLogContextGuard {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Drop for RunLogContextGuard {
    fn drop(&mut self) {
        set_run_log_context(None);
    }
}

pub(crate) fn set_run_log_context_for_campaign(
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
