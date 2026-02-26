use anyhow::Context;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

pub(super) fn run_log_file_cache() -> &'static Mutex<HashMap<PathBuf, fs::File>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, fs::File>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn append_run_log(path: &Path, message: impl AsRef<str>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create run log directory '{}'", parent.display())
        })?;
    }

    let path_buf = path.to_path_buf();
    let mut cache = run_log_file_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let file = match cache.entry(path_buf.clone()) {
        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::hash_map::Entry::Vacant(entry) => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path_buf)
                .with_context(|| format!("Failed to open run log '{}'", path.display()))?;
            entry.insert(file)
        }
    };

    writeln!(file, "{}", message.as_ref())
        .with_context(|| format!("Failed to write run log '{}'", path.display()))?;
    file.flush()
        .with_context(|| format!("Failed to flush run log '{}'", path.display()))?;
    Ok(())
}

pub(super) fn append_run_log_best_effort(path: &Path, message: impl AsRef<str>) {
    if let Err(err) = append_run_log(path, message) {
        eprintln!("run.log write failed ({}): {:#}", path.display(), err);
    }
}

pub(super) fn step_started(
    step: usize,
    total_steps: usize,
    label: &str,
    run_log: &Path,
) -> Instant {
    println!("[STEP {}/{}] {}: started", step, total_steps, label);
    append_run_log_best_effort(
        run_log,
        format!("step={} status=started", label.replace(' ', "_")),
    );
    Instant::now()
}

pub(super) fn step_succeeded(
    step: usize,
    total_steps: usize,
    label: &str,
    started_at: Instant,
    run_log: &Path,
) {
    let elapsed_secs = started_at.elapsed().as_secs_f64();
    println!(
        "[STEP {}/{}] {}: completed ({:.1}s)",
        step, total_steps, label, elapsed_secs
    );
    append_run_log_best_effort(
        run_log,
        format!(
            "step={} status=completed elapsed_secs={:.3}",
            label.replace(' ', "_"),
            elapsed_secs
        ),
    );
}

pub(super) fn step_skipped(
    step: usize,
    total_steps: usize,
    label: &str,
    reason: &str,
    run_log: &Path,
) {
    println!(
        "[STEP {}/{}] {}: skipped ({})",
        step, total_steps, label, reason
    );
    append_run_log_best_effort(
        run_log,
        format!(
            "step={} status=skipped reason={}",
            label.replace(' ', "_"),
            reason
        ),
    );
}

pub(super) fn step_failed(
    step: usize,
    total_steps: usize,
    label: &str,
    started_at: Instant,
    run_log: &Path,
    err: &anyhow::Error,
) {
    let elapsed_secs = started_at.elapsed().as_secs_f64();
    println!(
        "[STEP {}/{}] {}: FAILED ({:.1}s)",
        step, total_steps, label, elapsed_secs
    );
    append_run_log_best_effort(
        run_log,
        format!(
            "step={} status=failed elapsed_secs={:.3} error={}",
            label.replace(' ', "_"),
            elapsed_secs,
            err.to_string().replace('\n', " | ")
        ),
    );
}
