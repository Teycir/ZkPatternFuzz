use std::path::Path;
use std::time::{Duration, Instant};

fn output_lock_wait_seconds() -> u64 {
    let default_wait_secs = 2u64;
    let Some(raw) = super::read_optional_env("ZKF_OUTPUT_LOCK_WAIT_SECS") else {
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

pub(crate) fn acquire_output_dir_lock(
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
