pub mod file_lock;

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Build a deterministic per-trial benchmark output root to avoid cross-trial collisions.
pub fn benchmark_scan_output_root(
    output_dir: &Path,
    suite_name: &str,
    target_name: &str,
    trial_idx: usize,
    seed: u64,
) -> PathBuf {
    output_dir
        .join("scan_outputs")
        .join(suite_name)
        .join(target_name)
        .join(format!("trial_{}_seed_{}", trial_idx, seed))
}

/// Write file contents atomically by writing to a temp sibling file and renaming.
///
/// This ensures readers either observe the old full file or the new full file,
/// but never a partially written snapshot.
pub fn write_file_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let file_name = file_name.to_string_lossy();

    let mut last_err: Option<io::Error> = None;
    for attempt in 0..8u8 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let tmp_name = format!(
            ".{}.tmp.{}.{}.{}",
            file_name,
            std::process::id(),
            nanos,
            attempt
        );
        let tmp_path: PathBuf = parent.join(tmp_name);

        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
        {
            Ok(mut tmp_file) => {
                if let Err(err) = (|| -> io::Result<()> {
                    tmp_file.write_all(data)?;
                    tmp_file.sync_all()?;
                    drop(tmp_file);
                    std::fs::rename(&tmp_path, path)?;
                    Ok(())
                })() {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(err);
                }
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                last_err = Some(err);
                continue;
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::other("failed to allocate temporary file for atomic write")))
}
