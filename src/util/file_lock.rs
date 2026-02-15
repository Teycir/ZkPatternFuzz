use anyhow::Context;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Blocking,
    NonBlocking,
}

#[derive(Debug)]
pub struct FileLock {
    path: PathBuf,
    file: File,
}

impl FileLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
fn flock(file: &File, operation: i32) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn flock(_file: &File, _operation: i32) -> std::io::Result<()> {
    // Best-effort no-op on non-Unix platforms.
    Ok(())
}

impl Drop for FileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if let Err(e) = flock(&self.file, libc::LOCK_UN) {
                tracing::warn!(
                    "Failed to unlock file lock {}: {}",
                    self.path.display(),
                    e
                );
            }
        }
    }
}

pub fn lock_file_exclusive(path: impl AsRef<Path>, mode: LockMode) -> anyhow::Result<FileLock> {
    let path = path.as_ref().to_path_buf();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("Failed to open lock file: {}", path.display()))?;

    #[cfg(unix)]
    {
        let mut op = libc::LOCK_EX;
        if mode == LockMode::NonBlocking {
            op |= libc::LOCK_NB;
        }
        flock(&file, op).with_context(|| {
            format!(
                "Failed to acquire exclusive lock (mode={:?}) on {}",
                mode,
                path.display()
            )
        })?;
    }

    // Helpful metadata for humans.
    // Failure to write metadata should not prevent locking.
    if let Err(e) = file.set_len(0) {
        tracing::warn!("Failed to truncate lock file {}: {}", path.display(), e);
    }
    if let Err(e) = writeln!(
        file,
        "pid={} started={}",
        std::process::id(),
        chrono::Utc::now().to_rfc3339()
    ) {
        tracing::warn!("Failed to write lock metadata {}: {}", path.display(), e);
    }
    if let Err(e) = file.sync_all() {
        tracing::warn!("Failed to sync lock file {}: {}", path.display(), e);
    }

    Ok(FileLock { path, file })
}

pub fn lock_dir_exclusive(
    dir: impl AsRef<Path>,
    lock_filename: &str,
    mode: LockMode,
) -> anyhow::Result<FileLock> {
    let dir = dir.as_ref();
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create dir for lock: {}", dir.display()))?;
    let lock_path = dir.join(lock_filename);
    lock_file_exclusive(lock_path, mode)
}
