use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub(crate) fn timeout_from_env(var: &str, default_secs: u64) -> Duration {
    match std::env::var(var) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs.max(1)),
            Err(err) => panic!("Invalid {}='{}': {}", var, raw, err),
        },
        Err(std::env::VarError::NotPresent) => Duration::from_secs(default_secs.max(1)),
        Err(e) => panic!("Invalid {} value: {}", var, e),
    }
}

pub(crate) fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<Output> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| "Failed to spawn external command")?;

    let start = Instant::now();
    loop {
        if let Some(_status) = child
            .try_wait()
            .context("Failed waiting on external command")?
        {
            return child
                .wait_with_output()
                .context("Failed collecting external command output");
        }

        if start.elapsed() >= timeout {
            if let Err(e) = child.kill() {
                tracing::warn!("Failed to kill timed out process: {}", e);
            }
            if let Err(e) = child.wait() {
                tracing::warn!("Failed to wait for timed out process: {}", e);
            }
            anyhow::bail!("Command timed out after {:?}", timeout);
        }

        std::thread::sleep(Duration::from_millis(5));
    }
}

#[derive(Debug)]
pub(crate) struct DirLock {
    path: PathBuf,
    file: File,
}

impl DirLock {
    fn open_lock_file(dir: &Path) -> Result<(PathBuf, File)> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(".zkfuzz_build.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("Failed to open build lock file: {}", path.display()))?;
        Ok((path, file))
    }

    pub(crate) fn acquire_exclusive(dir: &Path) -> Result<Self> {
        let (path, mut file) = Self::open_lock_file(dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Failed to lock dir: {}", dir.display()));
            }
        }

        if let Err(e) = file.set_len(0) {
            tracing::warn!("Failed to truncate lock file {}: {}", path.display(), e);
        }
        if let Err(e) = writeln!(file, "pid={}", std::process::id()) {
            tracing::warn!("Failed to write lock metadata {}: {}", path.display(), e);
        }
        if let Err(e) = file.sync_all() {
            tracing::warn!("Failed to sync lock file {}: {}", path.display(), e);
        }

        Ok(Self { path, file })
    }

    pub(crate) fn acquire_shared(dir: &Path) -> Result<Self> {
        let (path, file) = Self::open_lock_file(dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Failed to lock dir: {}", dir.display()));
            }
        }

        Ok(Self { path, file })
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!("Failed to unlock dir lock {}: {}", self.path.display(), err);
            }
        }
    }
}
