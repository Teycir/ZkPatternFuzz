use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::ffi::OsStr;
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
    let mut sandboxed_cmd = maybe_wrap_with_tool_sandbox(cmd)?;
    let spawn_cmd = sandboxed_cmd.as_mut().unwrap_or(cmd);

    let mut child = spawn_cmd
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolSandboxMode {
    Disabled,
    Required,
}

fn tool_sandbox_mode() -> Result<ToolSandboxMode> {
    match std::env::var("ZKFUZZ_EXTERNAL_TOOL_SANDBOX") {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "0" | "false" | "disabled" => Ok(ToolSandboxMode::Disabled),
            "required" | "on" | "1" | "true" | "strict" => Ok(ToolSandboxMode::Required),
            other => anyhow::bail!(
                "Invalid ZKFUZZ_EXTERNAL_TOOL_SANDBOX='{}' (expected off|required)",
                other
            ),
        },
        Err(std::env::VarError::NotPresent) => Ok(ToolSandboxMode::Disabled),
        Err(e) => anyhow::bail!("Invalid ZKFUZZ_EXTERNAL_TOOL_SANDBOX value: {}", e),
    }
}

fn command_basename(program: &OsStr) -> Option<String> {
    Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
}

fn command_targets_backend_tool(cmd: &Command) -> bool {
    let Some(program) = command_basename(cmd.get_program()) else {
        return false;
    };

    if matches!(
        program.as_str(),
        "circom" | "snarkjs" | "nargo" | "scarb" | "cargo"
    ) {
        return true;
    }

    if program == "npx" {
        if let Some(first_arg) = cmd.get_args().next().and_then(|arg| arg.to_str()) {
            let tool = first_arg.to_ascii_lowercase();
            return matches!(tool.as_str(), "snarkjs" | "circom");
        }
    }

    false
}

fn resolve_current_dir(cmd: &Command) -> Result<PathBuf> {
    let raw_dir = if let Some(dir) = cmd.get_current_dir() {
        dir.to_path_buf()
    } else {
        std::env::current_dir().context("Failed to resolve current working directory")?
    };
    let absolute = if raw_dir.is_absolute() {
        raw_dir
    } else {
        std::env::current_dir()
            .context("Failed resolving base cwd for relative command dir")?
            .join(raw_dir)
    };
    absolute.canonicalize().with_context(|| {
        format!(
            "Failed to canonicalize command working directory '{}'",
            absolute.display()
        )
    })
}

fn candidate_writable_bind_paths(cmd: &Command, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = BTreeSet::<PathBuf>::new();
    paths.insert(cwd.to_path_buf());
    paths.insert(PathBuf::from("/tmp"));

    let tracked_env = [
        "HOME",
        "CARGO_HOME",
        "NARGO_HOME",
        "SCARB_CACHE",
        "RUSTUP_HOME",
        "CARGO_TARGET_DIR",
        "NARGO_TARGET_DIR",
        "SCARB_TARGET_DIR",
    ];

    for key in tracked_env {
        if let Ok(value) = std::env::var(key) {
            let path = PathBuf::from(value);
            let absolute = if path.is_absolute() { path } else { cwd.join(path) };
            paths.insert(absolute);
        }
    }

    for (key, value) in cmd.get_envs() {
        let key_name = match key.to_str() {
            Some(k) => k,
            None => continue,
        };
        if !tracked_env.iter().any(|tracked| tracked == &key_name) {
            continue;
        }
        if let Some(raw_value) = value {
            let path = PathBuf::from(raw_value);
            let absolute = if path.is_absolute() { path } else { cwd.join(path) };
            paths.insert(absolute);
        }
    }

    paths
        .into_iter()
        .filter(|p| p.exists())
        .collect::<Vec<PathBuf>>()
}

fn find_binary_on_path(name: &str) -> bool {
    if name.contains('/') {
        return Path::new(name).is_file();
    }
    let Some(path_os) = std::env::var_os("PATH") else {
        return false;
    };

    std::env::split_paths(&path_os).any(|dir| dir.join(name).is_file())
}

fn maybe_wrap_with_tool_sandbox(cmd: &Command) -> Result<Option<Command>> {
    if tool_sandbox_mode()? == ToolSandboxMode::Disabled {
        return Ok(None);
    }
    if !command_targets_backend_tool(cmd) {
        return Ok(None);
    }

    #[cfg(not(unix))]
    {
        anyhow::bail!(
            "ZKFUZZ_EXTERNAL_TOOL_SANDBOX=required is unsupported on non-Unix platforms"
        );
    }

    #[cfg(unix)]
    {
        let sandbox_bin = std::env::var("ZKFUZZ_EXTERNAL_TOOL_SANDBOX_BIN")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "bwrap".to_string());

        if !find_binary_on_path(&sandbox_bin) {
            anyhow::bail!(
                "External tool sandbox is required but '{}' was not found in PATH",
                sandbox_bin
            );
        }

        let cwd = resolve_current_dir(cmd)?;
        let writable_paths = candidate_writable_bind_paths(cmd, &cwd);

        let mut wrapped = Command::new(&sandbox_bin);
        wrapped
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--unshare-pid")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--ro-bind")
            .arg("/")
            .arg("/")
            .arg("--tmpfs")
            .arg("/tmp");

        for path in writable_paths {
            wrapped.arg("--bind").arg(&path).arg(&path);
        }

        wrapped.arg("--chdir").arg(&cwd);
        wrapped.arg("--");
        wrapped.arg(cmd.get_program());
        for arg in cmd.get_args() {
            wrapped.arg(arg);
        }

        if let Some(dir) = cmd.get_current_dir() {
            wrapped.current_dir(dir);
        }

        for (key, value) in cmd.get_envs() {
            match value {
                Some(v) => {
                    wrapped.env(key, v);
                }
                None => {
                    wrapped.env_remove(key);
                }
            }
        }

        Ok(Some(wrapped))
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

#[cfg(test)]
mod tests {
    use super::command_targets_backend_tool;
    use std::process::Command;

    #[test]
    fn test_command_targets_backend_tool_direct_binaries() {
        let cmd = Command::new("nargo");
        assert!(command_targets_backend_tool(&cmd));

        let cmd = Command::new("scarb");
        assert!(command_targets_backend_tool(&cmd));

        let cmd = Command::new("cargo");
        assert!(command_targets_backend_tool(&cmd));
    }

    #[test]
    fn test_command_targets_backend_tool_npx_snarkjs() {
        let mut cmd = Command::new("npx");
        cmd.arg("snarkjs").arg("--version");
        assert!(command_targets_backend_tool(&cmd));
    }

    #[test]
    fn test_command_targets_backend_tool_non_backend_command() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("echo hi");
        assert!(!command_targets_backend_tool(&cmd));
    }
}
