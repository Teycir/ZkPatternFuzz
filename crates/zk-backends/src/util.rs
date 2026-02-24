use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(not(unix))]
use std::process::Child;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;
#[cfg(not(unix))]
use std::time::Instant;

fn truncate_for_diagnostics(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let mut count = 0usize;
    for ch in trimmed.chars() {
        if count >= max_chars {
            out.push_str(" ...<truncated>");
            break;
        }
        out.push(ch);
        count = count.saturating_add(1);
    }
    out
}

pub(crate) fn command_output_summary(output: &Output) -> String {
    const MAX_DIAG_CHARS: usize = 2_000;

    let stderr = truncate_for_diagnostics(&String::from_utf8_lossy(&output.stderr), MAX_DIAG_CHARS);
    let stdout = truncate_for_diagnostics(&String::from_utf8_lossy(&output.stdout), MAX_DIAG_CHARS);

    match (!stderr.is_empty(), !stdout.is_empty()) {
        (true, true) => format!("stderr: {}\nstdout: {}", stderr, stdout),
        (true, false) => format!("stderr: {}", stderr),
        (false, true) => format!("stdout: {}", stdout),
        (false, false) => "no command output captured".to_string(),
    }
}

pub(crate) fn timeout_from_env(var: &str, default_secs: u64) -> Duration {
    let fallback = Duration::from_secs(default_secs.max(1));
    match std::env::var(var) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs.max(1)),
            Err(err) => {
                tracing::warn!(
                    "Invalid {}='{}' ({}); falling back to {}s",
                    var,
                    raw,
                    err,
                    fallback.as_secs()
                );
                fallback
            }
        },
        Err(std::env::VarError::NotPresent) => fallback,
        Err(e) => {
            tracing::warn!(
                "Invalid {} value ({}); falling back to {}s",
                var,
                e,
                fallback.as_secs()
            );
            fallback
        }
    }
}

pub(crate) fn parse_command_candidates(raw: Option<&str>) -> Vec<String> {
    let mut parsed = Vec::new();
    let Some(raw) = raw else {
        return parsed;
    };

    for token in raw.split([',', ';']) {
        let candidate = token.trim();
        if candidate.is_empty() {
            continue;
        }
        if parsed.iter().any(|existing| existing == candidate) {
            continue;
        }
        parsed.push(candidate.to_string());
    }

    parsed
}

pub(crate) fn build_command_candidates(
    preferred: Option<&str>,
    binary_candidates_raw: Option<&str>,
    version_candidates_raw: Option<&str>,
    default_binary: &str,
) -> Vec<String> {
    let mut candidates = Vec::new();

    if let Some(preferred) = preferred.map(str::trim).filter(|value| !value.is_empty()) {
        candidates.push(preferred.to_string());
    }

    for candidate in parse_command_candidates(binary_candidates_raw) {
        if candidates.iter().any(|existing| existing == &candidate) {
            continue;
        }
        candidates.push(candidate);
    }

    for version in parse_command_candidates(version_candidates_raw) {
        let by_version_binary = format!("{default_binary}-{version}");
        if candidates
            .iter()
            .any(|existing| existing == &by_version_binary)
        {
            continue;
        }
        candidates.push(by_version_binary);
    }

    if !candidates.iter().any(|existing| existing == default_binary) {
        candidates.push(default_binary.to_string());
    }

    candidates
}

pub(crate) fn run_command_with_fallback<F>(
    candidates: &[String],
    timeout: Duration,
    context: &str,
    mut configure: F,
) -> Result<(Output, String)>
where
    F: FnMut(&mut Command),
{
    run_candidate_commands_with_fallback(
        candidates,
        timeout,
        context,
        |candidate| candidate.clone(),
        |candidate| {
            let mut cmd = Command::new(candidate);
            configure(&mut cmd);
            Ok(cmd)
        },
    )
}

pub(crate) fn run_candidate_commands_with_fallback<T, L, B>(
    candidates: &[T],
    timeout: Duration,
    context: &str,
    mut label: L,
    mut build: B,
) -> Result<(Output, String)>
where
    L: FnMut(&T) -> String,
    B: FnMut(&T) -> Result<Command>,
{
    let mut failures = Vec::new();
    let mut labels_seen = Vec::new();

    for candidate in candidates {
        let candidate_label = label(candidate);
        labels_seen.push(candidate_label.clone());

        let mut cmd = match build(candidate) {
            Ok(cmd) => cmd,
            Err(err) => {
                failures.push(format!("{candidate_label}: {err}"));
                continue;
            }
        };

        match run_with_timeout(&mut cmd, timeout) {
            Ok(output) if output.status.success() => {
                return Ok((output, candidate_label));
            }
            Ok(output) => {
                failures.push(format!(
                    "{candidate_label}: {}",
                    command_output_summary(&output)
                ));
            }
            Err(err) => {
                failures.push(format!("{candidate_label}: {err}"));
            }
        }
    }

    anyhow::bail!(
        "{context}. Candidates tried: {}. Last errors: {}",
        labels_seen.join(", "),
        failures.join(" || ")
    )
}

#[cfg(unix)]
fn prepare_child_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Put the spawned command in its own process group so timeout enforcement can
    // terminate the entire subtree (e.g., shell-launched descendants).
    // SAFETY: `pre_exec` runs in the child process immediately before `exec`.
    // The closure performs one async-signal-safe libc call (`setpgid`) and
    // returns an OS error on failure without touching shared process state.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn prepare_child_process_group(_cmd: &mut Command) {}

#[cfg(not(unix))]
fn kill_child_tree(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

#[cfg(unix)]
fn kill_process_group_by_pid(pid: u32) -> std::io::Result<()> {
    // SAFETY: PID comes from a live child process ID and is only used as
    // the process-group selector for `killpg`.
    let rc = unsafe { libc::killpg(pid as i32, libc::SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(crate) fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<Output> {
    let mut sandboxed_cmd = maybe_wrap_with_tool_sandbox(cmd)?;
    let spawn_cmd = sandboxed_cmd.as_mut().unwrap_or(cmd);
    prepare_child_process_group(spawn_cmd);

    let child = spawn_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| "Failed to spawn external command")?;

    #[cfg(unix)]
    {
        let child_id = child.id();
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });

        return match rx.recv_timeout(timeout) {
            Ok(output) => output.context("Failed collecting external command output"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Err(e) = kill_process_group_by_pid(child_id) {
                    tracing::warn!("Failed to kill timed out process subtree: {}", e);
                }
                // Give the waiter a short grace period to observe process termination.
                let _ = rx.recv_timeout(Duration::from_secs(1));
                anyhow::bail!("Command timed out after {:?}", timeout);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("External command waiter disconnected unexpectedly")
            }
        };
    }

    #[cfg(not(unix))]
    {
        let mut child = child;
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
                if let Err(e) = kill_child_tree(&mut child) {
                    tracing::warn!("Failed to kill timed out process subtree: {}", e);
                }
                if let Err(e) = child.wait() {
                    tracing::warn!("Failed to wait for timed out process: {}", e);
                }
                anyhow::bail!("Command timed out after {:?}", timeout);
            }

            // Non-Unix fallback keeps bounded polling because `killpg` is unavailable.
            std::thread::sleep(Duration::from_millis(25));
        }
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

fn candidate_writable_bind_paths(cmd: &Command, cwd: &Path) -> Result<Vec<PathBuf>> {
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
            let absolute = if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            };
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
            let absolute = if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            };
            paths.insert(absolute);
        }
    }

    let mut writable_paths = Vec::with_capacity(paths.len());
    for path in paths {
        if path.exists() {
            writable_paths.push(path);
            continue;
        }
        std::fs::create_dir_all(&path).with_context(|| {
            format!(
                "Failed to create sandbox writable directory '{}'",
                path.display()
            )
        })?;
        writable_paths.push(path);
    }

    Ok(writable_paths)
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
        anyhow::bail!("ZKFUZZ_EXTERNAL_TOOL_SANDBOX=required is unsupported on non-Unix platforms");
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
        let writable_paths = candidate_writable_bind_paths(cmd, &cwd)?;

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
    use super::{
        build_command_candidates, candidate_writable_bind_paths, command_output_summary,
        command_targets_backend_tool, parse_command_candidates, run_command_with_fallback,
        run_with_timeout, timeout_from_env,
    };
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

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

    #[test]
    fn test_timeout_from_env_invalid_value_uses_default() {
        let key = "ZK_FUZZER_TEST_TIMEOUT_PARSE_INVALID";
        std::env::set_var(key, "not-a-number");
        let timeout = timeout_from_env(key, 7);
        std::env::remove_var(key);
        assert_eq!(timeout, Duration::from_secs(7));
    }

    #[test]
    fn test_command_output_summary_uses_stdout_when_stderr_empty() {
        let output = Command::new("rustc")
            .arg("--version")
            .output()
            .expect("rustc --version should run");

        let summary = command_output_summary(&output);
        assert!(summary.contains("stdout:"));
        assert!(summary.contains("rustc"));
    }

    #[test]
    fn test_parse_command_candidates_splits_and_dedupes() {
        let parsed = parse_command_candidates(Some("scarb-2.5.3, scarb-2.5.3;scarb-2.9.0"));
        assert_eq!(parsed, vec!["scarb-2.5.3", "scarb-2.9.0"]);
    }

    #[test]
    fn test_build_command_candidates_orders_preferred_then_fallbacks() {
        let candidates = build_command_candidates(
            Some("scarb-2.5.3"),
            Some("scarb-2.9.0,scarb-2.5.3"),
            Some("2.15.1"),
            "scarb",
        );

        assert_eq!(
            candidates,
            vec!["scarb-2.5.3", "scarb-2.9.0", "scarb-2.15.1", "scarb"]
        );
    }

    #[test]
    fn test_run_command_with_fallback_uses_next_candidate() {
        let candidates = vec!["definitely-missing-binary".to_string(), "rustc".to_string()];
        let (output, used) = run_command_with_fallback(
            &candidates,
            Duration::from_secs(5),
            "fallback command test failed",
            |cmd| {
                cmd.arg("--version");
            },
        )
        .expect("expected fallback command execution to succeed");

        assert_eq!(used, "rustc");
        assert!(output.status.success());
    }

    #[test]
    fn test_candidate_writable_bind_paths_creates_missing_env_dirs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("missing-sandbox-cache");
        assert!(
            !missing.exists(),
            "precondition: test directory should start absent"
        );

        let mut cmd = Command::new("cargo");
        cmd.env("SCARB_CACHE", &missing);

        let paths =
            candidate_writable_bind_paths(&cmd, temp.path()).expect("collect writable bind paths");

        assert!(
            missing.exists(),
            "writable path should be created for sandbox bind"
        );
        assert!(
            paths.contains(&missing),
            "created writable path should be included in bind list"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_run_with_timeout_kills_process_subtree() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker_path = temp.path().join("timed_out_subprocess_marker.txt");
        let marker_env: PathBuf = marker_path.clone();

        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("(sleep 0.4; printf leaked > \"$MARKER_PATH\") & wait");
        cmd.env("MARKER_PATH", marker_env);

        let err = run_with_timeout(&mut cmd, Duration::from_millis(100))
            .expect_err("command should time out");
        assert!(
            err.to_string().contains("timed out"),
            "expected timeout error, got: {err}"
        );

        std::thread::sleep(Duration::from_millis(700));
        assert!(
            !marker_path.exists(),
            "timed out command subtree should be fully terminated"
        );
    }
}
