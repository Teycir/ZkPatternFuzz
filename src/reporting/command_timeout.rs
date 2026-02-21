//! Timeout wrapper for external commands

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[cfg(unix)]
fn prepare_child_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Put the spawned command in its own process group so timeout enforcement can
    // terminate the entire subtree (e.g., `sh -c "sleep ..."` descendants).
    // SAFETY: `pre_exec` runs in the child process immediately before `exec`.
    // The closure performs a single async-signal-safe libc call (`setpgid`) and
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

#[cfg(unix)]
fn kill_child_tree(child: &mut Child) -> std::io::Result<()> {
    let pgid = child.id() as i32;
    // Best-effort kill of the whole process group.
    // SAFETY: `pgid` is derived from the spawned child PID and is used only as
    // a target identifier for `killpg`; no borrowed memory is involved.
    let rc = unsafe { libc::killpg(pgid, libc::SIGKILL) };
    if rc == 0 {
        return Ok(());
    }
    // Fall back to killing only the direct child when group kill is unavailable.
    child.kill()
}

#[cfg(not(unix))]
fn kill_child_tree(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

fn spawn_pipe_reader<R>(mut reader: R) -> JoinHandle<anyhow::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    })
}

fn join_pipe_reader(
    handle: Option<JoinHandle<anyhow::Result<Vec<u8>>>>,
) -> anyhow::Result<Vec<u8>> {
    match handle {
        Some(handle) => {
            let result = handle
                .join()
                .map_err(|_| anyhow::anyhow!("failed to join command output reader thread"))?;
            result
        }
        None => Ok(Vec::new()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolSandboxMode {
    Disabled,
    Required,
}

fn tool_sandbox_mode() -> anyhow::Result<ToolSandboxMode> {
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

fn command_basename(program: &std::ffi::OsStr) -> Option<String> {
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

fn resolve_current_dir(cmd: &Command) -> anyhow::Result<PathBuf> {
    if let Some(dir) = cmd.get_current_dir() {
        return Ok(dir.to_path_buf());
    }
    Ok(std::env::current_dir()?)
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

fn maybe_wrap_with_tool_sandbox(cmd: &Command) -> anyhow::Result<Option<Command>> {
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
        let mut wrapped = Command::new(&sandbox_bin);
        wrapped
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--unshare-pid")
            .arg("--unshare-net")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--ro-bind")
            .arg("/")
            .arg("/")
            .arg("--tmpfs")
            .arg("/tmp")
            .arg("--bind")
            .arg(&cwd)
            .arg(&cwd)
            .arg("--chdir")
            .arg(&cwd)
            .arg("--")
            .arg(cmd.get_program());

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

/// Execute a command with timeout using std::process polling.
/// This avoids environment-specific SIGCHLD handler failures.
pub fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    let mut sandboxed_cmd = maybe_wrap_with_tool_sandbox(cmd)?;
    let spawn_cmd = sandboxed_cmd.as_mut().unwrap_or(cmd);

    prepare_child_process_group(spawn_cmd);

    let mut child = spawn_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Start draining outputs immediately so verbose children cannot block on full pipe buffers.
    let stdout_reader = child.stdout.take().map(spawn_pipe_reader);
    let stderr_reader = child.stderr.take().map(spawn_pipe_reader);

    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = join_pipe_reader(stdout_reader)?;
            let stderr = join_pipe_reader(stderr_reader)?;
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }

        if Instant::now() >= deadline {
            kill_child_tree(&mut child)?;
            child.wait()?;
            // Ensure reader threads observe EOF and exit cleanly.
            let _stdout = join_pipe_reader(stdout_reader)?;
            let _stderr = join_pipe_reader(stderr_reader)?;
            anyhow::bail!("Command timed out after {:?}", timeout);
        }

        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
#[path = "command_timeout_tests.rs"]
mod tests;
