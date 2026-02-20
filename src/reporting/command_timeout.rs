//! Timeout wrapper for external commands

use std::io::Read;
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

/// Execute a command with timeout using std::process polling.
/// This avoids environment-specific SIGCHLD handler failures.
pub fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    prepare_child_process_group(cmd);

    let mut child = cmd
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
