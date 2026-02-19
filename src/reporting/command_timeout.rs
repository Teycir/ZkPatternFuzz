//! Timeout wrapper for external commands

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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
            child.kill()?;
            child.wait()?;
            // Ensure reader threads observe EOF and exit cleanly.
            let _stdout = join_pipe_reader(stdout_reader)?;
            let _stderr = join_pipe_reader(stderr_reader)?;
            anyhow::bail!("Command timed out after {:?}", timeout);
        }

        thread::sleep(Duration::from_millis(20));
    }
}
