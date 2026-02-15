//! Timeout wrapper for external commands

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use wait_timeout::ChildExt;

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

/// Execute a command with timeout using wait-timeout crate.
/// This avoids orphaned timeout threads and race conditions.
pub fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Start draining outputs immediately so verbose children cannot block on full pipe buffers.
    let stdout_reader = child.stdout.take().map(spawn_pipe_reader);
    let stderr_reader = child.stderr.take().map(spawn_pipe_reader);

    match child.wait_timeout(timeout)? {
        Some(status) => {
            let stdout = join_pipe_reader(stdout_reader)?;
            let stderr = join_pipe_reader(stderr_reader)?;
            Ok(Output {
                status,
                stdout,
                stderr,
            })
        }
        None => {
            child.kill()?;
            child.wait()?;
            // Ensure reader threads observe EOF and exit cleanly.
            let _stdout = join_pipe_reader(stdout_reader)?;
            let _stderr = join_pipe_reader(stderr_reader)?;
            anyhow::bail!("Command timed out after {:?}", timeout)
        }
    }
}
