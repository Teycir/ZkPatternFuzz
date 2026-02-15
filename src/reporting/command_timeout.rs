//! Timeout wrapper for external commands

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

/// Execute a command with timeout using wait-timeout crate.
/// This avoids orphaned timeout threads and race conditions.
pub fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    match child.wait_timeout(timeout)? {
        Some(status) => {
            let stdout = child
                .stdout
                .take()
                .map(|mut s| -> anyhow::Result<Vec<u8>> {
                    let mut buf = Vec::new();
                    s.read_to_end(&mut buf)?;
                    Ok(buf)
                })
                .transpose()?;
            let stdout = match stdout {
                Some(bytes) => bytes,
                None => Vec::new(),
            };
            let stderr = child
                .stderr
                .take()
                .map(|mut s| -> anyhow::Result<Vec<u8>> {
                    let mut buf = Vec::new();
                    s.read_to_end(&mut buf)?;
                    Ok(buf)
                })
                .transpose()?;
            let stderr = match stderr {
                Some(bytes) => bytes,
                None => Vec::new(),
            };
            Ok(Output {
                status,
                stdout,
                stderr,
            })
        }
        None => {
            child.kill()?;
            child.wait()?;
            anyhow::bail!("Command timed out after {:?}", timeout)
        }
    }
}
