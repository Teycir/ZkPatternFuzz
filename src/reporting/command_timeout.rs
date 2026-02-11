//! Timeout wrapper for external commands

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Execute a command with timeout without relying on PID-based kills.
pub fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    let mut child = cmd
        .stdin(Stdio::null()) // Prevent interactive prompts
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let (result_tx, result_rx) = mpsc::channel();
    let (kill_tx, kill_rx) = mpsc::channel();

    thread::spawn(move || {
        let mut stdout_reader = child.stdout.take().map(|mut out| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = out.read_to_end(&mut buf);
                buf
            })
        });
        let mut stderr_reader = child.stderr.take().map(|mut err| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = err.read_to_end(&mut buf);
                buf
            })
        });

        loop {
            if kill_rx.try_recv().is_ok() {
                let _ = child.kill();
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    let stdout = stdout_reader
                        .take()
                        .map(|h| h.join().unwrap_or_default())
                        .unwrap_or_default();
                    let stderr = stderr_reader
                        .take()
                        .map(|h| h.join().unwrap_or_default())
                        .unwrap_or_default();
                    let _ = result_tx.send(Ok(Output {
                        status,
                        stdout,
                        stderr,
                    }));
                    return;
                }
                Ok(None) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    let _ = result_tx.send(Err(err.into()));
                    return;
                }
            }
        }
    });

    match result_rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = kill_tx.send(());
            let _ = result_rx.recv_timeout(Duration::from_secs(5));
            anyhow::bail!("Command timed out after {:?}", timeout);
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            anyhow::bail!("Command execution failed: worker disconnected");
        }
    }
}
