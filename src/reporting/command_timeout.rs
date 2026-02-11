//! Timeout wrapper for external commands

use std::process::{Command, Output};
use std::time::Duration;

/// Execute a command with timeout using wait-timeout pattern
pub fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    let mut child = cmd
        .stdin(std::process::Stdio::null()) // Prevent interactive prompts
        .spawn()?;

    // Simple timeout using thread + kill
    let child_id = child.id();
    let timeout_handle = std::thread::spawn(move || {
        std::thread::sleep(timeout);
        // Kill if still running
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("kill")
                .args(["-9", &child_id.to_string()])
                .output();
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &child_id.to_string()])
                .output();
        }
    });

    let output = child.wait_with_output()?;
    drop(timeout_handle); // Best effort cancel

    Ok(output)
}
