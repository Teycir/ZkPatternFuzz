/// Kill existing zk-fuzzer instances with graceful shutdown.
pub(crate) async fn kill_existing_instances() {
    let current_pid = std::process::id();

    let pgrep_output = std::process::Command::new("pgrep")
        .args(["-x", "zk-fuzzer"])
        .output();

    if let Ok(output) = pgrep_output {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        // Try graceful shutdown first (SIGTERM).
                        match std::process::Command::new("kill")
                            .args(["-15", &pid.to_string()])
                            .output()
                        {
                            Ok(output) if output.status.success() => {}
                            Ok(output) => tracing::warn!(
                                "Failed to send SIGTERM to {}: {}",
                                pid,
                                String::from_utf8_lossy(&output.stderr)
                            ),
                            Err(err) => {
                                tracing::warn!("Error sending SIGTERM to {}: {}", pid, err)
                            }
                        }
                    }
                }
            }

            // Wait for graceful shutdown.
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Force kill any remaining processes (SIGKILL).
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != current_pid {
                        match std::process::Command::new("kill")
                            .args(["-9", &pid.to_string()])
                            .output()
                        {
                            Ok(output) if output.status.success() => {}
                            Ok(output) => tracing::warn!(
                                "Failed to send SIGKILL to {}: {}",
                                pid,
                                String::from_utf8_lossy(&output.stderr)
                            ),
                            Err(err) => {
                                tracing::warn!("Error sending SIGKILL to {}: {}", pid, err)
                            }
                        }
                    }
                }
            }

            eprintln!(
                "Terminated existing zk-fuzzer instances (excluding PID {})",
                current_pid
            );
        }
    }
}
