#[path = "../src/reporting/command_timeout.rs"]
mod command_timeout;

use command_timeout::run_with_timeout;
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(unix)]
#[test]
fn test_run_with_timeout_reports_timeout_for_sleep_command() {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("sleep 2");

    let start = Instant::now();
    let err = run_with_timeout(&mut cmd, Duration::from_millis(150))
        .expect_err("sleep command should time out");
    let elapsed = start.elapsed();

    assert!(
        err.to_string().contains("timed out"),
        "expected timeout error, got: {}",
        err
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "timeout wrapper should return before child completes naturally; elapsed={elapsed:?}"
    );
}

#[cfg(unix)]
#[test]
fn test_run_with_timeout_captures_stdout_and_stderr() {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("printf 'ok-out'; printf 'ok-err' 1>&2");

    let output = run_with_timeout(&mut cmd, Duration::from_secs(2))
        .expect("command should complete without timeout");

    assert!(output.status.success(), "expected successful exit status");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok-out");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "ok-err");
}
