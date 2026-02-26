#![cfg(feature = "halo2")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, OnceLock};
use tempfile::tempdir;
use zk_backends::Halo2Target;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvVarGuard {
    saved: Vec<(String, Option<String>)>,
}

impl EnvVarGuard {
    fn set(overrides: &[(&str, &str)]) -> Self {
        let mut saved = Vec::with_capacity(overrides.len());
        for (key, value) in overrides {
            let key_string = (*key).to_string();
            saved.push((key_string.clone(), std::env::var(&key_string).ok()));
            std::env::set_var(&key_string, value);
        }
        Self { saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, prior) in self.saved.drain(..).rev() {
            if let Some(value) = prior {
                std::env::set_var(&key, value);
            } else {
                std::env::remove_var(&key);
            }
        }
    }
}

#[test]
fn halo2_stops_toolchain_cascade_when_dependency_resolution_fails() {
    let _guard = env_lock().lock().expect("lock env");
    let temp = tempdir().expect("tempdir");

    let project_dir = temp.path().join("halo2_project");
    fs::create_dir_all(project_dir.join("src")).expect("create project tree");
    fs::write(
        project_dir.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write Cargo.toml");
    fs::write(project_dir.join("src/main.rs"), "fn main() {}\n").expect("write src/main.rs");

    let attempt_log = temp.path().join("attempts.log");
    let probe_script = temp.path().join("offline_probe.sh");
    fs::write(
        &probe_script,
        "#!/usr/bin/env bash\n\
echo probe >> \"${ZKF_TEST_OFFLINE_PROBE_LOG}\"\n\
echo \"failed to load source for dependency demo\" >&2\n\
echo \"you are in the offline mode (--offline)\" >&2\n\
exit 1\n",
    )
    .expect("write probe script");
    let mut perms = fs::metadata(&probe_script).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&probe_script, perms).expect("chmod");

    let probe_script_str = probe_script.to_string_lossy().to_string();
    let attempt_log_str = attempt_log.to_string_lossy().to_string();
    let _env_guard = EnvVarGuard::set(&[
        ("ZK_FUZZER_CARGO_BIN_CANDIDATES", &probe_script_str),
        (
            "ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES",
            "nightly-a,nightly-b",
        ),
        ("ZK_FUZZER_HALO2_TOOLCHAIN_CASCADE_LIMIT", "2"),
        ("ZK_FUZZER_HALO2_RUSTUP_TOOLCHAIN_CASCADE", "false"),
        ("ZK_FUZZER_HALO2_AUTO_ONLINE_RETRY", "false"),
        ("ZKF_TEST_OFFLINE_PROBE_LOG", &attempt_log_str),
    ]);

    let mut target = Halo2Target::new(project_dir.to_str().expect("project path")).expect("target");
    let err = target.setup().expect_err("setup should fail");

    let attempts = fs::read_to_string(&attempt_log)
        .expect("attempt log")
        .lines()
        .count();
    assert_eq!(
        attempts, 1,
        "dependency failures should stop cascading through extra toolchain candidates"
    );

    let err_text = format!("{err:#}");
    assert!(
        err_text.contains("stopping toolchain cascade"),
        "error should report fail-fast cascade stop, got: {}",
        err_text
    );
}
