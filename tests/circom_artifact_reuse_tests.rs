use std::env;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use tempfile::tempdir;
use zk_core::Framework;
use zk_fuzzer::executor::{ExecutorFactory, ExecutorFactoryOptions};

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct EnvRestore {
    current_dir: PathBuf,
    path: Option<String>,
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        env::set_current_dir(&self.current_dir).expect("restore current dir");
        if let Some(path) = &self.path {
            env::set_var("PATH", path);
        } else {
            env::remove_var("PATH");
        }
    }
}

fn cve_fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("cve_fixtures")
        .join(format!("{}.circom", name))
}

#[test]
fn circom_executor_reuses_bundled_artifacts_without_circom_on_path() {
    let _guard = env_lock();
    let restore = EnvRestore {
        current_dir: env::current_dir().expect("current dir"),
        path: env::var("PATH").ok(),
    };

    let sandbox = tempdir().expect("tempdir");
    env::set_current_dir(sandbox.path()).expect("switch to isolated cwd");
    env::set_var("PATH", sandbox.path());

    let circuit_path = cve_fixture_path("signature_canonical_guard");
    assert!(circuit_path.exists(), "fixture circuit should exist");

    let options = ExecutorFactoryOptions {
        circom_skip_compile_if_artifacts: true,
        ..ExecutorFactoryOptions::default()
    };

    let executor = ExecutorFactory::create_with_options(
        Framework::Circom,
        circuit_path.to_str().expect("utf8 fixture path"),
        "SignatureCanonicalGuard",
        &options,
    );

    drop(restore);

    assert!(
        executor.is_ok(),
        "executor should reuse bundled artifacts without circom on PATH: {:?}",
        executor.err()
    );
}
