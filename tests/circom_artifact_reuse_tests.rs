use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use tempfile::tempdir;
use zk_core::Framework;
use zk_fuzzer::executor::{ExecutorFactory, ExecutorFactoryOptions};
use zk_fuzzer::targets::CircomTarget;

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

fn build_cve_fixture_bundle(name: &str, main_component: &str, dest_root: &Path) -> PathBuf {
    CircomTarget::check_circom_available().expect("Circom CLI required to build fixture bundle");
    CircomTarget::check_snarkjs_available().expect("snarkjs CLI required to build fixture bundle");

    let circuit_path = cve_fixture_path(name);
    let staged_circuit_path = dest_root.join(format!("{}.circom", name));
    let build_dir = dest_root.join("build");
    fs::create_dir_all(dest_root).expect("create fixture destination");
    fs::copy(&circuit_path, &staged_circuit_path).expect("copy fixture circuit");

    let options = ExecutorFactoryOptions {
        circom_build_dir: Some(build_dir.clone()),
        ..ExecutorFactoryOptions::default()
    };
    ExecutorFactory::create_with_options(
        Framework::Circom,
        staged_circuit_path.to_str().expect("utf8 fixture path"),
        main_component,
        &options,
    )
    .expect("build reusable fixture bundle");

    assert!(
        build_dir.join(format!("{}.r1cs", name)).exists(),
        "expected Circom R1CS artifact in staged bundle"
    );
    assert!(
        build_dir
            .join(format!("{}_js", name))
            .join(format!("{}.wasm", name))
            .exists(),
        "expected Circom WASM artifact in staged bundle"
    );
    assert!(
        build_dir
            .join(format!("{}_constraints.json", name))
            .exists(),
        "expected Circom constraints JSON in staged bundle"
    );
    assert!(
        build_dir.join(format!("{}_metadata.json", name)).exists(),
        "expected Circom metadata cache in staged bundle"
    );

    staged_circuit_path
}

#[test]
fn circom_executor_reuses_bundled_artifacts_without_circom_on_path() {
    let _guard = env_lock();
    let restore = EnvRestore {
        current_dir: env::current_dir().expect("current dir"),
        path: env::var("PATH").ok(),
    };

    let sandbox = tempdir().expect("tempdir");
    let fixture_root = sandbox.path().join("staged_fixture");
    let circuit_path = build_cve_fixture_bundle(
        "signature_canonical_guard",
        "SignatureCanonicalGuard",
        &fixture_root,
    );
    env::set_current_dir(sandbox.path()).expect("switch to isolated cwd");
    env::set_var("PATH", sandbox.path());

    let options = ExecutorFactoryOptions {
        circom_build_dir: Some(fixture_root.join("build")),
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

#[test]
fn circom_executor_reuses_bundled_artifacts_when_source_is_newer_than_cache() {
    let _guard = env_lock();
    let restore = EnvRestore {
        current_dir: env::current_dir().expect("current dir"),
        path: env::var("PATH").ok(),
    };

    let sandbox = tempdir().expect("tempdir");
    env::set_current_dir(sandbox.path()).expect("switch to isolated cwd");
    let fixture_root = sandbox.path().join("staged_fixture");
    let circuit_path = build_cve_fixture_bundle(
        "signature_canonical_guard",
        "SignatureCanonicalGuard",
        &fixture_root,
    );
    let original_source = fs::read_to_string(&circuit_path).expect("read staged fixture source");

    thread::sleep(Duration::from_millis(20));
    fs::write(&circuit_path, original_source).expect("refresh staged fixture source mtime");
    env::set_var("PATH", sandbox.path());

    let options = ExecutorFactoryOptions {
        circom_build_dir: Some(fixture_root.join("build")),
        circom_skip_compile_if_artifacts: true,
        ..ExecutorFactoryOptions::default()
    };

    let executor = ExecutorFactory::create_with_options(
        Framework::Circom,
        circuit_path.to_str().expect("utf8 staged fixture path"),
        "SignatureCanonicalGuard",
        &options,
    );

    drop(restore);

    assert!(
        executor.is_ok(),
        "executor should trust bundled artifacts even when source is newer than cache: {:?}",
        executor.err()
    );
}
