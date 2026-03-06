use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

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

fn cve_fixture_build_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("cve_fixtures")
        .join("build")
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create recursive destination");
    for entry in fs::read_dir(src).expect("read recursive source") {
        let entry = entry.expect("read recursive entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type().expect("entry file type").is_dir() {
            copy_dir_recursive(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).expect("copy recursive file");
        }
    }
}

fn stage_cve_fixture_bundle(name: &str, dest_root: &Path) -> PathBuf {
    let circuit_path = cve_fixture_path(name);
    let staged_circuit_path = dest_root.join(format!("{}.circom", name));
    fs::create_dir_all(dest_root).expect("create fixture destination");
    fs::copy(&circuit_path, &staged_circuit_path).expect("copy fixture circuit");

    let src_build_root = cve_fixture_build_root();
    let dst_build_root = dest_root.join("build");
    fs::create_dir_all(&dst_build_root).expect("create fixture build destination");
    for file_name in [
        format!("{}.r1cs", name),
        format!("{}.sym", name),
        format!("{}_constraints.json", name),
        format!("{}_metadata.json", name),
    ] {
        fs::copy(src_build_root.join(&file_name), dst_build_root.join(&file_name))
            .expect("copy fixture build artifact");
    }
    copy_dir_recursive(
        &src_build_root.join(format!("{}_js", name)),
        &dst_build_root.join(format!("{}_js", name)),
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

#[test]
fn circom_executor_reuses_bundled_artifacts_when_source_is_newer_than_cache() {
    let _guard = env_lock();
    let restore = EnvRestore {
        current_dir: env::current_dir().expect("current dir"),
        path: env::var("PATH").ok(),
    };

    let sandbox = tempdir().expect("tempdir");
    env::set_current_dir(sandbox.path()).expect("switch to isolated cwd");
    env::set_var("PATH", sandbox.path());

    let fixture_root = sandbox.path().join("staged_fixture");
    let circuit_path = stage_cve_fixture_bundle("signature_canonical_guard", &fixture_root);
    let original_source = fs::read_to_string(&circuit_path).expect("read staged fixture source");

    thread::sleep(Duration::from_millis(20));
    fs::write(&circuit_path, original_source).expect("refresh staged fixture source mtime");

    let options = ExecutorFactoryOptions {
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
