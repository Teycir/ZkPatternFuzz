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

fn build_cve_fixture_bundle(name: &str, main_component: &str, dest_root: &Path) -> PathBuf {
    let circuit_path = cve_fixture_path(name);
    let staged_circuit_path = dest_root.join(format!("{}.circom", name));
    let build_dir = dest_root.join("build");
    let wasm_dir = build_dir.join(format!("{}_js", name));
    fs::create_dir_all(dest_root).expect("create fixture destination");
    fs::copy(&circuit_path, &staged_circuit_path).expect("copy fixture circuit");
    fs::create_dir_all(&wasm_dir).expect("create synthetic wasm directory");

    fs::write(build_dir.join(format!("{}.r1cs", name)), b"synthetic r1cs")
        .expect("write synthetic r1cs");
    fs::write(build_dir.join(format!("{}.sym", name)), b"synthetic sym")
        .expect("write synthetic sym");
    fs::write(wasm_dir.join(format!("{}.wasm", name)), b"\0asm").expect("write synthetic wasm");
    fs::write(
        wasm_dir.join("witness_calculator.js"),
        "// synthetic witness calculator placeholder\n",
    )
    .expect("write synthetic witness calculator");
    fs::write(
        build_dir.join(format!("{}_constraints.json", name)),
        serde_json::to_vec_pretty(&serde_json::json!({
            "constraints": [
                [
                    { "0": "1" },
                    { "0": "1" },
                    { "0": "1" }
                ]
            ]
        }))
        .expect("serialize synthetic constraints"),
    )
    .expect("write synthetic constraints");
    fs::write(
        build_dir.join(format!("{}_metadata.json", name)),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "metadata": {
                "num_constraints": 1,
                "num_private_inputs": 0,
                "num_public_inputs": 0,
                "num_outputs": 1,
                "signals": {
                    "one": 0,
                    format!("{}.out", main_component): 1
                },
                "input_signals": [],
                "input_signal_sizes": {},
                "input_signal_indices": [],
                "public_input_indices": [],
                "private_input_indices": [],
                "output_signals": [format!("{}.out", main_component)],
                "output_signal_indices": [1],
                "prime": "bn128"
            }
        }))
        .expect("serialize synthetic metadata"),
    )
    .expect("write synthetic metadata");

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
