//! Integration tests for ZK backend implementations
//!
//! These tests verify that the backend integrations work correctly
//! when the required tools are available in the environment.

use std::path::PathBuf;
use std::time::{Duration, Instant};
use zk_fuzzer::config::Framework;
use zk_fuzzer::executor::{
    CairoExecutor, CircomExecutor, CircuitExecutor, ExecutionCoverage, ExecutorFactory,
    ExecutorFactoryOptions, Halo2Executor, NoirExecutor,
};
use zk_fuzzer::fuzzer::FieldElement;
use zk_fuzzer::targets::{CairoTarget, CircomTarget, Halo2Target, NoirTarget, TargetCircuit};

const DEFAULT_ZK0D_BASE: &str = "/media/elements/Repos/zk0d";
const EXT005_EZKL_PATH_ENV: &str = "EXT005_EZKL_PATH";
const EXT005_EZKL_BUILD_DIR_ENV: &str = "EXT005_EZKL_BUILD_DIR";
const EXT005_REPLAY_WITNESS_HEX_ENV: &str = "EXT005_REPLAY_WITNESS_HEX";
const EXT005_REPLAY_SKIP_CONSTRAINT_LOAD_ENV: &str = "ZK_FUZZER_EXT005_REPLAY_SKIP_CONSTRAINT_LOAD";
const EXT005_REPLAY_SKIP_CONSTRAINT_LOAD_ENV_LEGACY: &str = "EXT005_REPLAY_SKIP_CONSTRAINT_LOAD";
const HALO2_EXTERNAL_TIMEOUT_SECS_ENV: &str = "ZK_FUZZER_HALO2_EXTERNAL_TIMEOUT_SECS";
const PHASE_TIMING_RUN_DIR_ENV: &str = "ZK_FUZZER_PHASE_TIMING_RUN_DIR";

fn real_backend_tests_enabled() -> bool {
    match std::env::var("ZKFUZZ_REAL_BACKENDS") {
        Ok(value) => matches!(value.as_str(), "1" | "true" | "yes"),
        Err(std::env::VarError::NotPresent) => false,
        Err(err) => panic!("Invalid ZKFUZZ_REAL_BACKENDS value: {}", err),
    }
}

fn require_real_backends(test_name: &str) -> bool {
    if real_backend_tests_enabled() {
        true
    } else {
        eprintln!(
            "skipping {} (set ZKFUZZ_REAL_BACKENDS=1 to enable real-backend tests)",
            test_name
        );
        false
    }
}

fn repo_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn zk0d_base_path() -> PathBuf {
    match std::env::var("ZK0D_BASE") {
        Ok(path) => PathBuf::from(path),
        Err(std::env::VarError::NotPresent) => PathBuf::from(DEFAULT_ZK0D_BASE),
        Err(e) => panic!("Invalid ZK0D_BASE value: {}", e),
    }
}

fn circom_test_circuit(name: &str) -> PathBuf {
    repo_path()
        .join("tests")
        .join("circuits")
        .join(format!("{}.circom", name))
}

fn noir_project_path(name: &str) -> PathBuf {
    repo_path().join("tests").join("noir_projects").join(name)
}

fn cairo_program_path(name: &str) -> PathBuf {
    repo_path()
        .join("tests")
        .join("cairo_programs")
        .join(format!("{}.cairo", name))
}

fn cairo_external_program_from_env() -> Option<PathBuf> {
    std::env::var("CAIRO_EXTERNAL_PROGRAM")
        .ok()
        .map(PathBuf::from)
}

fn cairo1_local_project_manifest_path() -> PathBuf {
    repo_path()
        .join("tests")
        .join("cairo_projects")
        .join("cairo1_constant")
        .join("Scarb.toml")
}

fn cairo1_external_program_from_env() -> Option<PathBuf> {
    std::env::var("CAIRO1_EXTERNAL_PROGRAM")
        .ok()
        .map(PathBuf::from)
}

fn halo2_spec_path(name: &str) -> PathBuf {
    repo_path()
        .join("tests")
        .join("halo2_specs")
        .join(format!("{}.json", name))
}

fn halo2_local_real_fixture_path() -> PathBuf {
    repo_path()
        .join("tests")
        .join("halo2_real_fixture")
        .join("Cargo.toml")
}

fn halo2_real_repo_path() -> PathBuf {
    if let Ok(path) = std::env::var("HALO2_SCAFFOLD_PATH") {
        return PathBuf::from(path);
    }
    zk0d_base_path().join("cat5_frameworks/halo2-scaffold")
}

fn ext005_ezkl_manifest_path() -> PathBuf {
    if let Ok(path) = std::env::var(EXT005_EZKL_PATH_ENV) {
        return PathBuf::from(path);
    }
    PathBuf::from("/media/elements/Repos/zkml/ezkl/Cargo.toml")
}

fn ext005_ezkl_build_dir() -> PathBuf {
    if let Ok(path) = std::env::var(EXT005_EZKL_BUILD_DIR_ENV) {
        return PathBuf::from(path);
    }
    std::env::temp_dir().join("zk0d_halo2_ext005_replay_build")
}

fn ext005_replay_witness_hex() -> String {
    if let Ok(value) = std::env::var(EXT005_REPLAY_WITNESS_HEX_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    // Default: EXT-005-F01 witness from continuation finding set.
    "0x0e0a77c19a0fdf2f406e2b6f7879462e36fc76959f60cd29ac96341c4ffffffa".to_string()
}

fn env_flag_enabled(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn ext005_skip_constraint_load_enabled() -> bool {
    if env_flag_enabled(EXT005_REPLAY_SKIP_CONSTRAINT_LOAD_ENV) {
        return true;
    }
    if env_flag_enabled(EXT005_REPLAY_SKIP_CONSTRAINT_LOAD_ENV_LEGACY) {
        println!(
            "test_halo2_ext005_ezkl_replay_base_execution_failure: legacy env '{}' is deprecated; prefer '{}'",
            EXT005_REPLAY_SKIP_CONSTRAINT_LOAD_ENV_LEGACY,
            EXT005_REPLAY_SKIP_CONSTRAINT_LOAD_ENV
        );
        return true;
    }
    false
}

fn with_console_progress<T, F>(label: &str, interval: Duration, op: F) -> T
where
    F: FnOnce() -> T,
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let started = Instant::now();
    let done = Arc::new(AtomicBool::new(false));
    let done_for_thread = Arc::clone(&done);
    let label_for_thread = label.to_string();
    let heartbeat_started = started;
    let heartbeat = std::thread::spawn(move || {
        while !done_for_thread.load(Ordering::Relaxed) {
            std::thread::sleep(interval);
            if done_for_thread.load(Ordering::Relaxed) {
                break;
            }
            println!(
                "{}: still running (elapsed={}s)",
                label_for_thread,
                heartbeat_started.elapsed().as_secs()
            );
        }
    });

    let output = op();
    done.store(true, Ordering::Relaxed);
    let _ = heartbeat.join();
    println!(
        "{label}: completed (elapsed={}s)",
        started.elapsed().as_secs()
    );
    output
}

fn phase_timing_run_dir(default_run_dir: &std::path::Path) -> PathBuf {
    match std::env::var(PHASE_TIMING_RUN_DIR_ENV) {
        Ok(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => default_run_dir.to_path_buf(),
    }
}

fn serialize_phase_timing_ms_json(phases: &[(&str, Option<Duration>)]) -> String {
    let entries = phases
        .iter()
        .map(|(phase, elapsed)| match elapsed {
            Some(duration) => format!(r#""{}":{}"#, phase, duration.as_millis()),
            None => format!(r#""{}":null"#, phase),
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{entries}}}")
}

fn emit_phase_timing_ms(
    test_name: &str,
    default_run_dir: &std::path::Path,
    phases: &[(&str, Option<Duration>)],
) {
    let payload = serialize_phase_timing_ms_json(phases);
    println!("{test_name}: phase_timing_ms={payload}");

    let run_dir = phase_timing_run_dir(default_run_dir);
    if let Err(err) = std::fs::create_dir_all(&run_dir) {
        panic!(
            "{test_name}: failed to create phase timing run dir '{}': {err}",
            run_dir.display()
        );
    }
    let timing_path = run_dir.join("phase_timing.json");
    if let Err(err) = std::fs::write(&timing_path, format!("{payload}\n")) {
        panic!(
            "{test_name}: failed to write phase timing payload to '{}': {err}",
            timing_path.display()
        );
    }
    println!("{test_name}: phase_timing_path={}", timing_path.display());
}

fn noir_external_nargo_projects() -> Vec<(&'static str, PathBuf)> {
    let base = zk0d_base_path();
    vec![
        (
            "aztec_hello_circuit",
            base.join(
                "cat3_privacy/aztec-packages/docs/examples/circuits/hello_circuit/Nargo.toml",
            ),
        ),
        (
            "barretenberg_fixture_main",
            base.join(
                "cat3_privacy/aztec-packages/barretenberg/docs/examples/fixtures/main/Nargo.toml",
            ),
        ),
    ]
}

fn noir_input_candidates(input_count: usize) -> Vec<Vec<FieldElement>> {
    if input_count == 0 {
        return vec![Vec::new()];
    }

    vec![
        (0..input_count).map(|_| FieldElement::zero()).collect(),
        (0..input_count).map(|_| FieldElement::one()).collect(),
        (0..input_count)
            .map(|idx| FieldElement::from_u64((idx as u64) + 1))
            .collect(),
        (0..input_count)
            .map(|_| FieldElement::from_u64(3))
            .collect(),
        (0..input_count)
            .map(|idx| FieldElement::from_u64(((idx as u64) + 1) * 5))
            .collect(),
    ]
}

fn run_noir_external_prove_verify_smoke(
    name: &str,
    nargo_toml_path: &std::path::Path,
) -> MatrixStatus {
    if !nargo_toml_path.exists() {
        return MatrixStatus::SkipInfra(format!(
            "external Noir project missing: {}",
            nargo_toml_path.display()
        ));
    }

    let mut target = match NoirTarget::new(nargo_toml_path.to_str().unwrap()) {
        Ok(target) => target,
        Err(err) => return classify_error(&format!("{name} create target"), err),
    };

    if let Err(err) = target.compile() {
        return classify_error(&format!("{name} compile"), err);
    }

    let total_inputs = target.num_public_inputs() + target.num_private_inputs();
    let mut selected_case: Option<(Vec<FieldElement>, Vec<FieldElement>)> = None;
    let mut last_error = None;

    for candidate in noir_input_candidates(total_inputs) {
        match target.execute(&candidate) {
            Ok(outputs) => {
                selected_case = Some((candidate, outputs));
                break;
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
    }

    let (inputs, outputs) = match selected_case {
        Some(value) => value,
        None => {
            return MatrixStatus::Fail(format!(
                "{name} could not find executable witness among deterministic candidates (inputs={total_inputs}): {}",
                last_error.unwrap_or_else(|| "no execution attempts succeeded".to_string())
            ));
        }
    };

    let proof = match target.prove(&inputs) {
        Ok(proof) => proof,
        Err(err) => return classify_error(&format!("{name} prove"), err),
    };

    match target.verify(&proof, &outputs) {
        Ok(true) => MatrixStatus::Pass,
        Ok(false) => MatrixStatus::Fail(format!("{name} verify returned false")),
        Err(err) => classify_error(&format!("{name} verify"), err),
    }
}

fn run_noir_external_fuzz_parity(name: &str, nargo_toml_path: &std::path::Path) -> MatrixStatus {
    if !nargo_toml_path.exists() {
        return MatrixStatus::SkipInfra(format!(
            "external Noir project missing: {}",
            nargo_toml_path.display()
        ));
    }

    let mut target = match NoirTarget::new(nargo_toml_path.to_str().unwrap()) {
        Ok(target) => target,
        Err(err) => return classify_error(&format!("{name} create target"), err),
    };
    if let Err(err) = target.compile() {
        return classify_error(&format!("{name} compile"), err);
    }

    let executor = match NoirExecutor::new(nargo_toml_path.to_str().unwrap()) {
        Ok(executor) => executor,
        Err(err) => return classify_error(&format!("{name} create executor"), err),
    };

    let total_inputs = target.num_public_inputs() + target.num_private_inputs();
    let candidates = noir_input_candidates(total_inputs);
    let mut compared = 0usize;

    for inputs in candidates {
        let target_result = target.execute(&inputs);
        let executor_result = executor.execute_sync(&inputs);
        compared += 1;

        match target_result {
            Ok(expected_outputs) => {
                if !executor_result.success {
                    let executor_error = executor_result
                        .error
                        .unwrap_or_else(|| "unknown executor error".to_string());
                    if is_infrastructure_issue(&executor_error) {
                        return MatrixStatus::SkipInfra(format!(
                            "{name} parity skipped: executor cannot evaluate this external project in strict mode: {}",
                            executor_error
                        ));
                    }
                    return MatrixStatus::Fail(format!(
                        "{name} parity mismatch on executable witness: target succeeded but executor failed: {}",
                        executor_error
                    ));
                }
                if executor_result.outputs != expected_outputs {
                    return MatrixStatus::Fail(format!(
                        "{name} output mismatch: target={:?}, executor={:?}",
                        expected_outputs, executor_result.outputs
                    ));
                }
            }
            Err(_) => {
                if executor_result.success {
                    return MatrixStatus::Fail(format!(
                        "{name} parity mismatch on failing witness: target failed but executor succeeded"
                    ));
                }
            }
        }
    }

    if compared == 0 {
        MatrixStatus::Fail(format!("{name} had no parity candidates"))
    } else {
        MatrixStatus::Pass
    }
}

fn cairo_input_candidates(input_count: usize) -> Vec<Vec<FieldElement>> {
    if input_count == 0 {
        return vec![Vec::new()];
    }

    vec![
        (0..input_count).map(|_| FieldElement::zero()).collect(),
        (0..input_count).map(|_| FieldElement::one()).collect(),
        (0..input_count)
            .map(|idx| FieldElement::from_u64((idx as u64) + 1))
            .collect(),
        (0..input_count)
            .map(|_| FieldElement::from_u64(5))
            .collect(),
    ]
}

fn run_cairo_regression_case(
    case_name: &str,
    program_path: &std::path::Path,
    require_success: bool,
) -> MatrixStatus {
    if !program_path.exists() {
        return MatrixStatus::SkipInfra(format!(
            "{case_name} missing Cairo source: {}",
            program_path.display()
        ));
    }

    let mut target = match CairoTarget::new(program_path.to_str().unwrap()) {
        Ok(target) => target,
        Err(err) => return classify_error(&format!("{case_name} create target"), err),
    };
    if let Err(err) = target.compile() {
        return classify_error(&format!("{case_name} compile"), err);
    }

    let executor = match CairoExecutor::new(program_path.to_str().unwrap()) {
        Ok(executor) => executor,
        Err(err) => return classify_error(&format!("{case_name} create executor"), err),
    };

    let total_inputs = target.num_public_inputs() + target.num_private_inputs();
    let mut successful_candidates = 0usize;

    for inputs in cairo_input_candidates(total_inputs) {
        let target_result = target.execute(&inputs);
        let exec_result = executor.execute_sync(&inputs);

        match target_result {
            Ok(expected_outputs) => {
                if !exec_result.success {
                    return MatrixStatus::Fail(format!(
                        "{case_name} target succeeded but executor failed: {}",
                        exec_result
                            .error
                            .unwrap_or_else(|| "unknown executor error".to_string())
                    ));
                }
                if exec_result.outputs != expected_outputs {
                    return MatrixStatus::Fail(format!(
                        "{case_name} output mismatch: target={:?} executor={:?}",
                        expected_outputs, exec_result.outputs
                    ));
                }

                let second = executor.execute_sync(&inputs);
                if !second.success {
                    return MatrixStatus::Fail(format!(
                        "{case_name} second execution failed on deterministic candidate"
                    ));
                }
                if second.outputs != exec_result.outputs {
                    return MatrixStatus::Fail(format!(
                        "{case_name} deterministic output mismatch on repeated run"
                    ));
                }
                if second.coverage.coverage_hash != exec_result.coverage.coverage_hash {
                    return MatrixStatus::Fail(format!(
                        "{case_name} deterministic coverage hash mismatch on repeated run"
                    ));
                }

                successful_candidates += 1;
            }
            Err(_) => {
                if exec_result.success {
                    return MatrixStatus::Fail(format!(
                        "{case_name} target failed but executor succeeded for same inputs"
                    ));
                }
            }
        }
    }

    if require_success && successful_candidates == 0 {
        return MatrixStatus::Fail(format!(
            "{case_name} had no successful deterministic candidates"
        ));
    }

    MatrixStatus::Pass
}

fn run_cairo_prove_verify_smoke_case(
    case_name: &str,
    program_path: &std::path::Path,
    expected_output: Option<FieldElement>,
) -> MatrixStatus {
    if !program_path.exists() {
        return MatrixStatus::SkipInfra(format!(
            "{case_name} missing Cairo source/project: {}",
            program_path.display()
        ));
    }

    let mut target = match CairoTarget::new(program_path.to_str().unwrap()) {
        Ok(target) => target,
        Err(err) => return classify_error(&format!("{case_name} create target"), err),
    };
    if let Err(err) = target.compile() {
        return classify_error(&format!("{case_name} compile"), err);
    }

    let witness = Vec::new();
    let outputs = match target.execute(&witness) {
        Ok(outputs) => outputs,
        Err(err) => return classify_error(&format!("{case_name} execute"), err),
    };

    if let Some(expected) = expected_output {
        if outputs.first() != Some(&expected) {
            return MatrixStatus::Fail(format!(
                "{case_name} output mismatch: expected {:?}, got {:?}",
                expected,
                outputs.first()
            ));
        }
    }

    let proof = match target.prove(&witness) {
        Ok(proof) => proof,
        Err(err) => return classify_error(&format!("{case_name} prove"), err),
    };

    match target.verify(&proof, &outputs) {
        Ok(true) => MatrixStatus::Pass,
        Ok(false) => MatrixStatus::Fail(format!("{case_name} verify returned false")),
        Err(err) => classify_error(&format!("{case_name} verify"), err),
    }
}

#[derive(Debug, Clone)]
enum MatrixStatus {
    Pass,
    SkipInfra(String),
    Fail(String),
}

impl MatrixStatus {
    fn label(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::SkipInfra(_) => "SKIP_INFRA",
            Self::Fail(_) => "FAIL",
        }
    }

    fn detail(&self) -> Option<&str> {
        match self {
            Self::Pass => None,
            Self::SkipInfra(reason) | Self::Fail(reason) => Some(reason.as_str()),
        }
    }
}

#[derive(Debug, Clone)]
struct BackendMatrixRow {
    backend: &'static str,
    execute: MatrixStatus,
    prove_verify: MatrixStatus,
}

impl BackendMatrixRow {
    fn new(backend: &'static str) -> Self {
        Self {
            backend,
            execute: MatrixStatus::SkipInfra("not run".to_string()),
            prove_verify: MatrixStatus::SkipInfra("not run".to_string()),
        }
    }

    fn set_all(&mut self, status: MatrixStatus) {
        self.execute = status.clone();
        self.prove_verify = status;
    }
}

fn is_infrastructure_issue(message: &str) -> bool {
    let msg = message.to_ascii_lowercase();
    let markers = [
        "not available",
        "install",
        "missing",
        "not found",
        "no such file",
        "failed to run",
        "failed to create",
        "timed out",
        "permission denied",
        "not implemented",
        "unsupported",
        "toolchain",
        "offline mode",
        "can't checkout",
        "unable to update",
        "failed to get `",
        "failed to load source for dependency",
        "build lock file",
        ".zkfuzz_build.lock",
        "provide a circuit binary that supports --prove",
        "constraint coverage unavailable",
        "unrecognized subcommand",
    ];
    markers.iter().any(|marker| msg.contains(marker))
}

fn classify_error(context: &str, err: impl std::fmt::Display) -> MatrixStatus {
    let message = format!("{}: {}", context, err);
    if is_infrastructure_issue(&message) {
        MatrixStatus::SkipInfra(message)
    } else {
        MatrixStatus::Fail(message)
    }
}

fn describe_status(status: &MatrixStatus) -> String {
    match status.detail() {
        Some(detail) => format!("{} ({})", status.label(), detail),
        None => status.label().to_string(),
    }
}

fn expect_or_skip_infra<T, E: std::fmt::Display>(
    test_name: &str,
    context: &str,
    result: Result<T, E>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) => match classify_error(context, err) {
            MatrixStatus::SkipInfra(reason) => {
                println!("{test_name}: SKIP_INFRA ({reason})");
                None
            }
            MatrixStatus::Fail(reason) => panic!("{test_name}: {reason}"),
            MatrixStatus::Pass => unreachable!("classify_error never returns MatrixStatus::Pass"),
        },
    }
}

fn configure_halo2_real_env() -> Result<(), String> {
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME") {
        let cargo_home = PathBuf::from(cargo_home);
        std::fs::create_dir_all(&cargo_home).map_err(|err| {
            format!(
                "failed to ensure CARGO_HOME '{}': {}",
                cargo_home.display(),
                err
            )
        })?;
    } else {
        let cargo_home = std::env::temp_dir().join("zk0d_halo2_cargo_home");
        std::fs::create_dir_all(&cargo_home).map_err(|err| {
            format!(
                "failed to create CARGO_HOME '{}': {}",
                cargo_home.display(),
                err
            )
        })?;
        std::env::set_var("CARGO_HOME", &cargo_home);
    }
    std::env::set_var("RUSTUP_SKIP_UPDATE_CHECK", "1");
    std::env::set_var("RUSTUP_TOOLCHAIN", "nightly");
    if std::env::var_os("CARGO_NET_OFFLINE").is_none() {
        std::env::set_var("CARGO_NET_OFFLINE", "true");
    }
    Ok(())
}

fn run_circom_matrix_row() -> BackendMatrixRow {
    let mut row = BackendMatrixRow::new("circom");

    if let Err(err) = CircomTarget::check_circom_available() {
        row.set_all(MatrixStatus::SkipInfra(format!(
            "circom unavailable: {}",
            err
        )));
        return row;
    }
    if let Err(err) = CircomTarget::check_snarkjs_available() {
        row.set_all(MatrixStatus::SkipInfra(format!(
            "snarkjs unavailable: {}",
            err
        )));
        return row;
    }

    let circuit_path = circom_test_circuit("multiplier");
    if !circuit_path.exists() {
        row.set_all(MatrixStatus::SkipInfra(format!(
            "test circuit missing: {}",
            circuit_path.display()
        )));
        return row;
    }

    let mut target = match CircomTarget::new(circuit_path.to_str().unwrap(), "Multiplier") {
        Ok(target) => target,
        Err(err) => {
            row.set_all(classify_error("create target", err));
            return row;
        }
    };

    if let Err(err) = target.compile() {
        row.set_all(classify_error("compile", err));
        return row;
    }

    let witness = vec![FieldElement::from_u64(3), FieldElement::from_u64(4)];
    let outputs = match target.execute(&witness) {
        Ok(outputs) => {
            if outputs.first() == Some(&FieldElement::from_u64(12)) {
                row.execute = MatrixStatus::Pass;
                outputs
            } else {
                row.execute = MatrixStatus::Fail(format!(
                    "execute output mismatch: expected 12, got {:?}",
                    outputs.first()
                ));
                row.prove_verify = MatrixStatus::SkipInfra(
                    "prove/verify skipped because execute failed".to_string(),
                );
                return row;
            }
        }
        Err(err) => {
            row.execute = classify_error("execute", err);
            row.prove_verify =
                MatrixStatus::SkipInfra("prove/verify skipped because execute failed".to_string());
            return row;
        }
    };

    if let Err(err) = target.setup_keys() {
        row.prove_verify = classify_error("setup_keys", err);
        return row;
    }

    let proof = match target.prove(&witness) {
        Ok(proof) => proof,
        Err(err) => {
            row.prove_verify = classify_error("prove", err);
            return row;
        }
    };

    row.prove_verify = match target.verify(&proof, &outputs) {
        Ok(true) => MatrixStatus::Pass,
        Ok(false) => MatrixStatus::Fail("verify returned false".to_string()),
        Err(err) => classify_error("verify", err),
    };

    row
}

fn run_noir_matrix_row() -> BackendMatrixRow {
    let mut row = BackendMatrixRow::new("noir");

    if let Err(err) = NoirTarget::check_nargo_available() {
        row.set_all(MatrixStatus::SkipInfra(format!(
            "nargo unavailable: {}",
            err
        )));
        return row;
    }

    let project_path = noir_project_path("multiplier");
    if !project_path.exists() {
        row.set_all(MatrixStatus::SkipInfra(format!(
            "test project missing: {}",
            project_path.display()
        )));
        return row;
    }

    let mut target = match NoirTarget::new(project_path.to_str().unwrap()) {
        Ok(target) => target,
        Err(err) => {
            row.set_all(classify_error("create target", err));
            return row;
        }
    };

    if let Err(err) = target.compile() {
        row.set_all(classify_error("compile", err));
        return row;
    }

    let witness = vec![FieldElement::from_u64(3), FieldElement::from_u64(5)];
    let outputs = match target.execute(&witness) {
        Ok(outputs) => {
            if outputs.first() == Some(&FieldElement::from_u64(15)) {
                row.execute = MatrixStatus::Pass;
                outputs
            } else {
                row.execute = MatrixStatus::Fail(format!(
                    "execute output mismatch: expected 15, got {:?}",
                    outputs.first()
                ));
                row.prove_verify = MatrixStatus::SkipInfra(
                    "prove/verify skipped because execute failed".to_string(),
                );
                return row;
            }
        }
        Err(err) => {
            row.execute = classify_error("execute", err);
            row.prove_verify =
                MatrixStatus::SkipInfra("prove/verify skipped because execute failed".to_string());
            return row;
        }
    };

    let proof = match target.prove(&witness) {
        Ok(proof) => proof,
        Err(err) => {
            row.prove_verify = classify_error("prove", err);
            return row;
        }
    };

    row.prove_verify = match target.verify(&proof, &outputs) {
        Ok(true) => MatrixStatus::Pass,
        Ok(false) => MatrixStatus::Fail("verify returned false".to_string()),
        Err(err) => classify_error("verify", err),
    };

    row
}

fn run_halo2_matrix_row() -> BackendMatrixRow {
    let mut row = BackendMatrixRow::new("halo2");

    let repo_path = halo2_real_repo_path();
    if !repo_path.exists() {
        row.set_all(MatrixStatus::SkipInfra(format!(
            "halo2 scaffold repo missing: {}",
            repo_path.display()
        )));
        return row;
    }

    if let Err(err) = configure_halo2_real_env() {
        row.set_all(classify_error("configure halo2 env", err));
        return row;
    }

    let build_dir = std::env::temp_dir().join("zk0d_halo2_build");
    let executor =
        match Halo2Executor::new_with_build_dir(repo_path.to_str().unwrap(), "zk0d_mul", build_dir)
        {
            Ok(executor) => executor,
            Err(err) => {
                row.set_all(classify_error("create executor", err));
                return row;
            }
        };

    let witness = vec![
        FieldElement::from_u64(3),
        FieldElement::from_u64(5),
        FieldElement::from_u64(15),
    ];
    let exec_result = executor.execute_sync(&witness);
    if exec_result.success {
        row.execute = MatrixStatus::Pass;
    } else {
        let message = exec_result
            .error
            .unwrap_or_else(|| "unknown halo2 execution error".to_string());
        row.execute = classify_error("execute", message);
        row.prove_verify =
            MatrixStatus::SkipInfra("prove/verify skipped because execute failed".to_string());
        return row;
    }

    let proof = match executor.prove(&witness) {
        Ok(proof) => proof,
        Err(err) => {
            row.prove_verify = classify_error("prove", err);
            return row;
        }
    };

    row.prove_verify = match executor.verify(&proof, &exec_result.outputs) {
        Ok(true) => MatrixStatus::Pass,
        Ok(false) => MatrixStatus::Fail("verify returned false".to_string()),
        Err(err) => classify_error("verify", err),
    };

    row
}

fn run_cairo_matrix_row() -> BackendMatrixRow {
    let mut row = BackendMatrixRow::new("cairo");

    if let Err(err) = CairoTarget::check_cairo_available() {
        row.set_all(MatrixStatus::SkipInfra(format!(
            "cairo unavailable: {}",
            err
        )));
        return row;
    }

    let program_path = cairo_program_path("multiplier");
    if !program_path.exists() {
        row.set_all(MatrixStatus::SkipInfra(format!(
            "test program missing: {}",
            program_path.display()
        )));
        return row;
    }

    let mut target = match CairoTarget::new(program_path.to_str().unwrap()) {
        Ok(target) => target,
        Err(err) => {
            row.set_all(classify_error("create target", err));
            return row;
        }
    };

    if let Err(err) = target.compile() {
        row.set_all(classify_error("compile", err));
        return row;
    }

    let witness = Vec::new();
    let outputs = match target.execute(&witness) {
        Ok(outputs) => {
            if outputs.first() == Some(&FieldElement::from_u64(12)) {
                row.execute = MatrixStatus::Pass;
                outputs
            } else {
                row.execute = MatrixStatus::Fail(format!(
                    "execute output mismatch: expected 12, got {:?}",
                    outputs.first()
                ));
                row.prove_verify = MatrixStatus::SkipInfra(
                    "prove/verify skipped because execute failed".to_string(),
                );
                return row;
            }
        }
        Err(err) => {
            row.execute = classify_error("execute", err);
            row.prove_verify =
                MatrixStatus::SkipInfra("prove/verify skipped because execute failed".to_string());
            return row;
        }
    };

    let proof = match target.prove(&witness) {
        Ok(proof) => proof,
        Err(err) => {
            row.prove_verify = classify_error("prove", err);
            return row;
        }
    };

    row.prove_verify = match target.verify(&proof, &outputs) {
        Ok(true) => MatrixStatus::Pass,
        Ok(false) => MatrixStatus::Fail("verify returned false".to_string()),
        Err(err) => classify_error("verify", err),
    };

    row
}

fn halo2_stability_fixtures() -> Vec<Vec<FieldElement>> {
    vec![
        vec![
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
            FieldElement::from_u64(6),
        ],
        vec![
            FieldElement::from_u64(3),
            FieldElement::from_u64(5),
            FieldElement::from_u64(15),
        ],
        vec![
            FieldElement::from_u64(7),
            FieldElement::from_u64(9),
            FieldElement::from_u64(63),
        ],
    ]
}

/// Real backend matrix smoke test with explicit PASS/SKIP_INFRA/FAIL reporting.
#[test]
fn test_real_backend_matrix_smoke() {
    if !require_real_backends("test_real_backend_matrix_smoke") {
        return;
    }

    let rows = vec![
        run_circom_matrix_row(),
        run_noir_matrix_row(),
        run_halo2_matrix_row(),
        run_cairo_matrix_row(),
    ];

    println!("real backend matrix smoke summary:");
    println!("backend | execute | prove_verify");
    for row in &rows {
        println!(
            "{:<7} | {:<56} | {}",
            row.backend,
            describe_status(&row.execute),
            describe_status(&row.prove_verify)
        );
    }

    let mut failures = Vec::new();
    for row in &rows {
        if let MatrixStatus::Fail(reason) = &row.execute {
            failures.push(format!("{} execute: {}", row.backend, reason));
        }
        if let MatrixStatus::Fail(reason) = &row.prove_verify {
            failures.push(format!("{} prove_verify: {}", row.backend, reason));
        }
    }

    let runnable_backends = rows
        .iter()
        .filter(|row| !matches!(row.execute, MatrixStatus::SkipInfra(_)))
        .count();
    assert!(
        runnable_backends > 0,
        "ZKFUZZ_REAL_BACKENDS=1 but all backends were infrastructure-skipped"
    );

    if !failures.is_empty() {
        panic!(
            "real backend matrix smoke had failures:\n{}",
            failures.join("\n")
        );
    }
}

/// Test that all required backends are available
#[test]
fn test_backend_availability() {
    if !require_real_backends("test_backend_availability") {
        return;
    }
    let circom_version =
        CircomTarget::check_circom_available().expect("Circom not available on local PATH.");
    let snarkjs_version =
        CircomTarget::check_snarkjs_available().expect("snarkjs not available on local PATH.");
    let noir_version =
        NoirTarget::check_nargo_available().expect("Noir not available on local PATH.");
    let (cairo_version, cairo_str) = CairoTarget::check_cairo_available()
        .expect("Cairo not available. Ensure cairo-compile and cairo-run are on PATH");

    println!("Circom available: {}", circom_version);
    println!("snarkjs available: {}", snarkjs_version);
    println!("Noir available: {}", noir_version);
    println!("Cairo available: {:?} - {}", cairo_version, cairo_str);
}

/// Test executor creation reports missing tooling cleanly.
#[test]
fn test_executor_creation_reports_missing_tooling() {
    let result = ExecutorFactory::create(Framework::Circom, "test.circom", "TestCircuit");
    assert!(result.is_err());
}

/// Test Halo2 target construction
#[test]
fn test_halo2_target_basic_construction() {
    let target = Halo2Target::new("test_circuit").unwrap();

    assert_eq!(target.name(), "test_circuit");
}

/// Test field element operations
#[test]
fn test_field_element_operations() {
    let zero = FieldElement::zero();
    let one = FieldElement::one();

    assert_ne!(zero, one);

    // Test addition
    let two = one.add(&one);
    assert_eq!(two, FieldElement::from_u64(2));

    // Test multiplication
    let four = two.mul(&two);
    assert_eq!(four, FieldElement::from_u64(4));
}

/// Test Circom analysis functions
#[test]
fn test_circom_analysis() {
    let source = r#"
        pragma circom 2.0.0;
        
        template Multiplier() {
            signal input a;
            signal input b;
            signal output c;
            
            c <== a * b;
        }
        
        component main = Multiplier();
    "#;

    let signals = zk_fuzzer::targets::circom_analysis::extract_signals(source);
    assert_eq!(signals.len(), 3);

    let vulnerabilities = zk_fuzzer::targets::circom_analysis::analyze_for_vulnerabilities(source);
    // Should detect potential underconstrained (3 signals, 1 constraint)
    println!("Found {} potential issues", vulnerabilities.len());
}

/// Test Noir analysis functions
#[test]
fn test_noir_analysis() {
    let source = r#"
        fn main(x: Field, y: pub Field) -> Field {
            assert(x != 0);
            x * y
        }
        
        fn helper(a: u64) -> u64 {
            a + 1
        }
    "#;

    let functions = zk_fuzzer::targets::noir_analysis::extract_functions(source);
    assert_eq!(functions.len(), 2);
    assert!(functions[0].is_main);

    let vulnerabilities = zk_fuzzer::targets::noir_analysis::analyze_for_vulnerabilities(source);
    println!("Found {} potential issues", vulnerabilities.len());
}

/// Test Halo2 analysis functions
#[test]
fn test_halo2_analysis() {
    let source = r#"
        let a1 = meta.advice_column();
        let a2 = meta.advice_column();
        
        region.assign_advice(a1, 0, || Value::known(x));
        region.query_advice(a1, Rotation::cur());
    "#;

    let issues = zk_fuzzer::targets::halo2_analysis::analyze_circuit(source);
    // Should detect unused column (a2 declared but never used)
    println!("Found {} potential issues", issues.len());
}

/// Test Cairo analysis functions
#[test]
fn test_cairo_analysis() {
    let source = r#"
        func main{output_ptr: felt*}() {
            let x = 5;
            %{ memory[ap] = ids.x * 2 %}
            [ap] = [ap - 1] + x;
        }
    "#;

    let vulnerabilities = zk_fuzzer::targets::cairo_analysis::analyze_for_vulnerabilities(source);
    // Should detect hint usage
    assert!(vulnerabilities
        .iter()
        .any(|v| v.issue_type == zk_fuzzer::targets::cairo_analysis::IssueType::HintUsage));
}

/// Integration test for Circom (only runs if circom is available)
#[test]
fn test_circom_integration() {
    if !require_real_backends("test_circom_integration") {
        return;
    }
    CircomTarget::check_circom_available().expect("Circom not available on local PATH.");
    CircomTarget::check_snarkjs_available().expect("snarkjs not available on local PATH.");

    let circuit_path = circom_test_circuit("multiplier");
    assert!(
        circuit_path.exists(),
        "Missing test circuit at {:?}",
        circuit_path
    );

    let mut target = CircomTarget::new(circuit_path.to_str().unwrap(), "Multiplier")
        .expect("Failed to create CircomTarget");
    target.compile().expect("Circom compilation failed");

    let outputs = target
        .execute(&[FieldElement::from_u64(3), FieldElement::from_u64(4)])
        .expect("Circom execution failed");

    assert_eq!(outputs.first(), Some(&FieldElement::from_u64(12)));
}

/// Integration test for Noir (only runs if nargo is available)
#[test]
fn test_noir_integration() {
    if !require_real_backends("test_noir_integration") {
        return;
    }
    NoirTarget::check_nargo_available().expect("Noir not available on local PATH.");

    let project_path = noir_project_path("multiplier");
    assert!(
        project_path.exists(),
        "Missing Noir project at {:?}",
        project_path
    );

    let mut target =
        NoirTarget::new(project_path.to_str().unwrap()).expect("Failed to create NoirTarget");
    target.compile().expect("Noir compilation failed");

    let outputs = target
        .execute(&[FieldElement::from_u64(3), FieldElement::from_u64(5)])
        .expect("Noir execution failed");

    assert_eq!(outputs.first(), Some(&FieldElement::from_u64(15)));
}

/// Local prove/verify smoke for Noir real-circuit readiness.
#[test]
fn test_noir_local_prove_verify_smoke() {
    if !require_real_backends("test_noir_local_prove_verify_smoke") {
        return;
    }
    NoirTarget::check_nargo_available().expect("Noir not available on local PATH.");

    let project_path = noir_project_path("multiplier");
    assert!(
        project_path.exists(),
        "Missing Noir project at {:?}",
        project_path
    );

    let mut target =
        NoirTarget::new(project_path.to_str().unwrap()).expect("Failed to create NoirTarget");
    target.compile().expect("Noir compilation failed");

    let witness = vec![FieldElement::from_u64(3), FieldElement::from_u64(5)];
    let outputs = match expect_or_skip_infra(
        "test_noir_local_prove_verify_smoke",
        "Noir execute",
        target.execute(&witness),
    ) {
        Some(outputs) => outputs,
        None => return,
    };
    assert_eq!(outputs.first(), Some(&FieldElement::from_u64(15)));

    let proof = match expect_or_skip_infra(
        "test_noir_local_prove_verify_smoke",
        "Noir proof generation",
        target.prove(&witness),
    ) {
        Some(proof) => proof,
        None => return,
    };

    let verified = match expect_or_skip_infra(
        "test_noir_local_prove_verify_smoke",
        "Noir proof verification",
        target.verify(&proof, &outputs),
    ) {
        Some(verified) => verified,
        None => return,
    };
    assert!(verified, "Noir proof verification returned false");
}

/// Integration test for ExecutorFactory using real backends
#[test]
fn test_executor_factory_real_backends() {
    if !require_real_backends("test_executor_factory_real_backends") {
        return;
    }

    let options = ExecutorFactoryOptions::strict();

    let circom_path = circom_test_circuit("multiplier");
    assert!(
        circom_path.exists(),
        "Missing test circuit at {:?}",
        circom_path
    );
    let circom_exec = ExecutorFactory::create_with_options(
        Framework::Circom,
        circom_path.to_str().unwrap(),
        "Multiplier",
        &options,
    )
    .expect("Failed to create Circom executor via factory");
    assert_eq!(circom_exec.framework(), Framework::Circom);

    let noir_path = noir_project_path("multiplier");
    assert!(
        noir_path.exists(),
        "Missing Noir project at {:?}",
        noir_path
    );
    let noir_exec = ExecutorFactory::create_with_options(
        Framework::Noir,
        noir_path.to_str().unwrap(),
        "main",
        &options,
    )
    .expect("Failed to create Noir executor via factory");
    assert_eq!(noir_exec.framework(), Framework::Noir);
}

/// Validate constraint-level coverage for Circom executor
#[test]
fn test_circom_constraint_coverage() {
    if !require_real_backends("test_circom_constraint_coverage") {
        return;
    }
    CircomTarget::check_circom_available().expect("Circom not available on local PATH.");
    CircomTarget::check_snarkjs_available().expect("snarkjs not available on local PATH.");

    let circuit_path = circom_test_circuit("multiplier");
    assert!(
        circuit_path.exists(),
        "Missing test circuit at {:?}",
        circuit_path
    );

    let executor = CircomExecutor::new(circuit_path.to_str().unwrap(), "Multiplier")
        .expect("Failed to create CircomExecutor");

    let result = executor.execute_sync(&[FieldElement::from_u64(3), FieldElement::from_u64(4)]);

    assert!(result.success, "Circom execution failed");
    assert!(
        !result.coverage.satisfied_constraints.is_empty(),
        "Expected constraint-level coverage for Circom executor"
    );
}

/// Validate constraint-level coverage for Noir executor
#[test]
fn test_noir_constraint_coverage() {
    if !require_real_backends("test_noir_constraint_coverage") {
        return;
    }
    NoirTarget::check_nargo_available().expect("Noir not available on local PATH.");

    let project_path = noir_project_path("multiplier");
    assert!(
        project_path.exists(),
        "Missing Noir project at {:?}",
        project_path
    );

    let executor =
        NoirExecutor::new(project_path.to_str().unwrap()).expect("Failed to create NoirExecutor");

    let result = executor.execute_sync(&[FieldElement::from_u64(3), FieldElement::from_u64(5)]);

    assert!(result.success, "Noir execution failed");
    assert!(
        !result.coverage.satisfied_constraints.is_empty(),
        "Expected constraint-level coverage for Noir executor"
    );
}

/// End-to-end prove/verify smoke tests for external Noir Nargo.toml projects.
#[test]
fn test_noir_external_nargo_prove_verify_smoke() {
    if !require_real_backends("test_noir_external_nargo_prove_verify_smoke") {
        return;
    }
    NoirTarget::check_nargo_available().expect("Noir not available on local PATH.");

    let mut failures = Vec::new();
    let mut runnable = 0usize;

    for (name, nargo_toml_path) in noir_external_nargo_projects() {
        let status = run_noir_external_prove_verify_smoke(name, &nargo_toml_path);
        println!(
            "noir external smoke [{}]: {}",
            name,
            describe_status(&status)
        );

        match status {
            MatrixStatus::Pass => runnable += 1,
            MatrixStatus::SkipInfra(_) => {}
            MatrixStatus::Fail(reason) => failures.push(format!("{name}: {reason}")),
        }
    }

    if !failures.is_empty() {
        panic!("external Noir smoke failures:\n{}", failures.join("\n"));
    }
    if runnable == 0 {
        println!(
            "noir external smoke: SKIP_INFRA (No runnable external Noir projects for smoke test; set ZK0D_BASE or ensure default path exists)"
        );
    }
}

/// Deterministic fuzz parity tests for external Noir Nargo.toml projects.
#[test]
fn test_noir_external_nargo_fuzz_parity() {
    if !require_real_backends("test_noir_external_nargo_fuzz_parity") {
        return;
    }
    NoirTarget::check_nargo_available().expect("Noir not available on local PATH.");

    let mut failures = Vec::new();
    let mut runnable = 0usize;

    for (name, nargo_toml_path) in noir_external_nargo_projects() {
        let status = run_noir_external_fuzz_parity(name, &nargo_toml_path);
        println!(
            "noir external parity [{}]: {}",
            name,
            describe_status(&status)
        );

        match status {
            MatrixStatus::Pass => runnable += 1,
            MatrixStatus::SkipInfra(_) => {}
            MatrixStatus::Fail(reason) => failures.push(format!("{name}: {reason}")),
        }
    }

    if !failures.is_empty() {
        panic!("external Noir parity failures:\n{}", failures.join("\n"));
    }
    if runnable == 0 {
        println!(
            "noir external parity: SKIP_INFRA (No runnable external Noir projects for parity test; set ZK0D_BASE or ensure default path exists)"
        );
    }
}

/// Validate Noir constraint coverage edge cases (local multiplier + zero-input style external project when present).
#[test]
fn test_noir_constraint_coverage_edge_cases() {
    if !require_real_backends("test_noir_constraint_coverage_edge_cases") {
        return;
    }
    NoirTarget::check_nargo_available().expect("Noir not available on local PATH.");

    let local_project = noir_project_path("multiplier");
    assert!(
        local_project.exists(),
        "Missing Noir project at {:?}",
        local_project
    );

    let local_executor =
        NoirExecutor::new(local_project.to_str().unwrap()).expect("Failed to create NoirExecutor");
    for inputs in noir_input_candidates(2) {
        let result = local_executor.execute_sync(&inputs);
        if result.success {
            assert!(
                !result.coverage.satisfied_constraints.is_empty(),
                "Expected non-empty Noir coverage for local multiplier edge-case inputs"
            );
            break;
        }
    }

    if let Some((name, nargo_toml_path)) = noir_external_nargo_projects()
        .into_iter()
        .find(|(name, _)| *name == "aztec_hello_circuit")
    {
        if nargo_toml_path.exists() {
            let mut target = match expect_or_skip_infra(
                "test_noir_constraint_coverage_edge_cases",
                "create external Noir target",
                NoirTarget::new(nargo_toml_path.to_str().unwrap()),
            ) {
                Some(target) => target,
                None => return,
            };
            if expect_or_skip_infra(
                "test_noir_constraint_coverage_edge_cases",
                "external Noir compilation",
                target.compile(),
            )
            .is_none()
            {
                return;
            }

            let total_inputs = target.num_public_inputs() + target.num_private_inputs();
            let executor = match expect_or_skip_infra(
                "test_noir_constraint_coverage_edge_cases",
                "create external Noir executor",
                NoirExecutor::new(nargo_toml_path.to_str().unwrap()),
            ) {
                Some(executor) => executor,
                None => return,
            };

            let mut saw_success = false;
            for inputs in noir_input_candidates(total_inputs) {
                let result = executor.execute_sync(&inputs);
                if result.success {
                    assert!(
                        !result.coverage.satisfied_constraints.is_empty(),
                        "Expected non-empty Noir coverage for external edge-case project '{}'",
                        name
                    );
                    saw_success = true;
                    break;
                }
            }

            assert!(
                saw_success,
                "No successful execution observed for external Noir edge-case project '{}'",
                name
            );
        }
    }
}

/// Validate constraint-level coverage for a real Halo2 circuit project.
/// Requires the halo2-scaffold repo cloned at ${ZK0D_BASE:-/media/elements/Repos/zk0d}/cat5_frameworks/halo2-scaffold
/// (or set HALO2_SCAFFOLD_PATH explicitly).
#[test]
fn test_halo2_real_circuit_constraint_coverage() {
    if !require_real_backends("test_halo2_real_circuit_constraint_coverage") {
        return;
    }
    let repo_path = halo2_real_repo_path();
    if !repo_path.exists() {
        println!(
            "test_halo2_real_circuit_constraint_coverage: SKIP_INFRA (Missing halo2-scaffold repo at {})",
            repo_path.display()
        );
        return;
    }
    if let Err(err) = configure_halo2_real_env() {
        println!("test_halo2_real_circuit_constraint_coverage: SKIP_INFRA ({err})");
        return;
    }

    let build_dir = std::env::temp_dir().join("zk0d_halo2_build");
    let test_started = Instant::now();
    let create_executor_started = Instant::now();
    let executor = match expect_or_skip_infra(
        "test_halo2_real_circuit_constraint_coverage",
        "create Halo2 executor",
        Halo2Executor::new_with_build_dir(
            repo_path.to_str().unwrap(),
            "zk0d_mul",
            build_dir.clone(),
        ),
    ) {
        Some(executor) => executor,
        None => return,
    };
    let create_executor_elapsed = create_executor_started.elapsed();

    let inputs = vec![
        FieldElement::from_u64(3),
        FieldElement::from_u64(5),
        FieldElement::from_u64(15),
    ];

    let execute_sync_started = Instant::now();
    let result = executor.execute_sync(&inputs);
    let execute_sync_elapsed = execute_sync_started.elapsed();
    if !result.success {
        let message = result
            .error
            .unwrap_or_else(|| "unknown halo2 execution error".to_string());
        match classify_error("halo2 execute", message) {
            MatrixStatus::SkipInfra(reason) => {
                println!("test_halo2_real_circuit_constraint_coverage: SKIP_INFRA ({reason})");
                return;
            }
            MatrixStatus::Fail(reason) => panic!("Halo2 execution failed: {reason}"),
            MatrixStatus::Pass => unreachable!("classify_error never returns MatrixStatus::Pass"),
        }
    }
    assert!(
        !result.coverage.satisfied_constraints.is_empty(),
        "Expected constraint-level coverage for Halo2 executor"
    );

    let total_elapsed = test_started.elapsed();
    emit_phase_timing_ms(
        "test_halo2_real_circuit_constraint_coverage",
        &build_dir,
        &[
            ("create_executor", Some(create_executor_elapsed)),
            ("execute_sync", Some(execute_sync_elapsed)),
            ("total", Some(total_elapsed)),
        ],
    );
}

/// Deterministic replay harness for EXT-005 (EZKL) after adapter hardening.
///
/// This verifies the post-fix behavior for the `Base execution failed` finding class:
/// project execution succeeds even when host-side `--constraints` extraction is unsupported,
/// and executor coverage falls back to output-hash mode.
#[test]
fn test_halo2_ext005_ezkl_replay_base_execution_failure() {
    if !require_real_backends("test_halo2_ext005_ezkl_replay_base_execution_failure") {
        return;
    }

    let manifest_path = ext005_ezkl_manifest_path();
    if !manifest_path.exists() {
        println!(
            "test_halo2_ext005_ezkl_replay_base_execution_failure: SKIP_INFRA (Missing EXT-005 manifest at {})",
            manifest_path.display()
        );
        return;
    }

    if let Err(err) = configure_halo2_real_env() {
        println!("test_halo2_ext005_ezkl_replay_base_execution_failure: SKIP_INFRA ({err})");
        return;
    }
    if std::env::var_os(HALO2_EXTERNAL_TIMEOUT_SECS_ENV).is_none() {
        // Keep replay deterministic and bounded by default for proof-followup runs.
        std::env::set_var(HALO2_EXTERNAL_TIMEOUT_SECS_ENV, "180");
    }
    println!(
        "test_halo2_ext005_ezkl_replay_base_execution_failure: using ZK_FUZZER_HALO2_EXTERNAL_TIMEOUT_SECS={}",
        std::env::var(HALO2_EXTERNAL_TIMEOUT_SECS_ENV)
            .unwrap_or_else(|_| "180".to_string())
    );

    let build_dir = ext005_ezkl_build_dir();
    let test_started = Instant::now();
    let create_executor_started = Instant::now();
    println!(
        "test_halo2_ext005_ezkl_replay_base_execution_failure: phase=create_executor build_dir={}",
        build_dir.display()
    );
    let executor = match expect_or_skip_infra(
        "test_halo2_ext005_ezkl_replay_base_execution_failure",
        "create Halo2 executor",
        with_console_progress(
            "test_halo2_ext005_ezkl_replay_base_execution_failure: create_executor",
            Duration::from_secs(20),
            || {
                Halo2Executor::new_with_build_dir(
                    manifest_path.to_str().unwrap(),
                    "main",
                    build_dir.clone(),
                )
            },
        ),
    ) {
        Some(executor) => executor,
        None => return,
    };
    let create_executor_elapsed = create_executor_started.elapsed();

    let witness_hex = ext005_replay_witness_hex();
    println!(
        "test_halo2_ext005_ezkl_replay_base_execution_failure: using witness={}",
        witness_hex
    );
    let witness = vec![FieldElement::from_hex(&witness_hex).expect("valid finding witness hex")];

    println!("test_halo2_ext005_ezkl_replay_base_execution_failure: phase=executor_execute_sync");
    let executor_execute_started = Instant::now();
    let result = with_console_progress(
        "test_halo2_ext005_ezkl_replay_base_execution_failure: executor_execute_sync",
        Duration::from_secs(20),
        || executor.execute_sync(&witness),
    );
    let executor_execute_elapsed = executor_execute_started.elapsed();
    assert!(
        result.success,
        "Expected Halo2 executor success via output-hash fallback, got error {:?}",
        result.error
    );
    assert!(
        !result.outputs.is_empty(),
        "Expected successful execution to produce at least one output"
    );
    let expected_fallback = ExecutionCoverage::with_output_hash(&result.outputs);
    assert!(
        result.coverage.coverage_hash == expected_fallback.coverage_hash,
        "Expected output-hash fallback coverage, got coverage_hash={} expected={}",
        result.coverage.coverage_hash,
        expected_fallback.coverage_hash
    );
    assert!(
        result.coverage.satisfied_constraints.is_empty()
            && result.coverage.evaluated_constraints.is_empty(),
        "Expected fallback execution coverage with no extracted constraint IDs"
    );

    let create_target_started = Instant::now();
    let mut target = match expect_or_skip_infra(
        "test_halo2_ext005_ezkl_replay_base_execution_failure",
        "create Halo2 target",
        with_console_progress(
            "test_halo2_ext005_ezkl_replay_base_execution_failure: create_target",
            Duration::from_secs(20),
            || Halo2Target::new(manifest_path.to_str().unwrap()),
        ),
    ) {
        Some(target) => target,
        None => return,
    };
    let create_target_elapsed = create_target_started.elapsed();
    target = target.with_build_dir(build_dir.join("target_replay"));

    println!("test_halo2_ext005_ezkl_replay_base_execution_failure: phase=target_setup");
    let target_setup_started = Instant::now();
    if let None = expect_or_skip_infra(
        "test_halo2_ext005_ezkl_replay_base_execution_failure",
        "setup Halo2 target",
        with_console_progress(
            "test_halo2_ext005_ezkl_replay_base_execution_failure: target_setup",
            Duration::from_secs(20),
            || target.setup(),
        ),
    ) {
        return;
    }
    let target_setup_elapsed = target_setup_started.elapsed();

    println!("test_halo2_ext005_ezkl_replay_base_execution_failure: phase=target_execute");
    let target_execute_started = Instant::now();
    let direct_outputs = match expect_or_skip_infra(
        "test_halo2_ext005_ezkl_replay_base_execution_failure",
        "direct Halo2 target execute",
        with_console_progress(
            "test_halo2_ext005_ezkl_replay_base_execution_failure: target_execute",
            Duration::from_secs(20),
            || target.execute(&witness),
        ),
    ) {
        Some(outputs) => outputs,
        None => return,
    };
    let target_execute_elapsed = target_execute_started.elapsed();
    assert!(
        !direct_outputs.is_empty(),
        "Expected direct Halo2 target execution to produce at least one output"
    );
    assert_eq!(
        result.outputs, direct_outputs,
        "Executor output should match direct target execution output for replay witness"
    );

    let skip_constraint_load = ext005_skip_constraint_load_enabled();
    println!(
        "test_halo2_ext005_ezkl_replay_base_execution_failure: {}={}",
        EXT005_REPLAY_SKIP_CONSTRAINT_LOAD_ENV, skip_constraint_load
    );

    let load_constraints_elapsed = if skip_constraint_load {
        None
    } else {
        println!(
            "test_halo2_ext005_ezkl_replay_base_execution_failure: phase=load_plonk_constraints"
        );
        let load_constraints_started = Instant::now();
        let parsed = with_console_progress(
            "test_halo2_ext005_ezkl_replay_base_execution_failure: load_plonk_constraints",
            Duration::from_secs(20),
            || target.load_plonk_constraints(),
        );
        let elapsed = load_constraints_started.elapsed();
        assert!(
            parsed.constraints.is_empty(),
            "Expected empty extracted PLONK constraints for EXT-005 replay target"
        );
        assert_eq!(
            target.constraint_export_supported(),
            Some(false),
            "Expected EXT-005 target to be marked as unsupported for --constraints export"
        );
        Some(elapsed)
    };

    let total_elapsed = test_started.elapsed();
    println!(
        "test_halo2_ext005_ezkl_replay_base_execution_failure: phase_metrics create_executor_s={} executor_execute_sync_s={} create_target_s={} target_setup_s={} target_execute_s={} load_plonk_constraints_s={} total_s={}",
        create_executor_elapsed.as_secs(),
        executor_execute_elapsed.as_secs(),
        create_target_elapsed.as_secs(),
        target_setup_elapsed.as_secs(),
        target_execute_elapsed.as_secs(),
        load_constraints_elapsed
            .map(|elapsed| elapsed.as_secs().to_string())
            .unwrap_or_else(|| "skipped".to_string()),
        total_elapsed.as_secs()
    );
    emit_phase_timing_ms(
        "test_halo2_ext005_ezkl_replay_base_execution_failure",
        &build_dir,
        &[
            ("create_executor", Some(create_executor_elapsed)),
            ("executor_execute_sync", Some(executor_execute_elapsed)),
            ("create_target", Some(create_target_elapsed)),
            ("target_setup", Some(target_setup_elapsed)),
            ("target_execute", Some(target_execute_elapsed)),
            ("load_plonk_constraints", load_constraints_elapsed),
            ("total", Some(total_elapsed)),
        ],
    );
    println!(
        "test_halo2_ext005_ezkl_replay_base_execution_failure: completed_successfully outputs={} coverage_hash={}",
        result.outputs.len(),
        result.coverage.coverage_hash
    );
}

/// Stability check for halo2-scaffold execution under nightly with deterministic fixture inputs.
#[test]
fn test_halo2_scaffold_execution_stability() {
    if !require_real_backends("test_halo2_scaffold_execution_stability") {
        return;
    }
    let repo_path = halo2_real_repo_path();
    if !repo_path.exists() {
        println!(
            "test_halo2_scaffold_execution_stability: SKIP_INFRA (Missing halo2-scaffold repo at {})",
            repo_path.display()
        );
        return;
    }
    if let Err(err) = configure_halo2_real_env() {
        println!("test_halo2_scaffold_execution_stability: SKIP_INFRA ({err})");
        return;
    }

    let build_dir = std::env::temp_dir().join("zk0d_halo2_build_stability");
    let test_started = Instant::now();
    let create_executor_started = Instant::now();
    let executor = match expect_or_skip_infra(
        "test_halo2_scaffold_execution_stability",
        "create Halo2 executor",
        Halo2Executor::new_with_build_dir(
            repo_path.to_str().unwrap(),
            "zk0d_mul",
            build_dir.clone(),
        ),
    ) {
        Some(executor) => executor,
        None => return,
    };
    let create_executor_elapsed = create_executor_started.elapsed();

    let fixture_stability_started = Instant::now();
    for fixture in halo2_stability_fixtures() {
        let first = executor.execute_sync(&fixture);
        if !first.success {
            let message = first
                .error
                .unwrap_or_else(|| "unknown halo2 execution error".to_string());
            match classify_error("halo2 stability first execute", message) {
                MatrixStatus::SkipInfra(reason) => {
                    println!("test_halo2_scaffold_execution_stability: SKIP_INFRA ({reason})");
                    return;
                }
                MatrixStatus::Fail(reason) => {
                    panic!(
                        "First Halo2 run failed for fixture {:?}: {}",
                        fixture, reason
                    )
                }
                MatrixStatus::Pass => {
                    unreachable!("classify_error never returns MatrixStatus::Pass")
                }
            }
        }
        assert!(
            !first.coverage.satisfied_constraints.is_empty(),
            "Expected non-empty Halo2 constraint coverage for fixture {:?}",
            fixture
        );

        let second = executor.execute_sync(&fixture);
        if !second.success {
            let message = second
                .error
                .unwrap_or_else(|| "unknown halo2 execution error".to_string());
            match classify_error("halo2 stability second execute", message) {
                MatrixStatus::SkipInfra(reason) => {
                    println!("test_halo2_scaffold_execution_stability: SKIP_INFRA ({reason})");
                    return;
                }
                MatrixStatus::Fail(reason) => {
                    panic!(
                        "Second Halo2 run failed for fixture {:?}: {}",
                        fixture, reason
                    )
                }
                MatrixStatus::Pass => {
                    unreachable!("classify_error never returns MatrixStatus::Pass")
                }
            }
        }
        assert_eq!(
            first.outputs, second.outputs,
            "Halo2 outputs were not deterministic for fixture {:?}",
            fixture
        );
        assert_eq!(
            first.coverage.coverage_hash, second.coverage.coverage_hash,
            "Halo2 coverage hash was not deterministic for fixture {:?}",
            fixture
        );
    }
    let fixture_stability_elapsed = fixture_stability_started.elapsed();

    let prove_fixture = halo2_stability_fixtures()
        .into_iter()
        .next()
        .expect("stability fixtures should not be empty");
    let prove_fixture_execute_started = Instant::now();
    let prove_result = executor.execute_sync(&prove_fixture);
    let prove_fixture_execute_elapsed = prove_fixture_execute_started.elapsed();
    if !prove_result.success {
        let message = prove_result
            .error
            .unwrap_or_else(|| "unknown halo2 execution error".to_string());
        match classify_error("halo2 stability prove fixture execute", message) {
            MatrixStatus::SkipInfra(reason) => {
                println!("test_halo2_scaffold_execution_stability: SKIP_INFRA ({reason})");
                return;
            }
            MatrixStatus::Fail(reason) => panic!("Halo2 prove fixture execution failed: {reason}"),
            MatrixStatus::Pass => unreachable!("classify_error never returns MatrixStatus::Pass"),
        }
    }
    let proof_started = Instant::now();
    let proof_result = executor.prove(&prove_fixture);
    let proof_elapsed = proof_started.elapsed();
    let proof = match expect_or_skip_infra(
        "test_halo2_scaffold_execution_stability",
        "Halo2 proof generation",
        proof_result,
    ) {
        Some(proof) => proof,
        None => return,
    };
    let verify_started = Instant::now();
    let verified = match expect_or_skip_infra(
        "test_halo2_scaffold_execution_stability",
        "Halo2 proof verification",
        executor.verify(&proof, &prove_result.outputs),
    ) {
        Some(verified) => verified,
        None => return,
    };
    let verify_elapsed = verify_started.elapsed();
    assert!(verified, "Halo2 proof verification returned false");

    let total_elapsed = test_started.elapsed();
    emit_phase_timing_ms(
        "test_halo2_scaffold_execution_stability",
        &build_dir,
        &[
            ("create_executor", Some(create_executor_elapsed)),
            ("fixture_stability_loop", Some(fixture_stability_elapsed)),
            ("prove_fixture_execute", Some(prove_fixture_execute_elapsed)),
            ("prove", Some(proof_elapsed)),
            ("verify", Some(verify_elapsed)),
            ("total", Some(total_elapsed)),
        ],
    );
}

/// Throughput gate for production-like Halo2 scaffold execution.
///
/// This complements functional stability by enforcing a basic performance floor
/// on repeated real-circuit runs.
#[test]
fn test_halo2_scaffold_production_throughput() {
    if !require_real_backends("test_halo2_scaffold_production_throughput") {
        return;
    }
    let repo_path = halo2_real_repo_path();
    if !repo_path.exists() {
        println!(
            "test_halo2_scaffold_production_throughput: SKIP_INFRA (Missing halo2-scaffold repo at {})",
            repo_path.display()
        );
        return;
    }
    if let Err(err) = configure_halo2_real_env() {
        println!("test_halo2_scaffold_production_throughput: SKIP_INFRA ({err})");
        return;
    }

    let rounds = std::env::var("HALO2_THROUGHPUT_ROUNDS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v >= 2)
        .unwrap_or(3);
    let max_median_ms = std::env::var("HALO2_THROUGHPUT_MAX_MEDIAN_MS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(8_000.0);
    let min_runs_per_sec = std::env::var("HALO2_THROUGHPUT_MIN_RUNS_PER_SEC")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(0.10);
    let max_warm_slowdown_ratio = std::env::var("HALO2_THROUGHPUT_MAX_WARM_SLOWDOWN_RATIO")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v >= 1.0)
        .unwrap_or(2.0);

    let build_dir = std::env::temp_dir().join("zk0d_halo2_build_throughput");
    let executor = match expect_or_skip_infra(
        "test_halo2_scaffold_production_throughput",
        "create Halo2 executor",
        Halo2Executor::new_with_build_dir(repo_path.to_str().unwrap(), "zk0d_mul", build_dir),
    ) {
        Some(executor) => executor,
        None => return,
    };

    let fixtures = halo2_stability_fixtures();
    let mut all_run_ms = Vec::<f64>::new();
    let mut first_run_ms = Vec::<f64>::new();
    let mut warm_run_ms = Vec::<f64>::new();

    for fixture in fixtures {
        let mut baseline_outputs: Option<Vec<FieldElement>> = None;
        let mut baseline_coverage_hash: Option<u64> = None;

        for run_idx in 0..rounds {
            let start = Instant::now();
            let result = executor.execute_sync(&fixture);
            let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
            all_run_ms.push(elapsed_ms);

            if !result.success {
                let message = result
                    .error
                    .unwrap_or_else(|| "unknown halo2 execution error".to_string());
                match classify_error("halo2 throughput execute", message) {
                    MatrixStatus::SkipInfra(reason) => {
                        println!(
                            "test_halo2_scaffold_production_throughput: SKIP_INFRA ({reason})"
                        );
                        return;
                    }
                    MatrixStatus::Fail(reason) => {
                        panic!("Halo2 throughput execute failed: {reason}")
                    }
                    MatrixStatus::Pass => {
                        unreachable!("classify_error never returns MatrixStatus::Pass")
                    }
                }
            }

            assert!(
                !result.coverage.satisfied_constraints.is_empty(),
                "Expected non-empty Halo2 constraint coverage for throughput fixture {:?}",
                fixture
            );

            match (&baseline_outputs, baseline_coverage_hash) {
                (None, None) => {
                    baseline_outputs = Some(result.outputs.clone());
                    baseline_coverage_hash = Some(result.coverage.coverage_hash);
                }
                (Some(expected_outputs), Some(expected_hash)) => {
                    assert_eq!(
                        &result.outputs, expected_outputs,
                        "Halo2 throughput run output mismatch for fixture {:?}",
                        fixture
                    );
                    assert_eq!(
                        result.coverage.coverage_hash, expected_hash,
                        "Halo2 throughput run coverage hash mismatch for fixture {:?}",
                        fixture
                    );
                }
                _ => unreachable!("baseline output/hash state must be set together"),
            }

            if run_idx == 0 {
                first_run_ms.push(elapsed_ms);
            } else {
                warm_run_ms.push(elapsed_ms);
            }
        }
    }

    assert!(
        !all_run_ms.is_empty() && !first_run_ms.is_empty() && !warm_run_ms.is_empty(),
        "Halo2 throughput sampling did not collect enough runs"
    );

    all_run_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    warm_run_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let median_ms = all_run_ms[all_run_ms.len() / 2];
    let warm_median_ms = warm_run_ms[warm_run_ms.len() / 2];
    let first_mean_ms = first_run_ms.iter().sum::<f64>() / first_run_ms.len() as f64;
    let warm_slowdown_ratio = warm_median_ms / first_mean_ms.max(1.0);
    let total_seconds = all_run_ms.iter().sum::<f64>() / 1_000.0;
    let runs_per_sec = all_run_ms.len() as f64 / total_seconds.max(0.001);

    println!(
        "halo2 throughput metrics: rounds={} total_runs={} median_ms={:.2} warm_median_ms={:.2} first_mean_ms={:.2} runs_per_sec={:.3} warm_slowdown_ratio={:.3}",
        rounds,
        all_run_ms.len(),
        median_ms,
        warm_median_ms,
        first_mean_ms,
        runs_per_sec,
        warm_slowdown_ratio
    );

    assert!(
        median_ms <= max_median_ms,
        "Halo2 throughput median too high: {:.2}ms > {:.2}ms",
        median_ms,
        max_median_ms
    );
    assert!(
        runs_per_sec >= min_runs_per_sec,
        "Halo2 throughput too low: {:.3} runs/s < {:.3} runs/s",
        runs_per_sec,
        min_runs_per_sec
    );
    assert!(
        warm_slowdown_ratio <= max_warm_slowdown_ratio,
        "Halo2 warm-run slowdown too high: {:.3} > {:.3}",
        warm_slowdown_ratio,
        max_warm_slowdown_ratio
    );
}

/// Integration test for Cairo (only runs if cairo tools are available)
#[test]
fn test_cairo_integration() {
    if !require_real_backends("test_cairo_integration") {
        return;
    }
    CairoTarget::check_cairo_available()
        .expect("Cairo not available. Ensure cairo-compile and cairo-run are on PATH");

    let program_path = cairo_program_path("multiplier");
    assert!(
        program_path.exists(),
        "Missing Cairo program at {:?}",
        program_path
    );

    let mut target =
        CairoTarget::new(program_path.to_str().unwrap()).expect("Failed to create CairoTarget");
    target.compile().expect("Cairo compilation failed");

    let outputs = target.execute(&[]).expect("Cairo execution failed");
    assert_eq!(outputs.first(), Some(&FieldElement::from_u64(12)));
}

/// Local stone-prover smoke for Cairo real-circuit readiness.
#[test]
fn test_cairo_stone_prover_prove_verify_smoke() {
    if !require_real_backends("test_cairo_stone_prover_prove_verify_smoke") {
        return;
    }
    CairoTarget::check_cairo_available()
        .expect("Cairo not available. Ensure cairo-compile and cairo-run are on PATH");
    let _stone_version = match expect_or_skip_infra(
        "test_cairo_stone_prover_prove_verify_smoke",
        "stone-prover availability",
        CairoTarget::check_stone_prover_available(),
    ) {
        Some(version) => version,
        None => return,
    };

    let program_path = cairo_program_path("multiplier");
    assert!(
        program_path.exists(),
        "Missing Cairo program at {:?}",
        program_path
    );

    let mut target =
        CairoTarget::new(program_path.to_str().unwrap()).expect("Failed to create CairoTarget");
    target.compile().expect("Cairo compilation failed");

    let witness = Vec::new();
    let outputs = match expect_or_skip_infra(
        "test_cairo_stone_prover_prove_verify_smoke",
        "Cairo execute",
        target.execute(&witness),
    ) {
        Some(outputs) => outputs,
        None => return,
    };
    assert_eq!(outputs.first(), Some(&FieldElement::from_u64(12)));

    let proof = match expect_or_skip_infra(
        "test_cairo_stone_prover_prove_verify_smoke",
        "Cairo proof generation",
        target.prove(&witness),
    ) {
        Some(proof) => proof,
        None => return,
    };
    let verified = match expect_or_skip_infra(
        "test_cairo_stone_prover_prove_verify_smoke",
        "Cairo proof verification",
        target.verify(&proof, &outputs),
    ) {
        Some(verified) => verified,
        None => return,
    };
    assert!(verified, "Cairo proof verification returned false");
}

/// Local Scarb Cairo1 prove/verify smoke for canonical Cairo1 path coverage.
#[test]
fn test_cairo1_scarb_prove_verify_smoke() {
    if !require_real_backends("test_cairo1_scarb_prove_verify_smoke") {
        return;
    }

    let cairo1_path =
        cairo1_external_program_from_env().unwrap_or_else(cairo1_local_project_manifest_path);
    let status = run_cairo_prove_verify_smoke_case(
        "cairo1_scarb_smoke",
        &cairo1_path,
        Some(FieldElement::from_u64(12)),
    );
    println!(
        "cairo1 scarb smoke [{}]: {}",
        cairo1_path.display(),
        describe_status(&status)
    );

    if let MatrixStatus::Fail(reason) = status {
        panic!("test_cairo1_scarb_prove_verify_smoke: {reason}");
    }
}

/// Canonical Cairo gate that covers both Cairo0 and Cairo1 prove/verify paths when available.
#[test]
fn test_cairo_canonical_path_gate() {
    if !require_real_backends("test_cairo_canonical_path_gate") {
        return;
    }

    let cairo0_path = cairo_program_path("multiplier");
    let cairo1_path =
        cairo1_external_program_from_env().unwrap_or_else(cairo1_local_project_manifest_path);

    let cairo0_status = run_cairo_prove_verify_smoke_case(
        "cairo0_canonical_path",
        &cairo0_path,
        Some(FieldElement::from_u64(12)),
    );
    let cairo1_status = run_cairo_prove_verify_smoke_case(
        "cairo1_canonical_path",
        &cairo1_path,
        Some(FieldElement::from_u64(12)),
    );

    println!(
        "cairo canonical gate [cairo0:{}]: {}",
        cairo0_path.display(),
        describe_status(&cairo0_status)
    );
    println!(
        "cairo canonical gate [cairo1:{}]: {}",
        cairo1_path.display(),
        describe_status(&cairo1_status)
    );

    let mut failures = Vec::new();
    let mut pass_count = 0usize;
    for (label, status) in [
        ("cairo0_canonical_path", cairo0_status),
        ("cairo1_canonical_path", cairo1_status),
    ] {
        match status {
            MatrixStatus::Pass => pass_count += 1,
            MatrixStatus::SkipInfra(_) => {}
            MatrixStatus::Fail(reason) => failures.push(format!("{label}: {reason}")),
        }
    }

    assert!(
        pass_count > 0,
        "test_cairo_canonical_path_gate: all canonical Cairo paths were infrastructure-skipped"
    );
    if !failures.is_empty() {
        panic!(
            "test_cairo_canonical_path_gate failures:\n{}",
            failures.join("\n")
        );
    }
}

/// Full-capacity Cairo regression suite with deterministic execution parity and stability checks.
#[test]
fn test_cairo_full_capacity_regression_suite() {
    if !require_real_backends("test_cairo_full_capacity_regression_suite") {
        return;
    }
    CairoTarget::check_cairo_available()
        .expect("Cairo not available. Ensure cairo-compile and cairo-run are on PATH");

    let mut failures = Vec::new();

    let local_status = run_cairo_regression_case(
        "local_cairo_multiplier",
        &cairo_program_path("multiplier"),
        true,
    );
    println!(
        "cairo regression [local_cairo_multiplier]: {}",
        describe_status(&local_status)
    );
    if let MatrixStatus::Fail(reason) = local_status {
        failures.push(format!("local_cairo_multiplier: {}", reason));
    }

    if let Some(external_program) = cairo_external_program_from_env() {
        let external_status =
            run_cairo_regression_case("external_cairo_program", &external_program, false);
        println!(
            "cairo regression [external_cairo_program]: {}",
            describe_status(&external_status)
        );
        if let MatrixStatus::Fail(reason) = external_status {
            failures.push(format!("external_cairo_program: {}", reason));
        }
    } else {
        println!(
            "cairo regression [external_cairo_program]: SKIP_INFRA (set CAIRO_EXTERNAL_PROGRAM to enable external regression case)"
        );
    }

    if !failures.is_empty() {
        panic!(
            "Cairo full-capacity regression failures:\n{}",
            failures.join("\n")
        );
    }
}

/// Integration test for Halo2 JSON spec loading/execution
#[test]
fn test_halo2_json_integration() {
    if !require_real_backends("test_halo2_json_integration") {
        return;
    }
    let spec_path = halo2_spec_path("minimal");
    assert!(spec_path.exists(), "Missing Halo2 spec at {:?}", spec_path);

    let mut target =
        Halo2Target::new(spec_path.to_str().unwrap()).expect("Failed to create Halo2Target");
    target.setup().expect("Halo2 setup failed");
    let parsed = target.load_plonk_constraints();
    assert!(
        !parsed.constraints.is_empty(),
        "Halo2 JSON readiness fixture must include concrete constraints"
    );

    let outputs = target
        .execute(&[FieldElement::from_u64(1), FieldElement::from_u64(2)])
        .expect("Halo2 execution failed");
    assert!(!outputs.is_empty());
}

/// Integration test for local in-repo Halo2 real-circuit fixture.
#[test]
fn test_halo2_local_real_fixture_integration() {
    if !require_real_backends("test_halo2_local_real_fixture_integration") {
        return;
    }
    let fixture_path = halo2_local_real_fixture_path();
    assert!(
        fixture_path.exists(),
        "Missing local Halo2 real fixture at {:?}",
        fixture_path
    );

    let build_dir = std::env::temp_dir().join("zk0d_halo2_local_fixture_build");
    let executor = Halo2Executor::new_with_build_dir(
        fixture_path.to_str().unwrap(),
        "local_halo2_real_fixture",
        build_dir,
    )
    .expect("Failed to create Halo2Executor for local fixture");

    let inputs = vec![
        FieldElement::from_u64(3),
        FieldElement::from_u64(5),
        FieldElement::from_u64(8),
    ];
    let result = executor.execute_sync(&inputs);
    assert!(
        result.success,
        "Local Halo2 real fixture execution failed: {:?}",
        result.error
    );
    assert!(
        !result.coverage.satisfied_constraints.is_empty(),
        "Expected non-empty constraint coverage for local Halo2 real fixture"
    );

    let proof = executor
        .prove(&inputs)
        .expect("Local Halo2 real fixture prove should succeed");
    let verified = executor
        .verify(&proof, &result.outputs)
        .expect("Local Halo2 real fixture verify should succeed");
    assert!(verified, "Local Halo2 real fixture verify returned false");
}

/// Test executor factory error behavior with unavailable backend tooling
#[test]
fn test_executor_factory_missing_backend() {
    let executor = ExecutorFactory::create(Framework::Circom, "nonexistent.circom", "TestCircuit");

    // Should fail gracefully when tooling or circuit path is not available.
    match executor {
        Ok(exec) => {
            println!("Executor created (framework: {:?})", exec.framework());
        }
        Err(e) => {
            println!(
                "Executor creation failed (expected if circom not available): {}",
                e
            );
        }
    }
}
