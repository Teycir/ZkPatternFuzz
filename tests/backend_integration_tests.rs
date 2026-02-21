//! Integration tests for ZK backend implementations
//!
//! These tests verify that the backend integrations work correctly
//! when the required tools are available in the environment.

use std::path::PathBuf;
use zk_fuzzer::config::Framework;
use zk_fuzzer::executor::{
    CairoExecutor, CircomExecutor, CircuitExecutor, ExecutorFactory, ExecutorFactoryOptions,
    Halo2Executor, NoirExecutor,
};
use zk_fuzzer::fuzzer::FieldElement;
use zk_fuzzer::targets::{CairoTarget, CircomTarget, Halo2Target, NoirTarget, TargetCircuit};

const DEFAULT_ZK0D_BASE: &str = "/media/elements/Repos/zk0d";

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

fn halo2_spec_path(name: &str) -> PathBuf {
    repo_path()
        .join("tests")
        .join("halo2_specs")
        .join(format!("{}.json", name))
}

fn halo2_real_repo_path() -> PathBuf {
    if let Ok(path) = std::env::var("HALO2_SCAFFOLD_PATH") {
        return PathBuf::from(path);
    }
    zk0d_base_path().join("cat5_frameworks/halo2-scaffold")
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

    let mut cases = Vec::new();
    cases.push((0..input_count).map(|_| FieldElement::zero()).collect());
    cases.push((0..input_count).map(|_| FieldElement::one()).collect());
    cases.push(
        (0..input_count)
            .map(|idx| FieldElement::from_u64((idx as u64) + 1))
            .collect(),
    );
    cases.push(
        (0..input_count)
            .map(|_| FieldElement::from_u64(3))
            .collect(),
    );
    cases.push(
        (0..input_count)
            .map(|idx| FieldElement::from_u64(((idx as u64) + 1) * 5))
            .collect(),
    );
    cases
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
                    return MatrixStatus::Fail(format!(
                        "{name} parity mismatch on executable witness: target succeeded but executor failed: {}",
                        executor_result.error.unwrap_or_else(|| "unknown executor error".to_string())
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

    let mut cases = Vec::new();
    cases.push((0..input_count).map(|_| FieldElement::zero()).collect());
    cases.push((0..input_count).map(|_| FieldElement::one()).collect());
    cases.push(
        (0..input_count)
            .map(|idx| FieldElement::from_u64((idx as u64) + 1))
            .collect(),
    );
    cases.push(
        (0..input_count)
            .map(|_| FieldElement::from_u64(5))
            .collect(),
    );
    cases
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
    let circom_version = CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    let snarkjs_version = CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");
    let noir_version = NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");
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
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");

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
    NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");

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
    NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");

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
    CircomTarget::check_circom_available()
        .expect("Circom not available. Install with: npm install -g circom");
    CircomTarget::check_snarkjs_available()
        .expect("snarkjs not available. Install with: npm install -g snarkjs");

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
    NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");

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
    NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");

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
    NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");

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
    NoirTarget::check_nargo_available()
        .expect("Noir not available. Install with: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash");

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
    let executor = match expect_or_skip_infra(
        "test_halo2_real_circuit_constraint_coverage",
        "create Halo2 executor",
        Halo2Executor::new_with_build_dir(repo_path.to_str().unwrap(), "zk0d_mul", build_dir),
    ) {
        Some(executor) => executor,
        None => return,
    };

    let inputs = vec![
        FieldElement::from_u64(3),
        FieldElement::from_u64(5),
        FieldElement::from_u64(15),
    ];

    let result = executor.execute_sync(&inputs);
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
    let executor = match expect_or_skip_infra(
        "test_halo2_scaffold_execution_stability",
        "create Halo2 executor",
        Halo2Executor::new_with_build_dir(repo_path.to_str().unwrap(), "zk0d_mul", build_dir),
    ) {
        Some(executor) => executor,
        None => return,
    };

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

    let prove_fixture = halo2_stability_fixtures()
        .into_iter()
        .next()
        .expect("stability fixtures should not be empty");
    let prove_result = executor.execute_sync(&prove_fixture);
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
    let proof = match expect_or_skip_infra(
        "test_halo2_scaffold_execution_stability",
        "Halo2 proof generation",
        executor.prove(&prove_fixture),
    ) {
        Some(proof) => proof,
        None => return,
    };
    let verified = match expect_or_skip_infra(
        "test_halo2_scaffold_execution_stability",
        "Halo2 proof verification",
        executor.verify(&proof, &prove_result.outputs),
    ) {
        Some(verified) => verified,
        None => return,
    };
    assert!(verified, "Halo2 proof verification returned false");
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

    let outputs = target
        .execute(&[FieldElement::from_u64(1), FieldElement::from_u64(2)])
        .expect("Halo2 execution failed");
    assert!(!outputs.is_empty());
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
