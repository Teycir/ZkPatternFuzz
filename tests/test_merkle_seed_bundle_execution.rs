use std::path::PathBuf;
use std::sync::Arc;

use num_bigint::BigUint;
use tempfile::TempDir;
use zk_core::{CircuitExecutor, FieldElement, Framework};
use zk_fuzzer::executor::{ExecutorFactory, ExecutorFactoryOptions, IsolatedExecutor};

fn parse_decimal_field(raw: &str) -> FieldElement {
    let value = BigUint::parse_bytes(raw.as_bytes(), 10).expect("valid decimal field element");
    let bytes = value.to_bytes_be();
    let mut buf = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    buf[start..start + bytes.len()].copy_from_slice(&bytes);
    FieldElement::from_bytes_checked(&buf).expect("canonical field element")
}

fn load_first_merkle_seed() -> Vec<FieldElement> {
    let raw = std::fs::read_to_string(
        "campaigns/benchmark/seed_inputs/merkle_unconstrained_seed_inputs.json",
    )
    .expect("read merkle seed bundle");
    let seeds: serde_json::Value = serde_json::from_str(&raw).expect("parse merkle seed bundle");
    let first = seeds[0].as_object().expect("first seed object");

    let mut inputs = Vec::new();
    inputs.push(parse_decimal_field(
        first["root"].as_str().expect("root string"),
    ));
    inputs.push(parse_decimal_field(
        first["leaf"].as_str().expect("leaf string"),
    ));
    for value in first["path_elements"]
        .as_array()
        .expect("path_elements array")
    {
        inputs.push(parse_decimal_field(
            value.as_str().expect("path element string"),
        ));
    }
    for value in first["path_indices"]
        .as_array()
        .expect("path_indices array")
    {
        inputs.push(parse_decimal_field(
            value.as_str().expect("path index string"),
        ));
    }
    inputs
}

fn executor_options(build_dir: &TempDir) -> ExecutorFactoryOptions {
    ExecutorFactoryOptions {
        circom_build_dir: Some(build_dir.path().join("circom")),
        circom_skip_compile_if_artifacts: true,
        ..ExecutorFactoryOptions::default()
    }
}

#[test]
fn merkle_seed_bundle_executes_in_direct_circom_executor() {
    let build_dir = TempDir::new().expect("temp build dir");
    let options = executor_options(&build_dir);
    let executor = ExecutorFactory::create_with_options(
        Framework::Circom,
        "tests/ground_truth_circuits/merkle_unconstrained.circom",
        "main",
        &options,
    )
    .expect("create direct executor");

    let result = executor.execute_sync(&load_first_merkle_seed());
    assert!(
        result.success,
        "expected first bundled Merkle seed to execute successfully, got error {:?}",
        result.error
    );
}

#[test]
fn merkle_seed_bundle_executes_in_isolated_circom_executor() {
    let build_dir = TempDir::new().expect("temp build dir");
    let options = executor_options(&build_dir);
    let inner = ExecutorFactory::create_with_options(
        Framework::Circom,
        "tests/ground_truth_circuits/merkle_unconstrained.circom",
        "main",
        &options,
    )
    .expect("create direct executor");
    let isolated = IsolatedExecutor::new(
        Arc::clone(&inner),
        Framework::Circom,
        "tests/ground_truth_circuits/merkle_unconstrained.circom".to_string(),
        "main".to_string(),
        options,
        30_000,
    )
    .expect("create isolated executor");

    let result = isolated.execute_sync(&load_first_merkle_seed());
    assert!(
        result.success,
        "expected first bundled Merkle seed to execute successfully in isolated mode, got error {:?}",
        result.error
    );
}
