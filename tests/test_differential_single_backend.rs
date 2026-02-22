use std::fs;
use std::path::Path;

use zk_core::AttackType;
use zk_core::FieldElement;
use zk_fuzzer::config::FuzzConfig;
use zk_fuzzer::executor::{ExecutorFactory, ExecutorFactoryOptions};
use zk_fuzzer::fuzzer::FuzzingEngine;
use zk_fuzzer::oracles::CrossBackendDifferential;

fn write_halo2_spec(path: &Path, content: &str) {
    fs::write(path, content).expect("failed to write Halo2 spec");
}

#[test]
fn single_backend_differential_uses_reference_backend_path() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let primary_path = temp_dir.path().join("primary.json");
    let reference_path = temp_dir.path().join("reference.json");
    let output_dir = temp_dir.path().join("reports");

    // Primary spec: always-satisfiable gate, so execution accepts.
    write_halo2_spec(
        &primary_path,
        r#"{
  "name": "primary_accepting",
  "k": 4,
  "advice_columns": 2,
  "fixed_columns": 1,
  "instance_columns": 1,
  "constraints": 1,
  "private_inputs": 2,
  "public_inputs": 1,
  "lookups": 0,
  "gates": [
    {
      "wires": [1, 1, 1],
      "selectors": { "q_l": "1", "q_r": "0", "q_o": "-1", "q_m": "0", "q_c": "0" }
    }
  ]
}"#,
    );

    // Reference spec: unsatisfiable gate so execution rejects.
    write_halo2_spec(
        &reference_path,
        r#"{
  "name": "reference_unsat",
  "k": 4,
  "advice_columns": 2,
  "fixed_columns": 1,
  "instance_columns": 1,
  "constraints": 1,
  "private_inputs": 2,
  "public_inputs": 1,
  "lookups": 0,
  "gates": [
    {
      "wires": [1, 1, 1],
      "selectors": { "q_l": "1", "q_r": "0", "q_o": "-1", "q_m": "0", "q_c": "1" }
    }
  ]
}"#,
    );

    let direct_primary = ExecutorFactory::create_with_options(
        zk_core::Framework::Halo2,
        primary_path.to_str().expect("primary path string"),
        "main",
        &ExecutorFactoryOptions::default(),
    )
    .expect("primary executor");
    let direct_reference = ExecutorFactory::create_with_options(
        zk_core::Framework::Halo2,
        reference_path.to_str().expect("reference path string"),
        "main",
        &ExecutorFactoryOptions::default(),
    )
    .expect("reference executor");
    let direct_oracle = CrossBackendDifferential::new()
        .with_sample_count(1)
        .with_tolerance_bits(0);
    let direct_witness = vec![FieldElement::from_u64(7), FieldElement::from_u64(11)];
    let primary_result = direct_primary.execute_sync(&direct_witness);
    let reference_result = direct_reference.execute_sync(&direct_witness);
    assert!(
        primary_result.success,
        "expected primary spec to accept witness, error={:?}",
        primary_result.error
    );
    assert!(
        !reference_result.success,
        "expected reference spec to reject witness but it succeeded with outputs={:?}",
        reference_result.outputs
    );
    let direct_findings = direct_oracle.run(
        direct_primary.as_ref(),
        direct_reference.as_ref(),
        &[direct_witness],
    );
    assert!(
        !direct_findings.is_empty(),
        "expected direct oracle divergence between primary/reference Halo2 specs"
    );

    let yaml = format!(
        r#"
campaign:
  name: "single-backend-differential"
  version: "1.0"
  target:
    framework: halo2
    circuit_path: "{}"
    main_component: "main"
  parameters:
    field: bn254
    max_constraints: 128
    timeout_seconds: 10
    additional:
      max_iterations: 1

attacks:
  - type: differential
    description: "Single backend differential with explicit reference backend"
    config:
      backends: ["halo2"]
      num_tests: 1
      cross_backend:
        enabled: true
        sample_count: 4
        tolerance_bits: 0
        reference_backend: "halo2"
        reference_circuit_path: "{}"

inputs:
  - name: "in0"
    type: "field"
    fuzz_strategy: random
  - name: "in1"
    type: "field"
    fuzz_strategy: random

reporting:
  output_dir: "{}"
  formats: ["json"]
"#,
        primary_path.display(),
        reference_path.display(),
        output_dir.display()
    );

    let config: FuzzConfig = serde_yaml::from_str(&yaml).expect("valid campaign yaml");
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let report = runtime.block_on(async {
        let mut engine = FuzzingEngine::new(config, Some(7), 1).expect("engine init");
        engine.run(None).await.expect("engine run")
    });

    let has_differential = report
        .findings
        .iter()
        .any(|finding| finding.attack_type == AttackType::Differential);
    assert!(
        has_differential,
        "expected at least one differential finding from single-backend reference comparison; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| finding.description.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn single_backend_differential_without_reference_backend_fails_hard() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let primary_path = temp_dir.path().join("primary.json");
    let output_dir = temp_dir.path().join("reports");

    write_halo2_spec(
        &primary_path,
        r#"{
  "name": "primary_accepting",
  "k": 4,
  "advice_columns": 2,
  "fixed_columns": 1,
  "instance_columns": 1,
  "constraints": 1,
  "private_inputs": 2,
  "public_inputs": 1,
  "lookups": 0,
  "gates": [
    {
      "wires": [1, 1, 1],
      "selectors": { "q_l": "1", "q_r": "0", "q_o": "-1", "q_m": "0", "q_c": "0" }
    }
  ]
}"#,
    );

    let yaml = format!(
        r#"
campaign:
  name: "single-backend-differential-no-reference"
  version: "1.0"
  target:
    framework: halo2
    circuit_path: "{}"
    main_component: "main"
  parameters:
    field: bn254
    max_constraints: 128
    timeout_seconds: 10
    additional:
      max_iterations: 1

attacks:
  - type: differential
    description: "Single backend differential without reference backend must fail"
    config:
      backends: ["halo2"]
      num_tests: 1
      cross_backend:
        enabled: true
        sample_count: 2
        tolerance_bits: 0

inputs:
  - name: "in0"
    type: "field"
    fuzz_strategy: random
  - name: "in1"
    type: "field"
    fuzz_strategy: random

reporting:
  output_dir: "{}"
  formats: ["json"]
"#,
        primary_path.display(),
        output_dir.display()
    );

    let config: FuzzConfig = serde_yaml::from_str(&yaml).expect("valid campaign yaml");
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let result = runtime.block_on(async {
        let mut engine = FuzzingEngine::new(config, Some(13), 1).expect("engine init");
        engine.run(None).await
    });

    assert!(
        result.is_err(),
        "single-backend differential without reference backend should hard-fail"
    );
    let err = result.err().expect("error").to_string();
    assert!(
        err.contains("reference_backend"),
        "expected missing reference_backend error, got: {}",
        err
    );
}
