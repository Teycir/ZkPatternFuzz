use std::path::PathBuf;

use tempfile::{NamedTempFile, TempDir};
use zk_fuzzer::config::*;
use zk_fuzzer::fuzzer::FuzzingEngine;

fn is_missing_circom_backend_error(err: &anyhow::Error) -> bool {
    let text = err.to_string();
    text.contains("Circom backend required but not available")
        || text.contains("circom not found in PATH")
}

fn create_engine_or_skip(
    config: FuzzConfig,
    seed: Option<u64>,
    workers: usize,
    test_name: &str,
) -> Option<FuzzingEngine> {
    match FuzzingEngine::new(config, seed, workers) {
        Ok(engine) => Some(engine),
        Err(err) if is_missing_circom_backend_error(&err) => {
            println!("Skipping {test_name}: {err}");
            None
        }
        Err(err) => panic!("{test_name}: engine init should succeed: {err:#}"),
    }
}

fn build_underconstrained_config(circuit_path: &str, main_component: &str) -> FuzzConfig {
    FuzzConfig {
        campaign: Campaign {
            name: "Underconstrained Runner Regression".to_string(),
            version: "1.0".to_string(),
            target: Target {
                framework: Framework::Circom,
                circuit_path: PathBuf::from(circuit_path),
                main_component: main_component.to_string(),
            },
            parameters: Parameters {
                field: "bn254".to_string(),
                max_constraints: 1000,
                timeout_seconds: 30,
                additional: AdditionalConfig::default(),
            },
        },
        attacks: vec![Attack {
            attack_type: AttackType::Underconstrained,
            description: "Underconstrained regression".to_string(),
            plugin: None,
            config: serde_yaml::from_str(
                r#"
witness_pairs: 16
"#,
            )
            .expect("valid underconstrained config"),
        }],
        inputs: vec![Input {
            name: "a".to_string(),
            input_type: "field".to_string(),
            fuzz_strategy: FuzzStrategy::Random,
            constraints: vec![],
            interesting: vec![],
            length: None,
        }],
        mutations: vec![],
        oracles: vec![],
        reporting: ReportingConfig::default(),
        chains: vec![],
    }
}

fn temp_circom_build_dir(name: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("zkfuzz_{name}_"))
        .tempdir()
        .expect("temp circom build dir")
}

fn configure_underconstrained_runtime(config: &mut FuzzConfig, build_dir: &TempDir) {
    config.campaign.parameters.additional.insert(
        "fuzzing_iterations".to_string(),
        serde_yaml::Value::Number(1.into()),
    );
    config.campaign.parameters.additional.insert(
        "fuzzing_timeout_seconds".to_string(),
        serde_yaml::Value::Number(15.into()),
    );
    config.campaign.parameters.additional.insert(
        "symbolic_enabled".to_string(),
        serde_yaml::Value::Bool(false),
    );
    config.campaign.parameters.additional.insert(
        "circom_build_dir".to_string(),
        serde_yaml::Value::String(build_dir.path().display().to_string()),
    );
}

#[tokio::test]
async fn underconstrained_runner_errors_when_no_executable_witness_exists() {
    let mut config =
        build_underconstrained_config("tests/fixtures/underconstrained_unsat.circom", "main");
    let build_dir = temp_circom_build_dir("underconstrained_unsat");
    configure_underconstrained_runtime(&mut config, &build_dir);

    let Some(mut engine) = create_engine_or_skip(
        config,
        Some(7),
        1,
        "underconstrained_runner_errors_when_no_executable_witness_exists",
    ) else {
        return;
    };
    let err = engine
        .run(None)
        .await
        .expect_err("unsatisfiable circuit should fail underconstrained witness seeding");
    let err_text = format!("{:#}", err);

    assert!(
        err_text.contains("could not find any executable witness pairs"),
        "unexpected error: {}",
        err_text
    );
}

#[tokio::test]
async fn underconstrained_runner_uses_external_witness_seeds_directly() {
    let seed_file = NamedTempFile::new().expect("seed file");
    std::fs::write(
        seed_file.path(),
        r#"[
  {"pub": "5", "a": "2", "b": "3"},
  {"pub": "5", "a": "1", "b": "4"}
]
"#,
    )
    .expect("write seed file");

    let mut config = build_underconstrained_config(
        "tests/fixtures/underconstrained_seeded_collision.circom",
        "main",
    );
    let build_dir = temp_circom_build_dir("underconstrained_seeded_collision");
    configure_underconstrained_runtime(&mut config, &build_dir);
    config.campaign.parameters.additional.insert(
        "seed_inputs_path".to_string(),
        serde_yaml::Value::String(seed_file.path().display().to_string()),
    );

    let Some(mut engine) = create_engine_or_skip(
        config,
        Some(23),
        1,
        "underconstrained_runner_uses_external_witness_seeds_directly",
    ) else {
        return;
    };
    let report = engine.run(None).await.expect("run should succeed");

    let has_underconstrained = report
        .findings
        .iter()
        .any(|finding| matches!(finding.attack_type, AttackType::Underconstrained));
    assert!(
        has_underconstrained,
        "expected underconstrained finding from direct witness seeds, found {:?}",
        report
            .findings
            .iter()
            .map(|finding| &finding.attack_type)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn underconstrained_runner_adds_behavioral_confirmation_for_non_binary_path_selectors() {
    let seed_file = NamedTempFile::new().expect("seed file");
    std::fs::write(
        seed_file.path(),
        r#"[
  {"root": "5", "leaf": "2", "path_indices": ["2", "3"]},
  {"root": "5", "leaf": "9", "path_indices": ["4", "7"]}
]
"#,
    )
    .expect("write seed file");

    let mut config = build_underconstrained_config(
        "tests/fixtures/underconstrained_path_selector_collision.circom",
        "main",
    );
    let build_dir = temp_circom_build_dir("underconstrained_path_selector_collision");
    config.inputs = vec![
        Input {
            name: "root".to_string(),
            input_type: "field".to_string(),
            fuzz_strategy: FuzzStrategy::Random,
            constraints: vec![],
            interesting: vec![],
            length: None,
        },
        Input {
            name: "leaf".to_string(),
            input_type: "field".to_string(),
            fuzz_strategy: FuzzStrategy::Random,
            constraints: vec![],
            interesting: vec![],
            length: None,
        },
        Input {
            name: "path_indices".to_string(),
            input_type: "array<field>".to_string(),
            fuzz_strategy: FuzzStrategy::Random,
            constraints: vec![],
            interesting: vec![],
            length: Some(2),
        },
    ];
    configure_underconstrained_runtime(&mut config, &build_dir);
    config.campaign.parameters.additional.insert(
        "seed_inputs_path".to_string(),
        serde_yaml::Value::String(seed_file.path().display().to_string()),
    );

    let Some(mut engine) = create_engine_or_skip(
        config,
        Some(29),
        1,
        "underconstrained_runner_adds_behavioral_confirmation_for_non_binary_path_selectors",
    ) else {
        return;
    };
    let report = engine.run(None).await.expect("run should succeed");

    let attack_types: Vec<_> = report
        .findings
        .iter()
        .map(|finding| finding.attack_type.clone())
        .collect();
    assert!(
        attack_types.contains(&AttackType::Underconstrained),
        "expected underconstrained finding, found {:?}",
        attack_types
    );
    assert!(
        attack_types.contains(&AttackType::Boundary),
        "expected behavioral confirmation finding, found {:?}",
        attack_types
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.description.contains("Correlation: HIGH")),
        "expected high-confidence correlated finding, found {:?}",
        report
            .findings
            .iter()
            .map(|finding| finding.description.clone())
            .collect::<Vec<_>>()
    );
}
