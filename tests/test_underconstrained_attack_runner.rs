use std::path::PathBuf;

use zk_fuzzer::config::*;
use zk_fuzzer::fuzzer::FuzzingEngine;

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

#[tokio::test]
async fn underconstrained_runner_errors_when_no_executable_witness_exists() {
    let mut config =
        build_underconstrained_config("tests/fixtures/underconstrained_unsat.circom", "main");
    config.campaign.parameters.additional.insert(
        "fuzzing_iterations".to_string(),
        serde_yaml::Value::Number(1.into()),
    );
    config.campaign.parameters.additional.insert(
        "fuzzing_timeout_seconds".to_string(),
        serde_yaml::Value::Number(5.into()),
    );
    config.campaign.parameters.additional.insert(
        "symbolic_enabled".to_string(),
        serde_yaml::Value::Bool(false),
    );
    config.campaign.parameters.additional.insert(
        "circom_build_dir".to_string(),
        serde_yaml::Value::String("/tmp/zkfuzz_tests/underconstrained_unsat".to_string()),
    );

    let mut engine = FuzzingEngine::new(config, Some(7), 1).expect("engine init should succeed");
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
