use anyhow::Context;
use std::path::PathBuf;
use zk_fuzzer::config::FuzzConfig;

fn parse_preflight_executor_options(
    config: &FuzzConfig,
) -> anyhow::Result<zk_fuzzer::executor::ExecutorFactoryOptions> {
    let additional = &config.campaign.parameters.additional;
    let mut options = zk_fuzzer::executor::ExecutorFactoryOptions {
        build_dir_base: additional
            .get_path("build_dir_base")
            .or_else(|| additional.get_path("build_dir")),
        circom_build_dir: additional.get_path("circom_build_dir"),
        noir_build_dir: additional.get_path("noir_build_dir"),
        halo2_build_dir: additional.get_path("halo2_build_dir"),
        cairo_build_dir: additional.get_path("cairo_build_dir"),
        strict_backend: true,
        ..Default::default()
    };

    if let Some(auto_setup) = additional.get_bool("circom_auto_setup_keys") {
        options.circom_auto_setup_keys = auto_setup;
    }
    if let Some(require_setup) = additional.get_bool("circom_require_setup_keys") {
        options.circom_require_setup_keys = require_setup;
        if require_setup {
            options.circom_auto_setup_keys = true;
        }
    }
    options.circom_ptau_path = additional.get_path("circom_ptau_path");
    options.circom_snarkjs_path = additional.get_path("circom_snarkjs_path");
    if let Some(skip_compile) = additional.get_bool("circom_skip_compile_if_artifacts") {
        options.circom_skip_compile_if_artifacts = skip_compile;
    }
    if let Some(skip_check) = additional.get_bool("circom_skip_constraint_check") {
        if skip_check {
            anyhow::bail!(
                "Invalid config: circom_skip_constraint_check=true is disallowed. \
                 Mode 2/3 require real constraint coverage. Set circom_skip_constraint_check: false."
            );
        }
        options.circom_skip_constraint_check = false;
    }
    if let Some(sanity_check) = additional.get_bool("circom_witness_sanity_check") {
        options.circom_witness_sanity_check = sanity_check;
    }

    if let Some(value) = additional.get("include_paths") {
        let mut paths = Vec::new();
        match value {
            serde_yaml::Value::Sequence(items) => {
                for item in items {
                    if let Some(raw) = item.as_str() {
                        let trimmed = raw.trim();
                        if !trimmed.is_empty() {
                            paths.push(PathBuf::from(trimmed));
                        }
                    }
                }
            }
            serde_yaml::Value::String(s) => {
                for part in s.split(',') {
                    let trimmed = part.trim();
                    if !trimmed.is_empty() {
                        paths.push(PathBuf::from(trimmed));
                    }
                }
            }
            _ => {}
        }
        if !paths.is_empty() {
            options.circom_include_paths = paths;
        }
    }

    Ok(options)
}

pub(crate) fn run_backend_preflight(config: &FuzzConfig) -> anyhow::Result<()> {
    let framework = config.campaign.target.framework;
    let circuit_path = config
        .campaign
        .target
        .circuit_path
        .to_string_lossy()
        .to_string();
    let main_component = config.campaign.target.main_component.clone();
    let options = parse_preflight_executor_options(config)?;

    tracing::info!(
        "Backend preflight: framework={:?}, target='{}', component='{}'",
        framework,
        circuit_path,
        main_component
    );

    let _executor = zk_fuzzer::executor::ExecutorFactory::create_with_options(
        framework,
        &circuit_path,
        &main_component,
        &options,
    )
    .context("Backend preflight failed while initializing executor")?;

    tracing::info!("Backend preflight passed");
    Ok(())
}

pub(crate) fn preflight_campaign(config_path: &str, setup_keys: bool) -> anyhow::Result<()> {
    tracing::info!("Running backend preflight for campaign: {}", config_path);
    let mut config = FuzzConfig::from_yaml(config_path)?;

    if setup_keys {
        config.campaign.parameters.additional.insert(
            "circom_auto_setup_keys".to_string(),
            serde_yaml::Value::Bool(true),
        );
        config.campaign.parameters.additional.insert(
            "circom_require_setup_keys".to_string(),
            serde_yaml::Value::Bool(true),
        );
    }

    run_backend_preflight(&config)?;

    println!("✓ Backend preflight passed");
    if setup_keys {
        println!("✓ Circom key-setup preflight passed");
    }

    Ok(())
}
