use crate::cli::ChainRunOptions;

pub(crate) fn apply_chain_mode_overrides(
    config: &mut zk_fuzzer::config::FuzzConfig,
    options: &ChainRunOptions,
) {
    config
        .campaign
        .parameters
        .additional
        .insert("evidence_mode".to_string(), serde_yaml::Value::Bool(true));
    config.campaign.parameters.additional.insert(
        "engagement_strict".to_string(),
        serde_yaml::Value::Bool(true),
    );
    config
        .campaign
        .parameters
        .additional
        .insert("strict_backend".to_string(), serde_yaml::Value::Bool(true));
    config.campaign.parameters.additional.insert(
        "chain_budget_seconds".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.timeout)),
    );
    config.campaign.parameters.additional.insert(
        "chain_iterations".to_string(),
        serde_yaml::Value::Number(serde_yaml::Number::from(options.iterations)),
    );
    config.campaign.parameters.additional.insert(
        "chain_resume".to_string(),
        serde_yaml::Value::Bool(options.resume),
    );
}
