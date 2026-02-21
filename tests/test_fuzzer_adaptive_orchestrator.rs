use std::path::PathBuf;
use std::time::Duration;

use zk_fuzzer::fuzzer::adaptive_orchestrator::{
    run_from_cli, AdaptiveOrchestrator, AdaptiveOrchestratorBuilder, AdaptiveOrchestratorConfig,
};

#[test]
fn test_config_defaults() {
    let config = AdaptiveOrchestratorConfig::default();
    assert!(config.adaptive_budget);
    assert!(config.zero_day_hunt_mode);
    assert!(config.workers >= 1);
    assert_eq!(config.max_duration, Duration::from_secs(3600));
}

#[test]
fn test_builder_builds_with_overrides() {
    let _orchestrator = AdaptiveOrchestratorBuilder::new()
        .workers(4)
        .max_duration(Duration::from_secs(600))
        .output_dir(PathBuf::from("target/test_adaptive"))
        .zero_day_hunt_mode(true)
        .adaptive_budget(true)
        .build();
}

#[test]
fn test_new_orchestrator_construction() {
    let _orchestrator = AdaptiveOrchestrator::new();
}

#[tokio::test]
async fn test_run_from_cli_missing_project_is_handled() {
    let missing_project = PathBuf::from("target/nonexistent_project_for_adaptive_orchestrator");
    let output_dir = PathBuf::from("target/test_adaptive_output");

    let result = run_from_cli(&missing_project, 1, 1, &output_dir).await;
    assert!(result.is_ok());
    let campaign = result.expect("missing project should be handled gracefully");
    assert_eq!(campaign.circuits_analyzed, 0);
    assert!(campaign.total_findings.is_empty());
}
