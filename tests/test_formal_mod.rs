use zk_fuzzer::formal::{FormalConfig, FormalVerificationManager, ProofSystem};

#[test]
fn test_formal_config_default() {
    let config = FormalConfig::default();
    assert_eq!(config.system, ProofSystem::Lean4);
    assert!(config.generate_skeletons);
}

#[test]
fn test_formal_manager_creation() {
    let config = FormalConfig::default();
    let manager = FormalVerificationManager::new(config);
    assert!(manager.properties().is_empty());
    assert!(manager.obligations().is_empty());
}
