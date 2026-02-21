use zk_fuzzer::config::AdditionalConfig;

#[test]
fn hoists_legacy_additional_mapping() {
    let mut cfg = AdditionalConfig::default();

    // Top-level key should win over legacy nested key.
    cfg.insert("strict_backend".to_string(), serde_yaml::Value::Bool(false));

    let mut legacy = serde_yaml::Mapping::new();
    legacy.insert(
        serde_yaml::Value::String("strict_backend".to_string()),
        serde_yaml::Value::Bool(true),
    );
    legacy.insert(
        serde_yaml::Value::String("per_exec_isolation".to_string()),
        serde_yaml::Value::Bool(true),
    );
    cfg.insert("additional".to_string(), serde_yaml::Value::Mapping(legacy));

    assert!(cfg.hoist_legacy_additional());
    assert_eq!(cfg.get_bool("strict_backend"), Some(false));
    assert_eq!(cfg.get_bool("per_exec_isolation"), Some(true));
    assert!(!cfg.contains_key("additional"));
}
