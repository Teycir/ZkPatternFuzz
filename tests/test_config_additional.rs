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

#[test]
fn invalid_numeric_strings_do_not_panic() {
    let mut cfg = AdditionalConfig::default();
    cfg.insert(
        "bad_usize".to_string(),
        serde_yaml::Value::String("not-a-usize".to_string()),
    );
    cfg.insert(
        "bad_u64".to_string(),
        serde_yaml::Value::String("not-a-u64".to_string()),
    );
    cfg.insert(
        "bad_f64".to_string(),
        serde_yaml::Value::String("not-a-f64".to_string()),
    );

    assert_eq!(cfg.get_usize("bad_usize"), None);
    assert_eq!(cfg.get_u64("bad_u64"), None);
    assert_eq!(cfg.get_f64("bad_f64"), None);
}
