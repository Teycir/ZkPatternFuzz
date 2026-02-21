use zk_fuzzer::config::migration::migrate_config_value;

fn yaml_key(name: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(name.to_string())
}

fn get_mapping<'a>(value: &'a serde_yaml::Value, keys: &[&str]) -> &'a serde_yaml::Mapping {
    let mut current = value;
    for key in keys {
        current = current
            .as_mapping()
            .and_then(|map| map.get(yaml_key(key)))
            .expect("missing nested mapping");
    }
    current.as_mapping().expect("expected mapping")
}

#[test]
fn migrates_legacy_additional_map() {
    let raw = r#"
campaign:
  name: "migration-test"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "./tests/circuits/multiplier.circom"
    main_component: "Multiplier"
  parameters:
    field: "bn254"
    max_constraints: 1000
    timeout_seconds: 60
    additional:
      engagement_strict: true
      strict_backend: true
attacks:
  - type: "boundary"
    description: "boundary"
inputs:
  - name: "a"
    type: "field"
"#;

    let value: serde_yaml::Value = serde_yaml::from_str(raw).expect("valid yaml");
    let (migrated, report) = migrate_config_value(value);

    let parameters = get_mapping(&migrated, &["campaign", "parameters"]);
    assert!(parameters.get(yaml_key("additional")).is_none());
    assert_eq!(
        parameters
            .get(yaml_key("engagement_strict"))
            .and_then(serde_yaml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        parameters
            .get(yaml_key("strict_backend"))
            .and_then(serde_yaml::Value::as_bool),
        Some(true)
    );
    assert!(report.changed);
    assert!(report.rewritten_keys.iter().any(|change| change
        .path
        .contains("campaign.parameters.additional.engagement_strict")));
}

#[test]
fn migrates_plugin_from_attack_config_to_top_level_field() {
    let raw = r#"
campaign:
  name: "migration-test"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "./tests/circuits/multiplier.circom"
    main_component: "Multiplier"
attacks:
  - type: "boundary"
    description: "boundary"
    config:
      plugin: "example_plugin"
      samples: 16
inputs:
  - name: "a"
    type: "field"
"#;

    let value: serde_yaml::Value = serde_yaml::from_str(raw).expect("valid yaml");
    let (migrated, report) = migrate_config_value(value);

    let attacks = migrated
        .as_mapping()
        .and_then(|map| map.get(yaml_key("attacks")))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("attacks sequence");
    let attack = attacks[0].as_mapping().expect("attack mapping");
    assert_eq!(
        attack
            .get(yaml_key("plugin"))
            .and_then(serde_yaml::Value::as_str),
        Some("example_plugin")
    );
    let config = attack
        .get(yaml_key("config"))
        .and_then(serde_yaml::Value::as_mapping)
        .expect("config mapping");
    assert!(config.get(yaml_key("plugin")).is_none());
    assert!(report
        .rewritten_keys
        .iter()
        .any(|change| change.path == "attacks[0].config.plugin"));
}

#[test]
fn normalizes_attack_plugin_dirs_comma_string() {
    let raw = r#"
campaign:
  name: "migration-test"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "./tests/circuits/multiplier.circom"
    main_component: "Multiplier"
  parameters:
    attack_plugin_dirs: "/opt/plugins,/var/lib/plugins , ./target/release"
attacks:
  - type: "boundary"
    description: "boundary"
inputs:
  - name: "a"
    type: "field"
"#;

    let value: serde_yaml::Value = serde_yaml::from_str(raw).expect("valid yaml");
    let (migrated, report) = migrate_config_value(value);

    let parameters = get_mapping(&migrated, &["campaign", "parameters"]);
    let plugin_dirs = parameters
        .get(yaml_key("attack_plugin_dirs"))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("attack_plugin_dirs sequence");
    assert_eq!(plugin_dirs.len(), 3);
    assert_eq!(plugin_dirs[0].as_str(), Some("/opt/plugins"));
    assert_eq!(plugin_dirs[1].as_str(), Some("/var/lib/plugins"));
    assert_eq!(plugin_dirs[2].as_str(), Some("./target/release"));
    assert!(report
        .rewritten_keys
        .iter()
        .any(|change| change.path == "campaign.parameters.attack_plugin_dirs"));
}

#[test]
fn reports_no_changes_for_modern_shape() {
    let raw = r#"
campaign:
  name: "migration-test"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "./tests/circuits/multiplier.circom"
    main_component: "Multiplier"
  parameters:
    engagement_strict: true
    attack_plugin_dirs:
      - "/opt/plugins"
attacks:
  - type: "boundary"
    description: "boundary"
    plugin: "example_plugin"
    config:
      samples: 64
inputs:
  - name: "a"
    type: "field"
"#;

    let value: serde_yaml::Value = serde_yaml::from_str(raw).expect("valid yaml");
    let (_migrated, report) = migrate_config_value(value);

    assert!(!report.changed);
    assert!(report.rewritten_keys.is_empty());
}
