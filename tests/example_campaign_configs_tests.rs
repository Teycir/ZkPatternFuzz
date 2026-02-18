use std::path::PathBuf;

use zk_fuzzer::config::{AttackType, FuzzConfig};

fn example_path(file: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("campaigns")
        .join("examples")
        .join(file)
        .to_string_lossy()
        .to_string()
}

fn load_example_config(file: &str) -> FuzzConfig {
    FuzzConfig::from_yaml(&example_path(file))
        .unwrap_or_else(|err| panic!("failed to load example '{}': {:#}", file, err))
}

fn assert_has_attack(config: &FuzzConfig, expected: AttackType, file: &str) {
    assert!(
        config
            .attacks
            .iter()
            .any(|attack| attack.attack_type == expected),
        "example '{}' should contain attack {:?}, got {:?}",
        file,
        expected,
        config
            .attacks
            .iter()
            .map(|a| a.attack_type.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_security_example_campaigns_load_with_expected_attacks() {
    let cases = [
        ("trusted_setup_audit.yaml", AttackType::TrustedSetup),
        ("sidechannel_audit.yaml", AttackType::SidechannelAdvanced),
        (
            "quantum_resistance_audit.yaml",
            AttackType::QuantumResistance,
        ),
        ("privacy_audit.yaml", AttackType::PrivacyAdvanced),
        ("defi_audit.yaml", AttackType::DefiAdvanced),
        (
            "circom_static_lint_audit.yaml",
            AttackType::CircomStaticLint,
        ),
    ];

    for (file, expected_attack) in cases {
        let config = load_example_config(file);
        assert_has_attack(&config, expected_attack, file);
        assert!(
            !config.inputs.is_empty(),
            "example '{}' should define at least one input",
            file
        );
    }
}

#[test]
fn test_security_example_campaigns_preserve_attack_config_sections() {
    let cases = [
        ("trusted_setup_audit.yaml", "trusted_setup_test"),
        ("sidechannel_audit.yaml", "sidechannel_advanced"),
        ("quantum_resistance_audit.yaml", "quantum_resistance"),
        ("privacy_audit.yaml", "privacy_advanced"),
        ("defi_audit.yaml", "defi_advanced"),
        ("circom_static_lint_audit.yaml", "circom_static_lint"),
    ];

    for (file, section_key) in cases {
        let config = load_example_config(file);
        let attack = config
            .attacks
            .first()
            .unwrap_or_else(|| panic!("example '{}' should have at least one attack", file));
        assert!(
            attack.config.get(section_key).is_some(),
            "example '{}' attack config should contain section '{}'",
            file,
            section_key
        );
    }
}
