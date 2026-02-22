//! AI Module Tests

use std::fs;
use std::io::Write;

use tempfile::{NamedTempFile, TempDir};
use zk_fuzzer::ai::{
    build_ai_circuit_context_with_options, redact_sensitive_text, AIAssistant,
    AICircuitContextOptions,
};
use zk_fuzzer::config::{AIAssistanceMode, AIAssistantConfig, FuzzConfig};

#[test]
fn test_ai_assistant_creation() {
    let config = AIAssistantConfig {
        enabled: true,
        model: "mistral".to_string(),
        endpoint: None,
        api_key: None,
        temperature: 0.7,
        max_tokens: 1000,
        modes: vec![
            AIAssistanceMode::InvariantGeneration,
            AIAssistanceMode::ResultAnalysis,
        ],
        system_prompt: None,
    };

    let ai = AIAssistant::new(config);
    assert!(ai.is_enabled());
}

#[test]
fn test_ai_mode_checking() {
    let config = AIAssistantConfig {
        enabled: true,
        model: "mistral".to_string(),
        endpoint: None,
        api_key: None,
        temperature: 0.7,
        max_tokens: 1000,
        modes: vec![AIAssistanceMode::InvariantGeneration, AIAssistanceMode::All],
        system_prompt: None,
    };

    let ai = AIAssistant::new(config);

    // Test specific mode
    assert!(ai.is_mode_enabled(&AIAssistanceMode::InvariantGeneration));

    // Test "All" mode enables everything
    assert!(ai.is_mode_enabled(&AIAssistanceMode::ResultAnalysis));
    assert!(ai.is_mode_enabled(&AIAssistanceMode::ConfigSuggestion));
    assert!(ai.is_mode_enabled(&AIAssistanceMode::VulnerabilityExplanation));
}

#[test]
fn test_ai_disabled() {
    let config = AIAssistantConfig {
        enabled: false,
        model: "mistral".to_string(),
        endpoint: None,
        api_key: None,
        temperature: 0.7,
        max_tokens: 1000,
        modes: vec![AIAssistanceMode::All],
        system_prompt: None,
    };

    let ai = AIAssistant::new(config);
    assert!(!ai.is_enabled());
    assert!(!ai.is_mode_enabled(&AIAssistanceMode::InvariantGeneration));
}

#[tokio::test]
async fn test_invariant_generation() {
    let config = AIAssistantConfig {
        enabled: true,
        model: "mistral".to_string(),
        endpoint: None,
        api_key: None,
        temperature: 0.7,
        max_tokens: 1000,
        modes: vec![AIAssistanceMode::InvariantGeneration],
        system_prompt: None,
    };

    let ai = AIAssistant::new(config);
    let circuit_info = "Merkle tree circuit with nullifier checks";

    let invariants = ai.generate_invariants(circuit_info).await.unwrap();
    assert!(!invariants.is_empty());
    assert!(invariants.iter().any(|i| i.contains("merkle")));
    assert!(invariants.iter().any(|i| i.contains("nullifier")));
}

#[tokio::test]
async fn test_yaml_suggestion() {
    let config = AIAssistantConfig {
        enabled: true,
        model: "mistral".to_string(),
        endpoint: None,
        api_key: None,
        temperature: 0.7,
        max_tokens: 1000,
        modes: vec![AIAssistanceMode::ConfigSuggestion],
        system_prompt: None,
    };

    let ai = AIAssistant::new(config);
    let circuit_info = "Range check circuit";

    let yaml = ai.suggest_yaml(circuit_info).await.unwrap();
    assert!(yaml.contains("ai_assistant"));
    assert!(yaml.contains("mistral"));
    assert!(yaml.contains("range"));
}

#[tokio::test]
async fn test_invariant_generation_is_deduplicated_and_bounded() {
    let config = AIAssistantConfig {
        enabled: true,
        model: "mistral".to_string(),
        endpoint: None,
        api_key: None,
        temperature: 0.1,
        max_tokens: 128,
        modes: vec![AIAssistanceMode::InvariantGeneration],
        system_prompt: None,
    };

    let ai = AIAssistant::new(config);
    let circuit_info =
        "Merkle merkle nullifier NULLIFIER range RANGE signature hash balance transfer";

    let invariants = ai.generate_invariants(circuit_info).await.unwrap();
    assert!(!invariants.is_empty());
    assert!(invariants.len() <= 8);

    let unique: std::collections::HashSet<_> = invariants.iter().collect();
    assert_eq!(unique.len(), invariants.len());
}

#[tokio::test]
async fn test_invariant_generation_uses_contextual_prompt_hints() {
    let config = AIAssistantConfig {
        enabled: true,
        model: "mistral".to_string(),
        endpoint: None,
        api_key: None,
        temperature: 0.7,
        max_tokens: 1000,
        modes: vec![AIAssistanceMode::InvariantGeneration],
        system_prompt: Some("focus on privacy and replay protections for bridge flows".to_string()),
    };

    let ai = AIAssistant::new(config);
    let invariants = ai.generate_invariants("generic circuit").await.unwrap();

    assert!(invariants
        .iter()
        .any(|item| item.contains("privacy_leakage_bound")));
    assert!(invariants
        .iter()
        .any(|item| item.contains("nonce_monotonicity")));
}

fn create_temp_config(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("temp config file");
    file.write_all(content.as_bytes())
        .expect("write temp config");
    file
}

fn build_minimal_ai_test_config(temp_dir: &TempDir, circuit_source: &str) -> FuzzConfig {
    let circuit_path = temp_dir.path().join("ai_context_test.circom");
    fs::write(&circuit_path, circuit_source).expect("write circuit");
    let escaped_circuit_path = circuit_path.display().to_string().replace('\\', "\\\\");

    let config_content = format!(
        r#"
campaign:
  name: "AI Context Test"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "{escaped_circuit_path}"
    main_component: "Main"

attacks:
  - type: underconstrained
    description: "Test attack"
    config:
      witness_pairs: 2

inputs:
  - name: "input1"
    type: "field"
    fuzz_strategy: random
"#
    );

    let config_file = create_temp_config(&config_content);
    FuzzConfig::from_yaml(config_file.path().to_str().expect("utf8 config path"))
        .expect("parse config")
}

#[test]
fn test_ai_context_omits_circuit_source_by_default() {
    let temp_dir = TempDir::new().expect("temp dir");
    let config = build_minimal_ai_test_config(
        &temp_dir,
        r#"component Main { signal private input1; signal output out; out <== input1 + 1; }"#,
    );
    let context =
        build_ai_circuit_context_with_options(&config, AICircuitContextOptions::default());

    assert!(context.contains("source_preview_included=false"));
    assert!(context.contains("circuit_preview:\n<omitted_by_default"));
    assert!(!context.contains("signal private input1"));
}

#[test]
fn test_ai_context_opt_in_includes_redacted_preview() {
    let temp_dir = TempDir::new().expect("temp dir");
    let config = build_minimal_ai_test_config(
        &temp_dir,
        r#"component Main {
  // secret=top_secret_value
  const api_key = "sk_test_12345";
  signal private input1;
  signal output out;
  out <== input1 + 1;
}"#,
    );
    let context = build_ai_circuit_context_with_options(
        &config,
        AICircuitContextOptions {
            include_circuit_source: true,
            source_preview_max_chars: 512,
        },
    );

    assert!(context.contains("source_preview_included=true"));
    assert!(context.contains("signal private input1"));
    assert!(context.contains("<redacted>"));
    assert!(!context.contains("top_secret_value"));
    assert!(!context.contains("sk_test_12345"));
}

#[test]
fn test_redact_sensitive_text_masks_secrets() {
    let input =
        "api_key=abc123\nAuthorization: Bearer very.secret.token\nurl=https://x.test?a=1&token=xyz";
    let redacted = redact_sensitive_text(input);

    assert!(!redacted.contains("abc123"));
    assert!(!redacted.contains("very.secret.token"));
    assert!(!redacted.contains("token=xyz"));
    assert!(redacted.contains("<redacted>"));
}
