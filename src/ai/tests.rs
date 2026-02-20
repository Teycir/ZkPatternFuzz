//! AI Module Tests

use crate::ai::{AIAssistanceMode, AIAssistant};
use crate::config::{AIAssistanceMode as ConfigMode, AIAssistantConfig};

#[test]
fn test_ai_assistant_creation() {
    let config = AIAssistantConfig {
        enabled: true,
        model: "mistral".to_string(),
        endpoint: None,
        api_key: None,
        temperature: 0.7,
        max_tokens: 1000,
        modes: vec![ConfigMode::InvariantGeneration, ConfigMode::ResultAnalysis],
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
        modes: vec![ConfigMode::InvariantGeneration, ConfigMode::All],
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
        modes: vec![ConfigMode::All],
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
        modes: vec![ConfigMode::InvariantGeneration],
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
        modes: vec![ConfigMode::ConfigSuggestion],
        system_prompt: None,
    };

    let ai = AIAssistant::new(config);
    let circuit_info = "Range check circuit";

    let yaml = ai.suggest_yaml(circuit_info).await.unwrap();
    assert!(yaml.contains("ai_assistant"));
    assert!(yaml.contains("mistral"));
    assert!(yaml.contains("range"));
}
