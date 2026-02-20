//! YAML Suggester Module
//!
//! Generates YAML configuration suggestions based on circuit analysis

use crate::config::AIAssistantConfig;
use anyhow::Result;

/// Generate YAML configuration suggestions
pub async fn suggest_yaml(config: &AIAssistantConfig, circuit_info: &str) -> Result<String> {
    let mut yaml = String::new();

    yaml.push_str("# AI-Generated YAML Configuration Suggestion\n");
    yaml.push_str("# Based on circuit analysis\n\n");

    yaml.push_str("campaign:\n");
    yaml.push_str("  name: \"AI-Suggested Audit\"\n");
    yaml.push_str("  version: \"1.0.0\"\n");
    yaml.push_str("  target:\n");
    yaml.push_str("    framework: circom  # Update based on your framework\n");
    yaml.push_str("    circuit_path: \"./your_circuit.circom\"\n");
    yaml.push_str("    main_component: MainComponent\n");
    yaml.push_str("  parameters:\n");
    yaml.push_str("    timeout_seconds: 300\n\n");

    // Suggest attacks based on circuit patterns
    yaml.push_str("attacks:\n");

    if circuit_info.contains("merkle") || circuit_info.contains("Merkle") {
        yaml.push_str("  - type: collision\n");
        yaml.push_str("    description: \"Merkle tree collision detection\"\n");
        yaml.push_str("    config:\n");
        yaml.push_str("      target: merkle\n\n");
    }

    if circuit_info.contains("nullifier") || circuit_info.contains("Nullifier") {
        yaml.push_str("  - type: collision\n");
        yaml.push_str("    description: \"Nullifier collision detection\"\n");
        yaml.push_str("    config:\n");
        yaml.push_str("      target: nullifier\n\n");
    }

    if circuit_info.contains("range") || circuit_info.contains("Range") {
        yaml.push_str("  - type: boundary\n");
        yaml.push_str("    description: \"Range check boundary testing\"\n");
        yaml.push_str("    config:\n");
        yaml.push_str("      target: range_checks\n\n");
    }

    // Always suggest underconstrained testing
    yaml.push_str("  - type: underconstrained\n");
    yaml.push_str("    description: \"Underconstrained witness detection\"\n");
    yaml.push_str("    config:\n");
    yaml.push_str("      max_attempts: 1000\n\n");

    // Add AI assistant configuration
    yaml.push_str("ai_assistant:\n");
    yaml.push_str("  enabled: true\n");
    yaml.push_str(&format!("  model: \"{}\"\n", config.model));
    yaml.push_str("  modes:\n");
    yaml.push_str("    - invariant_generation\n");
    yaml.push_str("    - result_analysis\n");
    yaml.push_str("    - config_suggestion\n");
    yaml.push_str("    - vulnerability_explanation\n");

    yaml.push_str("\n# Note: Review and customize this configuration before use\n");
    yaml.push_str("# Adjust attack types, parameters, and AI settings as needed\n");

    Ok(yaml)
}
