//! AI Assistant Module for ZkPatternFuzz
//!
//! Provides AI-assisted pentesting capabilities including:
//! - Invariant generation from circuit analysis
//! - Result analysis and next-step suggestions
//! - YAML configuration generation
//! - Vulnerability explanation

pub mod invariant_generator;
pub mod result_analyzer;
pub mod yaml_suggester;

use crate::config::{AIAssistanceMode, AIAssistantConfig};
use anyhow::Result;

/// AI Assistant service
#[derive(Debug, Clone)]
pub struct AIAssistant {
    config: AIAssistantConfig,
}

impl AIAssistant {
    /// Create a new AI Assistant
    pub fn new(config: AIAssistantConfig) -> Self {
        Self { config }
    }

    /// Check if AI assistance is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if a specific mode is enabled
    pub fn is_mode_enabled(&self, mode: &AIAssistanceMode) -> bool {
        if !self.is_enabled() {
            return false;
        }

        // Check if "All" mode is enabled
        if self.config.modes.contains(&AIAssistanceMode::All) {
            return true;
        }

        // Check if specific mode is enabled
        self.config.modes.contains(mode)
    }

    /// Generate candidate invariants from circuit analysis
    pub async fn generate_invariants(&self, circuit_info: &str) -> Result<Vec<String>> {
        if !self.is_mode_enabled(&AIAssistanceMode::InvariantGeneration) {
            return Ok(vec![]);
        }

        invariant_generator::generate_invariants(&self.config, circuit_info).await
    }

    /// Analyze fuzzing results and suggest next steps
    pub async fn analyze_results(&self, results: &str) -> Result<String> {
        if !self.is_mode_enabled(&AIAssistanceMode::ResultAnalysis) {
            return Ok(String::new());
        }

        result_analyzer::analyze_results(&self.config, results).await
    }

    /// Generate YAML configuration suggestions
    pub async fn suggest_yaml(&self, circuit_info: &str) -> Result<String> {
        if !self.is_mode_enabled(&AIAssistanceMode::ConfigSuggestion) {
            return Ok(String::new());
        }

        yaml_suggester::suggest_yaml(&self.config, circuit_info).await
    }

    /// Explain vulnerabilities in natural language
    pub async fn explain_vulnerability(&self, vulnerability: &str) -> Result<String> {
        if !self.is_mode_enabled(&AIAssistanceMode::VulnerabilityExplanation) {
            return Ok(String::new());
        }

        // Simple explanation for now - can be enhanced with AI calls
        Ok(format!("Vulnerability explanation: {}", vulnerability))
    }
}
