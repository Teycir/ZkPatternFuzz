//! YAML Configuration Suggester
//!
//! Generates YAML configuration suggestions based on fuzzing results,
//! near-misses, and adaptive scheduler feedback.
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::config::suggester::YamlSuggester;
//!
//! let suggester = YamlSuggester::new();
//! let suggestions = suggester.generate_suggestions(&report, &scheduler);
//! let updated_yaml = suggester.apply_suggestions(&original_yaml, &suggestions)?;
//! ```

use crate::fuzzer::adaptive_attack_scheduler::{AdaptiveScheduler, SuggestionType, YamlSuggestion};
use crate::fuzzer::near_miss::NearMiss;
use crate::reporting::FuzzReport;
use std::collections::HashMap;

/// YAML configuration suggester
pub struct YamlSuggester {
    /// Whether to include comments in output
    include_comments: bool,
}

impl Default for YamlSuggester {
    fn default() -> Self {
        Self::new()
    }
}

impl YamlSuggester {
    /// Create a new suggester
    pub fn new() -> Self {
        Self {
            include_comments: true,
        }
    }

    /// Generate suggestions from report and scheduler
    pub fn generate_suggestions(
        &self,
        report: &FuzzReport,
        scheduler: Option<&AdaptiveScheduler>,
    ) -> Vec<YamlSuggestion> {
        let mut suggestions = Vec::new();

        // Get suggestions from scheduler
        if let Some(sched) = scheduler {
            suggestions.extend(sched.suggest_yaml_edits());
        }

        // Suggest based on findings
        suggestions.extend(self.suggest_from_findings(report));

        // Suggest based on coverage
        suggestions.extend(self.suggest_from_coverage(report));

        // Deduplicate
        self.deduplicate_suggestions(&mut suggestions);

        suggestions
    }

    /// Generate suggestions from findings
    fn suggest_from_findings(&self, report: &FuzzReport) -> Vec<YamlSuggestion> {
        let mut suggestions = Vec::new();

        // Count findings by type
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for finding in &report.findings {
            let type_name = format!("{:?}", finding.attack_type);
            *by_type.entry(type_name).or_insert(0) += 1;
        }

        // Suggest more of what's working
        for (attack_type, count) in &by_type {
            if *count >= 3 {
                suggestions.push(YamlSuggestion {
                    suggestion_type: SuggestionType::IncreaseBudget,
                    key: attack_type.clone(),
                    value: "increase iterations".to_string(),
                    reason: format!(
                        "{} found {} bugs - consider increasing budget",
                        attack_type, count
                    ),
                });
            }
        }

        suggestions
    }

    /// Generate suggestions from coverage
    fn suggest_from_coverage(&self, report: &FuzzReport) -> Vec<YamlSuggestion> {
        let mut suggestions = Vec::new();

        // If coverage is low, suggest symbolic execution
        if report.statistics.coverage_percentage < 50.0 {
            suggestions.push(YamlSuggestion {
                suggestion_type: SuggestionType::ModifyMutation,
                key: "fuzz_strategy".to_string(),
                value: "symbolic".to_string(),
                reason: format!(
                    "Coverage is only {:.1}% - consider using symbolic execution",
                    report.statistics.coverage_percentage
                ),
            });
        }

        // If coverage is very high but no findings, suggest different attacks
        if report.statistics.coverage_percentage > 90.0 && report.findings.is_empty() {
            suggestions.push(YamlSuggestion {
                suggestion_type: SuggestionType::AddAttack,
                key: "spec_inference".to_string(),
                value: "true".to_string(),
                reason: "High coverage but no findings - try spec inference".to_string(),
            });
        }

        suggestions
    }

    /// Deduplicate suggestions
    fn deduplicate_suggestions(&self, suggestions: &mut Vec<YamlSuggestion>) {
        let mut seen: HashMap<String, usize> = HashMap::new();

        suggestions.retain(|s| {
            let key = format!("{:?}:{}", s.suggestion_type, s.key);
            if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(key) {
                e.insert(1);
                true
            } else {
                false
            }
        });
    }

    /// Apply suggestions to YAML configuration
    pub fn apply_suggestions(
        &self,
        original_yaml: &str,
        suggestions: &[YamlSuggestion],
    ) -> anyhow::Result<String> {
        let yaml_value: serde_yaml::Value = serde_yaml::from_str(original_yaml)?;

        // Add suggestions as comments at the end
        let mut output = serde_yaml::to_string(&yaml_value)?;

        if self.include_comments && !suggestions.is_empty() {
            output.push_str("\n\n# ==========================================\n");
            output.push_str("# ADAPTIVE SCHEDULER SUGGESTIONS\n");
            output.push_str("# ==========================================\n");
            output.push_str("# Based on fuzzing results, consider these changes:\n\n");

            for suggestion in suggestions {
                output.push_str(&suggestion.to_yaml_comment());
                output.push_str("\n\n");
            }
        }

        Ok(output)
    }

    /// Generate a full suggested YAML with modifications applied
    pub fn generate_suggested_yaml(
        &self,
        original_yaml: &str,
        suggestions: &[YamlSuggestion],
    ) -> anyhow::Result<String> {
        let mut yaml_value: serde_yaml::Value = serde_yaml::from_str(original_yaml)?;

        // Apply suggestions that can be auto-applied
        for suggestion in suggestions {
            self.apply_suggestion(&mut yaml_value, suggestion);
        }

        let output = serde_yaml::to_string(&yaml_value)?;

        // Add header
        let header = format!(
            "# Auto-generated suggested configuration\n\
             # Based on {} suggestions from adaptive scheduler\n\
             # Review changes before using in production\n\n",
            suggestions.len()
        );

        Ok(format!("{}{}", header, output))
    }

    /// Apply a single suggestion to YAML value
    fn apply_suggestion(&self, yaml: &mut serde_yaml::Value, suggestion: &YamlSuggestion) {
        match suggestion.suggestion_type {
            SuggestionType::AddInterestingValue => {
                // Find inputs section and add interesting value
                if let Some(inputs) = yaml.get_mut("inputs") {
                    if let Some(inputs_arr) = inputs.as_sequence_mut() {
                        for input in inputs_arr {
                            if let Some(interesting) = input.get_mut("interesting") {
                                if let Some(arr) = interesting.as_sequence_mut() {
                                    arr.push(serde_yaml::Value::String(suggestion.value.clone()));
                                }
                            }
                        }
                    }
                }
            }
            SuggestionType::IncreaseBudget => {
                // Add to parameters
                if let Some(params) = yaml
                    .get_mut("campaign")
                    .and_then(|c| c.get_mut("parameters"))
                {
                    if let Some(map) = params.as_mapping_mut() {
                        map.insert(
                            serde_yaml::Value::String(format!(
                                "{}_iterations",
                                suggestion.key.to_lowercase()
                            )),
                            serde_yaml::Value::Number(serde_yaml::Number::from(2000)),
                        );
                    }
                }
            }
            SuggestionType::AddInvariant => {
                // Add to invariants section
                if let Some(invariants) = yaml.get_mut("invariants") {
                    if let Some(arr) = invariants.as_sequence_mut() {
                        let mut new_invariant = serde_yaml::Mapping::new();
                        new_invariant.insert(
                            serde_yaml::Value::String("name".to_string()),
                            serde_yaml::Value::String(suggestion.key.clone()),
                        );
                        new_invariant.insert(
                            serde_yaml::Value::String("relation".to_string()),
                            serde_yaml::Value::String(suggestion.value.clone()),
                        );
                        arr.push(serde_yaml::Value::Mapping(new_invariant));
                    }
                }
            }
            _ => {
                // Other suggestions added as comments only
            }
        }
    }

    /// Generate suggestions from near-misses
    pub fn suggest_from_near_misses(&self, near_misses: &[NearMiss]) -> Vec<YamlSuggestion> {
        let mut suggestions = Vec::new();

        for nm in near_misses {
            if let Some(ref value) = nm.value {
                suggestions.push(YamlSuggestion {
                    suggestion_type: SuggestionType::AddInterestingValue,
                    key: "interesting".to_string(),
                    value: value.to_hex(),
                    reason: nm
                        .suggestion
                        .clone()
                        .unwrap_or_else(|| format!("Near-miss at distance {:.3}", nm.distance)),
                });
            }
        }

        suggestions
    }
}

/// Builder for suggested configurations
pub struct SuggestedConfigBuilder {
    original: String,
    suggestions: Vec<YamlSuggestion>,
    include_original_as_comment: bool,
}

impl SuggestedConfigBuilder {
    /// Create a new builder
    pub fn new(original_yaml: &str) -> Self {
        Self {
            original: original_yaml.to_string(),
            suggestions: Vec::new(),
            include_original_as_comment: false,
        }
    }

    /// Add suggestions
    pub fn with_suggestions(mut self, suggestions: Vec<YamlSuggestion>) -> Self {
        self.suggestions.extend(suggestions);
        self
    }

    /// Include original as comment
    pub fn with_original_as_comment(mut self, include: bool) -> Self {
        self.include_original_as_comment = include;
        self
    }

    /// Build the suggested YAML
    pub fn build(self) -> anyhow::Result<String> {
        let suggester = YamlSuggester::new();
        suggester.generate_suggested_yaml(&self.original, &self.suggestions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_core::{AttackType, Finding, ProofOfConcept, Severity};

    #[test]
    fn test_suggester_creation() {
        let suggester = YamlSuggester::new();
        assert!(suggester.include_comments);
    }

    #[test]
    fn test_suggestions_from_findings() {
        let suggester = YamlSuggester::new();

        let report = FuzzReport {
            campaign_name: "test".to_string(),
            timestamp: chrono::Utc::now(),
            duration_seconds: 100,
            findings: vec![
                Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: "Test 1".to_string(),
                    poc: ProofOfConcept::default(),
                    location: None,
                },
                Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: "Test 2".to_string(),
                    poc: ProofOfConcept::default(),
                    location: None,
                },
                Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: "Test 3".to_string(),
                    poc: ProofOfConcept::default(),
                    location: None,
                },
            ],
            statistics: Default::default(),
            config: Default::default(),
        };

        let suggestions = suggester.generate_suggestions(&report, None);

        // Should suggest increasing budget for Underconstrained
        assert!(suggestions
            .iter()
            .any(|s| s.key.contains("Underconstrained")
                && matches!(s.suggestion_type, SuggestionType::IncreaseBudget)));
    }

    #[test]
    fn test_apply_suggestions() {
        let suggester = YamlSuggester::new();

        let original = r#"
campaign:
  name: "Test"
  version: "1.0"
  target:
    framework: "mock"
    circuit_path: "./test.circom"
    main_component: "Main"

inputs:
  - name: "x"
    type: "field"
    interesting: ["0", "1"]

attacks:
  - type: "underconstrained"
    description: "Test"
"#;

        let suggestions = vec![YamlSuggestion {
            suggestion_type: SuggestionType::AddInterestingValue,
            key: "interesting".to_string(),
            value: "0xdeadbeef".to_string(),
            reason: "Near-miss detected".to_string(),
        }];

        let result = suggester.apply_suggestions(original, &suggestions).unwrap();

        assert!(result.contains("SUGGESTIONS"));
        assert!(result.contains("Near-miss detected"));
    }
}
