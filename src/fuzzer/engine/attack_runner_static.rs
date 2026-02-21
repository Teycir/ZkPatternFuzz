use super::prelude::*;
use super::FuzzingEngine;

impl FuzzingEngine {
    pub(super) async fn run_circom_static_lint_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{CircomStaticLint, CircomStaticLintConfig};

        if self.config.campaign.target.framework != Framework::Circom {
            tracing::warn!(
                "CircomStaticLint skipped: framework is {:?} (requires Circom)",
                self.config.campaign.target.framework
            );
            return Ok(());
        }

        let section = config.get("circom_static_lint").unwrap_or(config);
        let mut lint_config = CircomStaticLintConfig::default();

        if let Some(values) = section.get("enabled_checks").and_then(|v| v.as_sequence()) {
            let check_names: Vec<String> = values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect();
            let parsed_checks = CircomStaticLint::parse_checks(&check_names);
            if !parsed_checks.is_empty() {
                lint_config.enabled_checks = parsed_checks;
            }
        }

        if let Some(v) = section
            .get("max_findings_per_check")
            .and_then(|v| v.as_u64())
        {
            lint_config.max_findings_per_check = v as usize;
        }
        if let Some(v) = section.get("case_sensitive").and_then(|v| v.as_bool()) {
            lint_config.case_sensitive = v;
        }

        let lint = CircomStaticLint::new(lint_config);
        let source_path = self.config.campaign.target.circuit_path.clone();
        let findings = match lint.scan_file(&source_path) {
            Ok(findings) => findings,
            Err(err) => {
                tracing::warn!(
                    "CircomStaticLint skipped source read '{}': {}",
                    source_path.display(),
                    err
                );
                return Ok(());
            }
        };

        self.record_custom_findings(findings, AttackType::CircomStaticLint, progress)?;
        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }

    pub(super) async fn run_quantum_resistance_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{PrimitivePattern, QuantumResistanceAttack, QuantumResistanceConfig};

        fn parse_severity(raw: &str) -> Severity {
            match raw.trim().to_ascii_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            }
        }

        let section = config.get("quantum_resistance").unwrap_or(config);
        let mut quantum_config = QuantumResistanceConfig::default();
        if let Some(v) = section.get("case_sensitive").and_then(|v| v.as_bool()) {
            quantum_config.case_sensitive = v;
        }

        if let Some(entries) = section
            .get("vulnerable_primitives")
            .and_then(|v| v.get("detect"))
            .and_then(|v| v.as_sequence())
        {
            let mut parsed = Vec::new();
            for entry in entries {
                let Some(name) = entry.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let severity = entry
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(parse_severity)
                    .unwrap_or(Severity::High);
                let patterns: Vec<String> = entry
                    .get("patterns")
                    .and_then(|v| v.as_sequence())
                    .map(|seq| {
                        seq.iter()
                            .filter_map(|value| value.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_else(|| vec![name.to_ascii_lowercase()]);
                parsed.push(PrimitivePattern {
                    name: name.to_string(),
                    severity,
                    patterns,
                });
            }
            if !parsed.is_empty() {
                quantum_config.vulnerable_primitives = parsed;
            }
        }

        let source_path = self.config.campaign.target.circuit_path.clone();
        let witness: Vec<FieldElement> = Vec::new();
        let attack = QuantumResistanceAttack::new(quantum_config);
        let findings = match attack.scan_file(&source_path, &witness) {
            Ok(findings) => findings,
            Err(err) => {
                tracing::warn!(
                    "QuantumResistance scan skipped source read '{}': {}",
                    source_path.display(),
                    err
                );
                return Ok(());
            }
        };

        self.record_custom_findings(findings, AttackType::QuantumResistance, progress)?;
        if let Some(p) = progress {
            p.inc();
        }
        Ok(())
    }
}
