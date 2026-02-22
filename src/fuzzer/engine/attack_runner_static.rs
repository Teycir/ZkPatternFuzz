use super::prelude::*;
use super::FuzzingEngine;
use std::path::Path;

fn parse_static_severity(raw: &str) -> Severity {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "warning" | "warn" | "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn source_location(source_path: &Path, line: Option<usize>) -> Option<String> {
    let base = source_path.display().to_string();
    Some(match line {
        Some(line_no) => format!("{base}:{line_no}"),
        None => base,
    })
}

fn non_circom_static_findings(
    framework: Framework,
    source_path: &Path,
    source: &str,
    max_findings: usize,
) -> Vec<Finding> {
    use crate::targets::{cairo_analysis, halo2_analysis, noir_analysis};

    let limit = max_findings.max(1);
    let mut findings = Vec::new();
    match framework {
        Framework::Circom => {}
        Framework::Noir => {
            for hint in noir_analysis::analyze_for_vulnerabilities(source)
                .into_iter()
                .take(limit)
            {
                let severity = match hint.hint_type {
                    noir_analysis::VulnerabilityType::UnconstrainedFunction => Severity::High,
                    noir_analysis::VulnerabilityType::MissingAssertions => Severity::Medium,
                    noir_analysis::VulnerabilityType::UnsafeArithmetic => Severity::Medium,
                };
                findings.push(Finding {
                    attack_type: AttackType::CircomStaticLint,
                    severity,
                    description: format!(
                        "Noir constraint-inspection {:?}: {}",
                        hint.hint_type, hint.description
                    ),
                    poc: ProofOfConcept::default(),
                    location: source_location(source_path, hint.line),
                });
            }
        }
        Framework::Halo2 => {
            for issue in halo2_analysis::analyze_circuit(source)
                .into_iter()
                .take(limit)
            {
                findings.push(Finding {
                    attack_type: AttackType::CircomStaticLint,
                    severity: parse_static_severity(&issue.severity),
                    description: format!(
                        "Halo2 constraint-inspection [{}]: {}",
                        issue.gate_type, issue.description
                    ),
                    poc: ProofOfConcept::default(),
                    location: source_location(source_path, None),
                });
            }
        }
        Framework::Cairo => {
            for issue in cairo_analysis::analyze_for_vulnerabilities(source)
                .into_iter()
                .take(limit)
            {
                findings.push(Finding {
                    attack_type: AttackType::CircomStaticLint,
                    severity: parse_static_severity(&issue.severity),
                    description: format!(
                        "Cairo constraint-inspection {:?}: {}",
                        issue.issue_type, issue.description
                    ),
                    poc: ProofOfConcept::default(),
                    location: source_location(source_path, issue.line),
                });
            }
        }
    }

    findings
}

impl FuzzingEngine {
    pub(super) async fn run_circom_static_lint_attack(
        &mut self,
        config: &serde_yaml::Value,
        progress: Option<&ProgressReporter>,
    ) -> anyhow::Result<()> {
        use crate::oracles::{CircomStaticLint, CircomStaticLintConfig};

        let section = config.get("circom_static_lint").unwrap_or(config);
        let mut lint_config = CircomStaticLintConfig::default();
        let framework = self.config.campaign.target.framework;

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
        let max_findings = lint_config.max_findings_per_check;
        if let Some(v) = section.get("case_sensitive").and_then(|v| v.as_bool()) {
            lint_config.case_sensitive = v;
        }

        let source_path = self.config.campaign.target.circuit_path.clone();
        let findings = if framework == Framework::Circom {
            let lint = CircomStaticLint::new(lint_config);
            match lint.scan_file(&source_path) {
                Ok(findings) => findings,
                Err(err) => {
                    tracing::warn!(
                        "CircomStaticLint skipped source read '{}': {}",
                        source_path.display(),
                        err
                    );
                    return Ok(());
                }
            }
        } else {
            let source = match std::fs::read_to_string(&source_path) {
                Ok(value) => value,
                Err(err) => {
                    tracing::warn!(
                        "Static lint skipped source read '{}' (framework={:?}): {}",
                        source_path.display(),
                        framework,
                        err
                    );
                    return Ok(());
                }
            };
            non_circom_static_findings(framework, &source_path, &source, max_findings)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_circom_noir_emits_linted_findings_with_locations() {
        let source = r#"
        unconstrained fn helper(x: Field) -> Field { x }
        fn main(x: pub Field) -> pub Field { x }
        "#;
        let findings =
            non_circom_static_findings(Framework::Noir, Path::new("fixtures/main.nr"), source, 8);
        assert!(!findings.is_empty(), "expected noir static findings");
        assert!(findings
            .iter()
            .all(|f| f.attack_type == AttackType::CircomStaticLint));
        assert!(findings
            .iter()
            .all(|f| f.location.as_deref() == Some("fixtures/main.nr")));
    }

    #[test]
    fn non_circom_halo2_maps_warning_to_medium() {
        let source = "let advice = meta.advice_column();";
        let findings =
            non_circom_static_findings(Framework::Halo2, Path::new("fixtures/main.rs"), source, 8);
        assert!(!findings.is_empty(), "expected halo2 static findings");
        assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn non_circom_respects_max_findings_limit() {
        let source = r#"
        unconstrained fn helper(x: Field) -> Field { x }
        fn one() {}
        fn two() {}
        "#;
        let findings =
            non_circom_static_findings(Framework::Noir, Path::new("fixtures/main.nr"), source, 1);
        assert_eq!(findings.len(), 1);
    }
}
