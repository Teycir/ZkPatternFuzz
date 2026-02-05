//! Reporting module for fuzzing results
//!
//! Provides multiple output formats for fuzzing findings:
//! - JSON: Machine-readable format for automation
//! - Markdown: Human-readable reports for documentation
//! - SARIF: IDE integration (VS Code, GitHub Code Scanning)

pub mod sarif;

use crate::config::{ReportingConfig, Severity};
use crate::fuzzer::{CoverageMap, Finding};
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

pub use sarif::{SarifBuilder, SarifLevel, SarifReport};

/// Complete fuzzing report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzReport {
    pub campaign_name: String,
    pub timestamp: DateTime<Utc>,
    pub duration_seconds: u64,
    pub findings: Vec<Finding>,
    pub statistics: FuzzStatistics,
    #[serde(skip)]
    pub config: ReportingConfig,
}

/// Fuzzing statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FuzzStatistics {
    pub total_executions: u64,
    pub unique_crashes: u64,
    pub coverage_percentage: f64,
    pub findings_by_severity: HashMap<String, u64>,
    pub findings_by_type: HashMap<String, u64>,
}

impl FuzzReport {
    pub fn new(
        campaign_name: String,
        findings: Vec<Finding>,
        coverage: CoverageMap,
        config: ReportingConfig,
    ) -> Self {
        let mut stats = FuzzStatistics::default();
        stats.coverage_percentage = coverage.coverage_percentage();
        stats.unique_crashes = findings.len() as u64;

        // Count by severity
        for finding in &findings {
            *stats
                .findings_by_severity
                .entry(finding.severity.to_string())
                .or_insert(0) += 1;

            *stats
                .findings_by_type
                .entry(format!("{:?}", finding.attack_type))
                .or_insert(0) += 1;
        }

        Self {
            campaign_name,
            timestamp: Utc::now(),
            duration_seconds: 0,
            findings,
            statistics: stats,
            config,
        }
    }

    /// Check if there are any critical findings
    pub fn has_critical_findings(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    /// Print a summary to stdout
    pub fn print_summary(&self) {
        println!("\n{}", "═".repeat(60).bright_blue());
        println!(
            "{}",
            format!("  FUZZING REPORT: {}", self.campaign_name).bright_white()
        );
        println!("{}", "═".repeat(60).bright_blue());

        // Statistics
        println!("\n{}", "STATISTICS".bright_yellow().bold());
        println!("  Total Findings: {}", self.findings.len());
        println!("  Coverage: {:.2}%", self.statistics.coverage_percentage);

        // Findings by severity
        if !self.statistics.findings_by_severity.is_empty() {
            println!("\n{}", "FINDINGS BY SEVERITY".bright_yellow().bold());
            for (severity, count) in &self.statistics.findings_by_severity {
                let colored_severity = match severity.as_str() {
                    "CRITICAL" => severity.bright_red().bold(),
                    "HIGH" => severity.red(),
                    "MEDIUM" => severity.yellow(),
                    "LOW" => severity.bright_yellow(),
                    _ => severity.white(),
                };
                println!("  {}: {}", colored_severity, count);
            }
        }

        // Findings by type
        if !self.statistics.findings_by_type.is_empty() {
            println!("\n{}", "FINDINGS BY TYPE".bright_yellow().bold());
            for (attack_type, count) in &self.statistics.findings_by_type {
                println!("  {}: {}", attack_type, count);
            }
        }

        // Individual findings
        if !self.findings.is_empty() {
            println!("\n{}", "DETAILED FINDINGS".bright_yellow().bold());
            for (i, finding) in self.findings.iter().enumerate() {
                let severity_str = match finding.severity {
                    Severity::Critical => format!("[{}]", finding.severity).bright_red().bold(),
                    Severity::High => format!("[{}]", finding.severity).red(),
                    Severity::Medium => format!("[{}]", finding.severity).yellow(),
                    Severity::Low => format!("[{}]", finding.severity).bright_yellow(),
                    Severity::Info => format!("[{}]", finding.severity).white(),
                };

                println!("\n  {}. {} {:?}", i + 1, severity_str, finding.attack_type);
                println!("     {}", finding.description);

                if let Some(ref location) = finding.location {
                    println!("     Location: {}", location);
                }
            }
        } else {
            println!(
                "\n{}",
                "  ✓ No vulnerabilities found!".bright_green().bold()
            );
        }

        println!("\n{}", "═".repeat(60).bright_blue());
    }

    /// Save reports to files
    pub fn save_to_files(&self) -> anyhow::Result<()> {
        // Create output directory
        fs::create_dir_all(&self.config.output_dir)?;

        for format in &self.config.formats {
            match format.as_str() {
                "json" => self.save_json()?,
                "markdown" | "md" => self.save_markdown()?,
                "sarif" => self.save_sarif()?,
                _ => {
                    tracing::warn!("Unknown report format: {}", format);
                }
            }
        }

        Ok(())
    }

    fn save_json(&self) -> anyhow::Result<()> {
        let path = self.config.output_dir.join("report.json");
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        tracing::info!("Saved JSON report to {:?}", path);
        Ok(())
    }

    fn save_markdown(&self) -> anyhow::Result<()> {
        let path = self.config.output_dir.join("report.md");
        let mut md = String::new();

        md.push_str(&format!("# Fuzzing Report: {}\n\n", self.campaign_name));
        md.push_str(&format!("**Generated:** {}\n\n", self.timestamp));

        md.push_str("## Summary\n\n");
        md.push_str(&format!("- Total Findings: {}\n", self.findings.len()));
        md.push_str(&format!(
            "- Coverage: {:.2}%\n",
            self.statistics.coverage_percentage
        ));

        if !self.findings.is_empty() {
            md.push_str("\n## Findings\n\n");

            for (i, finding) in self.findings.iter().enumerate() {
                md.push_str(&format!(
                    "### {}. [{:?}] {:?}\n\n",
                    i + 1,
                    finding.severity,
                    finding.attack_type
                ));
                md.push_str(&format!("{}\n\n", finding.description));

                if self.config.include_poc {
                    md.push_str("**Proof of Concept:**\n\n");
                    md.push_str("```\n");
                    md.push_str(&format!(
                        "Witness A: {:?}\n",
                        finding
                            .poc
                            .witness_a
                            .iter()
                            .map(|fe| fe.to_hex())
                            .collect::<Vec<_>>()
                    ));
                    if let Some(ref witness_b) = finding.poc.witness_b {
                        md.push_str(&format!(
                            "Witness B: {:?}\n",
                            witness_b.iter().map(|fe| fe.to_hex()).collect::<Vec<_>>()
                        ));
                    }
                    md.push_str("```\n\n");
                }
            }
        }

        fs::write(&path, md)?;
        tracing::info!("Saved Markdown report to {:?}", path);
        Ok(())
    }

    fn save_sarif(&self) -> anyhow::Result<()> {
        let path = self.config.output_dir.join("report.sarif");

        // Use the full SARIF builder for comprehensive output
        let report = SarifBuilder::new("zk-fuzzer", env!("CARGO_PKG_VERSION"))
            .with_information_uri("https://github.com/example/zk-fuzzer")
            .with_circuit_path(
                self.campaign_name
                    .split('/')
                    .last()
                    .unwrap_or(&self.campaign_name),
            )
            .add_findings(&self.findings)
            .build();

        report.save_to_file(&path)?;
        tracing::info!("Saved SARIF report to {:?}", path);
        Ok(())
    }

    /// Generate SARIF report object for programmatic access
    pub fn to_sarif(&self) -> SarifReport {
        SarifBuilder::new("zk-fuzzer", env!("CARGO_PKG_VERSION"))
            .with_information_uri("https://github.com/example/zk-fuzzer")
            .add_findings(&self.findings)
            .build()
    }
}

// Implement Serialize for Finding
impl Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Finding", 5)?;
        state.serialize_field("attack_type", &format!("{:?}", self.attack_type))?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("location", &self.location)?;
        state.serialize_field(
            "poc_witness_a",
            &self
                .poc
                .witness_a
                .iter()
                .map(|fe| fe.to_hex())
                .collect::<Vec<_>>(),
        )?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Finding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            AttackType,
            Severity,
            Description,
            Location,
            PocWitnessA,
        }

        struct FindingVisitor;

        impl<'de> Visitor<'de> for FindingVisitor {
            type Value = Finding;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Finding")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Finding, V::Error>
            where
                V: MapAccess<'de>,
            {
                use crate::config::AttackType;
                use crate::fuzzer::{FieldElement, ProofOfConcept};

                let mut attack_type: Option<String> = None;
                let mut severity: Option<Severity> = None;
                let mut description: Option<String> = None;
                let mut location: Option<Option<String>> = None;
                let mut poc_witness_a: Option<Vec<String>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::AttackType => {
                            attack_type = Some(map.next_value()?);
                        }
                        Field::Severity => {
                            severity = Some(map.next_value()?);
                        }
                        Field::Description => {
                            description = Some(map.next_value()?);
                        }
                        Field::Location => {
                            location = Some(map.next_value()?);
                        }
                        Field::PocWitnessA => {
                            poc_witness_a = Some(map.next_value()?);
                        }
                    }
                }

                let attack_type_str =
                    attack_type.ok_or_else(|| de::Error::missing_field("attack_type"))?;
                let parsed_attack_type = match attack_type_str.as_str() {
                    "Underconstrained" => AttackType::Underconstrained,
                    "Soundness" => AttackType::Soundness,
                    "ArithmeticOverflow" => AttackType::ArithmeticOverflow,
                    "ConstraintBypass" => AttackType::ConstraintBypass,
                    "TrustedSetup" => AttackType::TrustedSetup,
                    "WitnessLeakage" => AttackType::WitnessLeakage,
                    "ReplayAttack" => AttackType::ReplayAttack,
                    "Collision" => AttackType::Collision,
                    "Boundary" => AttackType::Boundary,
                    "BitDecomposition" => AttackType::BitDecomposition,
                    "Malleability" => AttackType::Malleability,
                    "VerificationFuzzing" => AttackType::VerificationFuzzing,
                    "WitnessFuzzing" => AttackType::WitnessFuzzing,
                    "Differential" => AttackType::Differential,
                    "InformationLeakage" => AttackType::InformationLeakage,
                    "TimingSideChannel" => AttackType::TimingSideChannel,
                    "CircuitComposition" => AttackType::CircuitComposition,
                    "RecursiveProof" => AttackType::RecursiveProof,
                    _ => {
                        return Err(de::Error::unknown_variant(
                            &attack_type_str,
                            &[
                                "Underconstrained",
                                "Soundness",
                                "ArithmeticOverflow",
                                "Collision",
                                "Boundary",
                            ],
                        ))
                    }
                };

                let witness_a: Vec<FieldElement> = poc_witness_a
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|hex| FieldElement::from_hex(hex).ok())
                    .collect();

                Ok(Finding {
                    attack_type: parsed_attack_type,
                    severity: severity.ok_or_else(|| de::Error::missing_field("severity"))?,
                    description: description
                        .ok_or_else(|| de::Error::missing_field("description"))?,
                    location: location.unwrap_or(None),
                    poc: ProofOfConcept {
                        witness_a,
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                })
            }
        }

        const FIELDS: &[&str] = &[
            "attack_type",
            "severity",
            "description",
            "location",
            "poc_witness_a",
        ];
        deserializer.deserialize_struct("Finding", FIELDS, FindingVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AttackType;
    use crate::fuzzer::ProofOfConcept;

    #[test]
    fn test_report_creation() {
        let findings = vec![Finding {
            attack_type: AttackType::Underconstrained,
            severity: Severity::Critical,
            description: "Test finding".to_string(),
            poc: ProofOfConcept::default(),
            location: None,
        }];

        let report = FuzzReport::new(
            "test_campaign".to_string(),
            findings,
            CoverageMap::default(),
            ReportingConfig::default(),
        );

        assert!(report.has_critical_findings());
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn test_finding_serialization_roundtrip() {
        let original = Finding {
            attack_type: AttackType::Collision,
            severity: Severity::High,
            description: "Test collision finding".to_string(),
            poc: ProofOfConcept::default(),
            location: Some("test_circuit.circom:42".to_string()),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&original).expect("Failed to serialize Finding");

        // Deserialize back
        let deserialized: Finding =
            serde_json::from_str(&json).expect("Failed to deserialize Finding");

        assert_eq!(deserialized.attack_type, AttackType::Collision);
        assert_eq!(deserialized.severity, Severity::High);
        assert_eq!(deserialized.description, "Test collision finding");
        assert_eq!(
            deserialized.location,
            Some("test_circuit.circom:42".to_string())
        );
    }

    #[test]
    fn test_finding_deserialization_from_json() {
        // Note: Severity uses lowercase per serde rename_all = "lowercase"
        let json = r#"{
            "attack_type": "Soundness",
            "severity": "critical",
            "description": "Proof forgery detected",
            "location": null,
            "poc_witness_a": ["0x0000000000000000000000000000000000000000000000000000000000000001"]
        }"#;

        let finding: Finding = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(finding.attack_type, AttackType::Soundness);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.description, "Proof forgery detected");
        assert!(finding.location.is_none());
        assert_eq!(finding.poc.witness_a.len(), 1);
    }
}
