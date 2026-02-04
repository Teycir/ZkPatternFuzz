//! Reporting module for fuzzing results

use crate::config::{ReportingConfig, Severity};
use crate::fuzzer::{CoverageMap, Finding};
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;


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
        println!(
            "  Coverage: {:.2}%",
            self.statistics.coverage_percentage
        );

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

                println!(
                    "\n  {}. {} {:?}",
                    i + 1,
                    severity_str,
                    finding.attack_type
                );
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
        // SARIF (Static Analysis Results Interchange Format)
        let path = self.config.output_dir.join("report.sarif");

        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "zk-fuzzer",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/example/zk-fuzzer"
                    }
                },
                "results": self.findings.iter().map(|f| {
                    serde_json::json!({
                        "ruleId": format!("{:?}", f.attack_type),
                        "level": match f.severity {
                            Severity::Critical | Severity::High => "error",
                            Severity::Medium => "warning",
                            _ => "note"
                        },
                        "message": {
                            "text": f.description.clone()
                        }
                    })
                }).collect::<Vec<_>>()
            }]
        });

        let json = serde_json::to_string_pretty(&sarif)?;
        fs::write(&path, json)?;
        tracing::info!("Saved SARIF report to {:?}", path);
        Ok(())
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
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Simplified deserialization for now
        unimplemented!("Finding deserialization not implemented")
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
}
