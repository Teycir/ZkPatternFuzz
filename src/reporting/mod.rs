//! Reporting module for fuzzing results
//!
//! Provides multiple output formats for fuzzing findings:
//! - JSON: Machine-readable format for automation
//! - Markdown: Human-readable reports for documentation
//! - SARIF: IDE integration (VS Code, GitHub Code Scanning)
//! - Coverage Summary: Enhanced CLI coverage view
//! - PoC Generator: Exploit reproduction scripts

mod command_timeout; // Timeout wrapper for external commands

pub mod coverage_summary;
pub mod evidence; // Phase 5: Proof-level evidence bundles
pub mod evidence_cairo; // Phase 0: Cairo proof generation
pub mod evidence_halo2; // Phase 0: Halo2 proof generation
pub mod evidence_noir; // Phase 0: Noir proof generation
pub mod poc_generator;
pub mod sarif;
pub mod triage; // Phase 2: Automated triage system

pub use evidence::{BackendIdentity, EvidenceBundle, EvidenceGenerator, VerificationResult};
pub use evidence_cairo::generate_cairo_proof;
pub use evidence_halo2::generate_halo2_proof;
pub use evidence_noir::generate_noir_proof;

use crate::config::ReportingConfig;
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use zk_core::Severity;
use zk_core::{CoverageMap, Finding};

pub use coverage_summary::{AdditionalMetrics, CoverageSummary, CoverageSummaryBuilder};
pub use poc_generator::{PoCFormat, PoCGenerator, PoCGeneratorConfig};
pub use sarif::{SarifBuilder, SarifLevel, SarifReport};
pub use triage::{
    ConfidenceBreakdown, ConfidenceLevel, TriageConfig, TriagePipeline, TriageReport,
    TriageStatistics, TriagedFinding, VerificationStatus,
};

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

    // Phase 3: Enhanced coverage metrics
    /// Number of input dependency paths covered
    #[serde(default)]
    pub covered_dependency_paths: u64,
    /// Total number of input dependency paths
    #[serde(default)]
    pub total_dependency_paths: u64,
    /// Dependency path coverage percentage
    #[serde(default)]
    pub dependency_coverage_percentage: f64,
    /// Number of critical uncovered constraint paths
    #[serde(default)]
    pub critical_uncovered_paths: u64,

    // Oracle diversity metrics
    /// Number of oracle types that have fired
    #[serde(default)]
    pub oracle_types_fired: u64,
    /// Total number of registered oracle types
    #[serde(default)]
    pub oracle_types_registered: u64,
    /// Oracle diversity score (0.0 - 1.0)
    #[serde(default)]
    pub oracle_diversity_score: f64,
    /// Number of unique violation patterns
    #[serde(default)]
    pub unique_violation_patterns: u64,

    // Throughput metrics
    /// Executions per second
    #[serde(default)]
    pub executions_per_second: f64,
    /// Corpus size
    #[serde(default)]
    pub corpus_size: u64,
}

impl FuzzReport {
    pub fn new(
        campaign_name: String,
        findings: Vec<Finding>,
        coverage: CoverageMap,
        config: ReportingConfig,
    ) -> Self {
        let mut findings_by_severity = HashMap::new();
        let mut findings_by_type = HashMap::new();

        // Count by severity
        for finding in &findings {
            *findings_by_severity
                .entry(finding.severity.to_string())
                .or_insert(0) += 1;

            *findings_by_type
                .entry(format!("{:?}", finding.attack_type))
                .or_insert(0) += 1;
        }

        let stats = FuzzStatistics {
            coverage_percentage: coverage.coverage_percentage(),
            unique_crashes: findings.len() as u64,
            findings_by_severity,
            findings_by_type,
            ..Default::default()
        };

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
            .with_circuit_path(match self.campaign_name.rsplit('/').next() {
                Some(name) => name,
                None => &self.campaign_name,
            })
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
