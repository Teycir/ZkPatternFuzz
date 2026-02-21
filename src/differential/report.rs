//! Reporting for differential fuzzing results

use super::{DifferentialResult, DifferentialSeverity, DifferentialStats};
use std::fmt;
use zk_core::Framework;

/// Report of differential fuzzing campaign
#[derive(Debug, Clone)]
pub struct DifferentialReport {
    pub campaign_name: String,
    pub backends_tested: Vec<Framework>,
    pub findings: Vec<DifferentialResult>,
    pub stats: DifferentialStats,
}

impl DifferentialReport {
    pub fn new(
        campaign_name: &str,
        backends: Vec<Framework>,
        findings: Vec<DifferentialResult>,
        stats: DifferentialStats,
    ) -> Self {
        Self {
            campaign_name: campaign_name.to_string(),
            backends_tested: backends,
            findings,
            stats,
        }
    }

    /// Get critical findings (output mismatches)
    pub fn critical_findings(&self) -> Vec<&DifferentialResult> {
        self.findings
            .iter()
            .filter(|f| f.severity == DifferentialSeverity::OutputMismatch)
            .collect()
    }

    /// Get high severity findings (execution mismatches)
    pub fn high_findings(&self) -> Vec<&DifferentialResult> {
        self.findings
            .iter()
            .filter(|f| f.severity == DifferentialSeverity::ExecutionMismatch)
            .collect()
    }

    /// Check if any critical issues were found
    pub fn has_critical_issues(&self) -> bool {
        !self.critical_findings().is_empty()
    }

    /// Generate summary statistics
    pub fn summary(&self) -> String {
        format!(
            "Differential Fuzzing Report: {}\n\
             Backends: {:?}\n\
             Tests Run: {}\n\
             All Agreed: {}\n\
             Output Mismatches: {}\n\
             Execution Mismatches: {}\n\
             Coverage Mismatches: {}",
            self.campaign_name,
            self.backends_tested,
            self.stats.total_tests,
            self.stats.all_agreed,
            self.stats.output_mismatches,
            self.stats.execution_mismatches,
            self.stats.coverage_mismatches
        )
    }
}

impl fmt::Display for DifferentialReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "═══════════════════════════════════════════════════")?;
        writeln!(f, "         DIFFERENTIAL FUZZING REPORT")?;
        writeln!(f, "═══════════════════════════════════════════════════")?;
        writeln!(f)?;
        writeln!(f, "Campaign: {}", self.campaign_name)?;
        writeln!(f, "Backends: {:?}", self.backends_tested)?;
        writeln!(f)?;
        writeln!(f, "─── Statistics ───")?;
        writeln!(f, "  Total Tests:          {}", self.stats.total_tests)?;
        writeln!(f, "  All Backends Agreed:  {}", self.stats.all_agreed)?;
        writeln!(
            f,
            "  Output Mismatches:    {}",
            self.stats.output_mismatches
        )?;
        writeln!(
            f,
            "  Execution Mismatches: {}",
            self.stats.execution_mismatches
        )?;
        writeln!(
            f,
            "  Coverage Mismatches:  {}",
            self.stats.coverage_mismatches
        )?;
        writeln!(f)?;

        if !self.findings.is_empty() {
            writeln!(f, "─── Findings ───")?;
            for (i, finding) in self.findings.iter().enumerate() {
                writeln!(f)?;
                writeln!(f, "Finding #{}", i + 1)?;
                writeln!(f, "  Severity: {:?}", finding.severity)?;
                writeln!(f, "  Disagreeing: {:?}", finding.disagreeing_backends)?;
                writeln!(f, "  Input: {} field elements", finding.input.len())?;
            }
        }

        Ok(())
    }
}
