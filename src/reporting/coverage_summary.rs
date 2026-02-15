//! Enhanced Coverage Summary for CLI
//!
//! Provides a rich, tree-style coverage summary for terminal output,
//! integrating constraint coverage, dependency paths, and oracle diversity.
//!
//! # Example Output
//!
//! ```text
//! Coverage Summary:
//! ├─ Constraints: 1,234 / 2,000 (61.7%)
//! ├─ Input Dependencies: 45 / 50 paths (90.0%)
//! ├─ Oracle Diversity: 7 / 12 types (58.3%)
//! └─ Uncovered Paths: 5 critical paths
//! ```

use crate::analysis::dependency::{DependencyCoverageStats, DependencyGraph};
use crate::fuzzer::oracle_diversity::{OracleDiversityStats, OracleDiversityTracker};
use crate::reporting::FuzzStatistics;
use colored::*;
use std::io::{self, Write};
use zk_core::CoverageMap;

/// Coverage summary data
#[derive(Debug, Clone, Default)]
pub struct CoverageSummary {
    /// Constraint coverage statistics
    pub constraint_coverage: ConstraintCoverage,
    /// Dependency coverage statistics
    pub dependency_coverage: Option<DependencyCoverageStats>,
    /// Oracle diversity statistics
    pub oracle_diversity: Option<OracleDiversityStats>,
    /// Additional metrics
    pub additional: AdditionalMetrics,
}

/// Constraint coverage statistics
#[derive(Debug, Clone, Default)]
pub struct ConstraintCoverage {
    pub covered: usize,
    pub total: usize,
    pub percentage: f64,
}

/// Additional coverage metrics
#[derive(Debug, Clone, Default)]
pub struct AdditionalMetrics {
    /// Number of interesting test cases in corpus
    pub corpus_size: usize,
    /// Number of unique crashes/findings
    pub unique_findings: usize,
    /// Execution throughput (execs/sec)
    pub throughput: f64,
    /// Time elapsed in seconds
    pub elapsed_seconds: u64,
}

impl CoverageSummary {
    /// Create summary from coverage map
    pub fn from_coverage_map(coverage: &CoverageMap) -> Self {
        Self {
            constraint_coverage: ConstraintCoverage {
                covered: coverage.edge_coverage as usize,
                total: coverage.max_coverage as usize,
                percentage: coverage.coverage_percentage(),
            },
            dependency_coverage: None,
            oracle_diversity: None,
            additional: AdditionalMetrics::default(),
        }
    }

    /// Add dependency coverage
    pub fn with_dependency_coverage(mut self, stats: DependencyCoverageStats) -> Self {
        self.dependency_coverage = Some(stats);
        self
    }

    /// Add oracle diversity
    pub fn with_oracle_diversity(mut self, stats: OracleDiversityStats) -> Self {
        self.oracle_diversity = Some(stats);
        self
    }

    /// Add additional metrics
    pub fn with_additional(mut self, metrics: AdditionalMetrics) -> Self {
        self.additional = metrics;
        self
    }

    /// Build summary from FuzzStatistics and optional extended stats
    pub fn from_stats(
        stats: &FuzzStatistics,
        coverage: &CoverageMap,
        dependency_graph: Option<&DependencyGraph>,
        oracle_tracker: Option<&OracleDiversityTracker>,
    ) -> Self {
        let mut summary = Self::from_coverage_map(coverage);

        // Add dependency coverage if graph is available
        if let Some(graph) = dependency_graph {
            let dep_stats = graph.coverage_stats(coverage);
            summary = summary.with_dependency_coverage(dep_stats);
        }

        // Add oracle diversity if tracker is available
        if let Some(tracker) = oracle_tracker {
            summary = summary.with_oracle_diversity(tracker.stats());
        }

        // Add additional metrics
        summary.additional = AdditionalMetrics {
            unique_findings: stats.unique_crashes as usize,
            ..Default::default()
        };

        summary
    }

    /// Print summary to stdout with colors
    pub fn print(&self) {
        if let Err(e) = self.print_to(&mut io::stdout()) {
            tracing::error!("Failed to print coverage summary: {}", e);
        }
    }

    /// Print summary to a writer
    pub fn print_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(writer)?;
        writeln!(writer, "{}", "Coverage Summary:".bright_cyan().bold())?;

        // Constraint coverage
        let constraint_bar = self.make_progress_bar(self.constraint_coverage.percentage, 20);
        let constraint_color = self.color_for_percentage(self.constraint_coverage.percentage);
        writeln!(
            writer,
            "├─ {}: {} / {} ({}) {}",
            "Constraints".bright_white(),
            format!(
                "{:>5}",
                self.format_number(self.constraint_coverage.covered)
            )
            .color(constraint_color),
            self.format_number(self.constraint_coverage.total),
            format!("{:>5.1}%", self.constraint_coverage.percentage).color(constraint_color),
            constraint_bar
        )?;

        // Dependency coverage (if available)
        if let Some(ref dep) = self.dependency_coverage {
            let dep_bar = self.make_progress_bar(dep.input_path_coverage_percent, 20);
            let dep_color = self.color_for_percentage(dep.input_path_coverage_percent);
            writeln!(
                writer,
                "├─ {}: {} / {} paths ({}) {}",
                "Input Dependencies".bright_white(),
                format!("{:>5}", self.format_number(dep.covered_input_paths)).color(dep_color),
                self.format_number(dep.total_input_paths),
                format!("{:>5.1}%", dep.input_path_coverage_percent).color(dep_color),
                dep_bar
            )?;

            // Uncovered paths
            if dep.uncovered_path_count > 0 {
                let path_color = if dep.critical_uncovered_count > 0 {
                    Color::Red
                } else {
                    Color::Yellow
                };
                writeln!(
                    writer,
                    "│  └─ {}: {} ({} critical)",
                    "Uncovered Paths".bright_white(),
                    format!("{}", dep.uncovered_path_count).color(path_color),
                    format!("{}", dep.critical_uncovered_count).color(path_color)
                )?;
            }
        }

        // Oracle diversity (if available)
        if let Some(ref oracle) = self.oracle_diversity {
            let oracle_bar = self.make_progress_bar(oracle.coverage_percent, 20);
            let oracle_color = self.color_for_percentage(oracle.coverage_percent);
            writeln!(
                writer,
                "├─ {}: {} / {} types ({}) {}",
                "Oracle Diversity".bright_white(),
                format!("{:>5}", oracle.fired_count).color(oracle_color),
                oracle.registered_count,
                format!("{:>5.1}%", oracle.coverage_percent).color(oracle_color),
                oracle_bar
            )?;

            // Diversity score
            let score_color = self.color_for_percentage(oracle.diversity_score * 100.0);
            writeln!(
                writer,
                "│  ├─ {}: {}",
                "Diversity Score".bright_white(),
                format!("{:.2}", oracle.diversity_score).color(score_color)
            )?;

            // Unique patterns
            writeln!(
                writer,
                "│  └─ {}: {}",
                "Unique Patterns".bright_white(),
                oracle.unique_patterns.to_string().bright_green()
            )?;

            // Unfired oracles (if any)
            if !oracle.unfired_oracles.is_empty() && oracle.unfired_oracles.len() <= 5 {
                writeln!(
                    writer,
                    "│     └─ {}: {}",
                    "Unfired".yellow(),
                    oracle.unfired_oracles.join(", ").yellow()
                )?;
            }
        }

        // Additional metrics
        if self.additional.unique_findings > 0 {
            writeln!(
                writer,
                "├─ {}: {}",
                "Unique Findings".bright_white(),
                self.additional.unique_findings.to_string().bright_red()
            )?;
        }

        if self.additional.corpus_size > 0 {
            writeln!(
                writer,
                "├─ {}: {}",
                "Corpus Size".bright_white(),
                self.format_number(self.additional.corpus_size)
            )?;
        }

        if self.additional.throughput > 0.0 {
            writeln!(
                writer,
                "└─ {}: {} exec/s",
                "Throughput".bright_white(),
                format!("{:.1}", self.additional.throughput).bright_blue()
            )?;
        } else {
            writeln!(writer, "└─")?;
        }

        writeln!(writer)?;
        Ok(())
    }

    /// Print compact one-line summary
    pub fn print_compact(&self) {
        let constraint_pct = format!("{:.1}%", self.constraint_coverage.percentage);

        let dep_pct = self
            .dependency_coverage
            .as_ref()
            .map(|d| format!("{:.1}%", d.input_path_coverage_percent))
            .unwrap_or_else(|| "N/A".to_string());

        let oracle_pct = self
            .oracle_diversity
            .as_ref()
            .map(|o| format!("{:.1}%", o.coverage_percent))
            .unwrap_or_else(|| "N/A".to_string());

        println!(
            "{} cov:{} dep:{} oracle:{}",
            "Coverage:".bright_cyan(),
            constraint_pct.bright_green(),
            dep_pct.bright_yellow(),
            oracle_pct.bright_blue()
        );
    }

    /// Format number with thousand separators
    fn format_number(&self, n: usize) -> String {
        let s = n.to_string();
        let mut result = String::new();
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        result.chars().rev().collect()
    }

    /// Create ASCII progress bar
    fn make_progress_bar(&self, percentage: f64, width: usize) -> String {
        let filled = ((percentage / 100.0) * width as f64).round() as usize;
        let empty = width.saturating_sub(filled);

        let bar = format!("[{}{}]", "█".repeat(filled), "░".repeat(empty));

        let color = self.color_for_percentage(percentage);
        format!("{}", bar.color(color))
    }

    /// Get color based on percentage
    fn color_for_percentage(&self, percentage: f64) -> Color {
        if percentage >= 80.0 {
            Color::Green
        } else if percentage >= 50.0 {
            Color::Yellow
        } else if percentage >= 25.0 {
            Color::BrightYellow
        } else {
            Color::Red
        }
    }

    /// Generate markdown summary
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str("## Coverage Summary\n\n");

        // Constraint coverage
        md.push_str(&format!(
            "- **Constraints**: {} / {} ({:.1}%)\n",
            self.constraint_coverage.covered,
            self.constraint_coverage.total,
            self.constraint_coverage.percentage
        ));

        // Dependency coverage
        if let Some(ref dep) = self.dependency_coverage {
            md.push_str(&format!(
                "- **Input Dependencies**: {} / {} paths ({:.1}%)\n",
                dep.covered_input_paths, dep.total_input_paths, dep.input_path_coverage_percent
            ));

            if dep.uncovered_path_count > 0 {
                md.push_str(&format!(
                    "  - Uncovered Paths: {} ({} critical)\n",
                    dep.uncovered_path_count, dep.critical_uncovered_count
                ));
            }
        }

        // Oracle diversity
        if let Some(ref oracle) = self.oracle_diversity {
            md.push_str(&format!(
                "- **Oracle Diversity**: {} / {} types ({:.1}%)\n",
                oracle.fired_count, oracle.registered_count, oracle.coverage_percent
            ));
            md.push_str(&format!(
                "  - Diversity Score: {:.2}\n",
                oracle.diversity_score
            ));
            md.push_str(&format!(
                "  - Unique Patterns: {}\n",
                oracle.unique_patterns
            ));

            if !oracle.unfired_oracles.is_empty() {
                md.push_str(&format!(
                    "  - Unfired Oracles: {}\n",
                    oracle.unfired_oracles.join(", ")
                ));
            }
        }

        // Additional metrics
        if self.additional.unique_findings > 0 {
            md.push_str(&format!(
                "- **Unique Findings**: {}\n",
                self.additional.unique_findings
            ));
        }

        if self.additional.corpus_size > 0 {
            md.push_str(&format!(
                "- **Corpus Size**: {}\n",
                self.additional.corpus_size
            ));
        }

        md
    }

    /// Convert to JSON-serializable structure
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "constraint_coverage": {
                "covered": self.constraint_coverage.covered,
                "total": self.constraint_coverage.total,
                "percentage": self.constraint_coverage.percentage
            },
            "dependency_coverage": self.dependency_coverage.as_ref().map(|d| {
                serde_json::json!({
                    "covered_paths": d.covered_input_paths,
                    "total_paths": d.total_input_paths,
                    "percentage": d.input_path_coverage_percent,
                    "uncovered_count": d.uncovered_path_count,
                    "critical_uncovered": d.critical_uncovered_count
                })
            }),
            "oracle_diversity": self.oracle_diversity.as_ref().map(|o| {
                serde_json::json!({
                    "fired_count": o.fired_count,
                    "registered_count": o.registered_count,
                    "coverage_percent": o.coverage_percent,
                    "diversity_score": o.diversity_score,
                    "unique_patterns": o.unique_patterns,
                    "unfired_oracles": o.unfired_oracles
                })
            }),
            "additional": {
                "unique_findings": self.additional.unique_findings,
                "corpus_size": self.additional.corpus_size,
                "throughput": self.additional.throughput,
                "elapsed_seconds": self.additional.elapsed_seconds
            }
        })
    }
}

/// Builder for coverage summary
pub struct CoverageSummaryBuilder {
    summary: CoverageSummary,
}

impl CoverageSummaryBuilder {
    pub fn new() -> Self {
        Self {
            summary: CoverageSummary::default(),
        }
    }

    pub fn constraint_coverage(mut self, covered: usize, total: usize) -> Self {
        self.summary.constraint_coverage = ConstraintCoverage {
            covered,
            total,
            percentage: if total > 0 {
                (covered as f64 / total as f64) * 100.0
            } else {
                0.0
            },
        };
        self
    }

    pub fn dependency_coverage(mut self, stats: DependencyCoverageStats) -> Self {
        self.summary.dependency_coverage = Some(stats);
        self
    }

    pub fn oracle_diversity(mut self, stats: OracleDiversityStats) -> Self {
        self.summary.oracle_diversity = Some(stats);
        self
    }

    pub fn corpus_size(mut self, size: usize) -> Self {
        self.summary.additional.corpus_size = size;
        self
    }

    pub fn findings(mut self, count: usize) -> Self {
        self.summary.additional.unique_findings = count;
        self
    }

    pub fn throughput(mut self, execs_per_sec: f64) -> Self {
        self.summary.additional.throughput = execs_per_sec;
        self
    }

    pub fn elapsed(mut self, seconds: u64) -> Self {
        self.summary.additional.elapsed_seconds = seconds;
        self
    }

    pub fn build(self) -> CoverageSummary {
        self.summary
    }
}

impl Default for CoverageSummaryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_summary_creation() {
        let summary = CoverageSummaryBuilder::new()
            .constraint_coverage(500, 1000)
            .corpus_size(100)
            .findings(5)
            .throughput(1234.5)
            .build();

        assert_eq!(summary.constraint_coverage.covered, 500);
        assert_eq!(summary.constraint_coverage.total, 1000);
        assert!((summary.constraint_coverage.percentage - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_format_number() {
        let summary = CoverageSummary::default();
        assert_eq!(summary.format_number(1234567), "1,234,567");
        assert_eq!(summary.format_number(123), "123");
        assert_eq!(summary.format_number(0), "0");
    }

    #[test]
    fn test_progress_bar() {
        let summary = CoverageSummary::default();
        let bar = summary.make_progress_bar(50.0, 10);
        // Bar should contain filled and empty parts
        assert!(bar.contains('█') || bar.contains('░'));
    }

    #[test]
    fn test_to_markdown() {
        let summary = CoverageSummaryBuilder::new()
            .constraint_coverage(800, 1000)
            .findings(3)
            .build();

        let md = summary.to_markdown();
        assert!(md.contains("## Coverage Summary"));
        assert!(md.contains("800"));
        assert!(md.contains("1000"));
        assert!(md.contains("80.0%"));
    }

    #[test]
    fn test_to_json() {
        let summary = CoverageSummaryBuilder::new()
            .constraint_coverage(100, 200)
            .build();

        let json = summary.to_json();
        assert_eq!(json["constraint_coverage"]["covered"], 100);
        assert_eq!(json["constraint_coverage"]["total"], 200);
    }
}
