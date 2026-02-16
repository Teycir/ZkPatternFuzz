//! Mode 3: Depth Metrics - Computes D, P_deep, and depth distribution
//!
//! These metrics measure the effectiveness of multi-step chain fuzzing
//! as defined in docs/scan_metrics.md.

use super::types::ChainFinding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Depth metrics for Mode 3 chain fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepthMetrics {
    /// All chain findings
    pub findings: Vec<ChainFinding>,
}

impl DepthMetrics {
    /// Create new depth metrics from a list of findings
    pub fn new(findings: Vec<ChainFinding>) -> Self {
        Self { findings }
    }

    /// Create empty depth metrics
    pub fn empty() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: ChainFinding) {
        self.findings.push(finding);
    }

    /// Get the number of findings
    pub fn count(&self) -> usize {
        self.findings.len()
    }

    /// Compute D: mean L_min over confirmed findings
    ///
    /// D represents the average minimum chain length required to reproduce
    /// findings. Higher D indicates bugs that require more complex sequences.
    pub fn d_mean(&self) -> f64 {
        if self.findings.is_empty() {
            return 0.0;
        }

        let sum: usize = self.findings.iter().map(|f| f.l_min).sum();
        sum as f64 / self.findings.len() as f64
    }

    /// Compute P_deep: P(L_min >= 2)
    ///
    /// P_deep represents the probability that a finding requires at least
    /// two steps to reproduce. This indicates the proportion of "deep" bugs
    /// that wouldn't be found by single-step fuzzing.
    pub fn p_deep(&self) -> f64 {
        if self.findings.is_empty() {
            return 0.0;
        }

        let deep_count = self.findings.iter().filter(|f| f.l_min >= 2).count();
        deep_count as f64 / self.findings.len() as f64
    }

    /// Compute P_very_deep: P(L_min >= 3)
    ///
    /// Stricter measure of deep bugs requiring 3+ steps.
    pub fn p_very_deep(&self) -> f64 {
        if self.findings.is_empty() {
            return 0.0;
        }

        let deep_count = self.findings.iter().filter(|f| f.l_min >= 3).count();
        deep_count as f64 / self.findings.len() as f64
    }

    /// Compute the depth distribution: L_min → count
    ///
    /// Shows how many findings exist at each depth level.
    pub fn depth_distribution(&self) -> HashMap<usize, usize> {
        let mut distribution = HashMap::new();
        for finding in &self.findings {
            *distribution.entry(finding.l_min).or_insert(0) += 1;
        }
        distribution
    }

    /// Get the maximum L_min across all findings
    pub fn max_depth(&self) -> usize {
        self.findings
            .iter()
            .map(|f| f.l_min)
            .max()
            .unwrap_or_default()
    }

    /// Get the minimum L_min across all findings
    pub fn min_depth(&self) -> usize {
        self.findings
            .iter()
            .map(|f| f.l_min)
            .min()
            .unwrap_or_default()
    }

    /// Compute the standard deviation of L_min
    pub fn d_std(&self) -> f64 {
        if self.findings.len() < 2 {
            return 0.0;
        }

        let mean = self.d_mean();
        let variance: f64 = self
            .findings
            .iter()
            .map(|f| {
                let diff = f.l_min as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / (self.findings.len() - 1) as f64;

        variance.sqrt()
    }

    /// Get findings by severity
    pub fn findings_by_severity(&self) -> HashMap<String, Vec<&ChainFinding>> {
        let mut by_severity: HashMap<String, Vec<&ChainFinding>> = HashMap::new();
        for finding in &self.findings {
            by_severity
                .entry(finding.finding.severity.clone())
                .or_default()
                .push(finding);
        }
        by_severity
    }

    /// Get findings that are "deep" (L_min >= 2)
    pub fn deep_findings(&self) -> Vec<&ChainFinding> {
        self.findings.iter().filter(|f| f.is_deep()).collect()
    }

    /// Get findings by chain spec name
    pub fn findings_by_chain(&self) -> HashMap<String, Vec<&ChainFinding>> {
        let mut by_chain: HashMap<String, Vec<&ChainFinding>> = HashMap::new();
        for finding in &self.findings {
            by_chain
                .entry(finding.spec_name.clone())
                .or_default()
                .push(finding);
        }
        by_chain
    }

    /// Generate a summary report
    pub fn summary(&self) -> DepthMetricsSummary {
        DepthMetricsSummary {
            total_findings: self.count(),
            d_mean: self.d_mean(),
            d_std: self.d_std(),
            p_deep: self.p_deep(),
            p_very_deep: self.p_very_deep(),
            max_depth: self.max_depth(),
            min_depth: self.min_depth(),
            depth_distribution: self.depth_distribution(),
            deep_findings_count: self.deep_findings().len(),
        }
    }
}

/// Summary of depth metrics for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepthMetricsSummary {
    /// Total number of findings
    pub total_findings: usize,
    /// Mean L_min (D metric)
    pub d_mean: f64,
    /// Standard deviation of L_min
    pub d_std: f64,
    /// Probability of L_min >= 2
    pub p_deep: f64,
    /// Probability of L_min >= 3
    pub p_very_deep: f64,
    /// Maximum L_min
    pub max_depth: usize,
    /// Minimum L_min
    pub min_depth: usize,
    /// Distribution of L_min values
    pub depth_distribution: HashMap<usize, usize>,
    /// Number of deep findings
    pub deep_findings_count: usize,
}

impl DepthMetricsSummary {
    /// Format as a markdown report section
    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str("## Multi-Step Depth Metrics\n\n");
        output.push_str("| Metric | Value |\n");
        output.push_str("|--------|-------|\n");
        output.push_str(&format!("| Total Findings | {} |\n", self.total_findings));
        output.push_str(&format!("| D (mean L_min) | {:.2} |\n", self.d_mean));
        output.push_str(&format!("| D std | {:.2} |\n", self.d_std));
        output.push_str(&format!(
            "| P_deep (L_min ≥ 2) | {:.2}% |\n",
            self.p_deep * 100.0
        ));
        output.push_str(&format!(
            "| P_very_deep (L_min ≥ 3) | {:.2}% |\n",
            self.p_very_deep * 100.0
        ));
        output.push_str(&format!("| Max Depth | {} |\n", self.max_depth));
        output.push_str(&format!(
            "| Deep Findings | {} |\n",
            self.deep_findings_count
        ));

        output.push_str("\n### Depth Distribution\n\n");
        output.push_str("| L_min | Count |\n");
        output.push_str("|-------|-------|\n");

        let mut depths: Vec<_> = self.depth_distribution.keys().collect();
        depths.sort();
        for depth in depths {
            let count = match self.depth_distribution.get(depth) {
                Some(v) => *v,
                None => 0,
            };
            output.push_str(&format!("| {} | {} |\n", depth, count));
        }

        output
    }
}

impl Default for DepthMetrics {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_fuzzer::types::{ChainFindingCore, ChainTrace};

    fn create_test_finding(l_min: usize) -> ChainFinding {
        ChainFinding {
            finding: ChainFindingCore {
                attack_type: "Underconstrained".to_string(),
                severity: "high".to_string(),
                description: "Test finding".to_string(),
                witness_inputs: vec![],
                location: None,
            },
            chain_length: l_min + 1,
            l_min,
            trace: ChainTrace::new("test_chain"),
            spec_name: "test_chain".to_string(),
            violated_assertion: None,
        }
    }

    #[test]
    fn test_d_mean() {
        let findings = vec![
            create_test_finding(1),
            create_test_finding(2),
            create_test_finding(3),
            create_test_finding(4),
        ];
        let metrics = DepthMetrics::new(findings);

        assert!((metrics.d_mean() - 2.5).abs() < 0.001);
    }

    #[test]
    fn test_p_deep() {
        let findings = vec![
            create_test_finding(1), // Not deep
            create_test_finding(2), // Deep
            create_test_finding(3), // Deep
            create_test_finding(1), // Not deep
        ];
        let metrics = DepthMetrics::new(findings);

        assert!((metrics.p_deep() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_depth_distribution() {
        let findings = vec![
            create_test_finding(1),
            create_test_finding(1),
            create_test_finding(2),
            create_test_finding(3),
        ];
        let metrics = DepthMetrics::new(findings);

        let dist = metrics.depth_distribution();
        assert_eq!(dist.get(&1), Some(&2));
        assert_eq!(dist.get(&2), Some(&1));
        assert_eq!(dist.get(&3), Some(&1));
    }

    #[test]
    fn test_empty_metrics() {
        let metrics = DepthMetrics::empty();

        assert_eq!(metrics.d_mean(), 0.0);
        assert_eq!(metrics.p_deep(), 0.0);
        assert!(metrics.depth_distribution().is_empty());
    }

    #[test]
    fn test_summary_markdown() {
        let findings = vec![create_test_finding(2), create_test_finding(3)];
        let metrics = DepthMetrics::new(findings);
        let summary = metrics.summary();
        let markdown = summary.to_markdown();

        assert!(markdown.contains("Multi-Step Depth Metrics"));
        assert!(markdown.contains("D (mean L_min)"));
        assert!(markdown.contains("P_deep"));
    }
}
