//! Cross-Oracle Correlation Engine (Phase 6A)
//!
//! This module correlates findings from multiple oracles to:
//! 1. Increase confidence in findings (multiple oracles agree)
//! 2. Reduce false positives (single oracle with no corroboration)
//! 3. Identify patterns that individual oracles might miss
//!
//! # Confidence Scoring
//!
//! | Oracle Count | Corroboration         | Confidence |
//! |--------------|----------------------|------------|
//! | 1            | None                 | LOW        |
//! | 1            | Same witness, diff oracle | MEDIUM |
//! | 2+           | Independent oracles  | HIGH       |
//! | 2+           | With invariant violation | CRITICAL |

use std::collections::HashMap;
use zk_core::{Finding, Severity, FieldElement};
use sha2::{Sha256, Digest};

/// Confidence level for correlated findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfidenceLevel {
    /// Single oracle, no corroboration
    Low,
    /// Some corroboration but not definitive
    Medium,
    /// Multiple independent oracles agree
    High,
    /// Multiple oracles + invariant violation
    Critical,
}

impl ConfidenceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfidenceLevel::Low => "LOW",
            ConfidenceLevel::Medium => "MEDIUM",
            ConfidenceLevel::High => "HIGH",
            ConfidenceLevel::Critical => "CRITICAL",
        }
    }
}

/// A correlated finding with confidence score
#[derive(Debug, Clone)]
pub struct CorrelatedFinding {
    /// Primary finding
    pub primary: Finding,
    /// Additional findings that corroborate
    pub corroborating: Vec<Finding>,
    /// Number of independent oracles that agree
    pub oracle_count: usize,
    /// Names of oracles that fired
    pub oracle_names: Vec<String>,
    /// Computed confidence level
    pub confidence: ConfidenceLevel,
    /// Combined severity (max of all findings)
    pub combined_severity: Severity,
    /// Witness hash for grouping
    pub witness_hash: String,
    /// Whether this includes an invariant violation
    pub has_invariant_violation: bool,
}

impl CorrelatedFinding {
    /// Get the total number of findings in this correlation group
    pub fn total_findings(&self) -> usize {
        1 + self.corroborating.len()
    }

    /// Get all findings in this group
    pub fn all_findings(&self) -> Vec<&Finding> {
        let mut all = vec![&self.primary];
        all.extend(self.corroborating.iter());
        all
    }
}

/// Oracle correlation engine
pub struct OracleCorrelator {
    /// Minimum oracle count for HIGH confidence
    high_confidence_threshold: usize,
    /// Whether invariant violations boost confidence
    invariant_boost: bool,
}

impl Default for OracleCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl OracleCorrelator {
    pub fn new() -> Self {
        Self {
            high_confidence_threshold: 2,
            invariant_boost: true,
        }
    }

    /// Set the threshold for HIGH confidence
    pub fn with_high_threshold(mut self, threshold: usize) -> Self {
        self.high_confidence_threshold = threshold.max(2);
        self
    }

    /// Disable invariant confidence boost
    pub fn without_invariant_boost(mut self) -> Self {
        self.invariant_boost = false;
        self
    }

    /// Correlate findings from multiple oracles
    ///
    /// Groups findings by witness similarity and scores confidence based on
    /// how many independent oracles confirm each finding.
    pub fn correlate(&self, findings: &[Finding]) -> Vec<CorrelatedFinding> {
        if findings.is_empty() {
            return Vec::new();
        }

        // Group findings by witness hash
        let mut groups: HashMap<String, Vec<&Finding>> = HashMap::new();

        for finding in findings {
            let hash = self.compute_witness_hash(&finding.poc.witness_a);
            groups.entry(hash).or_default().push(finding);
        }

        // Convert groups to correlated findings
        let mut correlated = Vec::new();

        for (witness_hash, group_findings) in groups {
            if group_findings.is_empty() {
                continue;
            }

            // Collect unique oracle names (based on attack type)
            let mut oracle_names: Vec<String> = group_findings
                .iter()
                .map(|f| format!("{:?}", f.attack_type))
                .collect();
            oracle_names.sort();
            oracle_names.dedup();

            let oracle_count = oracle_names.len();

            // Check for invariant violations
            let has_invariant_violation = group_findings.iter().any(|f| {
                f.description.to_lowercase().contains("invariant")
            });

            // Compute confidence
            let confidence = self.compute_confidence(oracle_count, has_invariant_violation);

            // Compute combined severity (max)
            let combined_severity = group_findings
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Low);

            // Primary is highest severity, rest are corroborating
            let mut sorted_findings: Vec<_> = group_findings.into_iter().collect();
            sorted_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

            let primary = sorted_findings.remove(0).clone();
            let corroborating: Vec<_> = sorted_findings.into_iter().cloned().collect();

            correlated.push(CorrelatedFinding {
                primary,
                corroborating,
                oracle_count,
                oracle_names,
                confidence,
                combined_severity,
                witness_hash,
                has_invariant_violation,
            });
        }

        // Sort by confidence (highest first), then by severity
        correlated.sort_by(|a, b| {
            match b.confidence.cmp(&a.confidence) {
                std::cmp::Ordering::Equal => b.combined_severity.cmp(&a.combined_severity),
                other => other,
            }
        });

        correlated
    }

    /// Compute witness hash for grouping
    fn compute_witness_hash(&self, witness: &[FieldElement]) -> String {
        let mut hasher = Sha256::new();
        for fe in witness {
            hasher.update(&fe.0);
        }
        hex::encode(&hasher.finalize()[..16])
    }

    /// Compute confidence level based on oracle count and invariant status
    fn compute_confidence(&self, oracle_count: usize, has_invariant: bool) -> ConfidenceLevel {
        if oracle_count >= self.high_confidence_threshold {
            if has_invariant && self.invariant_boost {
                ConfidenceLevel::Critical
            } else {
                ConfidenceLevel::High
            }
        } else if oracle_count > 1 || (oracle_count == 1 && has_invariant) {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        }
    }

    /// Filter findings to only those with minimum confidence level
    pub fn filter_by_confidence(
        &self,
        findings: &[Finding],
        min_confidence: ConfidenceLevel,
    ) -> Vec<Finding> {
        let correlated = self.correlate(findings);

        correlated
            .into_iter()
            .filter(|cf| cf.confidence >= min_confidence)
            .flat_map(|cf| {
                let mut all = vec![cf.primary];
                all.extend(cf.corroborating);
                all
            })
            .collect()
    }

    /// Generate a correlation report
    pub fn generate_report(&self, findings: &[Finding]) -> CorrelationReport {
        let correlated = self.correlate(findings);

        let total_raw = findings.len();
        let total_groups = correlated.len();

        let by_confidence: HashMap<_, _> = [
            ConfidenceLevel::Critical,
            ConfidenceLevel::High,
            ConfidenceLevel::Medium,
            ConfidenceLevel::Low,
        ]
        .into_iter()
        .map(|level| {
            let count = correlated.iter().filter(|cf| cf.confidence == level).count();
            (level, count)
        })
        .collect();

        let high_confidence_findings: Vec<_> = correlated
            .iter()
            .filter(|cf| cf.confidence >= ConfidenceLevel::High)
            .map(|cf| cf.primary.clone())
            .collect();

        CorrelationReport {
            total_raw_findings: total_raw,
            total_correlated_groups: total_groups,
            findings_by_confidence: by_confidence,
            high_confidence_findings,
            correlated_groups: correlated,
        }
    }
}

/// Correlation analysis report
#[derive(Debug, Clone)]
pub struct CorrelationReport {
    pub total_raw_findings: usize,
    pub total_correlated_groups: usize,
    pub findings_by_confidence: HashMap<ConfidenceLevel, usize>,
    pub high_confidence_findings: Vec<Finding>,
    pub correlated_groups: Vec<CorrelatedFinding>,
}

impl CorrelationReport {
    /// Format the report as markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str("# Oracle Correlation Report\n\n");
        md.push_str(&format!(
            "**Raw Findings**: {} → **Correlated Groups**: {}\n\n",
            self.total_raw_findings, self.total_correlated_groups
        ));

        md.push_str("## Confidence Distribution\n\n");
        md.push_str("| Confidence | Count |\n");
        md.push_str("|------------|-------|\n");
        for level in [
            ConfidenceLevel::Critical,
            ConfidenceLevel::High,
            ConfidenceLevel::Medium,
            ConfidenceLevel::Low,
        ] {
            let count = self.findings_by_confidence.get(&level).unwrap_or(&0);
            md.push_str(&format!("| {} | {} |\n", level.as_str(), count));
        }
        md.push_str("\n");

        if !self.high_confidence_findings.is_empty() {
            md.push_str("## High Confidence Findings\n\n");
            for (i, group) in self.correlated_groups.iter()
                .filter(|g| g.confidence >= ConfidenceLevel::High)
                .enumerate()
            {
                md.push_str(&format!(
                    "### {}. {:?} ({})\n\n",
                    i + 1,
                    group.primary.attack_type,
                    group.confidence.as_str()
                ));
                md.push_str(&format!("**Oracles**: {}\n\n", group.oracle_names.join(", ")));
                md.push_str(&format!("**Description**: {}\n\n", group.primary.description));
                if group.has_invariant_violation {
                    md.push_str("⚠️ **Includes invariant violation**\n\n");
                }
            }
        }

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_core::{AttackType, ProofOfConcept};

    fn make_finding(attack_type: AttackType, severity: Severity, witness: Vec<FieldElement>) -> Finding {
        Finding {
            attack_type,
            severity,
            description: "Test finding".to_string(),
            poc: ProofOfConcept {
                witness_a: witness,
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: None,
        }
    }

    #[test]
    fn test_single_oracle_low_confidence() {
        let correlator = OracleCorrelator::new();
        
        let findings = vec![
            make_finding(AttackType::Soundness, Severity::High, vec![FieldElement::one()]),
        ];

        let correlated = correlator.correlate(&findings);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].confidence, ConfidenceLevel::Low);
    }

    #[test]
    fn test_multiple_oracles_high_confidence() {
        let correlator = OracleCorrelator::new();
        
        let witness = vec![FieldElement::one()];
        let findings = vec![
            make_finding(AttackType::Soundness, Severity::High, witness.clone()),
            make_finding(AttackType::Underconstrained, Severity::Critical, witness.clone()),
        ];

        let correlated = correlator.correlate(&findings);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].confidence, ConfidenceLevel::High);
        assert_eq!(correlated[0].oracle_count, 2);
    }
}
