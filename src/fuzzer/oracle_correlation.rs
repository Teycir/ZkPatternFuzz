//! Cross-Oracle Correlation Engine (Phase 6A)
//!
//! This module correlates findings from multiple oracles to:
//! 1. Increase confidence in findings (multiple oracles agree)
//! 2. Reduce false positives (single oracle with no corroboration)
//! 3. Identify patterns that individual oracles might miss
//!
//! # Confidence Scoring (Phase 0 Fix: Oracle Independence Weighting)
//!
//! Oracles are grouped by independence to prevent correlated oracles from
//! inflating confidence scores. Only cross-group agreement counts for HIGH confidence.
//!
//! | Oracle Groups | Corroboration              | Confidence |
//! |---------------|---------------------------|------------|
//! | 1             | None                      | LOW        |
//! | 1             | With invariant violation  | MEDIUM     |
//! | 2+            | Cross-group agreement     | HIGH       |
//! | 3             | All groups + invariant    | CRITICAL   |
//!
//! # Oracle Groups
//!
//! - **Structural**: Analyze constraint structure (Underconstrained, ConstraintInference, WitnessCollision)
//! - **Semantic**: Analyze circuit semantics (Soundness, Metamorphic, SpecInference)  
//! - **Behavioral**: Analyze runtime behavior (ArithmeticOverflow, Boundary, Malleability)

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use zk_core::{AttackType, FieldElement, Finding, Severity};

/// Oracle independence groups to prevent correlated oracles from inflating confidence.
///
/// Oracles within the same group often detect related issues and their agreement
/// should not count as independent confirmation. Only cross-group agreement
/// provides strong evidence of a real vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OracleGroup {
    /// Structural analysis oracles - analyze constraint structure
    /// Examples: Underconstrained, ConstraintInference, WitnessCollision, ConstraintSlice
    Structural,
    /// Semantic analysis oracles - analyze circuit semantics and logic
    /// Examples: Soundness, Metamorphic, SpecInference, Differential
    Semantic,
    /// Behavioral analysis oracles - analyze runtime behavior
    /// Examples: ArithmeticOverflow, Boundary, Malleability, ReplayAttack
    Behavioral,
}

impl OracleGroup {
    /// Classify an attack type into its oracle group
    pub fn from_attack_type(attack_type: AttackType) -> Self {
        match attack_type {
            // Structural group - constraint structure analysis
            AttackType::Underconstrained
            | AttackType::ConstraintInference
            | AttackType::ConstraintBypass
            | AttackType::ConstraintSlice
            | AttackType::WitnessCollision
            | AttackType::Collision => OracleGroup::Structural,

            // Semantic group - circuit semantics and logic
            AttackType::Soundness
            | AttackType::Metamorphic
            | AttackType::SpecInference
            | AttackType::Differential
            | AttackType::VerificationFuzzing
            | AttackType::RecursiveProof
            | AttackType::CircuitComposition
            | AttackType::TrustedSetup => OracleGroup::Semantic,

            // Behavioral group - runtime behavior analysis
            AttackType::ArithmeticOverflow
            | AttackType::Boundary
            | AttackType::BitDecomposition
            | AttackType::Malleability
            | AttackType::ReplayAttack
            | AttackType::WitnessLeakage
            | AttackType::InformationLeakage
            | AttackType::TimingSideChannel => OracleGroup::Behavioral,

            // Default to Behavioral for unknown attack types
            _ => OracleGroup::Behavioral,
        }
    }

    /// Get all oracle groups
    pub fn all() -> [OracleGroup; 3] {
        [
            OracleGroup::Structural,
            OracleGroup::Semantic,
            OracleGroup::Behavioral,
        ]
    }
}

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
    /// Number of independent oracles that agree (deprecated, use independent_group_count)
    pub oracle_count: usize,
    /// Number of independent oracle GROUPS that agree (Phase 0 fix)
    pub independent_group_count: usize,
    /// Names of oracles that fired
    pub oracle_names: Vec<String>,
    /// Oracle groups represented in this correlation
    pub oracle_groups: Vec<OracleGroup>,
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
    /// Minimum independent oracle GROUP count for HIGH confidence (Phase 0 fix)
    /// Now counts distinct groups, not just oracles, to prevent correlated oracle inflation
    high_confidence_threshold: usize,
    /// Whether invariant violations boost confidence
    invariant_boost: bool,
    /// Whether to use oracle independence weighting (Phase 0 fix)
    use_independence_weighting: bool,
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
            use_independence_weighting: true, // Phase 0: Enable by default
        }
    }

    /// Set the threshold for HIGH confidence (minimum independent groups)
    pub fn with_high_threshold(mut self, threshold: usize) -> Self {
        self.high_confidence_threshold = threshold.max(2);
        self
    }

    /// Disable invariant confidence boost
    pub fn without_invariant_boost(mut self) -> Self {
        self.invariant_boost = false;
        self
    }

    /// Disable oracle independence weighting (for backward compatibility)
    pub fn without_independence_weighting(mut self) -> Self {
        self.use_independence_weighting = false;
        self
    }

    /// Count distinct oracle groups from findings
    fn count_independent_groups(&self, findings: &[&Finding]) -> (usize, Vec<OracleGroup>) {
        let groups: HashSet<OracleGroup> = findings
            .iter()
            .map(|f| OracleGroup::from_attack_type(f.attack_type.clone()))
            .collect();
        let group_vec: Vec<OracleGroup> = groups.into_iter().collect();
        (group_vec.len(), group_vec)
    }

    /// Correlate findings from multiple oracles
    ///
    /// Groups findings by witness similarity and scores confidence based on
    /// how many INDEPENDENT oracle GROUPS confirm each finding.
    ///
    /// # Phase 0 Fix: Oracle Independence Weighting
    ///
    /// Previously, any 2+ oracles would give HIGH confidence. This caused
    /// correlated oracles (e.g., UnderconstrainedOracle + NullifierOracle,
    /// both in the Structural group) to inflate confidence scores.
    ///
    /// Now, confidence is based on cross-GROUP agreement:
    /// - 1 group: LOW (or MEDIUM with invariant)
    /// - 2 groups: HIGH  
    /// - 3 groups: CRITICAL (with invariant boost)
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

            // Phase 0 Fix: Count independent oracle GROUPS, not just oracles
            let (independent_group_count, oracle_groups) =
                self.count_independent_groups(&group_findings);

            // Check for invariant violations
            let has_invariant_violation = group_findings
                .iter()
                .any(|f| f.description.to_lowercase().contains("invariant"));

            // Compute confidence using independence weighting
            let confidence = if self.use_independence_weighting {
                self.compute_confidence_with_groups(
                    independent_group_count,
                    has_invariant_violation,
                )
            } else {
                // Legacy behavior for backward compatibility
                self.compute_confidence(oracle_count, has_invariant_violation)
            };

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
                independent_group_count,
                oracle_names,
                oracle_groups,
                confidence,
                combined_severity,
                witness_hash,
                has_invariant_violation,
            });
        }

        // Sort by confidence (highest first), then by severity
        correlated.sort_by(|a, b| match b.confidence.cmp(&a.confidence) {
            std::cmp::Ordering::Equal => b.combined_severity.cmp(&a.combined_severity),
            other => other,
        });

        correlated
    }

    /// Compute witness hash for grouping
    fn compute_witness_hash(&self, witness: &[FieldElement]) -> String {
        let mut hasher = Sha256::new();
        for fe in witness {
            hasher.update(fe.0);
        }
        hex::encode(&hasher.finalize()[..16])
    }

    /// Compute confidence level based on oracle count and invariant status (legacy)
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

    /// Compute confidence level based on independent oracle GROUPS (Phase 0 fix)
    ///
    /// This prevents correlated oracles from inflating confidence scores.
    /// Only cross-group agreement provides strong evidence.
    ///
    /// # Confidence Levels
    ///
    /// - 3 groups + invariant: CRITICAL (all groups agree + invariant violation)
    /// - 2+ groups: HIGH (cross-group agreement)
    /// - 1 group + invariant: MEDIUM (single group but with invariant)
    /// - 1 group alone: LOW (needs corroboration from different group)
    fn compute_confidence_with_groups(
        &self,
        group_count: usize,
        has_invariant: bool,
    ) -> ConfidenceLevel {
        match group_count {
            // All 3 groups agree - very strong evidence
            3 => {
                if has_invariant && self.invariant_boost {
                    ConfidenceLevel::Critical
                } else {
                    ConfidenceLevel::High
                }
            }
            // 2 groups agree - cross-group corroboration
            2 => ConfidenceLevel::High,
            // Single group - needs more evidence
            1 => {
                if has_invariant && self.invariant_boost {
                    ConfidenceLevel::Medium
                } else {
                    ConfidenceLevel::Low
                }
            }
            // No oracles (shouldn't happen)
            _ => ConfidenceLevel::Low,
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
            let count = correlated
                .iter()
                .filter(|cf| cf.confidence == level)
                .count();
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
        md.push('\n');

        if !self.high_confidence_findings.is_empty() {
            md.push_str("## High Confidence Findings\n\n");
            for (i, group) in self
                .correlated_groups
                .iter()
                .filter(|g| g.confidence >= ConfidenceLevel::High)
                .enumerate()
            {
                md.push_str(&format!(
                    "### {}. {:?} ({})\n\n",
                    i + 1,
                    group.primary.attack_type,
                    group.confidence.as_str()
                ));
                md.push_str(&format!(
                    "**Oracles**: {}\n\n",
                    group.oracle_names.join(", ")
                ));
                md.push_str(&format!(
                    "**Description**: {}\n\n",
                    group.primary.description
                ));
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

    fn make_finding(
        attack_type: AttackType,
        severity: Severity,
        witness: Vec<FieldElement>,
    ) -> Finding {
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

    fn make_invariant_finding(
        attack_type: AttackType,
        severity: Severity,
        witness: Vec<FieldElement>,
    ) -> Finding {
        Finding {
            attack_type,
            severity,
            description: "Invariant violation detected".to_string(),
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

        let findings = vec![make_finding(
            AttackType::Soundness,
            Severity::High,
            vec![FieldElement::one()],
        )];

        let correlated = correlator.correlate(&findings);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].confidence, ConfidenceLevel::Low);
    }

    #[test]
    fn test_multiple_oracles_same_group_low_confidence() {
        // Phase 0 Fix: Correlated oracles in same group should NOT inflate confidence
        let correlator = OracleCorrelator::new();

        let witness = vec![FieldElement::one()];
        // Both are in the Structural group
        let findings = vec![
            make_finding(
                AttackType::Underconstrained,
                Severity::Critical,
                witness.clone(),
            ),
            make_finding(
                AttackType::WitnessCollision,
                Severity::High,
                witness.clone(),
            ),
        ];

        let correlated = correlator.correlate(&findings);
        assert_eq!(correlated.len(), 1);
        // With independence weighting, same-group oracles = LOW confidence
        assert_eq!(correlated[0].confidence, ConfidenceLevel::Low);
        assert_eq!(correlated[0].oracle_count, 2); // 2 oracles...
        assert_eq!(correlated[0].independent_group_count, 1); // ...but only 1 group
    }

    #[test]
    fn test_cross_group_oracles_high_confidence() {
        // Phase 0 Fix: Cross-group agreement = HIGH confidence
        let correlator = OracleCorrelator::new();

        let witness = vec![FieldElement::one()];
        let findings = vec![
            // Semantic group
            make_finding(AttackType::Soundness, Severity::High, witness.clone()),
            // Structural group
            make_finding(
                AttackType::Underconstrained,
                Severity::Critical,
                witness.clone(),
            ),
        ];

        let correlated = correlator.correlate(&findings);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].confidence, ConfidenceLevel::High);
        assert_eq!(correlated[0].independent_group_count, 2);
    }

    #[test]
    fn test_all_groups_with_invariant_critical() {
        // All 3 groups + invariant = CRITICAL
        let correlator = OracleCorrelator::new();

        let witness = vec![FieldElement::one()];
        let findings = vec![
            // Semantic group
            make_finding(AttackType::Soundness, Severity::High, witness.clone()),
            // Structural group
            make_finding(
                AttackType::Underconstrained,
                Severity::Critical,
                witness.clone(),
            ),
            // Behavioral group + invariant
            make_invariant_finding(
                AttackType::ArithmeticOverflow,
                Severity::High,
                witness.clone(),
            ),
        ];

        let correlated = correlator.correlate(&findings);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].confidence, ConfidenceLevel::Critical);
        assert_eq!(correlated[0].independent_group_count, 3);
    }

    #[test]
    fn test_single_group_with_invariant_medium() {
        // Single group + invariant = MEDIUM
        let correlator = OracleCorrelator::new();

        let witness = vec![FieldElement::one()];
        let findings = vec![make_invariant_finding(
            AttackType::Underconstrained,
            Severity::Critical,
            witness.clone(),
        )];

        let correlated = correlator.correlate(&findings);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].confidence, ConfidenceLevel::Medium);
    }

    #[test]
    fn test_oracle_group_classification() {
        // Test that attack types are correctly classified
        assert_eq!(
            OracleGroup::from_attack_type(AttackType::Underconstrained),
            OracleGroup::Structural
        );
        assert_eq!(
            OracleGroup::from_attack_type(AttackType::WitnessCollision),
            OracleGroup::Structural
        );
        assert_eq!(
            OracleGroup::from_attack_type(AttackType::Soundness),
            OracleGroup::Semantic
        );
        assert_eq!(
            OracleGroup::from_attack_type(AttackType::Metamorphic),
            OracleGroup::Semantic
        );
        assert_eq!(
            OracleGroup::from_attack_type(AttackType::ArithmeticOverflow),
            OracleGroup::Behavioral
        );
        assert_eq!(
            OracleGroup::from_attack_type(AttackType::Boundary),
            OracleGroup::Behavioral
        );
    }

    #[test]
    fn test_legacy_behavior_without_independence() {
        // Verify backward compatibility when independence weighting is disabled
        let correlator = OracleCorrelator::new().without_independence_weighting();

        let witness = vec![FieldElement::one()];
        // Both in same Structural group
        let findings = vec![
            make_finding(
                AttackType::Underconstrained,
                Severity::Critical,
                witness.clone(),
            ),
            make_finding(
                AttackType::WitnessCollision,
                Severity::High,
                witness.clone(),
            ),
        ];

        let correlated = correlator.correlate(&findings);
        assert_eq!(correlated.len(), 1);
        // Legacy: 2 oracles = HIGH (ignores group independence)
        assert_eq!(correlated[0].confidence, ConfidenceLevel::High);
    }
}
