//! Automated Triage System (Phase 2: Milestone 2.4)
//!
//! Provides confidence-based ranking and prioritization of findings.
//!
//! # Confidence Scoring
//!
//! Findings are ranked by confidence (0.0-1.0) based on:
//! - Cross-oracle validation: Multiple oracles agree = higher confidence
//! - Picus verification: Formal verification bonus
//! - Reproduction success: Can reproduce the issue = higher confidence
//! - Code coverage correlation: High-coverage findings more reliable
//! - Severity weight: Critical findings get priority
//!
//! # Confidence Levels
//!
//! - **High (>0.8):** <5% false positive rate, auto-report
//! - **Medium (0.5-0.8):** Flagged for review
//! - **Low (<0.5):** Auto-filtered in evidence mode
//!
//! # Usage
//!
//! ```rust,ignore
//! use zk_fuzzer::reporting::triage::{TriagePipeline, TriageConfig};
//!
//! let config = TriageConfig::default();
//! let mut pipeline = TriagePipeline::new(config);
//!
//! // Add findings from fuzzing
//! for finding in findings {
//!     pipeline.add_finding(finding);
//! }
//!
//! // Get triaged results
//! let report = pipeline.generate_report();
//! println!("High confidence findings: {}", report.high_confidence.len());
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zk_core::{Finding, ProofOfConcept, Severity};

/// Configuration for the triage system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageConfig {
    /// Threshold for high confidence findings (auto-report)
    pub high_confidence_threshold: f64,
    /// Threshold for medium confidence findings (review)
    pub medium_confidence_threshold: f64,
    /// Weight for cross-oracle validation bonus
    pub cross_oracle_weight: f64,
    /// Weight for Picus verification bonus
    pub picus_verification_weight: f64,
    /// Weight for reproduction success bonus
    pub reproduction_weight: f64,
    /// Weight for code coverage correlation
    pub coverage_weight: f64,
    /// Enable automatic filtering of low-confidence findings
    pub auto_filter_low_confidence: bool,
    /// Enable deduplication
    pub enable_deduplication: bool,
    /// Minimum confidence for evidence mode
    pub evidence_mode_min_confidence: f64,
}

impl Default for TriageConfig {
    fn default() -> Self {
        Self {
            high_confidence_threshold: 0.8,
            medium_confidence_threshold: 0.5,
            cross_oracle_weight: 0.15,
            picus_verification_weight: 0.25,
            reproduction_weight: 0.20,
            coverage_weight: 0.10,
            auto_filter_low_confidence: true,
            enable_deduplication: true,
            evidence_mode_min_confidence: 0.5,
        }
    }
}

/// Confidence level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// High confidence (>0.8): <5% false positive rate
    High,
    /// Medium confidence (0.5-0.8): Needs review
    Medium,
    /// Low confidence (<0.5): Auto-filtered in evidence mode
    Low,
}

impl ConfidenceLevel {
    pub fn from_score(score: f64, config: &TriageConfig) -> Self {
        if score >= config.high_confidence_threshold {
            ConfidenceLevel::High
        } else if score >= config.medium_confidence_threshold {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ConfidenceLevel::High => "HIGH",
            ConfidenceLevel::Medium => "MEDIUM",
            ConfidenceLevel::Low => "LOW",
        }
    }
}

/// Verification status for a finding
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum VerificationStatus {
    /// Not verified
    #[default]
    NotVerified,
    /// Verified by Picus formal verification
    PicusVerified,
    /// Verified by reproduction
    Reproduced,
    /// Verified by multiple methods
    MultipleVerifications(Vec<String>),
    /// Verification failed
    VerificationFailed(String),
}

impl VerificationStatus {
    pub fn is_verified(&self) -> bool {
        !matches!(self, VerificationStatus::NotVerified | VerificationStatus::VerificationFailed(_))
    }
}

/// A finding with triage metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriagedFinding {
    /// The original finding
    pub finding: Finding,
    /// Computed confidence score (0.0-1.0)
    pub confidence_score: f64,
    /// Confidence level classification
    pub confidence_level: ConfidenceLevel,
    /// Oracles that detected this finding
    pub detected_by_oracles: Vec<String>,
    /// Verification status
    pub verification_status: VerificationStatus,
    /// Reproduction attempts
    pub reproduction_attempts: u32,
    /// Successful reproductions
    pub reproduction_successes: u32,
    /// Coverage percentage when this finding was discovered
    pub discovery_coverage: f64,
    /// Priority rank (1 = highest priority)
    pub priority_rank: u32,
    /// Deduplication cluster ID (if deduplicated)
    pub cluster_id: Option<String>,
    /// Reason for confidence score breakdown
    pub score_breakdown: ConfidenceBreakdown,
}

impl TriagedFinding {
    /// Create a new triaged finding from a base finding
    pub fn new(finding: Finding, config: &TriageConfig) -> Self {
        let score_breakdown = ConfidenceBreakdown::default();
        let confidence_score = score_breakdown.total();
        let confidence_level = ConfidenceLevel::from_score(confidence_score, config);

        Self {
            finding,
            confidence_score,
            confidence_level,
            detected_by_oracles: Vec::new(),
            verification_status: VerificationStatus::NotVerified,
            reproduction_attempts: 0,
            reproduction_successes: 0,
            discovery_coverage: 0.0,
            priority_rank: 0,
            cluster_id: None,
            score_breakdown,
        }
    }

    /// Recalculate confidence score based on all factors
    pub fn recalculate_confidence(&mut self, config: &TriageConfig) {
        self.score_breakdown = ConfidenceBreakdown::calculate(self, config);
        self.confidence_score = self.score_breakdown.total();
        self.confidence_level = ConfidenceLevel::from_score(self.confidence_score, config);
    }

    /// Add an oracle that detected this finding
    pub fn add_detecting_oracle(&mut self, oracle_name: String) {
        if !self.detected_by_oracles.contains(&oracle_name) {
            self.detected_by_oracles.push(oracle_name);
        }
    }

    /// Mark as verified by Picus
    pub fn mark_picus_verified(&mut self) {
        self.verification_status = VerificationStatus::PicusVerified;
    }

    /// Record a reproduction attempt
    pub fn record_reproduction(&mut self, success: bool) {
        self.reproduction_attempts += 1;
        if success {
            self.reproduction_successes += 1;
            self.verification_status = VerificationStatus::Reproduced;
        }
    }

    /// Get reproduction success rate
    pub fn reproduction_rate(&self) -> f64 {
        if self.reproduction_attempts == 0 {
            return 0.0;
        }
        self.reproduction_successes as f64 / self.reproduction_attempts as f64
    }
}

/// Breakdown of confidence score components
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfidenceBreakdown {
    /// Base score from severity and attack type
    pub base_score: f64,
    /// Bonus for cross-oracle validation
    pub cross_oracle_bonus: f64,
    /// Bonus for Picus verification
    pub picus_bonus: f64,
    /// Bonus for successful reproduction
    pub reproduction_bonus: f64,
    /// Bonus for code coverage correlation
    pub coverage_bonus: f64,
    /// Bonus for PoC quality
    pub poc_quality_bonus: f64,
    /// Penalty for low-quality evidence
    pub quality_penalty: f64,
}

impl ConfidenceBreakdown {
    /// Calculate breakdown for a triaged finding
    pub fn calculate(finding: &TriagedFinding, config: &TriageConfig) -> Self {
        let mut breakdown = Self::default();

        // Base score from severity (0.3-0.5)
        breakdown.base_score = match finding.finding.severity {
            Severity::Critical => 0.50,
            Severity::High => 0.45,
            Severity::Medium => 0.40,
            Severity::Low => 0.35,
            Severity::Info => 0.30,
        };

        // Cross-oracle validation bonus (up to config.cross_oracle_weight)
        let oracle_count = finding.detected_by_oracles.len();
        if oracle_count > 1 {
            // More oracles = higher confidence
            let oracle_factor = (oracle_count as f64 - 1.0).min(3.0) / 3.0;
            breakdown.cross_oracle_bonus = config.cross_oracle_weight * oracle_factor;
        }

        // Picus verification bonus
        if matches!(finding.verification_status, VerificationStatus::PicusVerified) {
            breakdown.picus_bonus = config.picus_verification_weight;
        }

        // Reproduction bonus
        let repro_rate = finding.reproduction_rate();
        if repro_rate > 0.0 {
            breakdown.reproduction_bonus = config.reproduction_weight * repro_rate;
        }

        // Coverage correlation bonus
        if finding.discovery_coverage > 50.0 {
            let coverage_factor = (finding.discovery_coverage - 50.0) / 50.0;
            breakdown.coverage_bonus = config.coverage_weight * coverage_factor.min(1.0);
        }

        // PoC quality bonus
        breakdown.poc_quality_bonus = Self::calculate_poc_quality(&finding.finding.poc);

        // Quality penalties
        if finding.finding.description.len() < 20 {
            breakdown.quality_penalty += 0.05; // Vague description
        }
        if finding.finding.location.is_none() {
            breakdown.quality_penalty += 0.05; // No location info
        }

        breakdown
    }

    /// Calculate PoC quality score (0.0-0.10)
    fn calculate_poc_quality(poc: &ProofOfConcept) -> f64 {
        let mut score = 0.0;

        // Has witness_a
        if !poc.witness_a.is_empty() {
            score += 0.03;
        }

        // Has witness_b (differential witness)
        if poc.witness_b.is_some() {
            score += 0.04;
        }

        // Has public inputs
        if !poc.public_inputs.is_empty() {
            score += 0.02;
        }

        // Has proof
        if poc.proof.is_some() {
            score += 0.01;
        }

        score
    }

    /// Calculate total confidence score
    pub fn total(&self) -> f64 {
        let raw_score = self.base_score
            + self.cross_oracle_bonus
            + self.picus_bonus
            + self.reproduction_bonus
            + self.coverage_bonus
            + self.poc_quality_bonus
            - self.quality_penalty;

        // Clamp to [0.0, 1.0]
        raw_score.clamp(0.0, 1.0)
    }
}

/// Triage pipeline for processing findings
#[derive(Debug)]
pub struct TriagePipeline {
    config: TriageConfig,
    findings: Vec<TriagedFinding>,
    dedup_hashes: HashSet<String>,
    oracle_counts: HashMap<String, usize>,
}

impl TriagePipeline {
    /// Create a new triage pipeline
    pub fn new(config: TriageConfig) -> Self {
        Self {
            config,
            findings: Vec::new(),
            dedup_hashes: HashSet::new(),
            oracle_counts: HashMap::new(),
        }
    }

    /// Create with default configuration
    pub fn default_pipeline() -> Self {
        Self::new(TriageConfig::default())
    }

    /// Add a finding to the pipeline
    pub fn add_finding(&mut self, finding: Finding) -> Option<usize> {
        // Deduplication check
        if self.config.enable_deduplication {
            let hash = self.compute_finding_hash(&finding);
            if self.dedup_hashes.contains(&hash) {
                return None; // Duplicate
            }
            self.dedup_hashes.insert(hash.clone());
        }

        let mut triaged = TriagedFinding::new(finding, &self.config);
        triaged.recalculate_confidence(&self.config);

        let idx = self.findings.len();
        self.findings.push(triaged);
        Some(idx)
    }

    /// Add a finding with oracle information
    pub fn add_finding_with_oracle(&mut self, finding: Finding, oracle_name: &str) -> Option<usize> {
        let idx = self.add_finding(finding)?;
        
        // Track oracle
        *self.oracle_counts.entry(oracle_name.to_string()).or_insert(0) += 1;
        
        // Add oracle to finding
        if let Some(triaged) = self.findings.get_mut(idx) {
            triaged.add_detecting_oracle(oracle_name.to_string());
            triaged.recalculate_confidence(&self.config);
        }
        
        Some(idx)
    }

    /// Mark a finding as verified by multiple oracles
    pub fn add_oracle_to_finding(&mut self, finding_idx: usize, oracle_name: &str) {
        if let Some(triaged) = self.findings.get_mut(finding_idx) {
            triaged.add_detecting_oracle(oracle_name.to_string());
            triaged.recalculate_confidence(&self.config);
        }
    }

    /// Mark a finding as verified by Picus
    pub fn mark_picus_verified(&mut self, finding_idx: usize) {
        if let Some(triaged) = self.findings.get_mut(finding_idx) {
            triaged.mark_picus_verified();
            triaged.recalculate_confidence(&self.config);
        }
    }

    /// Record reproduction result for a finding
    pub fn record_reproduction(&mut self, finding_idx: usize, success: bool) {
        if let Some(triaged) = self.findings.get_mut(finding_idx) {
            triaged.record_reproduction(success);
            triaged.recalculate_confidence(&self.config);
        }
    }

    /// Set discovery coverage for a finding
    pub fn set_discovery_coverage(&mut self, finding_idx: usize, coverage: f64) {
        if let Some(triaged) = self.findings.get_mut(finding_idx) {
            triaged.discovery_coverage = coverage;
            triaged.recalculate_confidence(&self.config);
        }
    }

    /// Compute deduplication hash for a finding
    fn compute_finding_hash(&self, finding: &Finding) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        format!("{:?}", finding.attack_type).hash(&mut hasher);
        finding.description.hash(&mut hasher);
        if let Some(ref loc) = finding.location {
            loc.hash(&mut hasher);
        }
        format!("{:x}", hasher.finish())
    }

    /// Assign priority ranks to all findings
    fn assign_priority_ranks(&mut self) {
        // Sort by confidence score descending
        let mut indices: Vec<usize> = (0..self.findings.len()).collect();
        indices.sort_by(|&a, &b| {
            self.findings[b]
                .confidence_score
                .partial_cmp(&self.findings[a].confidence_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Assign ranks
        for (rank, idx) in indices.into_iter().enumerate() {
            self.findings[idx].priority_rank = (rank + 1) as u32;
        }
    }

    /// Generate the triage report
    pub fn generate_report(&mut self) -> TriageReport {
        // Assign priority ranks
        self.assign_priority_ranks();

        let config = &self.config;

        // Classify findings by confidence level
        let (high, medium, low): (Vec<_>, Vec<_>, Vec<_>) = {
            let mut high = Vec::new();
            let mut medium = Vec::new();
            let mut low = Vec::new();

            for finding in &self.findings {
                match finding.confidence_level {
                    ConfidenceLevel::High => high.push(finding.clone()),
                    ConfidenceLevel::Medium => medium.push(finding.clone()),
                    ConfidenceLevel::Low => low.push(finding.clone()),
                }
            }

            (high, medium, low)
        };

        // Calculate statistics
        let total_findings = self.findings.len();
        let filtered_count = if config.auto_filter_low_confidence {
            low.len()
        } else {
            0
        };

        let avg_confidence = if total_findings > 0 {
            self.findings.iter().map(|f| f.confidence_score).sum::<f64>() / total_findings as f64
        } else {
            0.0
        };

        TriageReport {
            high_confidence: high,
            medium_confidence: medium,
            low_confidence: low,
            statistics: TriageStatistics {
                total_findings,
                high_confidence_count: self.findings.iter()
                    .filter(|f| f.confidence_level == ConfidenceLevel::High)
                    .count(),
                medium_confidence_count: self.findings.iter()
                    .filter(|f| f.confidence_level == ConfidenceLevel::Medium)
                    .count(),
                low_confidence_count: self.findings.iter()
                    .filter(|f| f.confidence_level == ConfidenceLevel::Low)
                    .count(),
                filtered_count,
                average_confidence: avg_confidence,
                oracle_diversity: self.oracle_counts.len(),
                oracles_by_finding_count: self.oracle_counts.clone(),
            },
            config: config.clone(),
        }
    }

    /// Get findings filtered for evidence mode
    pub fn evidence_mode_findings(&self) -> Vec<&TriagedFinding> {
        self.findings
            .iter()
            .filter(|f| f.confidence_score >= self.config.evidence_mode_min_confidence)
            .collect()
    }

    /// Get count of findings by confidence level
    pub fn count_by_level(&self, level: ConfidenceLevel) -> usize {
        self.findings
            .iter()
            .filter(|f| f.confidence_level == level)
            .count()
    }
}

/// Triage report containing classified findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    /// High confidence findings (>0.8)
    pub high_confidence: Vec<TriagedFinding>,
    /// Medium confidence findings (0.5-0.8)
    pub medium_confidence: Vec<TriagedFinding>,
    /// Low confidence findings (<0.5)
    pub low_confidence: Vec<TriagedFinding>,
    /// Triage statistics
    pub statistics: TriageStatistics,
    /// Configuration used
    pub config: TriageConfig,
}

impl TriageReport {
    /// Get all findings sorted by priority
    pub fn all_findings_by_priority(&self) -> Vec<&TriagedFinding> {
        let mut all: Vec<&TriagedFinding> = self.high_confidence.iter()
            .chain(self.medium_confidence.iter())
            .chain(self.low_confidence.iter())
            .collect();
        
        all.sort_by_key(|f| f.priority_rank);
        all
    }

    /// Get findings suitable for automated reporting
    pub fn auto_report_findings(&self) -> &[TriagedFinding] {
        &self.high_confidence
    }

    /// Get findings that need manual review
    pub fn review_findings(&self) -> &[TriagedFinding] {
        &self.medium_confidence
    }

    /// Save report to JSON file
    pub fn save_to_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Generate markdown summary
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str("# Triage Report\n\n");
        md.push_str("## Summary\n\n");
        md.push_str(&format!("| Metric | Value |\n"));
        md.push_str(&format!("|--------|-------|\n"));
        md.push_str(&format!("| Total Findings | {} |\n", self.statistics.total_findings));
        md.push_str(&format!("| High Confidence | {} |\n", self.statistics.high_confidence_count));
        md.push_str(&format!("| Medium Confidence | {} |\n", self.statistics.medium_confidence_count));
        md.push_str(&format!("| Low Confidence | {} |\n", self.statistics.low_confidence_count));
        md.push_str(&format!("| Average Confidence | {:.2} |\n", self.statistics.average_confidence));
        md.push_str(&format!("| Oracle Diversity | {} |\n\n", self.statistics.oracle_diversity));

        // High confidence findings
        if !self.high_confidence.is_empty() {
            md.push_str("## High Confidence Findings (Auto-Report)\n\n");
            for finding in &self.high_confidence {
                md.push_str(&format!(
                    "### #{} [{:?}] {:?} (Confidence: {:.2})\n\n",
                    finding.priority_rank,
                    finding.finding.severity,
                    finding.finding.attack_type,
                    finding.confidence_score
                ));
                md.push_str(&format!("{}\n\n", finding.finding.description));
                md.push_str(&format!(
                    "**Oracles:** {}\n\n",
                    finding.detected_by_oracles.join(", ")
                ));
            }
        }

        // Medium confidence findings
        if !self.medium_confidence.is_empty() {
            md.push_str("## Medium Confidence Findings (Needs Review)\n\n");
            for finding in &self.medium_confidence {
                md.push_str(&format!(
                    "### #{} [{:?}] {:?} (Confidence: {:.2})\n\n",
                    finding.priority_rank,
                    finding.finding.severity,
                    finding.finding.attack_type,
                    finding.confidence_score
                ));
                md.push_str(&format!("{}\n\n", finding.finding.description));
            }
        }

        // Low confidence summary
        if !self.low_confidence.is_empty() {
            md.push_str(&format!(
                "## Low Confidence Findings (Filtered)\n\n{} findings with confidence < {:.2} were filtered.\n\n",
                self.low_confidence.len(),
                self.config.medium_confidence_threshold
            ));
        }

        md
    }
}

/// Statistics about the triage process
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TriageStatistics {
    /// Total findings processed
    pub total_findings: usize,
    /// High confidence findings count
    pub high_confidence_count: usize,
    /// Medium confidence findings count
    pub medium_confidence_count: usize,
    /// Low confidence findings count
    pub low_confidence_count: usize,
    /// Findings filtered (low confidence, auto-filter enabled)
    pub filtered_count: usize,
    /// Average confidence score
    pub average_confidence: f64,
    /// Number of unique oracles that fired
    pub oracle_diversity: usize,
    /// Oracle name -> finding count
    pub oracles_by_finding_count: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_core::{AttackType, FieldElement};

    fn make_finding(attack_type: AttackType, severity: Severity, description: &str) -> Finding {
        Finding {
            attack_type,
            severity,
            description: description.to_string(),
            poc: ProofOfConcept {
                witness_a: vec![FieldElement::from_u64(1)],
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some("test.circom:42".to_string()),
        }
    }

    #[test]
    fn test_triage_pipeline_basic() {
        let config = TriageConfig::default();
        let mut pipeline = TriagePipeline::new(config);

        // Add a critical finding
        let finding = make_finding(
            AttackType::Soundness,
            Severity::Critical,
            "Critical soundness violation detected",
        );
        let idx = pipeline.add_finding(finding);
        assert!(idx.is_some());

        let report = pipeline.generate_report();
        assert_eq!(report.statistics.total_findings, 1);
    }

    #[test]
    fn test_confidence_levels() {
        let config = TriageConfig::default();

        assert_eq!(
            ConfidenceLevel::from_score(0.9, &config),
            ConfidenceLevel::High
        );
        assert_eq!(
            ConfidenceLevel::from_score(0.6, &config),
            ConfidenceLevel::Medium
        );
        assert_eq!(
            ConfidenceLevel::from_score(0.3, &config),
            ConfidenceLevel::Low
        );
    }

    #[test]
    fn test_cross_oracle_bonus() {
        let config = TriageConfig::default();
        let mut pipeline = TriagePipeline::new(config);

        let finding = make_finding(
            AttackType::Collision,
            Severity::Critical,
            "Nullifier collision detected by multiple oracles",
        );
        let idx = pipeline.add_finding_with_oracle(finding, "NullifierOracle").unwrap();

        // Add more oracles
        pipeline.add_oracle_to_finding(idx, "CollisionOracle");
        pipeline.add_oracle_to_finding(idx, "SemanticOracle");

        let triaged = &pipeline.findings[idx];
        assert_eq!(triaged.detected_by_oracles.len(), 3);
        assert!(triaged.score_breakdown.cross_oracle_bonus > 0.0);
    }

    #[test]
    fn test_picus_verification_bonus() {
        let config = TriageConfig::default();
        let mut pipeline = TriagePipeline::new(config);

        let finding = make_finding(
            AttackType::Underconstrained,
            Severity::High,
            "Underconstrained circuit",
        );
        let idx = pipeline.add_finding(finding).unwrap();

        let score_before = pipeline.findings[idx].confidence_score;
        
        pipeline.mark_picus_verified(idx);
        
        let score_after = pipeline.findings[idx].confidence_score;
        assert!(score_after > score_before);
    }

    #[test]
    fn test_reproduction_bonus() {
        let config = TriageConfig::default();
        let mut pipeline = TriagePipeline::new(config);

        let finding = make_finding(
            AttackType::ArithmeticOverflow,
            Severity::Medium,
            "Arithmetic overflow detected",
        );
        let idx = pipeline.add_finding(finding).unwrap();

        let score_before = pipeline.findings[idx].confidence_score;
        
        // Record successful reproductions
        pipeline.record_reproduction(idx, true);
        pipeline.record_reproduction(idx, true);
        pipeline.record_reproduction(idx, false); // One failure
        
        let score_after = pipeline.findings[idx].confidence_score;
        assert!(score_after > score_before);
        
        let triaged = &pipeline.findings[idx];
        assert_eq!(triaged.reproduction_attempts, 3);
        assert_eq!(triaged.reproduction_successes, 2);
    }

    #[test]
    fn test_deduplication() {
        let config = TriageConfig {
            enable_deduplication: true,
            ..Default::default()
        };
        let mut pipeline = TriagePipeline::new(config);

        let finding1 = make_finding(
            AttackType::Collision,
            Severity::Critical,
            "Same collision finding",
        );
        let finding2 = make_finding(
            AttackType::Collision,
            Severity::Critical,
            "Same collision finding",
        );

        let idx1 = pipeline.add_finding(finding1);
        let idx2 = pipeline.add_finding(finding2);

        assert!(idx1.is_some());
        assert!(idx2.is_none()); // Should be deduplicated
        
        assert_eq!(pipeline.findings.len(), 1);
    }

    #[test]
    fn test_priority_ranking() {
        let config = TriageConfig::default();
        let mut pipeline = TriagePipeline::new(config);

        // Add findings of different severities
        pipeline.add_finding(make_finding(
            AttackType::Boundary,
            Severity::Low,
            "Low severity finding",
        ));
        pipeline.add_finding(make_finding(
            AttackType::Soundness,
            Severity::Critical,
            "Critical severity finding",
        ));
        pipeline.add_finding(make_finding(
            AttackType::ArithmeticOverflow,
            Severity::Medium,
            "Medium severity finding",
        ));

        let report = pipeline.generate_report();
        let all = report.all_findings_by_priority();

        // Critical should be ranked first
        assert_eq!(all[0].finding.severity, Severity::Critical);
        assert_eq!(all[0].priority_rank, 1);
    }

    #[test]
    fn test_evidence_mode_filter() {
        let config = TriageConfig {
            evidence_mode_min_confidence: 0.4, // Lower threshold for test
            ..Default::default()
        };
        let mut pipeline = TriagePipeline::new(config);

        // Add various findings - critical with good PoC
        let mut critical_finding = make_finding(
            AttackType::Soundness,
            Severity::Critical,
            "Critical soundness violation detected in circuit",
        );
        critical_finding.poc.witness_b = Some(vec![FieldElement::from_u64(2)]);
        pipeline.add_finding(critical_finding);
        
        // Info finding with minimal evidence
        pipeline.add_finding(make_finding(
            AttackType::Boundary,
            Severity::Info,
            "Info finding",
        ));

        let evidence_findings = pipeline.evidence_mode_findings();
        
        // At least critical finding should be included
        assert!(!evidence_findings.is_empty(), 
            "Evidence findings should not be empty. Total findings: {}", 
            pipeline.findings.len());
        for f in evidence_findings {
            assert!(f.confidence_score >= 0.4);
        }
    }

    #[test]
    fn test_report_generation() {
        let config = TriageConfig::default();
        let mut pipeline = TriagePipeline::new(config);

        // Add findings of different confidence levels
        let mut critical = make_finding(
            AttackType::Soundness,
            Severity::Critical,
            "High confidence critical finding",
        );
        critical.poc.witness_b = Some(vec![FieldElement::from_u64(2)]);
        
        pipeline.add_finding(critical);
        pipeline.add_finding(make_finding(
            AttackType::Boundary,
            Severity::Info,
            "Low confidence info finding",
        ));

        let report = pipeline.generate_report();
        
        assert_eq!(report.statistics.total_findings, 2);
        assert!(!report.high_confidence.is_empty() || !report.medium_confidence.is_empty());
    }

    #[test]
    fn test_markdown_generation() {
        let config = TriageConfig::default();
        let mut pipeline = TriagePipeline::new(config);

        pipeline.add_finding_with_oracle(
            make_finding(
                AttackType::Collision,
                Severity::Critical,
                "Critical nullifier collision",
            ),
            "NullifierOracle",
        );

        let report = pipeline.generate_report();
        let md = report.to_markdown();

        assert!(md.contains("# Triage Report"));
        assert!(md.contains("Total Findings"));
        assert!(md.contains("Critical"));
    }
}
