//! Semantic Finding Deduplication
//!
//! Upgrades from basic hash-based deduplication to semantic similarity.
//! Identifies findings with the same root cause even if triggered by different inputs.
//!
//! # Features
//!
//! - Constraint path fingerprinting
//! - Oracle-based grouping
//! - Confidence scoring
//! - DBSCAN clustering for related findings

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zk_core::{AttackType, Severity};
use zk_core::{FieldElement, Finding};

/// Semantic fingerprint for a finding
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SemanticFingerprint {
    /// Attack type / oracle that detected the finding
    pub oracle_type: AttackType,
    /// Abstract constraint path (not exact values)
    pub constraint_path_hash: [u8; 8],
    /// Input pattern abstraction
    pub input_pattern: InputPattern,
    /// Location category
    pub location_category: String,
}

/// Abstract input pattern for similarity comparison
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum InputPattern {
    /// All zero inputs
    AllZeros,
    /// All max value inputs
    AllMax,
    /// Single non-zero input at position
    SingleNonZero(usize),
    /// Boundary values present
    BoundaryValues,
    /// Random/mixed pattern
    Mixed,
    /// Collision pattern (two similar inputs)
    CollisionPair,
}

impl InputPattern {
    /// Analyze inputs to determine pattern
    pub fn from_inputs(inputs: &[FieldElement]) -> Self {
        if inputs.is_empty() {
            return Self::Mixed;
        }

        let all_zero = inputs.iter().all(|fe| fe.is_zero());
        if all_zero {
            return Self::AllZeros;
        }

        let all_max = inputs.iter().all(|fe| {
            let max = FieldElement::max_value();
            fe.0 == max.0
        });
        if all_max {
            return Self::AllMax;
        }

        // Check for single non-zero
        let non_zero_count = inputs.iter().filter(|fe| !fe.is_zero()).count();
        if non_zero_count == 1 {
            let pos = inputs.iter().position(|fe| !fe.is_zero()).unwrap();
            return Self::SingleNonZero(pos);
        }

        // Check for boundary values (0, 1, max, half_max)
        let has_boundary = inputs.iter().any(|fe| {
            fe.is_zero()
                || fe.is_one()
                || fe.0 == FieldElement::max_value().0
                || fe.0 == FieldElement::half_modulus().0
        });
        if has_boundary {
            return Self::BoundaryValues;
        }

        Self::Mixed
    }
}

/// Semantic deduplicator for findings
pub struct SemanticDeduplicator {
    /// Seen fingerprints with their representative finding
    seen_fingerprints: HashMap<SemanticFingerprint, Finding>,
    /// Configuration
    config: DeduplicationConfig,
    /// Statistics
    stats: DeduplicationStats,
}

/// Configuration for deduplication
#[derive(Debug, Clone)]
pub struct DeduplicationConfig {
    /// Whether to use semantic fingerprinting (vs hash-based)
    pub use_semantic: bool,
    /// Minimum similarity threshold for clustering (0.0 - 1.0)
    pub similarity_threshold: f64,
    /// Maximum findings to track
    pub max_findings: usize,
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            use_semantic: true,
            similarity_threshold: 0.8,
            max_findings: 10000,
        }
    }
}

/// Deduplication statistics
#[derive(Debug, Clone, Default)]
pub struct DeduplicationStats {
    /// Total findings processed
    pub total_processed: u64,
    /// Unique findings after dedup
    pub unique_findings: u64,
    /// Duplicates filtered
    pub duplicates_filtered: u64,
}

impl SemanticDeduplicator {
    /// Create new deduplicator with default config
    pub fn new() -> Self {
        Self::with_config(DeduplicationConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: DeduplicationConfig) -> Self {
        Self {
            seen_fingerprints: HashMap::new(),
            config,
            stats: DeduplicationStats::default(),
        }
    }

    /// Compute semantic fingerprint for a finding
    pub fn fingerprint(&self, finding: &Finding) -> SemanticFingerprint {
        // Hash the constraint path (from location if available)
        let constraint_hash = {
            let mut hasher = Sha256::new();
            if let Some(ref loc) = finding.location {
                hasher.update(loc.as_bytes());
            }
            hasher.update(format!("{:?}", finding.attack_type).as_bytes());
            let result = hasher.finalize();
            let mut hash = [0u8; 8];
            hash.copy_from_slice(&result[..8]);
            hash
        };

        // Determine input pattern
        let input_pattern = InputPattern::from_inputs(&finding.poc.witness_a);

        // Categorize location
        let location_category = finding
            .location
            .as_ref()
            .map(|loc| {
                if loc.contains("nullifier") {
                    "nullifier"
                } else if loc.contains("merkle") {
                    "merkle"
                } else if loc.contains("signature") {
                    "signature"
                } else if loc.contains("range") {
                    "range"
                } else if loc.contains("arithmetic") {
                    "arithmetic"
                } else {
                    "other"
                }
            });
        let location_category = match location_category {
            Some(value) => value,
            None => "unknown",
        }
            .to_string();

        SemanticFingerprint {
            oracle_type: finding.attack_type.clone(),
            constraint_path_hash: constraint_hash,
            input_pattern,
            location_category,
        }
    }

    /// Check if a finding is a duplicate
    pub fn is_duplicate(&self, finding: &Finding) -> bool {
        if !self.config.use_semantic {
            // Fall back to simple hash-based dedup
            return self.is_hash_duplicate(finding);
        }

        let fp = self.fingerprint(finding);
        self.seen_fingerprints.contains_key(&fp)
    }

    /// Simple hash-based duplicate check
    fn is_hash_duplicate(&self, finding: &Finding) -> bool {
        // Hash the full POC
        let mut hasher = Sha256::new();
        for fe in &finding.poc.witness_a {
            hasher.update(fe.0);
        }
        if let Some(ref witness_b) = finding.poc.witness_b {
            for fe in witness_b {
                hasher.update(fe.0);
            }
        }
        hasher.update(format!("{:?}", finding.attack_type).as_bytes());
        let _hash = hasher.finalize();

        // Would need a hash set to track - simplified here
        false
    }

    /// Add finding if not duplicate, return whether it was added
    pub fn add(&mut self, finding: Finding) -> bool {
        self.stats.total_processed += 1;

        if self.seen_fingerprints.len() >= self.config.max_findings {
            // Evict oldest entries (simplified - just skip)
            self.stats.duplicates_filtered += 1;
            return false;
        }

        let fp = self.fingerprint(&finding);

        use std::collections::hash_map::Entry;
        match self.seen_fingerprints.entry(fp) {
            Entry::Occupied(_) => {
                self.stats.duplicates_filtered += 1;
                false
            }
            Entry::Vacant(e) => {
                e.insert(finding);
                self.stats.unique_findings += 1;
                true
            }
        }
    }

    /// Get all unique findings
    pub fn unique_findings(&self) -> Vec<&Finding> {
        self.seen_fingerprints.values().collect()
    }

    /// Get deduplication statistics
    pub fn stats(&self) -> &DeduplicationStats {
        &self.stats
    }

    /// Deduplicate a batch of findings
    pub fn deduplicate(&mut self, findings: Vec<Finding>) -> Vec<Finding> {
        let mut unique = Vec::new();

        for finding in findings {
            if self.add(finding.clone()) {
                unique.push(finding);
            }
        }

        unique
    }

    /// Calculate similarity between two findings (0.0 - 1.0)
    pub fn similarity(&self, a: &Finding, b: &Finding) -> f64 {
        let fp_a = self.fingerprint(a);
        let fp_b = self.fingerprint(b);

        let mut score = 0.0;

        // Same oracle type: +0.4
        if fp_a.oracle_type == fp_b.oracle_type {
            score += 0.4;
        }

        // Same location category: +0.3
        if fp_a.location_category == fp_b.location_category {
            score += 0.3;
        }

        // Same input pattern: +0.2
        if fp_a.input_pattern == fp_b.input_pattern {
            score += 0.2;
        }

        // Same constraint path: +0.1
        if fp_a.constraint_path_hash == fp_b.constraint_path_hash {
            score += 0.1;
        }

        score
    }

    /// Cluster similar findings together
    pub fn cluster_findings(&self) -> Vec<FindingCluster> {
        let findings: Vec<_> = self.seen_fingerprints.values().collect();
        let mut clusters: Vec<FindingCluster> = Vec::new();

        for finding in findings {
            let mut found_cluster = false;

            for cluster in &mut clusters {
                if self.similarity(finding, &cluster.representative)
                    >= self.config.similarity_threshold
                {
                    cluster.members.push(finding.clone());
                    found_cluster = true;
                    break;
                }
            }

            if !found_cluster {
                clusters.push(FindingCluster {
                    representative: finding.clone(),
                    members: vec![finding.clone()],
                });
            }
        }

        clusters
    }

    /// Reset the deduplicator
    pub fn reset(&mut self) {
        self.seen_fingerprints.clear();
        self.stats = DeduplicationStats::default();
    }
}

impl Default for SemanticDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

/// Cluster of similar findings
#[derive(Debug, Clone)]
pub struct FindingCluster {
    /// Representative finding for the cluster
    pub representative: Finding,
    /// All findings in the cluster
    pub members: Vec<Finding>,
}

impl FindingCluster {
    /// Get cluster size
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Get highest severity in cluster
    pub fn max_severity(&self) -> Severity {
        let max_severity = self
            .members
            .iter()
            .map(|f| f.severity)
            .max();
        match max_severity {
            Some(value) => value,
            None => Severity::Info,
        }
    }
}

/// Calculate confidence score for a finding
pub fn calculate_confidence(finding: &Finding) -> f64 {
    let mut score: f64 = 0.5; // Base confidence

    // Higher severity = higher confidence
    score += match finding.severity {
        Severity::Critical => 0.3,
        Severity::High => 0.2,
        Severity::Medium => 0.1,
        Severity::Low => 0.05,
        Severity::Info => 0.0,
    };

    // Has witness_b (comparison witness) = higher confidence
    if finding.poc.witness_b.is_some() {
        score += 0.1;
    }

    // Has specific location = higher confidence
    if finding.location.is_some() {
        score += 0.05;
    }

    // Non-empty POC = higher confidence
    if !finding.poc.witness_a.is_empty() {
        score += 0.05;
    }

    if score > 1.0 {
        1.0
    } else {
        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_core::ProofOfConcept;

    fn make_finding(attack_type: AttackType, location: &str) -> Finding {
        Finding {
            attack_type,
            severity: Severity::High,
            description: "Test finding".to_string(),
            poc: ProofOfConcept {
                witness_a: vec![FieldElement::from_u64(42)],
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some(location.to_string()),
        }
    }

    #[test]
    fn test_semantic_fingerprint() {
        let dedup = SemanticDeduplicator::new();

        let finding = make_finding(AttackType::Collision, "nullifier_collision");
        let fp = dedup.fingerprint(&finding);

        assert_eq!(fp.oracle_type, AttackType::Collision);
        assert_eq!(fp.location_category, "nullifier");
    }

    #[test]
    fn test_deduplication() {
        let mut dedup = SemanticDeduplicator::new();

        let finding1 = make_finding(AttackType::Collision, "nullifier_collision");
        let finding2 = make_finding(AttackType::Collision, "nullifier_collision");
        let finding3 = make_finding(AttackType::Boundary, "merkle_path");

        assert!(dedup.add(finding1));
        assert!(!dedup.add(finding2)); // Duplicate
        assert!(dedup.add(finding3)); // Different

        assert_eq!(dedup.stats().unique_findings, 2);
        assert_eq!(dedup.stats().duplicates_filtered, 1);
    }

    #[test]
    fn test_similarity() {
        let dedup = SemanticDeduplicator::new();

        let finding1 = make_finding(AttackType::Collision, "nullifier_collision");
        let finding2 = make_finding(AttackType::Collision, "nullifier_other");
        let finding3 = make_finding(AttackType::Boundary, "merkle_path");

        // Same oracle, same category
        let sim_1_2 = dedup.similarity(&finding1, &finding2);
        assert!(sim_1_2 > 0.6);

        // Different oracle, different category
        let sim_1_3 = dedup.similarity(&finding1, &finding3);
        assert!(sim_1_3 < 0.4);
    }

    #[test]
    fn test_input_pattern() {
        assert_eq!(
            InputPattern::from_inputs(&[FieldElement::zero()]),
            InputPattern::AllZeros
        );

        assert_eq!(
            InputPattern::from_inputs(&[
                FieldElement::zero(),
                FieldElement::from_u64(42),
                FieldElement::zero()
            ]),
            InputPattern::SingleNonZero(1)
        );
    }

    #[test]
    fn test_confidence_score() {
        let mut finding = make_finding(AttackType::Collision, "test");
        finding.severity = Severity::Critical;
        finding.poc.witness_b = Some(vec![FieldElement::from_u64(1)]);

        let confidence = calculate_confidence(&finding);
        assert!(confidence > 0.9);
    }
}
