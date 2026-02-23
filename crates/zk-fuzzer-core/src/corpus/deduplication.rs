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
    /// Seen hash keys with representative finding (used when semantic mode is disabled)
    seen_hashes: HashMap<[u8; 32], Finding>,
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
    /// Findings dropped because max capacity was reached
    pub dropped_capacity: u64,
    /// Existing retained findings evicted to make room at max capacity
    pub evicted_capacity: u64,
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
            seen_hashes: HashMap::new(),
            config,
            stats: DeduplicationStats::default(),
        }
    }

    fn severity_rank(severity: Severity) -> u8 {
        match severity {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    fn retention_rank(&self, finding: &Finding) -> (u8, u16, [u8; 32]) {
        let severity_rank = Self::severity_rank(finding.severity);
        let confidence_rank = (calculate_confidence(finding) * 1000.0).round() as u16;
        let hash = self.finding_hash(finding);
        (severity_rank, confidence_rank, hash)
    }

    fn evict_one_hash_entry(&mut self) -> bool {
        let candidate = self
            .seen_hashes
            .iter()
            .map(|(hash, finding)| (self.retention_rank(finding), *hash))
            .min_by_key(|(rank, _)| *rank)
            .map(|(_, hash)| hash);
        if let Some(hash) = candidate {
            self.seen_hashes.remove(&hash);
            self.stats.evicted_capacity += 1;
            return true;
        }
        false
    }

    fn evict_one_semantic_entry(&mut self) -> bool {
        let candidate = self
            .seen_fingerprints
            .iter()
            .map(|(fp, finding)| (self.retention_rank(finding), fp.clone()))
            .min_by_key(|(rank, _)| *rank)
            .map(|(_, fp)| fp);
        if let Some(fp) = candidate {
            self.seen_fingerprints.remove(&fp);
            self.stats.evicted_capacity += 1;
            return true;
        }
        false
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
        let location_category = finding.location.as_ref().map(|loc| {
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
        let location_category = location_category.unwrap_or("unknown").to_string();

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
            // use simple hash-based dedup
            return self.is_hash_duplicate(finding);
        }

        let fp = self.fingerprint(finding);
        self.seen_fingerprints.contains_key(&fp)
    }

    fn finding_hash(&self, finding: &Finding) -> [u8; 32] {
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
        for fe in &finding.poc.public_inputs {
            hasher.update(fe.0);
        }
        if let Some(ref proof) = finding.poc.proof {
            hasher.update(proof);
        }
        hasher.update(format!("{:?}", finding.attack_type).as_bytes());
        hasher.update(format!("{:?}", finding.severity).as_bytes());
        hasher.update(finding.description.as_bytes());
        if let Some(ref location) = finding.location {
            hasher.update(location.as_bytes());
        }
        if let Some(ref class) = finding.class {
            hasher.update(format!("{:?}", class).as_bytes());
        }
        hasher.finalize().into()
    }

    /// Simple hash-based duplicate check
    fn is_hash_duplicate(&self, finding: &Finding) -> bool {
        self.seen_hashes.contains_key(&self.finding_hash(finding))
    }

    /// Add finding if not duplicate, return whether it was added
    pub fn add(&mut self, finding: Finding) -> bool {
        self.stats.total_processed += 1;

        if !self.config.use_semantic {
            let hash = self.finding_hash(&finding);
            if self.seen_hashes.contains_key(&hash) {
                self.stats.duplicates_filtered += 1;
                return false;
            }

            if self.config.max_findings == 0 {
                self.stats.dropped_capacity += 1;
                return false;
            }

            if self.seen_hashes.len() >= self.config.max_findings && !self.evict_one_hash_entry() {
                self.stats.dropped_capacity += 1;
                return false;
            }

            self.seen_hashes.insert(hash, finding);
            self.stats.unique_findings += 1;
            true
        } else {
            let fp = self.fingerprint(&finding);
            if self.seen_fingerprints.contains_key(&fp) {
                self.stats.duplicates_filtered += 1;
                return false;
            }

            if self.config.max_findings == 0 {
                self.stats.dropped_capacity += 1;
                return false;
            }

            if self.seen_fingerprints.len() >= self.config.max_findings
                && !self.evict_one_semantic_entry()
            {
                self.stats.dropped_capacity += 1;
                return false;
            }

            self.seen_fingerprints.insert(fp, finding);
            self.stats.unique_findings += 1;
            true
        }
    }

    /// Get all unique findings
    pub fn unique_findings(&self) -> Vec<&Finding> {
        if self.config.use_semantic {
            self.seen_fingerprints.values().collect()
        } else {
            self.seen_hashes.values().collect()
        }
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
        let mut findings = self.unique_findings();
        findings.sort_by_key(|finding| self.finding_hash(finding));
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
        self.seen_hashes.clear();
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
        let max_severity = self.members.iter().map(|f| f.severity).max();
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
#[path = "deduplication_tests.rs"]
mod tests;
