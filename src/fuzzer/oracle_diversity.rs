//! Oracle Diversity Tracking
//!
//! Tracks which oracle types have been triggered during fuzzing and measures
//! the diversity of violation patterns found.
//!
//! # Metrics
//!
//! - **Oracle Coverage**: Percentage of available oracle types that have fired
//! - **Violation Pattern Diversity**: Number of unique violation signatures
//! - **Diversity Score**: Combined metric of oracle utilization
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::fuzzer::oracle_diversity::OracleDiversityTracker;
//!
//! let mut tracker = OracleDiversityTracker::new();
//! tracker.register_oracle("underconstrained");
//! tracker.register_oracle("collision");
//!
//! tracker.record_fire("underconstrained", "missing_constraint_idx_42");
//!
//! let stats = tracker.stats();
//! println!("Oracle coverage: {:.1}%", stats.coverage_percent);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use zk_core::{AttackType, Finding, Severity};

/// Tracks oracle diversity and violation patterns
#[derive(Debug, Clone)]
pub struct OracleDiversityTracker {
    /// All registered oracle types
    registered_oracles: HashSet<String>,

    /// Oracle types that have fired at least once
    fired_oracles: HashSet<String>,

    /// Count of fires per oracle type
    fire_counts: HashMap<String, usize>,

    /// Unique violation patterns (hashed signatures)
    violation_patterns: HashSet<String>,

    /// Violation pattern details
    pattern_details: HashMap<String, ViolationPattern>,

    /// History of oracle fires for analysis
    fire_history: Vec<OracleFire>,

    /// Maximum history size
    max_history: usize,

    /// Start time for tracking
    start_time: Option<Instant>,
}

/// Record of an oracle fire event
#[derive(Debug, Clone)]
pub struct OracleFire {
    /// Oracle type that fired
    pub oracle_type: String,
    /// Violation pattern signature
    pub pattern: String,
    /// Timestamp (relative to start)
    pub elapsed_ms: u64,
    /// Severity of the finding
    pub severity: Option<Severity>,
}

/// Details about a violation pattern
#[derive(Debug, Clone)]
pub struct ViolationPattern {
    /// Pattern signature
    pub signature: String,
    /// Oracle type that detected it
    pub oracle_type: String,
    /// Number of times this pattern was seen
    pub occurrences: usize,
    /// First time this pattern was seen
    pub first_seen_ms: u64,
    /// Description
    pub description: Option<String>,
}

/// Oracle diversity statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleDiversityStats {
    /// Number of registered oracle types
    pub registered_count: usize,

    /// Number of oracle types that have fired
    pub fired_count: usize,

    /// Oracle coverage percentage
    pub coverage_percent: f64,

    /// Number of unique violation patterns
    pub unique_patterns: usize,

    /// Total number of oracle fires
    pub total_fires: usize,

    /// Diversity score (0.0 - 1.0)
    pub diversity_score: f64,

    /// Fire counts by oracle type
    pub fires_by_oracle: HashMap<String, usize>,

    /// Unfired oracle types
    pub unfired_oracles: Vec<String>,
}

impl Default for OracleDiversityTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl OracleDiversityTracker {
    /// Create a new oracle diversity tracker
    pub fn new() -> Self {
        Self {
            registered_oracles: HashSet::new(),
            fired_oracles: HashSet::new(),
            fire_counts: HashMap::new(),
            violation_patterns: HashSet::new(),
            pattern_details: HashMap::new(),
            fire_history: Vec::new(),
            max_history: 10000,
            start_time: None,
        }
    }

    /// Create tracker with standard ZK oracles pre-registered
    pub fn with_standard_oracles() -> Self {
        let mut tracker = Self::new();

        // Register standard oracle types
        let oracles = [
            "underconstrained",
            "soundness",
            "arithmetic_overflow",
            "collision",
            "boundary",
            "constraint_bypass",
            "witness_leakage",
            "replay_attack",
            "bit_decomposition",
            "malleability",
            "verification_fuzzing",
            "witness_fuzzing",
        ];

        for oracle in oracles {
            tracker.register_oracle(oracle);
        }

        tracker
    }

    /// Register an oracle type
    pub fn register_oracle(&mut self, oracle_type: &str) {
        self.registered_oracles.insert(oracle_type.to_string());
    }

    /// Register multiple oracle types
    pub fn register_oracles<I, S>(&mut self, oracle_types: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for oracle_type in oracle_types {
            self.register_oracle(oracle_type.as_ref());
        }
    }

    /// Start tracking (for timing)
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Record an oracle fire
    pub fn record_fire(&mut self, oracle_type: &str, pattern: &str) {
        self.record_fire_with_severity(oracle_type, pattern, None);
    }

    /// Record an oracle fire with severity
    pub fn record_fire_with_severity(
        &mut self,
        oracle_type: &str,
        pattern: &str,
        severity: Option<Severity>,
    ) {
        let oracle_type = oracle_type.to_string();
        let pattern = pattern.to_string();

        // Update fired oracles
        self.fired_oracles.insert(oracle_type.clone());

        // Update fire counts
        *self.fire_counts.entry(oracle_type.clone()).or_insert(0) += 1;

        // Update violation patterns
        let is_new_pattern = self.violation_patterns.insert(pattern.clone());

        // Calculate elapsed time
        let elapsed_ms = self.start_time.map(|t| t.elapsed().as_millis() as u64);
        let elapsed_ms = elapsed_ms.unwrap_or_default();

        // Update pattern details
        if is_new_pattern {
            self.pattern_details.insert(
                pattern.clone(),
                ViolationPattern {
                    signature: pattern.clone(),
                    oracle_type: oracle_type.clone(),
                    occurrences: 1,
                    first_seen_ms: elapsed_ms,
                    description: None,
                },
            );
        } else if let Some(detail) = self.pattern_details.get_mut(&pattern) {
            detail.occurrences += 1;
        }

        // Record in history
        if self.fire_history.len() < self.max_history {
            self.fire_history.push(OracleFire {
                oracle_type,
                pattern,
                elapsed_ms,
                severity,
            });
        }
    }

    /// Record a finding
    pub fn record_finding(&mut self, finding: &Finding) {
        let oracle_type = format!("{:?}", finding.attack_type).to_lowercase();
        let pattern = self.compute_finding_pattern(finding);
        self.record_fire_with_severity(&oracle_type, &pattern, Some(finding.severity));
    }

    /// Compute a pattern signature for a finding
    fn compute_finding_pattern(&self, finding: &Finding) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", finding.attack_type).as_bytes());
        hasher.update(finding.description.as_bytes());
        if let Some(ref loc) = finding.location {
            hasher.update(loc.as_bytes());
        }

        let hash = hasher.finalize();
        format!("{:x}", hash)[..16].to_string()
    }

    /// Get current statistics
    pub fn stats(&self) -> OracleDiversityStats {
        let registered_count = self.registered_oracles.len();
        let fired_count = self.fired_oracles.len();

        let coverage_percent = if registered_count > 0 {
            (fired_count as f64 / registered_count as f64) * 100.0
        } else {
            0.0
        };

        let unique_patterns = self.violation_patterns.len();
        let total_fires: usize = self.fire_counts.values().sum();

        // Calculate diversity score
        // Combines oracle coverage and pattern diversity
        let diversity_score = self.calculate_diversity_score();

        let unfired_oracles: Vec<String> = self
            .registered_oracles
            .difference(&self.fired_oracles)
            .cloned()
            .collect();

        OracleDiversityStats {
            registered_count,
            fired_count,
            coverage_percent,
            unique_patterns,
            total_fires,
            diversity_score,
            fires_by_oracle: self.fire_counts.clone(),
            unfired_oracles,
        }
    }

    /// Calculate diversity score (0.0 - 1.0)
    fn calculate_diversity_score(&self) -> f64 {
        if self.registered_oracles.is_empty() {
            return 0.0;
        }

        // Component 1: Oracle coverage (40%)
        let oracle_coverage =
            self.fired_oracles.len() as f64 / self.registered_oracles.len() as f64;

        // Component 2: Pattern diversity (30%)
        // Normalize by expected number of patterns
        let expected_patterns = 50.0; // Arbitrary expectation
        let pattern_diversity = (self.violation_patterns.len() as f64 / expected_patterns).min(1.0);

        // Component 3: Fire distribution evenness (30%)
        // Using normalized entropy
        let fire_evenness = self.calculate_fire_evenness();

        0.4 * oracle_coverage + 0.3 * pattern_diversity + 0.3 * fire_evenness
    }

    /// Calculate evenness of fire distribution using normalized entropy
    fn calculate_fire_evenness(&self) -> f64 {
        if self.fire_counts.is_empty() || self.fire_counts.len() == 1 {
            return 1.0;
        }

        let total: f64 = self.fire_counts.values().sum::<usize>() as f64;
        if total == 0.0 {
            return 0.0;
        }

        // Calculate Shannon entropy
        let entropy: f64 = self
            .fire_counts
            .values()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / total;
                -p * p.ln()
            })
            .sum();

        // Normalize by max entropy (uniform distribution)
        let max_entropy = (self.fire_counts.len() as f64).ln();
        if max_entropy == 0.0 {
            1.0
        } else {
            entropy / max_entropy
        }
    }

    /// Get recommendations for improving diversity
    pub fn recommendations(&self) -> Vec<DiversityRecommendation> {
        let mut recommendations = Vec::new();
        let stats = self.stats();

        // Recommend enabling unfired oracles
        if !stats.unfired_oracles.is_empty() {
            for oracle in &stats.unfired_oracles {
                recommendations.push(DiversityRecommendation {
                    priority: RecommendationPriority::High,
                    category: "oracle_coverage".to_string(),
                    description: format!("Enable or increase budget for '{}' oracle", oracle),
                    expected_improvement: 0.1,
                });
            }
        }

        // Recommend increasing pattern diversity
        if stats.unique_patterns < 10 {
            recommendations.push(DiversityRecommendation {
                priority: RecommendationPriority::Medium,
                category: "pattern_diversity".to_string(),
                description: "Increase mutation aggressiveness to discover more violation patterns"
                    .to_string(),
                expected_improvement: 0.15,
            });
        }

        // Check for imbalanced oracle usage
        if let Some((over_used, count)) = self.fire_counts.iter().max_by_key(|(_, c)| *c) {
            let avg_count = stats.total_fires as f64 / stats.fired_count.max(1) as f64;
            if *count as f64 > avg_count * 3.0 {
                recommendations.push(DiversityRecommendation {
                    priority: RecommendationPriority::Low,
                    category: "balance".to_string(),
                    description: format!(
                        "Oracle '{}' is over-represented ({} fires). Consider rebalancing.",
                        over_used, count
                    ),
                    expected_improvement: 0.05,
                });
            }
        }

        recommendations
    }

    /// Export history for analysis
    pub fn export_history(&self) -> &[OracleFire] {
        &self.fire_history
    }

    /// Get pattern details
    pub fn pattern_details(&self) -> &HashMap<String, ViolationPattern> {
        &self.pattern_details
    }

    /// Clear all tracking data
    pub fn reset(&mut self) {
        self.fired_oracles.clear();
        self.fire_counts.clear();
        self.violation_patterns.clear();
        self.pattern_details.clear();
        self.fire_history.clear();
        self.start_time = None;
    }
}

/// Recommendation for improving oracle diversity
#[derive(Debug, Clone)]
pub struct DiversityRecommendation {
    pub priority: RecommendationPriority,
    pub category: String,
    pub description: String,
    pub expected_improvement: f64,
}

/// Priority level for recommendations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecommendationPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Convert AttackType to oracle type string
pub fn attack_type_to_string(attack_type: AttackType) -> String {
    format!("{:?}", attack_type).to_lowercase()
}
