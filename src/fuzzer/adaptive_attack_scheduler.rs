//! Adaptive Attack Scheduler
//!
//! Dynamically reallocates budget between attack types based on their effectiveness.
//! Uses scoring heuristics to prioritize attacks that are finding bugs or making progress.
//!
//! # Scoring Heuristics
//!
//! - **Coverage gain**: +10 points per new constraint covered
//! - **Near-miss**: +5 points when oracle almost triggers
//! - **Finding**: +50 points for each bug found
//! - **Decay**: -1 point per iteration without progress
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::fuzzer::adaptive_attack_scheduler::AdaptiveScheduler;
//!
//! let mut scheduler = AdaptiveScheduler::new();
//! scheduler.update_scores(&attack_results);
//!
//! let budget = scheduler.allocate_budget(Duration::from_secs(300));
//! ```

use std::collections::HashMap;
use std::time::Duration;
use zk_core::{AttackType, Finding, Severity};

/// Configuration for the adaptive scheduler
#[derive(Debug, Clone)]
pub struct AdaptiveSchedulerConfig {
    /// Points for each new constraint covered
    pub coverage_gain_points: f64,
    /// Points for near-miss detection
    pub near_miss_points: f64,
    /// Points for finding a bug
    pub finding_points: f64,
    /// Points for critical findings
    pub critical_finding_points: f64,
    /// Decay per iteration without progress
    pub decay_per_iteration: f64,
    /// Minimum budget fraction per attack type
    pub min_budget_fraction: f64,
    /// Maximum budget fraction per attack type
    pub max_budget_fraction: f64,
    /// Learning rate for score updates
    pub learning_rate: f64,
}

impl Default for AdaptiveSchedulerConfig {
    fn default() -> Self {
        Self {
            coverage_gain_points: 10.0,
            near_miss_points: 5.0,
            finding_points: 50.0,
            critical_finding_points: 100.0,
            decay_per_iteration: 1.0,
            min_budget_fraction: 0.05,
            max_budget_fraction: 0.50,
            learning_rate: 0.1,
        }
    }
}

/// Results from an attack run
#[derive(Debug, Clone)]
pub struct AttackResults {
    /// Attack type that was run
    pub attack_type: AttackType,
    /// Number of new constraints covered
    pub new_coverage: usize,
    /// Findings discovered
    pub findings: Vec<Finding>,
    /// Near-misses detected
    pub near_misses: Vec<NearMissEvent>,
    /// Number of iterations executed
    pub iterations: usize,
    /// Time spent
    pub duration: Duration,
}

impl AttackResults {
    pub fn new(attack_type: AttackType) -> Self {
        Self {
            attack_type,
            new_coverage: 0,
            findings: Vec::new(),
            near_misses: Vec::new(),
            iterations: 0,
            duration: Duration::from_secs(0),
        }
    }
}

/// A near-miss event (oracle almost triggered)
#[derive(Debug, Clone)]
pub struct NearMissEvent {
    /// Type of near-miss
    pub event_type: NearMissType,
    /// Distance to triggering (lower is closer)
    pub distance: f64,
    /// Description
    pub description: String,
}

/// Types of near-miss events
#[derive(Debug, Clone)]
pub enum NearMissType {
    /// Almost out of range
    AlmostOutOfRange,
    /// Almost collision
    AlmostCollision,
    /// Almost invariant violation
    AlmostInvariantViolation,
    /// Almost constraint bypass
    AlmostConstraintBypass,
    /// Other near-miss
    Other(String),
}

/// Adaptive attack scheduler
pub struct AdaptiveScheduler {
    /// Configuration
    config: AdaptiveSchedulerConfig,
    /// Current scores per attack type
    attack_scores: HashMap<AttackType, f64>,
    /// Historical performance data
    history: Vec<AttackResults>,
    /// Iterations since last progress per attack
    iterations_without_progress: HashMap<AttackType, usize>,
    /// Total findings per attack type
    findings_per_attack: HashMap<AttackType, usize>,
    /// Near-misses collected
    near_misses: Vec<NearMissEvent>,
}

impl Default for AdaptiveScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveScheduler {
    /// Create a new adaptive scheduler
    pub fn new() -> Self {
        Self::with_config(AdaptiveSchedulerConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: AdaptiveSchedulerConfig) -> Self {
        Self {
            config,
            attack_scores: HashMap::new(),
            history: Vec::new(),
            iterations_without_progress: HashMap::new(),
            findings_per_attack: HashMap::new(),
            near_misses: Vec::new(),
        }
    }

    /// Initialize scores for attack types
    pub fn initialize(&mut self, attack_types: &[AttackType]) {
        let initial_score = 100.0 / attack_types.len() as f64;
        for attack_type in attack_types {
            self.attack_scores
                .insert(attack_type.clone(), initial_score);
            self.iterations_without_progress
                .insert(attack_type.clone(), 0);
            self.findings_per_attack.insert(attack_type.clone(), 0);
        }
    }

    /// Update scores based on attack results
    pub fn update_scores(&mut self, results: &AttackResults) {
        let attack_type = &results.attack_type;
        let mut score_delta = 0.0;

        // Coverage gain
        if results.new_coverage > 0 {
            score_delta += self.config.coverage_gain_points * results.new_coverage as f64;
            self.iterations_without_progress
                .insert(attack_type.clone(), 0);
        } else {
            // Decay
            let stale_iters = self
                .iterations_without_progress
                .entry(attack_type.clone())
                .or_insert(0);
            *stale_iters += results.iterations;
            score_delta -= self.config.decay_per_iteration * (*stale_iters as f64 / 100.0);
        }

        // Near-miss bonus
        for near_miss in &results.near_misses {
            // Closer near-misses get more points
            let proximity_bonus =
                (1.0 - near_miss.distance.min(1.0)) * self.config.near_miss_points;
            score_delta += proximity_bonus;
            self.near_misses.push(near_miss.clone());
        }

        // Finding bonus
        for finding in &results.findings {
            let points = if finding.severity == Severity::Critical {
                self.config.critical_finding_points
            } else {
                self.config.finding_points
            };
            score_delta += points;
        }

        *self
            .findings_per_attack
            .entry(attack_type.clone())
            .or_insert(0) += results.findings.len();

        // Apply update with learning rate
        let current_score = self
            .attack_scores
            .entry(attack_type.clone())
            .or_insert(10.0);
        *current_score = (*current_score + self.config.learning_rate * score_delta).max(1.0);

        // Record history
        self.history.push(results.clone());
    }

    /// Allocate time budget across attack types
    pub fn allocate_budget(&self, total_time: Duration) -> HashMap<AttackType, Duration> {
        let total_score: f64 = self.attack_scores.values().sum();
        if total_score == 0.0 {
            return HashMap::new();
        }

        let total_millis = total_time.as_millis() as u64;
        if total_millis == 0 {
            return HashMap::new();
        }

        // Phase 3A correctness fix:
        // Clamp per-attack fractions, then renormalize so the final allocation
        // always sums to the requested total budget.
        let mut fractions: Vec<(AttackType, f64)> = self
            .attack_scores
            .iter()
            .map(|(attack_type, score)| {
                let clamped = (score / total_score)
                    .max(self.config.min_budget_fraction)
                    .min(self.config.max_budget_fraction);
                (attack_type.clone(), clamped)
            })
            .collect();

        let clamped_sum: f64 = fractions.iter().map(|(_, value)| *value).sum();
        if clamped_sum <= f64::EPSILON {
            return HashMap::new();
        }
        for (_, value) in &mut fractions {
            *value /= clamped_sum;
        }

        // Use largest-remainder rounding so integer milliseconds sum exactly.
        let mut base_allocations: Vec<(AttackType, u64, f64)> = fractions
            .into_iter()
            .map(|(attack_type, fraction)| {
                let exact = fraction * total_millis as f64;
                let whole = exact.floor() as u64;
                let remainder = exact - whole as f64;
                (attack_type, whole, remainder)
            })
            .collect();

        let used_millis: u64 = base_allocations.iter().map(|(_, millis, _)| *millis).sum();
        let leftover = total_millis.saturating_sub(used_millis) as usize;
        base_allocations.sort_by(|a, b| b.2.total_cmp(&a.2));
        for (idx, (_, millis, _)) in base_allocations.iter_mut().enumerate() {
            if idx < leftover {
                *millis += 1;
            }
        }

        let mut allocations = HashMap::new();
        for (attack_type, millis, _) in base_allocations {
            allocations.insert(attack_type, Duration::from_millis(millis));
        }

        allocations
    }

    /// Get current scores
    pub fn scores(&self) -> &HashMap<AttackType, f64> {
        &self.attack_scores
    }

    /// Get the highest-scoring attack type
    pub fn best_attack(&self) -> Option<AttackType> {
        self.attack_scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, _)| k.clone())
    }

    /// Get attacks that should receive more budget
    pub fn under_explored(&self) -> Vec<AttackType> {
        let avg_score: f64 = if self.attack_scores.is_empty() {
            0.0
        } else {
            self.attack_scores.values().sum::<f64>() / self.attack_scores.len() as f64
        };

        self.attack_scores
            .iter()
            .filter(|(_, &score)| score < avg_score * 0.5)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Get near-misses for feedback
    pub fn near_misses(&self) -> &[NearMissEvent] {
        &self.near_misses
    }

    /// Generate YAML suggestions based on learned patterns
    pub fn suggest_yaml_edits(&self) -> Vec<YamlSuggestion> {
        let mut suggestions = Vec::new();

        // Suggest interesting values from near-misses
        for near_miss in &self.near_misses {
            if let NearMissType::AlmostOutOfRange = near_miss.event_type {
                suggestions.push(YamlSuggestion {
                    suggestion_type: SuggestionType::AddInterestingValue,
                    key: "interesting".to_string(),
                    value: near_miss.description.clone(),
                    reason: format!("Near-miss detected at distance {:.3}", near_miss.distance),
                });
            }
        }

        // Suggest budget increases for high-scoring attacks
        if let Some(best) = self.best_attack() {
            if let Some(&score) = self.attack_scores.get(&best) {
                let avg_score: f64 = self.attack_scores.values().sum::<f64>()
                    / self.attack_scores.len().max(1) as f64;

                if score > avg_score * 2.0 {
                    suggestions.push(YamlSuggestion {
                        suggestion_type: SuggestionType::IncreaseBudget,
                        key: format!("{:?}", best),
                        value: "2x".to_string(),
                        reason: format!(
                            "Attack {:?} has high effectiveness (score: {:.1})",
                            best, score
                        ),
                    });
                }
            }
        }

        // Suggest removing low-performing attacks
        for (attack_type, &score) in &self.attack_scores {
            let findings_count: usize = self
                .findings_per_attack
                .get(attack_type)
                .copied()
                .unwrap_or_default();
            if score < 5.0 && findings_count == 0 {
                suggestions.push(YamlSuggestion {
                    suggestion_type: SuggestionType::DecreaseBudget,
                    key: format!("{:?}", attack_type),
                    value: "remove or reduce".to_string(),
                    reason: format!(
                        "Attack {:?} has low effectiveness (score: {:.1}, 0 findings)",
                        attack_type, score
                    ),
                });
            }
        }

        suggestions
    }

    /// Get statistics
    pub fn stats(&self) -> AdaptiveSchedulerStats {
        AdaptiveSchedulerStats {
            attack_scores: self.attack_scores.clone(),
            findings_per_attack: self.findings_per_attack.clone(),
            total_near_misses: self.near_misses.len(),
            history_length: self.history.len(),
            best_attack: self.best_attack(),
            under_explored: self.under_explored(),
        }
    }
}

/// A YAML configuration suggestion
#[derive(Debug, Clone)]
pub struct YamlSuggestion {
    pub suggestion_type: SuggestionType,
    pub key: String,
    pub value: String,
    pub reason: String,
}

/// Types of YAML suggestions
#[derive(Debug, Clone)]
pub enum SuggestionType {
    AddInterestingValue,
    AddInvariant,
    IncreaseBudget,
    DecreaseBudget,
    AddAttack,
    RemoveAttack,
    ModifyMutation,
}

impl YamlSuggestion {
    /// Convert to YAML comment
    pub fn to_yaml_comment(&self) -> String {
        format!(
            "# Suggestion: {} {} to '{}'\n# Reason: {}",
            match self.suggestion_type {
                SuggestionType::AddInterestingValue => "add",
                SuggestionType::AddInvariant => "add invariant",
                SuggestionType::IncreaseBudget => "increase budget for",
                SuggestionType::DecreaseBudget => "decrease budget for",
                SuggestionType::AddAttack => "add attack",
                SuggestionType::RemoveAttack => "remove attack",
                SuggestionType::ModifyMutation => "modify mutation",
            },
            self.key,
            self.value,
            self.reason
        )
    }
}

/// Statistics from adaptive scheduling
#[derive(Debug, Clone)]
pub struct AdaptiveSchedulerStats {
    pub attack_scores: HashMap<AttackType, f64>,
    pub findings_per_attack: HashMap<AttackType, usize>,
    pub total_near_misses: usize,
    pub history_length: usize,
    pub best_attack: Option<AttackType>,
    pub under_explored: Vec<AttackType>,
}

#[cfg(test)]
#[path = "adaptive_attack_scheduler_tests.rs"]
mod tests;
