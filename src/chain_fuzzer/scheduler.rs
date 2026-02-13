//! Mode 3: Chain Scheduler - Budget allocation across chain scenarios
//!
//! Manages time budgets for different chain specifications based on
//! their effectiveness and coverage contributions.

use super::types::ChainSpec;
use std::collections::HashMap;
use std::time::Duration;

/// Allocates budget across chain scenarios within a campaign
pub struct ChainScheduler {
    /// Chain specifications to schedule
    chains: Vec<ChainSpec>,
    /// Total budget for chain fuzzing
    budget: Duration,
    /// Priority scores per chain (higher = more budget)
    priorities: HashMap<String, f64>,
    /// Minimum budget per chain
    min_budget_per_chain: Duration,
    /// Coverage contribution tracking
    coverage_gains: HashMap<String, u64>,
    /// Near-miss scores (higher = more promising)
    near_miss_scores: HashMap<String, f64>,
    /// Findings per chain
    findings_count: HashMap<String, usize>,
}

/// Allocation of budget to a chain
#[derive(Debug, Clone)]
pub struct ChainAllocation {
    /// The chain spec
    pub spec: ChainSpec,
    /// Allocated time budget
    pub budget: Duration,
    /// Priority score
    pub priority: f64,
}

/// Result of running a chain (for priority updates)
#[derive(Debug, Clone)]
pub struct ChainRunStats {
    /// Chain name
    pub chain_name: String,
    /// Whether any violations were found
    pub found_violation: bool,
    /// New coverage bits discovered
    pub new_coverage: u64,
    /// Near-miss score (0.0 to 1.0)
    pub near_miss_score: f64,
    /// Number of executions
    pub executions: usize,
    /// Time spent
    pub time_spent: Duration,
}

impl ChainScheduler {
    /// Create a new scheduler with the given chains and budget
    pub fn new(chains: Vec<ChainSpec>, budget: Duration) -> Self {
        let mut priorities = HashMap::new();
        for chain in &chains {
            // Start with equal priority
            priorities.insert(chain.name.clone(), 1.0);
        }

        Self {
            chains,
            budget,
            priorities,
            min_budget_per_chain: Duration::from_secs(10),
            coverage_gains: HashMap::new(),
            near_miss_scores: HashMap::new(),
            findings_count: HashMap::new(),
        }
    }

    /// Set the minimum budget per chain
    pub fn with_min_budget(mut self, min: Duration) -> Self {
        self.min_budget_per_chain = min;
        self
    }

    /// Allocate budget across chains based on priorities
    pub fn allocate(&self) -> Vec<ChainAllocation> {
        if self.chains.is_empty() {
            return Vec::new();
        }

        // Calculate total priority
        let total_priority: f64 = self.priorities.values().sum();

        if total_priority == 0.0 {
            // Equal distribution if no priorities
            let per_chain = self.budget.as_millis() as u64 / self.chains.len() as u64;
            return self
                .chains
                .iter()
                .map(|chain| ChainAllocation {
                    spec: chain.clone(),
                    budget: Duration::from_millis(per_chain),
                    priority: 1.0,
                })
                .collect();
        }

        // Calculate minimum guaranteed budget
        let min_total = self.min_budget_per_chain.as_millis() as u64 * self.chains.len() as u64;
        let remaining =
            self.budget.as_millis() as u64 - min_total.min(self.budget.as_millis() as u64);

        self.chains
            .iter()
            .map(|chain| {
                let priority = self.priorities.get(&chain.name).copied().unwrap_or(1.0);
                let priority_share = priority / total_priority;
                let allocated_remaining = (remaining as f64 * priority_share) as u64;
                let total_budget =
                    self.min_budget_per_chain.as_millis() as u64 + allocated_remaining;

                ChainAllocation {
                    spec: chain.clone(),
                    budget: Duration::from_millis(total_budget),
                    priority,
                }
            })
            .collect()
    }

    /// Update priorities based on run results
    pub fn update_priority(&mut self, stats: &ChainRunStats) {
        let current = self
            .priorities
            .get(&stats.chain_name)
            .copied()
            .unwrap_or(1.0);

        // Priority heuristics:
        // 1. Chains with violations get boost
        // 2. Chains with near-misses get moderate boost
        // 3. Chains with coverage gains get small boost
        // 4. Chains with no progress get penalized

        let mut new_priority = current;

        // Boost for finding violations
        if stats.found_violation {
            new_priority *= 1.5;
            *self
                .findings_count
                .entry(stats.chain_name.clone())
                .or_insert(0) += 1;
        }

        // Boost for near-misses
        if stats.near_miss_score > 0.5 {
            new_priority *= 1.0 + (stats.near_miss_score * 0.3);
            self.near_miss_scores
                .insert(stats.chain_name.clone(), stats.near_miss_score);
        }

        // Boost for coverage gains
        if stats.new_coverage > 0 {
            new_priority *= 1.0 + (stats.new_coverage as f64 * 0.01).min(0.2);
            *self
                .coverage_gains
                .entry(stats.chain_name.clone())
                .or_insert(0) += stats.new_coverage;
        }

        // Penalty for no progress
        if !stats.found_violation && stats.new_coverage == 0 && stats.near_miss_score < 0.1 {
            new_priority *= 0.9;
        }

        // Clamp priority
        new_priority = new_priority.clamp(0.1, 10.0);

        self.priorities
            .insert(stats.chain_name.clone(), new_priority);
    }

    /// Get current priority for a chain
    pub fn get_priority(&self, chain_name: &str) -> f64 {
        self.priorities.get(chain_name).copied().unwrap_or(1.0)
    }

    /// Add a new chain to the scheduler
    pub fn add_chain(&mut self, chain: ChainSpec) {
        self.priorities.insert(chain.name.clone(), 1.0);
        self.chains.push(chain);
    }

    /// Remove a chain from the scheduler
    pub fn remove_chain(&mut self, chain_name: &str) {
        self.chains.retain(|c| c.name != chain_name);
        self.priorities.remove(chain_name);
    }

    /// Get chains sorted by priority (highest first)
    pub fn chains_by_priority(&self) -> Vec<&ChainSpec> {
        let mut chains: Vec<_> = self.chains.iter().collect();
        chains.sort_by(|a, b| {
            let pa = self.priorities.get(&a.name).copied().unwrap_or(1.0);
            let pb = self.priorities.get(&b.name).copied().unwrap_or(1.0);
            pb.partial_cmp(&pa).unwrap_or(std::cmp::Ordering::Equal)
        });
        chains
    }

    /// Get scheduler statistics
    pub fn stats(&self) -> SchedulerStats {
        SchedulerStats {
            total_chains: self.chains.len(),
            total_budget: self.budget,
            priorities: self.priorities.clone(),
            coverage_gains: self.coverage_gains.clone(),
            near_miss_scores: self.near_miss_scores.clone(),
            findings_count: self.findings_count.clone(),
        }
    }

    /// Reset priorities to initial state
    pub fn reset_priorities(&mut self) {
        for chain in &self.chains {
            self.priorities.insert(chain.name.clone(), 1.0);
        }
        self.coverage_gains.clear();
        self.near_miss_scores.clear();
    }
}

/// Statistics about the scheduler state
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    /// Number of chains being scheduled
    pub total_chains: usize,
    /// Total budget
    pub total_budget: Duration,
    /// Current priorities per chain
    pub priorities: HashMap<String, f64>,
    /// Coverage gains per chain
    pub coverage_gains: HashMap<String, u64>,
    /// Near-miss scores per chain
    pub near_miss_scores: HashMap<String, f64>,
    /// Findings count per chain
    pub findings_count: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_fuzzer::types::StepSpec;

    fn create_test_chains() -> Vec<ChainSpec> {
        vec![
            ChainSpec::new("chain_a", vec![StepSpec::fresh("circuit_a")]),
            ChainSpec::new("chain_b", vec![StepSpec::fresh("circuit_b")]),
            ChainSpec::new("chain_c", vec![StepSpec::fresh("circuit_c")]),
        ]
    }

    #[test]
    fn test_equal_allocation() {
        let chains = create_test_chains();
        let scheduler = ChainScheduler::new(chains, Duration::from_secs(300));
        let allocations = scheduler.allocate();

        assert_eq!(allocations.len(), 3);
        // Each should get roughly 100 seconds
        for alloc in &allocations {
            assert!(alloc.budget >= Duration::from_secs(90));
            assert!(alloc.budget <= Duration::from_secs(110));
        }
    }

    #[test]
    fn test_priority_update() {
        let chains = create_test_chains();
        let mut scheduler = ChainScheduler::new(chains, Duration::from_secs(300));

        // Update chain_a with a violation
        scheduler.update_priority(&ChainRunStats {
            chain_name: "chain_a".to_string(),
            found_violation: true,
            new_coverage: 10,
            near_miss_score: 0.8,
            executions: 100,
            time_spent: Duration::from_secs(10),
        });

        // chain_a should now have higher priority
        let pa = scheduler.get_priority("chain_a");
        let pb = scheduler.get_priority("chain_b");
        assert!(pa > pb);
    }

    #[test]
    fn test_priority_allocation() {
        let chains = create_test_chains();
        let mut scheduler = ChainScheduler::new(chains, Duration::from_secs(300));

        // Boost chain_a priority
        scheduler.priorities.insert("chain_a".to_string(), 5.0);

        let allocations = scheduler.allocate();

        // chain_a should get more budget
        let alloc_a = allocations
            .iter()
            .find(|a| a.spec.name == "chain_a")
            .unwrap();
        let alloc_b = allocations
            .iter()
            .find(|a| a.spec.name == "chain_b")
            .unwrap();

        assert!(alloc_a.budget > alloc_b.budget);
    }

    #[test]
    fn test_chains_by_priority() {
        let chains = create_test_chains();
        let mut scheduler = ChainScheduler::new(chains, Duration::from_secs(300));

        scheduler.priorities.insert("chain_b".to_string(), 3.0);
        scheduler.priorities.insert("chain_a".to_string(), 1.0);
        scheduler.priorities.insert("chain_c".to_string(), 2.0);

        let sorted = scheduler.chains_by_priority();
        assert_eq!(sorted[0].name, "chain_b");
        assert_eq!(sorted[1].name, "chain_c");
        assert_eq!(sorted[2].name, "chain_a");
    }
}
