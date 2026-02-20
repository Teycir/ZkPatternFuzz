//! Power Scheduling for Fuzzing
//!
//! Implements AFL-style power schedules to prioritize test cases based on
//! various heuristics like execution speed, coverage, and novelty.

use std::str::FromStr;
use std::time::Duration;

/// Power schedule strategies (inspired by AFL)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerSchedule {
    /// Equal energy for all test cases
    #[default]
    None,
    /// Explore: favor test cases that exercise rare edges
    Explore,
    /// Exploit: favor test cases with recent findings
    Exploit,
    /// Fast: favor faster-executing test cases
    Fast,
    /// COE (Cut-Off Exponential): reduce energy for frequently-hit paths
    Coe,
    /// Lin (Linear): linear scaling based on hit count
    Lin,
    /// Quad (Quadratic): quadratic scaling for emphasis on rare paths
    Quad,
    /// MMOPT: Multi-Metric OPTimization
    Mmopt,
}

impl FromStr for PowerSchedule {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "explore" => Self::Explore,
            "exploit" => Self::Exploit,
            "fast" => Self::Fast,
            "coe" => Self::Coe,
            "lin" => Self::Lin,
            "quad" => Self::Quad,
            "mmopt" => Self::Mmopt,
            _ => Self::None,
        })
    }
}

/// Metrics used for power scheduling decisions
#[derive(Debug, Clone, Default)]
pub struct TestCaseMetrics {
    /// Number of times this test case has been selected
    pub selection_count: u64,
    /// Number of new coverage edges discovered from this test case
    pub new_coverage_count: u64,
    /// Number of findings generated from this test case
    pub findings_count: u64,
    /// Average execution time
    pub avg_execution_time: Duration,
    /// How many times the path was hit by other test cases (rarity)
    pub path_frequency: u64,
    /// Generation number (how many mutations from seed)
    pub generation: u32,
    /// Depth in the mutation tree
    pub depth: u32,
    /// Time since last finding
    pub time_since_finding: Duration,
}

/// Power scheduler that calculates energy for test cases
pub struct PowerScheduler {
    schedule: PowerSchedule,
    /// Base energy for calculations
    base_energy: usize,
    /// Maximum energy cap
    max_energy: usize,
    /// Minimum energy floor
    min_energy: usize,
    /// Global average execution time for normalization
    avg_global_exec_time: Duration,
    /// Total number of edges discovered
    total_edges: u64,
}

impl PowerScheduler {
    pub fn new(schedule: PowerSchedule) -> Self {
        Self {
            schedule,
            base_energy: 100,
            max_energy: 1600,
            min_energy: 1,
            avg_global_exec_time: Duration::from_micros(100),
            total_edges: 0,
        }
    }

    /// Set the power schedule
    pub fn with_schedule(mut self, schedule: PowerSchedule) -> Self {
        self.schedule = schedule;
        self
    }

    /// Set base energy
    pub fn with_base_energy(mut self, energy: usize) -> Self {
        self.base_energy = energy;
        self
    }

    /// Update global statistics
    pub fn update_globals(&mut self, avg_exec_time: Duration, total_edges: u64) {
        self.avg_global_exec_time = avg_exec_time;
        self.total_edges = total_edges;
    }

    /// Calculate energy for a test case based on its metrics
    pub fn calculate_energy(&self, metrics: &TestCaseMetrics) -> usize {
        let raw_energy = match self.schedule {
            PowerSchedule::None => self.base_energy,
            PowerSchedule::Explore => self.explore_energy(metrics),
            PowerSchedule::Exploit => self.exploit_energy(metrics),
            PowerSchedule::Fast => self.fast_energy(metrics),
            PowerSchedule::Coe => self.coe_energy(metrics),
            PowerSchedule::Lin => self.lin_energy(metrics),
            PowerSchedule::Quad => self.quad_energy(metrics),
            PowerSchedule::Mmopt => self.mmopt_energy(metrics),
        };

        raw_energy.clamp(self.min_energy, self.max_energy)
    }

    /// Explore: favor rare paths
    fn explore_energy(&self, metrics: &TestCaseMetrics) -> usize {
        if metrics.path_frequency == 0 {
            return self.max_energy;
        }

        // Inverse relationship with path frequency
        let rarity_factor = (self.total_edges as f64 / metrics.path_frequency as f64).min(16.0);
        (self.base_energy as f64 * rarity_factor) as usize
    }

    /// Exploit: favor test cases that found bugs
    fn exploit_energy(&self, metrics: &TestCaseMetrics) -> usize {
        let finding_bonus = (metrics.findings_count as f64).sqrt() * 4.0;
        let coverage_bonus = (metrics.new_coverage_count as f64).sqrt() * 2.0;

        // Decay based on time since last finding
        let decay = if metrics.time_since_finding.as_secs() > 60 {
            0.5
        } else {
            1.0
        };

        ((self.base_energy as f64 + finding_bonus + coverage_bonus) * decay) as usize
    }

    /// Fast: favor quick test cases
    fn fast_energy(&self, metrics: &TestCaseMetrics) -> usize {
        if metrics.avg_execution_time.is_zero() {
            return self.base_energy;
        }

        // Faster = more energy
        let speed_factor = (self.avg_global_exec_time.as_nanos() as f64
            / metrics.avg_execution_time.as_nanos() as f64)
            .clamp(0.25, 4.0);

        (self.base_energy as f64 * speed_factor) as usize
    }

    /// COE: Cut-Off Exponential - reduce energy for frequently selected cases
    fn coe_energy(&self, metrics: &TestCaseMetrics) -> usize {
        const CUT_OFF: u64 = 16;

        if metrics.selection_count > CUT_OFF {
            // Exponential decay after cut-off
            let decay_steps_u64 = metrics.selection_count.saturating_sub(CUT_OFF) / 8;
            let decay_steps = decay_steps_u64.min(i32::MAX as u64) as i32;
            let decay = 0.5_f64.powi(decay_steps);
            (self.base_energy as f64 * decay).max(self.min_energy as f64) as usize
        } else {
            self.base_energy
        }
    }

    /// Lin: Linear scaling inversely proportional to selection count
    fn lin_energy(&self, metrics: &TestCaseMetrics) -> usize {
        let factor = 1.0 / (1.0 + (metrics.selection_count as f64 / 16.0));
        (self.base_energy as f64 * factor * 2.0) as usize
    }

    /// Quad: Quadratic scaling for emphasis on less-explored cases
    fn quad_energy(&self, metrics: &TestCaseMetrics) -> usize {
        let factor = 1.0 / (1.0 + (metrics.selection_count as f64 / 16.0).powi(2));
        (self.base_energy as f64 * factor * 4.0) as usize
    }

    /// MMOPT: Multi-Metric Optimization - balance multiple factors
    fn mmopt_energy(&self, metrics: &TestCaseMetrics) -> usize {
        // Combine multiple factors with weights
        let coverage_score = (metrics.new_coverage_count as f64 + 1.0).ln();
        let finding_score = (metrics.findings_count as f64 + 1.0) * 2.0;
        let freshness_score = 1.0 / (1.0 + metrics.selection_count as f64 / 32.0);
        let depth_penalty = 1.0 / (1.0 + metrics.depth as f64 / 10.0);
        let generation_penalty = 1.0 / (1.0 + metrics.generation as f64 / 8.0);

        // Speed factor (prefer faster tests)
        let speed_factor = if !metrics.avg_execution_time.is_zero() {
            (self.avg_global_exec_time.as_nanos() as f64
                / metrics.avg_execution_time.as_nanos() as f64)
                .clamp(0.5, 2.0)
        } else {
            1.0
        };

        let combined = self.base_energy as f64
            * (1.0 + coverage_score)
            * (1.0 + finding_score / 10.0)
            * freshness_score
            * depth_penalty
            * generation_penalty
            * speed_factor;

        combined as usize
    }
}

#[cfg(test)]
#[path = "power_schedule_tests.rs"]
mod tests;
