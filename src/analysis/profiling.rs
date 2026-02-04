//! Performance Profiling for ZK Circuits
//!
//! Measures and analyzes:
//! - Proof generation time for different inputs
//! - Verification time
//! - Memory usage patterns
//! - Worst-case performance inputs

use crate::executor::CircuitExecutor;
use crate::fuzzer::FieldElement;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Performance profile for a circuit
#[derive(Debug, Clone)]
pub struct PerformanceProfile {
    /// Execution time statistics
    pub execution_stats: TimingStats,
    /// Proof generation statistics
    pub proving_stats: TimingStats,
    /// Verification statistics
    pub verification_stats: TimingStats,
    /// Inputs that caused worst-case performance
    pub worst_case_inputs: Vec<WorstCaseInput>,
    /// Performance recommendations
    pub recommendations: Vec<String>,
}

/// Timing statistics
#[derive(Debug, Clone, Default)]
pub struct TimingStats {
    pub min_us: u64,
    pub max_us: u64,
    pub mean_us: f64,
    pub median_us: u64,
    pub std_dev_us: f64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub sample_count: usize,
}

impl TimingStats {
    pub fn from_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }

        let mut sorted = samples.to_vec();
        sorted.sort_unstable();

        let min_us = sorted[0];
        let max_us = sorted[sorted.len() - 1];
        let mean_us = sorted.iter().sum::<u64>() as f64 / sorted.len() as f64;
        let median_us = sorted[sorted.len() / 2];

        let variance = sorted
            .iter()
            .map(|&x| (x as f64 - mean_us).powi(2))
            .sum::<f64>()
            / sorted.len() as f64;
        let std_dev_us = variance.sqrt();

        let p95_idx = (sorted.len() as f64 * 0.95) as usize;
        let p99_idx = (sorted.len() as f64 * 0.99) as usize;
        let p95_us = sorted[p95_idx.min(sorted.len() - 1)];
        let p99_us = sorted[p99_idx.min(sorted.len() - 1)];

        Self {
            min_us,
            max_us,
            mean_us,
            median_us,
            std_dev_us,
            p95_us,
            p99_us,
            sample_count: sorted.len(),
        }
    }

    /// Check if there's significant timing variation (potential side-channel)
    pub fn has_timing_variation(&self) -> bool {
        if self.mean_us == 0.0 {
            return false;
        }
        let cv = self.std_dev_us / self.mean_us;
        cv > 0.3 // 30% coefficient of variation
    }
}

/// Input that caused worst-case performance
#[derive(Debug, Clone)]
pub struct WorstCaseInput {
    pub inputs: Vec<FieldElement>,
    pub execution_time_us: u64,
    pub category: WorstCaseCategory,
}

/// Category of worst-case performance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorstCaseCategory {
    /// Slowest overall execution
    Slowest,
    /// Slowest proof generation
    SlowestProving,
    /// Slowest verification
    SlowestVerification,
    /// High memory usage
    HighMemory,
    /// Outlier (significantly slower than average)
    Outlier,
}

/// Performance profiler
pub struct Profiler {
    /// Number of samples to collect
    num_samples: usize,
    /// Track worst-case inputs
    track_worst_cases: bool,
    /// Number of worst cases to keep
    num_worst_cases: usize,
    /// Include proof generation in profiling
    profile_proving: bool,
    /// Include verification in profiling
    profile_verification: bool,
}

impl Default for Profiler {
    fn default() -> Self {
        Self {
            num_samples: 1000,
            track_worst_cases: true,
            num_worst_cases: 10,
            profile_proving: true,
            profile_verification: true,
        }
    }
}

impl Profiler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_samples(mut self, count: usize) -> Self {
        self.num_samples = count;
        self
    }

    pub fn with_worst_cases(mut self, count: usize) -> Self {
        self.num_worst_cases = count;
        self
    }

    /// Profile a circuit executor
    pub fn profile(
        &self,
        executor: &Arc<dyn CircuitExecutor>,
        rng: &mut impl Rng,
    ) -> PerformanceProfile {
        let mut execution_times: Vec<u64> = Vec::new();
        let mut proving_times: Vec<u64> = Vec::new();
        let mut verification_times: Vec<u64> = Vec::new();
        let mut worst_cases: Vec<WorstCaseInput> = Vec::new();

        for _ in 0..self.num_samples {
            let inputs: Vec<FieldElement> = (0..executor.num_private_inputs())
                .map(|_| FieldElement::random(rng))
                .collect();

            // Profile execution
            let start = Instant::now();
            let result = executor.execute_sync(&inputs);
            let exec_time = start.elapsed().as_micros() as u64;
            execution_times.push(exec_time);

            // Profile proving
            let proving_time = if self.profile_proving {
                let start = Instant::now();
                let _ = executor.prove(&inputs);
                start.elapsed().as_micros() as u64
            } else {
                0
            };
            proving_times.push(proving_time);

            // Profile verification
            let verification_time = if self.profile_verification && result.success {
                if let Ok(proof) = executor.prove(&inputs) {
                    let public_inputs: Vec<_> = inputs
                        .iter()
                        .take(executor.num_public_inputs())
                        .cloned()
                        .collect();
                    
                    let start = Instant::now();
                    let _ = executor.verify(&proof, &public_inputs);
                    start.elapsed().as_micros() as u64
                } else {
                    0
                }
            } else {
                0
            };
            verification_times.push(verification_time);

            // Track worst cases
            if self.track_worst_cases && worst_cases.len() < self.num_worst_cases {
                worst_cases.push(WorstCaseInput {
                    inputs: inputs.clone(),
                    execution_time_us: exec_time,
                    category: WorstCaseCategory::Slowest,
                });
            } else if self.track_worst_cases {
                // Replace if slower
                if let Some(min_idx) = worst_cases
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, wc)| wc.execution_time_us)
                    .map(|(i, _)| i)
                {
                    if exec_time > worst_cases[min_idx].execution_time_us {
                        worst_cases[min_idx] = WorstCaseInput {
                            inputs,
                            execution_time_us: exec_time,
                            category: WorstCaseCategory::Slowest,
                        };
                    }
                }
            }
        }

        // Sort worst cases by execution time
        worst_cases.sort_by_key(|wc| std::cmp::Reverse(wc.execution_time_us));

        // Generate statistics
        let execution_stats = TimingStats::from_samples(&execution_times);
        let proving_stats = TimingStats::from_samples(&proving_times);
        let verification_stats = TimingStats::from_samples(&verification_times);

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &execution_stats,
            &proving_stats,
            &verification_stats,
        );

        PerformanceProfile {
            execution_stats,
            proving_stats,
            verification_stats,
            worst_case_inputs: worst_cases,
            recommendations,
        }
    }

    fn generate_recommendations(
        &self,
        execution: &TimingStats,
        proving: &TimingStats,
        verification: &TimingStats,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Check for timing variation (potential side-channel)
        if execution.has_timing_variation() {
            recommendations.push(
                "High execution time variation detected. Consider investigating potential \
                 timing side-channels or input-dependent execution paths."
                    .to_string(),
            );
        }

        // Check for slow proving
        if proving.mean_us > 100_000.0 {
            // > 100ms average
            recommendations.push(format!(
                "Average proof generation time ({:.1}ms) is high. Consider circuit optimization \
                 or using recursive proofs for large circuits.",
                proving.mean_us / 1000.0
            ));
        }

        // Check for verification time
        if verification.mean_us > 10_000.0 {
            // > 10ms average
            recommendations.push(format!(
                "Average verification time ({:.1}ms) may be too slow for on-chain use. \
                 Consider using more efficient proof systems or aggregation.",
                verification.mean_us / 1000.0
            ));
        }

        // Check for outliers
        if execution.p99_us > execution.mean_us as u64 * 5 {
            recommendations.push(
                "Significant outliers in execution time detected (p99 > 5x mean). \
                 Some inputs may cause worst-case performance."
                    .to_string(),
            );
        }

        recommendations
    }

    /// Profile with specific test cases
    pub fn profile_with_inputs(
        &self,
        executor: &Arc<dyn CircuitExecutor>,
        test_inputs: &[Vec<FieldElement>],
    ) -> HashMap<String, u64> {
        let mut results = HashMap::new();

        for (i, inputs) in test_inputs.iter().enumerate() {
            let start = Instant::now();
            let _ = executor.execute_sync(inputs);
            let elapsed = start.elapsed().as_micros() as u64;
            results.insert(format!("test_case_{}", i), elapsed);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_timing_stats() {
        let samples = vec![100, 200, 150, 300, 250, 175, 225, 275, 125, 350];
        let stats = TimingStats::from_samples(&samples);

        assert_eq!(stats.min_us, 100);
        assert_eq!(stats.max_us, 350);
        assert_eq!(stats.sample_count, 10);
        assert!(stats.mean_us > 200.0 && stats.mean_us < 230.0);
    }

    #[test]
    fn test_profiler() {
        let profiler = Profiler::new().with_samples(10);
        let executor: Arc<dyn CircuitExecutor> = Arc::new(MockCircuitExecutor::new("test", 2, 1));
        let mut rng = StdRng::seed_from_u64(42);

        let profile = profiler.profile(&executor, &mut rng);

        assert_eq!(profile.execution_stats.sample_count, 10);
        assert!(profile.worst_case_inputs.len() <= 10);
    }
}
