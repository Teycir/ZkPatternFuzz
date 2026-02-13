//! Differential Fuzzing Module
//!
//! Compares outputs across different ZK backends (Circom vs Noir vs Halo2)
//! for the same circuit logic to detect implementation inconsistencies.

pub mod executor;
pub mod report;
pub mod translator;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use zk_core::{CircuitExecutor, ExecutionResult, FieldElement, Framework, TestCase};

/// Result of differential testing between backends
#[derive(Debug, Clone)]
pub struct DifferentialResult {
    /// Input that caused the difference
    pub input: Vec<FieldElement>,
    /// Outputs from each backend
    pub backend_outputs: HashMap<Framework, Vec<FieldElement>>,
    /// Which backends disagreed
    pub disagreeing_backends: Vec<(Framework, Framework)>,
    /// Severity assessment
    pub severity: DifferentialSeverity,
    /// Description of the difference
    pub description: String,
}

/// Severity of differential finding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentialSeverity {
    /// Critical: Different outputs for same input
    OutputMismatch,
    /// High: One backend fails while another succeeds
    ExecutionMismatch,
    /// Medium: Different constraint satisfaction patterns
    CoverageMismatch,
    /// Low: Performance differences
    PerformanceMismatch,
    /// Info: Minor timing differences
    TimingVariation,
}

/// Configuration for differential fuzzing
#[derive(Debug, Clone)]
pub struct DifferentialConfig {
    /// Backends to compare
    pub backends: Vec<Framework>,
    /// Number of test cases to run
    pub num_tests: usize,
    /// Tolerance for timing comparisons (percentage)
    pub timing_tolerance_percent: f64,
    /// Minimum timing to consider (microseconds)
    pub timing_min_us: u64,
    /// Minimum absolute timing delta to consider (microseconds)
    pub timing_abs_threshold_us: u64,
    /// Whether to compare coverage patterns
    pub compare_coverage: bool,
    /// Minimum constraints required to compare coverage
    pub coverage_min_constraints: usize,
    /// Jaccard threshold for coverage set overlap
    pub coverage_jaccard_threshold: f64,
    /// Absolute delta threshold for coverage size
    pub coverage_abs_delta_threshold: usize,
    /// Relative delta threshold for coverage size
    pub coverage_rel_delta_threshold: f64,
    /// Whether to compare proof generation
    pub compare_proofs: bool,
    /// Whether to compare execution timing
    pub compare_timing: bool,
}

impl Default for DifferentialConfig {
    fn default() -> Self {
        Self {
            backends: vec![Framework::Circom, Framework::Noir],
            num_tests: 1000,
            timing_tolerance_percent: 50.0,
            timing_min_us: 2_000,
            timing_abs_threshold_us: 5_000,
            compare_coverage: true,
            coverage_min_constraints: 16,
            coverage_jaccard_threshold: 0.5,
            coverage_abs_delta_threshold: 200,
            coverage_rel_delta_threshold: 0.25,
            compare_proofs: false,
            compare_timing: true,
        }
    }
}

/// Differential fuzzer for comparing ZK backends
pub struct DifferentialFuzzer {
    /// Executors for each backend
    executors: HashMap<Framework, Arc<dyn CircuitExecutor>>,
    /// Configuration
    config: DifferentialConfig,
    /// Findings
    findings: Vec<DifferentialResult>,
    /// Statistics
    stats: DifferentialStats,
}

/// Statistics from differential fuzzing
#[derive(Debug, Clone, Default)]
pub struct DifferentialStats {
    pub total_tests: u64,
    pub output_mismatches: u64,
    pub execution_mismatches: u64,
    pub coverage_mismatches: u64,
    pub timing_variations: u64,
    pub all_agreed: u64,
}

impl DifferentialFuzzer {
    /// Create a new differential fuzzer
    pub fn new(config: DifferentialConfig) -> Self {
        Self {
            executors: HashMap::new(),
            config,
            findings: Vec::new(),
            stats: DifferentialStats::default(),
        }
    }

    /// Add an executor for a backend
    pub fn add_executor(&mut self, framework: Framework, executor: Arc<dyn CircuitExecutor>) {
        self.executors.insert(framework, executor);
    }

    /// Run differential fuzzing with generated test cases
    pub fn run(&mut self, test_cases: &[TestCase]) -> Vec<DifferentialResult> {
        let mut results = Vec::new();

        for test_case in test_cases {
            if let Some(finding) = self.compare_backends(&test_case.inputs) {
                results.push(finding.clone());
                self.findings.push(finding);
            }
            self.stats.total_tests += 1;
        }

        results
    }

    /// Compare a single input across all backends
    pub fn compare_backends(&mut self, inputs: &[FieldElement]) -> Option<DifferentialResult> {
        let mut outputs: HashMap<Framework, ExecutionResult> = HashMap::new();

        // Execute on all backends
        for (framework, executor) in &self.executors {
            let result = executor.execute_sync(inputs);
            outputs.insert(*framework, result);
        }

        // Check for disagreements
        let frameworks: Vec<_> = outputs.keys().cloned().collect();
        let mut disagreements = Vec::new();
        let mut coverage_mismatches = Vec::new();
        let mut timing_variations = Vec::new();
        let mut backend_outputs: HashMap<Framework, Vec<FieldElement>> = HashMap::new();

        for (framework, result) in &outputs {
            backend_outputs.insert(*framework, result.outputs.clone());
        }

        // Compare pairs of backends
        for i in 0..frameworks.len() {
            for j in (i + 1)..frameworks.len() {
                let f1 = frameworks[i];
                let f2 = frameworks[j];
                let r1 = &outputs[&f1];
                let r2 = &outputs[&f2];

                // Check execution success mismatch
                if r1.success != r2.success {
                    self.stats.execution_mismatches += 1;
                    disagreements.push((f1, f2));
                    continue;
                }

                // Check output mismatch
                if r1.outputs != r2.outputs {
                    self.stats.output_mismatches += 1;
                    disagreements.push((f1, f2));
                    continue;
                }

                // Check coverage mismatch (if enabled)
                if self.config.compare_coverage && self.coverage_mismatch(r1, r2) {
                    self.stats.coverage_mismatches += 1;
                    coverage_mismatches.push((f1, f2));
                }

                // Check timing variation (if enabled)
                if self.config.compare_timing && self.timing_variation(r1, r2) {
                    self.stats.timing_variations += 1;
                    timing_variations.push((f1, f2));
                }
            }
        }

        if disagreements.is_empty()
            && coverage_mismatches.is_empty()
            && timing_variations.is_empty()
        {
            self.stats.all_agreed += 1;
            return None;
        }

        // Determine severity
        let severity = if !disagreements.is_empty() {
            self.assess_severity(&outputs, &disagreements)
        } else if !coverage_mismatches.is_empty() {
            DifferentialSeverity::CoverageMismatch
        } else {
            DifferentialSeverity::TimingVariation
        };

        if disagreements.is_empty() {
            disagreements.extend(coverage_mismatches);
            disagreements.extend(timing_variations);
        }

        Some(DifferentialResult {
            input: inputs.to_vec(),
            backend_outputs,
            disagreeing_backends: disagreements,
            severity,
            description: self.describe_difference(&outputs),
        })
    }

    fn assess_severity(
        &self,
        outputs: &HashMap<Framework, ExecutionResult>,
        disagreements: &[(Framework, Framework)],
    ) -> DifferentialSeverity {
        // Check for execution mismatches (one succeeds, one fails)
        for (f1, f2) in disagreements {
            let r1 = &outputs[f1];
            let r2 = &outputs[f2];

            if r1.success != r2.success {
                return DifferentialSeverity::ExecutionMismatch;
            }

            if r1.outputs != r2.outputs {
                return DifferentialSeverity::OutputMismatch;
            }
        }

        DifferentialSeverity::CoverageMismatch
    }

    fn describe_difference(&self, outputs: &HashMap<Framework, ExecutionResult>) -> String {
        let mut desc = String::new();

        for (framework, result) in outputs {
            desc.push_str(&format!(
                "{:?}: success={}, outputs={}\n",
                framework,
                result.success,
                result.outputs.len()
            ));
        }

        desc
    }

    fn coverage_mismatch(&self, r1: &ExecutionResult, r2: &ExecutionResult) -> bool {
        if !r1.success || !r2.success {
            return false;
        }
        let s1 = &r1.coverage.satisfied_constraints;
        let s2 = &r2.coverage.satisfied_constraints;
        if s1.is_empty() || s2.is_empty() {
            return false;
        }
        let min_constraints = self.config.coverage_min_constraints;
        if s1.len().min(s2.len()) < min_constraints {
            return false;
        }

        let (jaccard, abs_delta, rel_delta) = coverage_stats(s1, s2);
        if jaccard < self.config.coverage_jaccard_threshold {
            return true;
        }
        if abs_delta > self.config.coverage_abs_delta_threshold {
            return true;
        }
        if rel_delta > self.config.coverage_rel_delta_threshold {
            return true;
        }

        false
    }

    fn timing_variation(&self, r1: &ExecutionResult, r2: &ExecutionResult) -> bool {
        if !r1.success || !r2.success {
            return false;
        }
        let t1 = r1.execution_time_us;
        let t2 = r2.execution_time_us;
        let max_t = t1.max(t2);
        let min_t = t1.min(t2);
        if max_t < self.config.timing_min_us {
            return false;
        }
        let diff = max_t - min_t;
        if diff < self.config.timing_abs_threshold_us {
            return false;
        }
        let diff_pct = (diff as f64 / max_t as f64) * 100.0;
        diff_pct > self.config.timing_tolerance_percent
    }

    /// Get current statistics
    pub fn stats(&self) -> &DifferentialStats {
        &self.stats
    }

    /// Get all findings
    pub fn findings(&self) -> &[DifferentialResult] {
        &self.findings
    }
}

fn coverage_stats(a: &[usize], b: &[usize]) -> (f64, usize, f64) {
    let set_a: HashSet<usize> = a.iter().copied().collect();
    let set_b: HashSet<usize> = b.iter().copied().collect();
    let len_a = set_a.len();
    let len_b = set_b.len();
    let union = set_a.union(&set_b).count();
    let intersection = set_a.intersection(&set_b).count();
    let jaccard = if union == 0 {
        1.0
    } else {
        intersection as f64 / union as f64
    };
    let abs_delta = len_a.abs_diff(len_b);
    let max_len = len_a.max(len_b);
    let rel_delta = if max_len == 0 {
        0.0
    } else {
        abs_delta as f64 / max_len as f64
    };
    (jaccard, abs_delta, rel_delta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::FixtureCircuitExecutor;

    #[test]
    fn test_differential_fuzzer_creation() {
        let config = DifferentialConfig::default();
        let fuzzer = DifferentialFuzzer::new(config);
        assert!(fuzzer.executors.is_empty());
    }

    #[test]
    fn test_differential_comparison() {
        let config = DifferentialConfig {
            backends: vec![Framework::Circom, Framework::Circom],
            num_tests: 10,
            ..Default::default()
        };
        let mut fuzzer = DifferentialFuzzer::new(config);

        // Add identical executors - should agree on everything
        let exec1 = Arc::new(FixtureCircuitExecutor::new("test", 2, 1));
        let exec2 = Arc::new(FixtureCircuitExecutor::new("test", 2, 1));

        fuzzer.add_executor(Framework::Circom, exec1);
        fuzzer.add_executor(Framework::Circom, exec2);

        let inputs = vec![FieldElement::zero(), FieldElement::one()];
        let result = fuzzer.compare_backends(&inputs);

        // Same executor configuration should produce same outputs
        assert!(result.is_none() || result.unwrap().disagreeing_backends.is_empty());
    }

    #[test]
    fn test_coverage_stats_overlap() {
        let a = vec![1, 2, 3, 4];
        let b = vec![3, 4, 5, 6];
        let (jaccard, abs_delta, rel_delta) = coverage_stats(&a, &b);
        assert!((jaccard - 0.3333).abs() < 0.01);
        assert_eq!(abs_delta, 0);
        assert!((rel_delta - 0.0).abs() < 0.001);
    }
}
