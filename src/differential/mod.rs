//! Differential Fuzzing Module
//!
//! Compares outputs across different ZK backends (Circom vs Noir vs Halo2)
//! for the same circuit logic to detect implementation inconsistencies.

pub mod executor;
pub mod report;

use crate::config::Framework;
use crate::executor::{CircuitExecutor, ExecutionResult};
use crate::fuzzer::{FieldElement, TestCase};
use std::collections::HashMap;
use std::sync::Arc;

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
    /// Whether to compare coverage patterns
    pub compare_coverage: bool,
    /// Whether to compare proof generation
    pub compare_proofs: bool,
}

impl Default for DifferentialConfig {
    fn default() -> Self {
        Self {
            backends: vec![Framework::Circom, Framework::Noir],
            num_tests: 1000,
            timing_tolerance_percent: 50.0,
            compare_coverage: true,
            compare_proofs: false,
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
                if self.config.compare_coverage
                    && r1.coverage.coverage_hash != r2.coverage.coverage_hash
                {
                    self.stats.coverage_mismatches += 1;
                    // Don't add to disagreements - coverage differences are less severe
                }
            }
        }

        if disagreements.is_empty() {
            self.stats.all_agreed += 1;
            return None;
        }

        // Determine severity
        let severity = self.assess_severity(&outputs, &disagreements);

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

    /// Get current statistics
    pub fn stats(&self) -> &DifferentialStats {
        &self.stats
    }

    /// Get all findings
    pub fn findings(&self) -> &[DifferentialResult] {
        &self.findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;

    #[test]
    fn test_differential_fuzzer_creation() {
        let config = DifferentialConfig::default();
        let fuzzer = DifferentialFuzzer::new(config);
        assert!(fuzzer.executors.is_empty());
    }

    #[test]
    fn test_differential_comparison() {
        let config = DifferentialConfig {
            backends: vec![Framework::Mock, Framework::Circom],
            num_tests: 10,
            ..Default::default()
        };
        let mut fuzzer = DifferentialFuzzer::new(config);

        // Add identical executors - should agree on everything
        let exec1 = Arc::new(MockCircuitExecutor::new("test", 2, 1));
        let exec2 = Arc::new(MockCircuitExecutor::new("test", 2, 1));

        fuzzer.add_executor(Framework::Mock, exec1);
        fuzzer.add_executor(Framework::Circom, exec2);

        let inputs = vec![FieldElement::zero(), FieldElement::one()];
        let result = fuzzer.compare_backends(&inputs);

        // Same executor configuration should produce same outputs
        assert!(result.is_none() || result.unwrap().disagreeing_backends.is_empty());
    }
}
