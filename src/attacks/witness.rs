//! Witness Generation Fuzzing
//!
//! Tests witness generation for:
//! - Panics with valid inputs
//! - Non-deterministic witness generation
//! - Timing side-channels in witness computation

use super::{Attack, AttackContext};
use crate::config::{AttackType, Severity};
use crate::executor::CircuitExecutor;
use crate::fuzzer::{Finding, FieldElement, ProofOfConcept};
use rand::Rng;
use std::sync::Arc;
use std::time::Instant;

/// Witness generation fuzzer
pub struct WitnessFuzzer {
    /// Number of determinism tests (same input, multiple runs)
    determinism_tests: usize,
    /// Number of timing tests
    timing_tests: usize,
    /// Number of stress tests
    stress_tests: usize,
    /// Timing threshold for considering an input "slow" (microseconds)
    timing_threshold_us: u64,
    /// Coefficient of variation threshold for timing side-channel detection
    timing_cv_threshold: f64,
}

impl Default for WitnessFuzzer {
    fn default() -> Self {
        Self {
            determinism_tests: 100,
            timing_tests: 500,
            stress_tests: 1000,
            timing_threshold_us: 10000, // 10ms
            timing_cv_threshold: 0.5,    // 50% variation is suspicious
        }
    }
}

impl WitnessFuzzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_determinism_tests(mut self, count: usize) -> Self {
        self.determinism_tests = count;
        self
    }

    pub fn with_timing_tests(mut self, count: usize) -> Self {
        self.timing_tests = count;
        self
    }

    /// Run witness fuzzing against an executor
    pub fn fuzz(
        &self,
        executor: &Arc<dyn CircuitExecutor>,
        rng: &mut impl Rng,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Test 1: Determinism - same input should always produce same output
        findings.extend(self.test_determinism(executor, rng));

        // Test 2: Stress test - find inputs that cause failures
        findings.extend(self.test_stress(executor, rng));

        // Test 3: Timing analysis - detect timing side-channels
        findings.extend(self.test_timing(executor, rng));

        findings
    }

    /// Test if witness generation is deterministic
    fn test_determinism(
        &self,
        executor: &Arc<dyn CircuitExecutor>,
        rng: &mut impl Rng,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for _ in 0..self.determinism_tests {
            let inputs: Vec<FieldElement> = (0..executor.num_private_inputs())
                .map(|_| FieldElement::random(rng))
                .collect();

            // Run same input multiple times
            let result1 = executor.execute_sync(&inputs);
            let result2 = executor.execute_sync(&inputs);
            let result3 = executor.execute_sync(&inputs);

            // Check if all results are identical
            if result1.success && result2.success && result3.success {
                if result1.outputs != result2.outputs || result2.outputs != result3.outputs {
                    findings.push(Finding {
                        attack_type: AttackType::Underconstrained,
                        severity: Severity::Critical,
                        description: "Non-deterministic witness generation: same input produces \
                             different outputs across executions".to_string(),
                        poc: ProofOfConcept {
                            witness_a: inputs.clone(),
                            witness_b: None,
                            public_inputs: inputs,
                            proof: None,
                        },
                        location: None,
                    });
                }
            } else if result1.success != result2.success || result2.success != result3.success {
                // Intermittent failures are also suspicious
                findings.push(Finding {
                    attack_type: AttackType::Boundary,
                    severity: Severity::Medium,
                    description: format!(
                        "Intermittent witness generation failure: \
                         success varied across executions (run1={}, run2={}, run3={})",
                        result1.success, result2.success, result3.success
                    ),
                    poc: ProofOfConcept {
                        witness_a: inputs.clone(),
                        witness_b: None,
                        public_inputs: inputs,
                        proof: None,
                    },
                    location: None,
                });
            }
        }

        findings
    }

    /// Stress test witness generation with edge cases
    fn test_stress(
        &self,
        executor: &Arc<dyn CircuitExecutor>,
        rng: &mut impl Rng,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let num_inputs = executor.num_private_inputs();

        // Test cases to try
        let test_cases = self.generate_stress_inputs(num_inputs, rng);

        for (description, inputs) in test_cases {
            // Use catch_unwind equivalent via thread spawn for panic detection
            let executor_clone = executor.clone();
            let inputs_clone = inputs.clone();
            
            let start = Instant::now();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                executor_clone.execute_sync(&inputs_clone)
            }));
            let elapsed = start.elapsed();

            match result {
                Ok(exec_result) => {
                    // Check for extremely slow execution (potential DoS)
                    if elapsed.as_micros() as u64 > self.timing_threshold_us * 10 {
                        findings.push(Finding {
                            attack_type: AttackType::Boundary,
                            severity: Severity::Medium,
                            description: format!(
                                "Extremely slow witness generation ({}): {:?}",
                                description,
                                elapsed
                            ),
                            poc: ProofOfConcept {
                                witness_a: inputs.clone(),
                                witness_b: None,
                                public_inputs: vec![],
                                proof: None,
                            },
                            location: None,
                        });
                    }

                    // Check for unexpected failures on valid-looking inputs
                    if !exec_result.success {
                        tracing::debug!(
                            "Witness generation failed for {}: {:?}",
                            description,
                            exec_result.error
                        );
                    }
                }
                Err(_panic) => {
                    findings.push(Finding {
                        attack_type: AttackType::Boundary,
                        severity: Severity::High,
                        description: format!(
                            "Witness generation panicked on input: {}",
                            description
                        ),
                        poc: ProofOfConcept {
                            witness_a: inputs.clone(),
                            witness_b: None,
                            public_inputs: vec![],
                            proof: None,
                        },
                        location: None,
                    });
                }
            }
        }

        findings
    }

    /// Analyze timing to detect potential side-channels
    fn test_timing(
        &self,
        executor: &Arc<dyn CircuitExecutor>,
        rng: &mut impl Rng,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut timings: Vec<(Vec<FieldElement>, u64)> = Vec::new();

        // Collect timing data
        for _ in 0..self.timing_tests {
            let inputs: Vec<FieldElement> = (0..executor.num_private_inputs())
                .map(|_| FieldElement::random(rng))
                .collect();

            let start = Instant::now();
            let _ = executor.execute_sync(&inputs);
            let elapsed_us = start.elapsed().as_micros() as u64;

            timings.push((inputs, elapsed_us));
        }

        // Analyze timing distribution
        if !timings.is_empty() {
            let times: Vec<f64> = timings.iter().map(|(_, t)| *t as f64).collect();
            let mean = times.iter().sum::<f64>() / times.len() as f64;
            let variance = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / times.len() as f64;
            let std_dev = variance.sqrt();
            let cv = std_dev / mean; // Coefficient of variation

            if cv > self.timing_cv_threshold {
                // High timing variation detected
                let slowest = timings.iter().max_by_key(|(_, t)| *t);
                let fastest = timings.iter().min_by_key(|(_, t)| *t);

                findings.push(Finding {
                    attack_type: AttackType::InformationLeakage,
                    severity: Severity::Medium,
                    description: format!(
                        "Potential timing side-channel detected. \
                         Mean: {:.0}μs, StdDev: {:.0}μs, CV: {:.2}. \
                         Fastest: {}μs, Slowest: {}μs",
                        mean,
                        std_dev,
                        cv,
                        fastest.map(|(_, t)| *t).unwrap_or(0),
                        slowest.map(|(_, t)| *t).unwrap_or(0)
                    ),
                    poc: ProofOfConcept {
                        witness_a: slowest.map(|(i, _)| i.clone()).unwrap_or_default(),
                        witness_b: fastest.map(|(i, _)| i.clone()),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: None,
                });
            }

            // Find inputs that are significantly slower than average
            let threshold = mean + 3.0 * std_dev;
            for (inputs, time) in &timings {
                if (*time as f64) > threshold {
                    findings.push(Finding {
                        attack_type: AttackType::Boundary,
                        severity: Severity::Low,
                        description: format!(
                            "Slow witness generation: {}μs (mean: {:.0}μs, threshold: {:.0}μs)",
                            time, mean, threshold
                        ),
                        poc: ProofOfConcept {
                            witness_a: inputs.clone(),
                            witness_b: None,
                            public_inputs: vec![],
                            proof: None,
                        },
                        location: None,
                    });
                }
            }
        }

        findings
    }

    /// Generate stress test inputs
    fn generate_stress_inputs(
        &self,
        num_inputs: usize,
        rng: &mut impl Rng,
    ) -> Vec<(&'static str, Vec<FieldElement>)> {
        let mut inputs = Vec::new();

        // All zeros
        inputs.push(("all zeros", vec![FieldElement::zero(); num_inputs]));

        // All ones
        inputs.push(("all ones", vec![FieldElement::one(); num_inputs]));

        // All max values
        inputs.push((
            "all max values",
            vec![FieldElement([0xff; 32]); num_inputs],
        ));

        // Alternating zeros and ones
        let alternating: Vec<FieldElement> = (0..num_inputs)
            .map(|i| {
                if i % 2 == 0 {
                    FieldElement::zero()
                } else {
                    FieldElement::one()
                }
            })
            .collect();
        inputs.push(("alternating zero/one", alternating));

        // Random stress inputs
        for _ in 0..self.stress_tests.min(100) {
            let random: Vec<FieldElement> = (0..num_inputs)
                .map(|_| FieldElement::random(rng))
                .collect();
            inputs.push(("random", random));
        }

        inputs
    }
}

impl Attack for WitnessFuzzer {
    fn run(&self, _context: &AttackContext) -> Vec<Finding> {
        Vec::new()
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Underconstrained
    }

    fn description(&self) -> &str {
        "Witness generation fuzzing: tests for panics, non-determinism, and timing side-channels"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockCircuitExecutor;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_witness_fuzzer_creation() {
        let fuzzer = WitnessFuzzer::new()
            .with_determinism_tests(50)
            .with_timing_tests(100);

        assert_eq!(fuzzer.determinism_tests, 50);
        assert_eq!(fuzzer.timing_tests, 100);
    }

    #[test]
    fn test_witness_determinism() {
        let fuzzer = WitnessFuzzer::new().with_determinism_tests(10);
        let executor: Arc<dyn CircuitExecutor> = Arc::new(MockCircuitExecutor::new("test", 2, 1));
        let mut rng = StdRng::seed_from_u64(42);

        let findings = fuzzer.test_determinism(&executor, &mut rng);
        
        // Mock executor should be deterministic
        assert!(findings.is_empty(), "Expected no non-determinism findings");
    }
}
