//! Advanced privacy analysis helpers.
//!
//! This module combines:
//! - output-entropy analysis under private-input perturbations
//! - timing variance checks for metadata/timing leakage hints

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Configuration for advanced privacy analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAdvancedConfig {
    /// Number of randomized samples.
    pub sample_count: usize,
    /// Minimum acceptable output entropy (bits).
    pub entropy_threshold_bits: f64,
    /// Coefficient-of-variation threshold for timing leakage.
    pub timing_cv_threshold: f64,
    /// Enable metadata-leakage entropy checks.
    pub detect_metadata_leakage: bool,
    /// Enable timing leakage checks.
    pub detect_timing_leakage: bool,
    /// Optional deterministic seed.
    pub seed: Option<u64>,
}

impl Default for PrivacyAdvancedConfig {
    fn default() -> Self {
        Self {
            sample_count: 128,
            entropy_threshold_bits: 3.0,
            timing_cv_threshold: 0.25,
            detect_metadata_leakage: true,
            detect_timing_leakage: true,
            seed: None,
        }
    }
}

/// Composite privacy detector.
pub struct PrivacyAdvancedAttack {
    config: PrivacyAdvancedConfig,
    rng: ChaCha8Rng,
}

impl PrivacyAdvancedAttack {
    /// Create a new advanced privacy detector.
    pub fn new(config: PrivacyAdvancedConfig) -> Self {
        let seed = config.seed.unwrap_or_else(rand::random);
        Self {
            config,
            rng: ChaCha8Rng::seed_from_u64(seed),
        }
    }

    /// Run analysis against a circuit executor.
    pub fn run(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> anyhow::Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let sample_count = self.config.sample_count.max(1);

        let mut output_buckets: HashMap<[u8; 32], usize> = HashMap::new();
        let mut timings = Vec::with_capacity(sample_count);

        for _ in 0..sample_count {
            let inputs = mutate_private_inputs(&mut self.rng, executor, base_inputs);
            let started = Instant::now();
            let result = executor.execute_sync(&inputs);
            if !result.success {
                continue;
            }

            let elapsed = if result.execution_time_us > 0 {
                result.execution_time_us as f64
            } else {
                started.elapsed().as_micros() as f64
            };
            timings.push(elapsed.max(1.0));

            let key = output_fingerprint(&result.outputs);
            *output_buckets.entry(key).or_insert(0) += 1;
        }

        if self.config.detect_metadata_leakage {
            let entropy = entropy_bits(&output_buckets);
            if entropy < self.config.entropy_threshold_bits {
                findings.push(Finding {
                    attack_type: AttackType::PrivacyAdvanced,
                    severity: Severity::High,
                    description: format!(
                        "Low output entropy under private-input variation ({:.2} bits < {:.2} bits)",
                        entropy, self.config.entropy_threshold_bits
                    ),
                    poc: ProofOfConcept {
                        witness_a: base_inputs.to_vec(),
                        witness_b: None,
                        public_inputs: Vec::new(),
                        proof: None,
                    },
                    location: Some("privacy:metadata_entropy".to_string()),
                    class: None,
                });
            }
        }

        if self.config.detect_timing_leakage {
            if let Some(cv) = coefficient_of_variation(&timings) {
                if cv >= self.config.timing_cv_threshold {
                    findings.push(Finding {
                        attack_type: AttackType::PrivacyAdvanced,
                        severity: Severity::Medium,
                        description: format!(
                            "Timing variance may leak privacy-sensitive metadata (CV {:.2} >= {:.2})",
                            cv, self.config.timing_cv_threshold
                        ),
                        poc: ProofOfConcept {
                            witness_a: base_inputs.to_vec(),
                            witness_b: None,
                            public_inputs: Vec::new(),
                            proof: None,
                        },
                        location: Some("privacy:timing_variance".to_string()),
                        class: None,
                    });
                }
            }
        }

        Ok(findings)
    }
}

fn mutate_private_inputs(
    rng: &mut ChaCha8Rng,
    executor: &dyn CircuitExecutor,
    base_inputs: &[FieldElement],
) -> Vec<FieldElement> {
    let mut inputs = base_inputs.to_vec();
    let start = executor.num_public_inputs().min(inputs.len());
    let end = start
        .saturating_add(executor.num_private_inputs())
        .min(inputs.len());

    if start < end {
        for value in &mut inputs[start..end] {
            *value = FieldElement::random(rng);
        }
    } else {
        for value in &mut inputs {
            *value = FieldElement::random(rng);
        }
    }
    inputs
}

fn output_fingerprint(outputs: &[FieldElement]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for output in outputs {
        hasher.update(output.0);
    }
    hasher.finalize().into()
}

fn entropy_bits(output_buckets: &HashMap<[u8; 32], usize>) -> f64 {
    let total: usize = output_buckets.values().sum();
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    output_buckets
        .values()
        .map(|count| {
            let p = *count as f64 / total_f;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum()
}

fn coefficient_of_variation(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean <= f64::EPSILON {
        return None;
    }
    let variance = values
        .iter()
        .map(|v| {
            let d = *v - mean;
            d * d
        })
        .sum::<f64>()
        / values.len() as f64;
    Some(variance.sqrt() / mean)
}

#[cfg(test)]
#[path = "privacy_advanced_tests.rs"]
mod tests;
