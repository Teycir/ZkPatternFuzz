//! Advanced side-channel analysis helpers.
//!
//! This module provides a lightweight composite detector that combines:
//! - timing-variance profiling across randomized private inputs
//! - output-uniqueness analysis as a metadata leakage proxy

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Instant;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Configuration for advanced side-channel analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidechannelAdvancedConfig {
    /// Number of samples for timing analysis.
    pub timing_samples: usize,
    /// Number of samples for metadata-leakage analysis.
    pub leakage_samples: usize,
    /// Coefficient-of-variation threshold to flag timing variance.
    pub timing_cv_threshold: f64,
    /// Minimum unique-output ratio expected for safe behavior.
    pub leakage_uniqueness_threshold: f64,
    /// Enable timing-variance detection.
    pub detect_timing: bool,
    /// Enable metadata-leakage detection.
    pub detect_leakage: bool,
    /// Optional deterministic seed.
    pub seed: Option<u64>,
}

impl Default for SidechannelAdvancedConfig {
    fn default() -> Self {
        Self {
            timing_samples: 128,
            leakage_samples: 128,
            timing_cv_threshold: 0.25,
            leakage_uniqueness_threshold: 0.35,
            detect_timing: true,
            detect_leakage: true,
            seed: None,
        }
    }
}

/// Composite side-channel detector.
pub struct SidechannelAdvancedAttack {
    config: SidechannelAdvancedConfig,
    rng: ChaCha8Rng,
}

impl SidechannelAdvancedAttack {
    /// Create a new advanced side-channel detector.
    pub fn new(config: SidechannelAdvancedConfig) -> Self {
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

        if self.config.detect_timing {
            let mut timings = Vec::with_capacity(self.config.timing_samples.max(1));
            for _ in 0..self.config.timing_samples.max(1) {
                let inputs = self.mutate_private_inputs(executor, base_inputs);
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
            }

            if let Some(cv) = coefficient_of_variation(&timings) {
                if cv >= self.config.timing_cv_threshold {
                    findings.push(Finding {
                        attack_type: AttackType::SidechannelAdvanced,
                        severity: Severity::Medium,
                        description: format!(
                            "Timing variability indicates potential side-channel leakage (CV {:.2} >= {:.2})",
                            cv, self.config.timing_cv_threshold
                        ),
                        poc: ProofOfConcept {
                            witness_a: base_inputs.to_vec(),
                            witness_b: None,
                            public_inputs: Vec::new(),
                            proof: None,
                        },
                        location: Some("sidechannel:timing_variance".to_string()),
                        class: None,
                    });
                }
            }
        }

        if self.config.detect_leakage {
            let mut seen = HashSet::new();
            let mut successful = 0usize;
            for _ in 0..self.config.leakage_samples.max(1) {
                let inputs = self.mutate_private_inputs(executor, base_inputs);
                let result = executor.execute_sync(&inputs);
                if !result.success {
                    continue;
                }
                successful += 1;
                seen.insert(output_fingerprint(&result.outputs));
            }

            if successful > 1 {
                let uniqueness = seen.len() as f64 / successful as f64;
                if uniqueness < self.config.leakage_uniqueness_threshold {
                    findings.push(Finding {
                        attack_type: AttackType::SidechannelAdvanced,
                        severity: Severity::High,
                        description: format!(
                            "Low output uniqueness under private-input variation (ratio {:.2} < {:.2})",
                            uniqueness, self.config.leakage_uniqueness_threshold
                        ),
                        poc: ProofOfConcept {
                            witness_a: base_inputs.to_vec(),
                            witness_b: None,
                            public_inputs: Vec::new(),
                            proof: None,
                        },
                        location: Some("sidechannel:metadata_leakage".to_string()),
                        class: None,
                    });
                }
            }
        }

        Ok(findings)
    }

    fn mutate_private_inputs(
        &mut self,
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
                *value = FieldElement::random(&mut self.rng);
            }
        } else {
            for value in &mut inputs {
                *value = FieldElement::random(&mut self.rng);
            }
        }

        inputs
    }
}

fn output_fingerprint(outputs: &[FieldElement]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for output in outputs {
        hasher.update(output.0);
    }
    hasher.finalize().into()
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
#[path = "sidechannel_advanced_tests.rs"]
mod tests;
