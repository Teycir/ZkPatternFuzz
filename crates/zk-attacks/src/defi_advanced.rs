//! Advanced DeFi/protocol attack helpers.
//!
//! This module provides lightweight composite checks for:
//! - transaction ordering sensitivity (MEV-adjacent risk)
//! - low output entropy under private-input perturbation (front-running signal)

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Configuration for advanced DeFi/protocol analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefiAdvancedConfig {
    /// Number of order permutations to test.
    pub ordering_permutations: usize,
    /// Difference ratio threshold for ordering-sensitivity findings.
    pub ordering_delta_threshold: f64,
    /// Number of randomized samples for front-running signal checks.
    pub leakage_samples: usize,
    /// Minimum acceptable output entropy for front-running resistance.
    pub entropy_threshold_bits: f64,
    /// Enable ordering-sensitivity detection.
    pub detect_ordering: bool,
    /// Enable front-running signal detection.
    pub detect_front_running_signals: bool,
    /// Optional deterministic seed.
    pub seed: Option<u64>,
}

impl Default for DefiAdvancedConfig {
    fn default() -> Self {
        Self {
            ordering_permutations: 32,
            ordering_delta_threshold: 0.20,
            leakage_samples: 64,
            entropy_threshold_bits: 2.5,
            detect_ordering: true,
            detect_front_running_signals: true,
            seed: None,
        }
    }
}

/// Composite DeFi/protocol detector.
pub struct DefiAdvancedAttack {
    config: DefiAdvancedConfig,
    rng: ChaCha8Rng,
}

impl DefiAdvancedAttack {
    /// Create a new advanced DeFi detector.
    pub fn new(config: DefiAdvancedConfig) -> Self {
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

        if self.config.detect_ordering {
            let baseline = executor.execute_sync(base_inputs);
            if baseline.success && base_inputs.len() > 1 {
                for _ in 0..self.config.ordering_permutations.max(1) {
                    let candidate = self.permute_inputs(base_inputs);
                    if candidate == base_inputs {
                        continue;
                    }

                    let result = executor.execute_sync(&candidate);
                    if !result.success {
                        continue;
                    }

                    let delta = output_difference_ratio(&baseline.outputs, &result.outputs);
                    if delta >= self.config.ordering_delta_threshold {
                        findings.push(Finding {
                            attack_type: AttackType::DefiAdvanced,
                            severity: Severity::High,
                            description: format!(
                                "Ordering sensitivity detected in execution outputs (delta {:.2} >= {:.2})",
                                delta, self.config.ordering_delta_threshold
                            ),
                            poc: ProofOfConcept {
                                witness_a: candidate,
                                witness_b: Some(base_inputs.to_vec()),
                                public_inputs: Vec::new(),
                                proof: None,
                            },
                            location: Some("defi:ordering_dependency".to_string()),
                            class: None,
                        });
                        break;
                    }
                }
            }
        }

        if self.config.detect_front_running_signals {
            let mut output_buckets: HashMap<[u8; 32], usize> = HashMap::new();
            for _ in 0..self.config.leakage_samples.max(1) {
                let candidate = self.mutate_private_inputs(executor, base_inputs);
                let result = executor.execute_sync(&candidate);
                if !result.success {
                    continue;
                }
                let key = output_fingerprint(&result.outputs);
                *output_buckets.entry(key).or_insert(0) += 1;
            }

            let entropy = entropy_bits(&output_buckets);
            if entropy < self.config.entropy_threshold_bits {
                findings.push(Finding {
                    attack_type: AttackType::DefiAdvanced,
                    severity: Severity::Medium,
                    description: format!(
                        "Low output entropy may enable front-running signal extraction ({:.2} bits < {:.2})",
                        entropy, self.config.entropy_threshold_bits
                    ),
                    poc: ProofOfConcept {
                        witness_a: base_inputs.to_vec(),
                        witness_b: None,
                        public_inputs: Vec::new(),
                        proof: None,
                    },
                    location: Some("defi:front_running_signal".to_string()),
                    class: None,
                });
            }
        }

        Ok(findings)
    }

    fn mutate_private_inputs(
        &mut self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
    ) -> Vec<FieldElement> {
        let mut candidate = base_inputs.to_vec();
        let start = executor.num_public_inputs().min(candidate.len());
        let end = start
            .saturating_add(executor.num_private_inputs())
            .min(candidate.len());

        if start < end {
            for value in &mut candidate[start..end] {
                *value = FieldElement::random(&mut self.rng);
            }
        } else {
            for value in &mut candidate {
                *value = FieldElement::random(&mut self.rng);
            }
        }

        candidate
    }

    fn permute_inputs(&mut self, base_inputs: &[FieldElement]) -> Vec<FieldElement> {
        let mut indices: Vec<usize> = (0..base_inputs.len()).collect();
        indices.shuffle(&mut self.rng);
        indices
            .into_iter()
            .map(|idx| base_inputs[idx].clone())
            .collect()
    }
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

fn output_difference_ratio(a: &[FieldElement], b: &[FieldElement]) -> f64 {
    let len = a.len().max(b.len());
    if len == 0 {
        return 0.0;
    }
    let mut differing = 0usize;
    for idx in 0..len {
        let left = a.get(idx);
        let right = b.get(idx);
        if left != right {
            differing += 1;
        }
    }
    differing as f64 / len as f64
}

#[cfg(test)]
#[path = "defi_advanced_tests.rs"]
mod tests;
