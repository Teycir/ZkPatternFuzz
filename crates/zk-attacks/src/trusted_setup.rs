//! Trusted-setup poisoning checks.
//!
//! Detects cases where a proof generated under setup A verifies under setup B,
//! indicating key non-binding or setup contamination.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Configuration for trusted setup checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedSetupConfig {
    /// Whether trusted-setup checks are enabled.
    pub enabled: bool,
    /// Maximum cross-setup attempts.
    pub attempts: usize,
    /// Optional setup artifact path A (runtime wiring uses this).
    pub ptau_file_a: Option<String>,
    /// Optional setup artifact path B (runtime wiring uses this).
    pub ptau_file_b: Option<String>,
    /// Whether to validate setup artifact integrity/sanity before cross-setup proving.
    pub verify_artifact_integrity: bool,
}

impl Default for TrustedSetupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            attempts: 10,
            ptau_file_a: None,
            ptau_file_b: None,
            verify_artifact_integrity: true,
        }
    }
}

impl TrustedSetupConfig {
    /// Parse trusted-setup config from YAML root or `trusted_setup_test` section.
    pub fn from_yaml(config: &serde_yaml::Value) -> Self {
        let section = config.get("trusted_setup_test").unwrap_or(config);
        Self {
            enabled: section
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            attempts: section
                .get("attempts")
                .and_then(|v| v.as_u64())
                .unwrap_or(10)
                .max(1) as usize,
            ptau_file_a: section
                .get("ptau_file_a")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            ptau_file_b: section
                .get("ptau_file_b")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            verify_artifact_integrity: section
                .get("verify_artifact_integrity")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
        }
    }
}

/// First-class trusted-setup checker.
pub struct TrustedSetupAttack {
    config: TrustedSetupConfig,
}

impl TrustedSetupAttack {
    /// Create a new trusted-setup checker.
    pub fn new(config: TrustedSetupConfig) -> Self {
        Self { config }
    }

    /// Borrow current configuration.
    pub fn config(&self) -> &TrustedSetupConfig {
        &self.config
    }

    /// Execute cross-setup verification checks.
    pub fn run(
        &self,
        executor_a: &dyn CircuitExecutor,
        executor_b: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if !self.config.enabled || self.config.attempts == 0 {
            return Vec::new();
        }

        let info = executor_a.circuit_info();
        let mut findings = self.artifact_integrity_findings();

        for (idx, witness) in witnesses.iter().take(self.config.attempts).enumerate() {
            let proof_a = match executor_a.prove(witness) {
                Ok(p) => p,
                Err(err) => {
                    tracing::debug!(
                        "Skipping witness {} due to setup-A proof generation error: {}",
                        idx,
                        err
                    );
                    continue;
                }
            };

            if witness.len() < info.num_public_inputs {
                continue;
            }

            let public_inputs: Vec<FieldElement> = witness[..info.num_public_inputs].to_vec();
            if let Ok(true) = executor_b.verify(&proof_a, &public_inputs) {
                findings.push(Finding {
                    attack_type: AttackType::TrustedSetup,
                    severity: Severity::Critical,
                    description: format!(
                        "Cross-setup verification succeeded: proof from setup A verified under setup B key (witness {})",
                        idx
                    ),
                    poc: ProofOfConcept {
                        witness_a: witness.clone(),
                        witness_b: None,
                        public_inputs,
                        proof: Some(proof_a),
                    },
                    location: Some("trusted_setup:cross_verification".to_string()),
                });
            }
        }

        findings
    }

    fn artifact_integrity_findings(&self) -> Vec<Finding> {
        if !self.config.verify_artifact_integrity {
            return Vec::new();
        }
        let Some(path_a) = self.config.ptau_file_a.as_deref() else {
            return Vec::new();
        };
        let Some(path_b) = self.config.ptau_file_b.as_deref() else {
            return Vec::new();
        };

        let fingerprint_a = match fingerprint_file(path_a) {
            Ok(fp) => fp,
            Err(err) => {
                return vec![artifact_finding(
                    Severity::Medium,
                    format!(
                        "Unable to fingerprint trusted setup artifact A ('{}'): {}",
                        path_a, err
                    ),
                    Some(format!("trusted_setup:artifact:{}", path_a)),
                )];
            }
        };
        let fingerprint_b = match fingerprint_file(path_b) {
            Ok(fp) => fp,
            Err(err) => {
                return vec![artifact_finding(
                    Severity::Medium,
                    format!(
                        "Unable to fingerprint trusted setup artifact B ('{}'): {}",
                        path_b, err
                    ),
                    Some(format!("trusted_setup:artifact:{}", path_b)),
                )];
            }
        };

        let mut findings = Vec::new();
        if fingerprint_a.sha256 == fingerprint_b.sha256 {
            findings.push(artifact_finding(
                Severity::Critical,
                format!(
                    "Trusted setup artifacts are byte-identical (A: '{}', B: '{}'); independent ceremonies are not demonstrated",
                    path_a, path_b
                ),
                Some("trusted_setup:artifact:identical_hash".to_string()),
            ));
        }

        for (label, path, fp) in [("A", path_a, &fingerprint_a), ("B", path_b, &fingerprint_b)] {
            if fp.size < 1024 {
                findings.push(artifact_finding(
                    Severity::High,
                    format!(
                        "Trusted setup artifact {} ('{}') is unusually small ({} bytes)",
                        label, path, fp.size
                    ),
                    Some(format!("trusted_setup:artifact:small:{}", path)),
                ));
            }
            if fp.sample_len > 0 && fp.sample_entropy_bits_per_byte < 2.0 {
                findings.push(artifact_finding(
                    Severity::Medium,
                    format!(
                        "Trusted setup artifact {} ('{}') has low sampled entropy ({:.2} bits/byte)",
                        label, path, fp.sample_entropy_bits_per_byte
                    ),
                    Some(format!("trusted_setup:artifact:entropy:{}", path)),
                ));
            }
        }

        findings
    }
}

#[derive(Debug, Clone)]
struct ArtifactFingerprint {
    size: u64,
    sha256: [u8; 32],
    sample_len: usize,
    sample_entropy_bits_per_byte: f64,
}

fn artifact_finding(severity: Severity, description: String, location: Option<String>) -> Finding {
    Finding {
        attack_type: AttackType::TrustedSetup,
        severity,
        description,
        poc: ProofOfConcept::default(),
        location,
    }
}

fn fingerprint_file(path: &str) -> anyhow::Result<ArtifactFingerprint> {
    const SAMPLE_LIMIT: usize = 64 * 1024;
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut sample_counts = [0usize; 256];
    let mut remaining_sample = SAMPLE_LIMIT;
    let mut buf = [0u8; 8192];

    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        size += read as u64;

        if remaining_sample > 0 {
            let take = read.min(remaining_sample);
            for byte in &buf[..take] {
                sample_counts[*byte as usize] += 1;
            }
            remaining_sample -= take;
        }
    }

    let sample_len = SAMPLE_LIMIT.saturating_sub(remaining_sample);
    let entropy = shannon_entropy_bits_per_byte(&sample_counts, sample_len);
    let sha256: [u8; 32] = hasher.finalize().into();

    Ok(ArtifactFingerprint {
        size,
        sha256,
        sample_len,
        sample_entropy_bits_per_byte: entropy,
    })
}

fn shannon_entropy_bits_per_byte(counts: &[usize; 256], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

/// Backward-compatible detector alias around [`TrustedSetupAttack`].
pub struct SetupPoisoningDetector {
    attack: TrustedSetupAttack,
}

impl Default for SetupPoisoningDetector {
    fn default() -> Self {
        Self {
            attack: TrustedSetupAttack::new(TrustedSetupConfig {
                enabled: true,
                ..TrustedSetupConfig::default()
            }),
        }
    }
}

impl SetupPoisoningDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_attempts(mut self, attempts: usize) -> Self {
        self.attack.config.attempts = attempts.max(1);
        self
    }

    /// Run cross-verification between two setup-backed executors.
    pub fn run(
        &self,
        executor_a: &dyn CircuitExecutor,
        executor_b: &dyn CircuitExecutor,
        witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        self.attack.run(executor_a, executor_b, witnesses)
    }
}

#[cfg(test)]
#[path = "trusted_setup_tests.rs"]
mod tests;
