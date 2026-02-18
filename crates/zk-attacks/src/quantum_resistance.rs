//! Post-quantum posture scanning helpers.
//!
//! The detector is source-oriented: it scans circuit source text for usage
//! patterns tied to quantum-vulnerable primitives.

use serde::{Deserialize, Serialize};
use std::path::Path;
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity};

/// Primitive signature configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimitivePattern {
    pub name: String,
    pub severity: Severity,
    pub patterns: Vec<String>,
}

/// Configuration for quantum-resistance scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumResistanceConfig {
    pub vulnerable_primitives: Vec<PrimitivePattern>,
    pub case_sensitive: bool,
}

impl Default for QuantumResistanceConfig {
    fn default() -> Self {
        Self {
            vulnerable_primitives: vec![
                PrimitivePattern {
                    name: "RSA".to_string(),
                    severity: Severity::Critical,
                    patterns: vec!["rsa".to_string(), "rsa_verify".to_string(), "modexp".to_string()],
                },
                PrimitivePattern {
                    name: "ECDSA".to_string(),
                    severity: Severity::Critical,
                    patterns: vec![
                        "ecdsa".to_string(),
                        "ecdsa_verify".to_string(),
                        "secp256".to_string(),
                    ],
                },
                PrimitivePattern {
                    name: "ECDH".to_string(),
                    severity: Severity::High,
                    patterns: vec!["ecdh".to_string(), "shared_secret".to_string()],
                },
                PrimitivePattern {
                    name: "Diffie-Hellman".to_string(),
                    severity: Severity::High,
                    patterns: vec!["diffiehellman".to_string(), "dh_exchange".to_string()],
                },
            ],
            case_sensitive: false,
        }
    }
}

/// Source scanner for quantum-vulnerable primitives.
pub struct QuantumResistanceAttack {
    config: QuantumResistanceConfig,
}

impl QuantumResistanceAttack {
    /// Create a new source scanner.
    pub fn new(config: QuantumResistanceConfig) -> Self {
        Self { config }
    }

    /// Scan a source file and return findings.
    pub fn scan_file(
        &self,
        source_path: &Path,
        witness: &[FieldElement],
    ) -> anyhow::Result<Vec<Finding>> {
        let source = std::fs::read_to_string(source_path)?;
        Ok(self.scan_source(
            &source,
            Some(source_path.display().to_string()),
            witness,
        ))
    }

    /// Scan source text and return findings.
    pub fn scan_source(
        &self,
        source: &str,
        location: Option<String>,
        witness: &[FieldElement],
    ) -> Vec<Finding> {
        let source_cmp = if self.config.case_sensitive {
            source.to_string()
        } else {
            source.to_ascii_lowercase()
        };

        let mut findings = Vec::new();
        for primitive in &self.config.vulnerable_primitives {
            let matched = primitive.patterns.iter().any(|pattern| {
                if self.config.case_sensitive {
                    source_cmp.contains(pattern)
                } else {
                    source_cmp.contains(&pattern.to_ascii_lowercase())
                }
            });

            if !matched {
                continue;
            }

            findings.push(Finding {
                attack_type: AttackType::QuantumResistance,
                severity: primitive.severity,
                description: format!(
                    "Quantum-vulnerable primitive detected in source: {}",
                    primitive.name
                ),
                poc: ProofOfConcept {
                    witness_a: witness.to_vec(),
                    witness_b: None,
                    public_inputs: Vec::new(),
                    proof: None,
                },
                location: location.clone(),
            });
        }

        findings
    }
}

#[cfg(test)]
#[path = "quantum_resistance_tests.rs"]
mod tests;
