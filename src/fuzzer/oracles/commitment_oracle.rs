//! Commitment Scheme Oracle
//!
//! Detects vulnerabilities in cryptographic commitment schemes used in ZK circuits:
//! - **Binding Violations**: Different values committed with same commitment
//! - **Hiding Violations**: Commitment reveals information about committed value
//! - **Opening Malleability**: Multiple valid openings for same commitment
//!
//! Common in: Pedersen commitments, hash-based commitments, polynomial commitments

use super::{hash_field_elements, OracleConfig, OracleStats, SemanticOracle};
use std::collections::HashMap;
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity, TestCase};

/// Oracle for detecting commitment scheme vulnerabilities
pub struct CommitmentOracle {
    config: OracleConfig,
    /// Map: commitment -> (value, randomness, witness)
    seen_commitments: HashMap<Vec<u8>, (FieldElement, Option<FieldElement>, Vec<FieldElement>)>,
    /// Map: value -> list of commitments
    value_to_commitments: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    /// Statistics
    stats: OracleStats,
}

impl CommitmentOracle {
    pub fn new(config: OracleConfig) -> Self {
        Self {
            config,
            seen_commitments: HashMap::new(),
            value_to_commitments: HashMap::new(),
            stats: OracleStats::default(),
        }
    }

    /// Extract commitment from output
    /// Convention: commitment is typically a single output signal.
    fn extract_commitment(&self, output: &[FieldElement]) -> Option<Vec<u8>> {
        if output.len() != 1 {
            tracing::debug!(
                "Commitment oracle skipped: expected single commitment output, got {} outputs",
                output.len()
            );
            return None;
        }
        Some(hash_field_elements(std::slice::from_ref(&output[0])))
    }

    /// Extract committed value from inputs
    /// Convention: value is typically first input
    fn extract_value(&self, inputs: &[FieldElement]) -> Option<FieldElement> {
        inputs.first().cloned()
    }

    /// Extract randomness/blinding factor from inputs
    /// Convention: randomness is typically second input
    fn extract_randomness(&self, inputs: &[FieldElement]) -> Option<FieldElement> {
        inputs.get(1).cloned()
    }

    /// Check for binding violation (different values, same commitment)
    fn check_binding(
        &self,
        commitment: &[u8],
        value: &FieldElement,
        inputs: &[FieldElement],
    ) -> Option<Finding> {
        if let Some((prev_value, _, prev_witness)) = self.seen_commitments.get(commitment) {
            if prev_value != value {
                let poc = ProofOfConcept {
                    witness_a: prev_witness.clone(),
                    witness_b: Some(inputs.to_vec()),
                    public_inputs: vec![],
                    proof: None,
                };

                return Some(Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: format!(
                        "COMMITMENT BINDING VIOLATION!\n\
                         Different values produce the same commitment.\n\
                         Value A: {}\n\
                         Value B: {}\n\
                         Commitment: {}\n\n\
                         IMPACT: This breaks the binding property of the commitment scheme.\n\
                         An attacker could open a commitment to any value, enabling:\n\
                         - Double-spending\n\
                         - Fraud in commit-reveal protocols\n\
                         - Auction manipulation",
                        hex::encode(&prev_value.0[..8]),
                        hex::encode(&value.0[..8]),
                        hex::encode(&commitment[..commitment.len().min(16)])
                    ),
                    poc,
                    location: Some("commitment_binding".to_string()),
                    class: None,
                });
            }
        }
        None
    }

    /// Check for hiding violation (commitment reveals value information)
    fn check_hiding(&self, commitment: &[u8], value: &FieldElement) -> Option<Finding> {
        // Heuristic: if commitment contains value bytes, hiding is broken
        let value_bytes = &value.0;

        // Check if significant portion of value appears in commitment
        let overlap = count_overlapping_bytes(commitment, value_bytes);

        if overlap > 8 {
            return Some(Finding {
                attack_type: AttackType::InformationLeakage,
                severity: Severity::High,
                description: format!(
                    "POTENTIAL COMMITMENT HIDING VIOLATION!\n\
                     Commitment contains {} bytes matching the committed value.\n\
                     This may leak information about the committed value.\n\n\
                     IMPACT: The hiding property may be broken.\n\
                     Observers might infer the committed value before opening.",
                    overlap
                ),
                poc: ProofOfConcept {
                    witness_a: vec![value.clone()],
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                },
                location: Some("commitment_hiding".to_string()),
                class: None,
            });
        }

        None
    }

    /// Check for deterministic commitments (should require randomness)
    fn check_determinism(
        &mut self,
        value: &FieldElement,
        commitment: &[u8],
        inputs: &[FieldElement],
    ) -> Option<Finding> {
        let value_hash = hash_field_elements(std::slice::from_ref(value));
        let commitments = self.value_to_commitments.entry(value_hash).or_default();

        // If same value always produces same commitment, randomness might be missing
        if commitments.len() >= 5 && commitments.iter().all(|c| c == commitment) {
            return Some(Finding {
                attack_type: AttackType::WitnessFuzzing,
                severity: Severity::Medium,
                description: "DETERMINISTIC COMMITMENT DETECTED!\n\
                     Same value consistently produces identical commitment.\n\
                     This suggests missing or weak randomness/blinding.\n\n\
                     IMPACT: Without proper randomness, the commitment scheme\n\
                     provides no hiding - observers can check if a commitment\n\
                     is for a specific value by computing the commitment themselves."
                    .to_string(),
                poc: ProofOfConcept {
                    witness_a: inputs.to_vec(),
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                },
                location: Some("commitment_randomness".to_string()),
                class: None,
            });
        }

        if commitments.len() < 100 {
            commitments.push(commitment.to_vec());
        }

        None
    }

    fn maybe_evict(&mut self) {
        if self.seen_commitments.len() > self.config.max_observations {
            self.seen_commitments.clear();
            self.value_to_commitments.clear();
            tracing::debug!("CommitmentOracle: evicted observations");
        }
    }
}

fn count_overlapping_bytes(a: &[u8], b: &[u8]) -> usize {
    let mut count = 0;
    for window_a in a.windows(4) {
        for window_b in b.windows(4) {
            if window_a == window_b {
                count += 4;
            }
        }
    }
    count
}

impl SemanticOracle for CommitmentOracle {
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        self.stats.checks += 1;

        let commitment = self.extract_commitment(output)?;
        let value = self.extract_value(&test_case.inputs)?;
        let randomness = self.extract_randomness(&test_case.inputs);

        // Check 1: Binding violation
        if let Some(finding) = self.check_binding(&commitment, &value, &test_case.inputs) {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Check 2: Hiding violation
        if let Some(finding) = self.check_hiding(&commitment, &value) {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Check 3: Determinism (missing randomness)
        if let Some(finding) = self.check_determinism(&value, &commitment, &test_case.inputs) {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Record observation
        self.seen_commitments
            .insert(commitment, (value, randomness, test_case.inputs.clone()));
        self.stats.observations += 1;

        self.maybe_evict();

        None
    }

    fn name(&self) -> &str {
        "commitment_oracle"
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Underconstrained
    }

    fn reset(&mut self) {
        self.seen_commitments.clear();
        self.value_to_commitments.clear();
        self.stats = OracleStats::default();
    }

    fn stats(&self) -> OracleStats {
        let mut stats = self.stats.clone();
        stats.memory_bytes =
            self.seen_commitments.len() * 96 + self.value_to_commitments.len() * 64;
        stats
    }
}
