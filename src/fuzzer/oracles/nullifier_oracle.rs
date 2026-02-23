//! Nullifier Collision Oracle
//!
//! Detects nullifier reuse vulnerabilities in privacy protocols like:
//! - Tornado Cash
//! - Semaphore
//! - Zcash-style shielded transactions
//!
//! Nullifiers must be unique per transaction to prevent double-spending.
//! This oracle detects:
//! - **Collisions**: Different secrets producing the same nullifier
//! - **Non-determinism**: Same secret producing different nullifiers
//! - **Predictability**: Low-entropy nullifiers that can be guessed

use super::{compute_entropy, hash_field_elements, OracleConfig, OracleStats, SemanticOracle};
use std::collections::HashMap;
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity, TestCase};

/// Oracle for detecting nullifier-related vulnerabilities
pub struct NullifierOracle {
    config: OracleConfig,
    /// Map: nullifier_hash -> (secret inputs, transaction_id)
    seen_nullifiers: HashMap<Vec<u8>, (Vec<FieldElement>, u64)>,
    /// Map: secret inputs hash -> nullifier hash
    secret_to_nullifier: HashMap<Vec<u8>, Vec<u8>>,
    /// Transaction counter
    tx_counter: u64,
    /// Statistics
    stats: OracleStats,
}

impl NullifierOracle {
    pub fn new(config: OracleConfig) -> Self {
        Self {
            config,
            seen_nullifiers: HashMap::new(),
            secret_to_nullifier: HashMap::new(),
            tx_counter: 0,
            stats: OracleStats::default(),
        }
    }

    /// Extract nullifier from circuit output
    ///
    /// Common conventions:
    /// - Tornado Cash: output[1] is nullifierHash
    /// - Semaphore: output[0] is root, output[1] is nullifierHash
    /// - Zcash: nullifier is derived from note commitment
    fn extract_nullifier(&self, output: &[FieldElement]) -> Option<Vec<u8>> {
        // Strict rule: require explicit nullifier position (index 1).
        if output.len() >= 2 {
            return Some(hash_field_elements(&output[1..2]));
        }
        tracing::warn!(
            "Nullifier oracle expected at least 2 outputs (root, nullifierHash), got {}",
            output.len()
        );
        None
    }

    /// Extract secret inputs (typically first few private inputs)
    fn extract_secrets(&self, inputs: &[FieldElement]) -> Vec<FieldElement> {
        // Convention: first 1-2 inputs are secrets
        inputs.iter().take(2).cloned().collect()
    }

    /// Check if nullifier has suspiciously low entropy
    fn is_low_entropy_nullifier(&self, nullifier: &[u8]) -> bool {
        if !self.config.check_entropy {
            return false;
        }

        let entropy = compute_entropy(nullifier);
        entropy < self.config.min_entropy_threshold
    }

    /// Detect nullifier collision (different secrets, same nullifier)
    fn check_collision(
        &self,
        nullifier: &[u8],
        secrets: &[FieldElement],
        tx_id: u64,
    ) -> Option<Finding> {
        if let Some((prev_secrets, prev_tx)) = self.seen_nullifiers.get(nullifier) {
            // Check if secrets are different
            if prev_secrets != secrets {
                let poc = ProofOfConcept {
                    witness_a: prev_secrets.clone(),
                    witness_b: Some(secrets.to_vec()),
                    public_inputs: vec![],
                    proof: None,
                };

                return Some(Finding {
                    attack_type: AttackType::InformationLeakage,
                    severity: Severity::Critical,
                    description: format!(
                        "NULLIFIER COLLISION DETECTED!\n\
                         Different secrets produce identical nullifier.\n\
                         Transaction A (tx_{}): secret hash = {}\n\
                         Transaction B (tx_{}): secret hash = {}\n\
                         Nullifier: {}\n\n\
                         IMPACT: This enables double-spending attacks.\n\
                         An attacker can withdraw/spend the same note multiple times.",
                        prev_tx,
                        hex::encode(hash_field_elements(prev_secrets)),
                        tx_id,
                        hex::encode(hash_field_elements(secrets)),
                        hex::encode(&nullifier[..nullifier.len().min(16)])
                    ),
                    poc,
                    location: Some("nullifier_generation".to_string()),
                    class: None,
                });
            }
        }
        None
    }

    /// Detect non-deterministic nullifier generation
    fn check_determinism(&self, nullifier: &[u8], secrets: &[FieldElement]) -> Option<Finding> {
        if !self.config.check_determinism {
            return None;
        }

        let secret_hash = hash_field_elements(secrets);

        if let Some(prev_nullifier) = self.secret_to_nullifier.get(&secret_hash) {
            if prev_nullifier != nullifier {
                let poc = ProofOfConcept {
                    witness_a: secrets.to_vec(),
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                };

                return Some(Finding {
                    attack_type: AttackType::WitnessFuzzing,
                    severity: Severity::High,
                    description: format!(
                        "NON-DETERMINISTIC NULLIFIER GENERATION!\n\
                         Same secrets produce different nullifiers.\n\
                         Secret hash: {}\n\
                         Nullifier A: {}\n\
                         Nullifier B: {}\n\n\
                         IMPACT: This breaks nullifier uniqueness guarantees.\n\
                         Double-spending may be possible through timing attacks.",
                        hex::encode(&secret_hash[..8]),
                        hex::encode(&prev_nullifier[..prev_nullifier.len().min(8)]),
                        hex::encode(&nullifier[..nullifier.len().min(8)])
                    ),
                    poc,
                    location: Some("nullifier_derivation".to_string()),
                    class: None,
                });
            }
        }
        None
    }

    /// Check for predictable/low-entropy nullifiers
    fn check_predictability(&self, nullifier: &[u8], inputs: &[FieldElement]) -> Option<Finding> {
        if !self.is_low_entropy_nullifier(nullifier) {
            return None;
        }

        let entropy = compute_entropy(nullifier);
        let poc = ProofOfConcept {
            witness_a: inputs.to_vec(),
            witness_b: None,
            public_inputs: vec![],
            proof: None,
        };

        Some(Finding {
            attack_type: AttackType::InformationLeakage,
            severity: Severity::Medium,
            description: format!(
                "LOW ENTROPY NULLIFIER DETECTED!\n\
                 Nullifier entropy: {:.2} (threshold: {:.2})\n\
                 Nullifier: {}\n\n\
                 IMPACT: Predictable nullifiers may allow:\n\
                 - Front-running attacks\n\
                 - Transaction correlation\n\
                 - Privacy leaks",
                entropy,
                self.config.min_entropy_threshold,
                hex::encode(&nullifier[..nullifier.len().min(16)])
            ),
            poc,
            location: Some("nullifier_entropy".to_string()),
            class: None,
        })
    }

    /// Evict old observations if we exceed memory limit
    fn maybe_evict(&mut self) {
        if self.seen_nullifiers.len() > self.config.max_observations {
            // Simple eviction: remove oldest half
            let to_keep = self.config.max_observations / 2;
            let mut entries: Vec<_> = self.seen_nullifiers.drain().collect();
            entries.sort_by_key(|(_, (_, tx_id))| *tx_id);
            entries.reverse();
            entries.truncate(to_keep);
            self.seen_nullifiers = entries.into_iter().collect();

            tracing::debug!("NullifierOracle: evicted old observations");
        }
    }
}

impl SemanticOracle for NullifierOracle {
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        self.stats.checks += 1;

        let nullifier = self.extract_nullifier(output)?;
        let secrets = self.extract_secrets(&test_case.inputs);

        self.tx_counter += 1;
        let tx_id = self.tx_counter;

        // Check 1: Collision with different secret
        if let Some(finding) = self.check_collision(&nullifier, &secrets, tx_id) {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Check 2: Non-determinism (same secret, different nullifier)
        if let Some(finding) = self.check_determinism(&nullifier, &secrets) {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Check 3: Predictability
        if let Some(finding) = self.check_predictability(&nullifier, &test_case.inputs) {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Record observation
        let secret_hash = hash_field_elements(&secrets);
        self.seen_nullifiers
            .insert(nullifier.clone(), (secrets.clone(), tx_id));
        self.secret_to_nullifier.insert(secret_hash, nullifier);
        self.stats.observations += 1;

        // Evict if needed
        self.maybe_evict();

        None
    }

    fn name(&self) -> &str {
        "nullifier_collision_oracle"
    }

    fn attack_type(&self) -> AttackType {
        AttackType::InformationLeakage
    }

    fn reset(&mut self) {
        self.seen_nullifiers.clear();
        self.secret_to_nullifier.clear();
        self.tx_counter = 0;
        self.stats = OracleStats::default();
    }

    fn stats(&self) -> OracleStats {
        let mut stats = self.stats.clone();
        stats.memory_bytes = self.seen_nullifiers.len() * 64 + self.secret_to_nullifier.len() * 64;
        stats
    }
}
