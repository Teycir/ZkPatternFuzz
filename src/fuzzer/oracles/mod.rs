//! ZK-Specific Bug Detection Oracles
//!
//! This module contains specialized oracles for detecting vulnerabilities
//! unique to zero-knowledge circuits:
//!
//! - **Nullifier Oracle**: Detects nullifier collisions that enable double-spending
//! - **Merkle Oracle**: Detects invalid Merkle proof acceptance
//! - **Commitment Oracle**: Detects commitment scheme violations
//! - **Range Oracle**: Detects range proof bypasses
//!
//! These semantic oracles understand ZK protocol semantics and can detect
//! vulnerabilities that generic fuzzers miss.

mod commitment_oracle;
mod merkle_oracle;
mod nullifier_oracle;
mod range_oracle;

pub use commitment_oracle::CommitmentOracle;
pub use merkle_oracle::MerkleOracle;
pub use nullifier_oracle::NullifierOracle;
pub use range_oracle::RangeProofOracle;
pub use zk_core::{OracleConfig, OracleStats, SemanticOracle};

use zk_core::{FieldElement, Finding, TestCase};

/// Combined oracle that runs multiple semantic checks
pub struct CombinedSemanticOracle {
    oracles: Vec<Box<dyn SemanticOracle>>,
}

impl CombinedSemanticOracle {
    pub fn new() -> Self {
        Self {
            oracles: Vec::new(),
        }
    }

    /// Create with all default oracles enabled
    pub fn with_all_oracles(config: OracleConfig) -> Self {
        let mut combined = Self::new();
        combined.add_oracle(Box::new(NullifierOracle::new(config.clone())));
        combined.add_oracle(Box::new(MerkleOracle::new(config.clone())));
        combined.add_oracle(Box::new(CommitmentOracle::new(config.clone())));
        combined.add_oracle(Box::new(RangeProofOracle::new(config)));
        combined
    }

    pub fn add_oracle(&mut self, oracle: Box<dyn SemanticOracle>) {
        self.oracles.push(oracle);
    }

    /// Check all oracles and return first finding (if any)
    pub fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        for oracle in &mut self.oracles {
            if let Some(finding) = oracle.check(test_case, output) {
                return Some(finding);
            }
        }
        None
    }

    /// Check all oracles and return all findings
    pub fn check_all(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for oracle in &mut self.oracles {
            if let Some(finding) = oracle.check(test_case, output) {
                findings.push(finding);
            }
        }
        findings
    }

    pub fn reset_all(&mut self) {
        for oracle in &mut self.oracles {
            oracle.reset();
        }
    }

    pub fn stats(&self) -> Vec<(&str, OracleStats)> {
        self.oracles.iter().map(|o| (o.name(), o.stats())).collect()
    }
}

impl Default for CombinedSemanticOracle {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to compute entropy of byte slice
pub(crate) fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    // Normalize to 0-1 range (max entropy is 8 bits)
    entropy / 8.0
}

/// Helper to hash field element slice
pub(crate) fn hash_field_elements(elements: &[FieldElement]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for fe in elements {
        hasher.update(fe.0);
    }
    hasher.finalize().to_vec()
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
