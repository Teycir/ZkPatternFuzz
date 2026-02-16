//! Merkle Proof Soundness Oracle
//!
//! Detects invalid Merkle proof acceptance in ZK circuits.
//! Common vulnerabilities include:
//! - **Path Length Bypass**: Circuit accepts shorter/longer paths than expected
//! - **Sibling Order Malleability**: Same proof accepted with swapped siblings
//! - **Root Validation Skip**: Proof verified without checking against claimed root
//! - **Multiple Valid Paths**: Different paths lead to same (root, leaf) pair
//!
//! Used in: Tornado Cash, Semaphore, Zcash, rollups

use super::{hash_field_elements, OracleConfig, OracleStats, SemanticOracle};
use std::collections::HashMap;
use zk_core::{AttackType, FieldElement, Finding, ProofOfConcept, Severity, TestCase};

/// Oracle for detecting Merkle proof vulnerabilities
pub struct MerkleOracle {
    config: OracleConfig,
    /// Expected Merkle tree depth (None = detect automatically)
    expected_depth: Option<usize>,
    /// Map: (root, leaf) -> list of proof paths
    verified_pairs: HashMap<(Vec<u8>, Vec<u8>), Vec<ProofPath>>,
    /// Track path lengths seen
    path_lengths: HashMap<usize, u64>,
    /// Statistics
    stats: OracleStats,
}

/// Represents a Merkle proof path
#[derive(Debug, Clone)]
struct ProofPath {
    /// Path elements (siblings)
    elements: Vec<FieldElement>,
    /// Input witness for reproduction
    witness: Vec<FieldElement>,
}

impl MerkleOracle {
    pub fn new(config: OracleConfig) -> Self {
        Self {
            config,
            expected_depth: None,
            verified_pairs: HashMap::new(),
            path_lengths: HashMap::new(),
            stats: OracleStats::default(),
        }
    }

    /// Set expected tree depth (enables path length validation)
    pub fn with_expected_depth(mut self, depth: usize) -> Self {
        self.expected_depth = Some(depth);
        self
    }

    /// Extract root from output (typically first element)
    fn extract_root(&self, output: &[FieldElement]) -> Option<Vec<u8>> {
        output
            .first()
            .map(|fe| hash_field_elements(std::slice::from_ref(fe)))
    }

    /// Extract leaf from inputs (typically first input)
    fn extract_leaf(&self, inputs: &[FieldElement]) -> Option<Vec<u8>> {
        inputs
            .first()
            .map(|fe| hash_field_elements(std::slice::from_ref(fe)))
    }

    /// Extract path elements from inputs
    /// Convention: path elements are typically inputs[1..depth+1]
    fn extract_path_elements(&self, inputs: &[FieldElement]) -> Vec<FieldElement> {
        if inputs.len() <= 1 {
            return Vec::new();
        }

        // Heuristic: path elements are middle portion of inputs
        // After leaf (inputs[0]) and before path indices
        let potential_depth = (inputs.len() - 1) / 2;
        if potential_depth == 0 {
            return inputs[1..].to_vec();
        }

        inputs[1..=potential_depth].to_vec()
    }

    /// Extract path indices from inputs (left/right at each level)
    fn extract_path_indices(&self, inputs: &[FieldElement]) -> Vec<bool> {
        if inputs.len() <= 1 {
            return Vec::new();
        }

        let potential_depth = (inputs.len() - 1) / 2;
        if potential_depth == 0 || inputs.len() <= potential_depth + 1 {
            return Vec::new();
        }

        // Path indices are typically after path elements
        inputs[potential_depth + 1..]
            .iter()
            .map(|fe| !fe.is_zero())
            .collect()
    }

    /// Check for path length bypass vulnerability
    fn check_path_length(
        &mut self,
        path_elements: &[FieldElement],
        inputs: &[FieldElement],
    ) -> Option<Finding> {
        let path_len = path_elements.len();

        // Track path lengths
        *self.path_lengths.entry(path_len).or_insert(0) += 1;

        // If expected depth is set, validate
        if let Some(expected) = self.expected_depth {
            if path_len != expected {
                let poc = ProofOfConcept {
                    witness_a: inputs.to_vec(),
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                };

                return Some(Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: format!(
                        "MERKLE PATH LENGTH BYPASS!\n\
                         Circuit accepts path of length {}, expected {}.\n\n\
                         IMPACT: An attacker could:\n\
                         - Forge inclusion proofs for non-existent leaves\n\
                         - Create proofs for subtrees instead of leaves\n\
                         - Bypass membership verification entirely",
                        path_len, expected
                    ),
                    poc,
                    location: Some("merkle_path_validation".to_string()),
                });
            }
        }

        // Heuristic: if we've seen multiple different path lengths, warn
        if self.path_lengths.len() > 1 && self.stats.checks > 100 {
            let lengths: Vec<_> = self.path_lengths.keys().collect();
            if lengths.len() == 2 {
                // Auto-detect expected depth from most common length
                let (len1, count1) = self.path_lengths.iter().next().unwrap();
                let (len2, count2) = self.path_lengths.iter().nth(1).unwrap();

                // If one is much more common, the other might be a bypass
                if *count1 > *count2 * 10 && path_len == *len2 {
                    return Some(self.make_path_length_finding(*len2, *len1, inputs));
                } else if *count2 > *count1 * 10 && path_len == *len1 {
                    return Some(self.make_path_length_finding(*len1, *len2, inputs));
                }
            }
        }

        None
    }

    fn make_path_length_finding(
        &self,
        actual: usize,
        expected: usize,
        inputs: &[FieldElement],
    ) -> Finding {
        Finding {
            attack_type: AttackType::Underconstrained,
            severity: Severity::High,
            description: format!(
                "POTENTIAL MERKLE PATH LENGTH BYPASS!\n\
                 Circuit accepts path of length {} (rare), expected {} (common).\n\
                 Verify that path length is properly constrained.",
                actual, expected
            ),
            poc: ProofOfConcept {
                witness_a: inputs.to_vec(),
                witness_b: None,
                public_inputs: vec![],
                proof: None,
            },
            location: Some("merkle_path_validation".to_string()),
        }
    }

    /// Check for multiple valid paths to same (root, leaf)
    fn check_multiple_paths(
        &mut self,
        root: &[u8],
        leaf: &[u8],
        path: ProofPath,
        inputs: &[FieldElement],
    ) -> Option<Finding> {
        let key = (root.to_vec(), leaf.to_vec());

        let paths = self.verified_pairs.entry(key.clone()).or_default();

        // Check if we've seen a different path for same (root, leaf)
        for existing in paths.iter() {
            if !paths_equal(&existing.elements, &path.elements) {
                let poc = ProofOfConcept {
                    witness_a: existing.witness.clone(),
                    witness_b: Some(inputs.to_vec()),
                    public_inputs: vec![],
                    proof: None,
                };

                return Some(Finding {
                    attack_type: AttackType::Underconstrained,
                    severity: Severity::Critical,
                    description: format!(
                        "MULTIPLE MERKLE PATHS ACCEPTED!\n\
                         Different proof paths validate for same (root, leaf).\n\
                         Root: {}\n\
                         Leaf: {}\n\
                         Path A length: {}\n\
                         Path B length: {}\n\n\
                         IMPACT: This indicates missing constraints in Merkle verification.\n\
                         Attackers may forge proofs for arbitrary leaves.",
                        hex::encode(&root[..root.len().min(8)]),
                        hex::encode(&leaf[..leaf.len().min(8)]),
                        existing.elements.len(),
                        path.elements.len()
                    ),
                    poc,
                    location: Some("merkle_proof_uniqueness".to_string()),
                });
            }
        }

        // Record this path
        if paths.len() < 10 {
            // Limit stored paths per (root, leaf)
            paths.push(path);
        }

        None
    }

    /// Check for sibling order malleability
    fn check_sibling_order(
        &self,
        path_elements: &[FieldElement],
        _path_indices: &[bool],
        inputs: &[FieldElement],
    ) -> Option<Finding> {
        // Check if swapping siblings at any level would produce the same root
        // This is a heuristic - we look for symmetric patterns

        if path_elements.len() < 2 {
            return None;
        }

        // Check for identical siblings (common bug pattern)
        for (i, window) in path_elements.windows(2).enumerate() {
            if window[0] == window[1] {
                return Some(Finding {
                    attack_type: AttackType::WitnessFuzzing,
                    severity: Severity::Medium,
                    description: format!(
                        "IDENTICAL MERKLE SIBLINGS DETECTED!\n\
                         Path elements at positions {} and {} are identical.\n\
                         This may indicate:\n\
                         - Improper constraint on sibling selection\n\
                        - Hash collision in tree construction\n\
                         - Potential sibling order malleability",
                        i,
                        i + 1
                    ),
                    poc: ProofOfConcept {
                        witness_a: inputs.to_vec(),
                        witness_b: None,
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: Some(format!("merkle_level_{}", i)),
                });
            }
        }

        None
    }

    fn maybe_evict(&mut self) {
        if self.verified_pairs.len() > self.config.max_observations {
            self.verified_pairs.clear();
            tracing::debug!("MerkleOracle: evicted observations");
        }
    }
}

fn paths_equal(a: &[FieldElement], b: &[FieldElement]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| x == y)
}

impl SemanticOracle for MerkleOracle {
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        self.stats.checks += 1;

        let root = self.extract_root(output)?;
        let leaf = self.extract_leaf(&test_case.inputs)?;
        let path_elements = self.extract_path_elements(&test_case.inputs);
        let path_indices = self.extract_path_indices(&test_case.inputs);

        // Check 1: Path length validation
        if let Some(finding) = self.check_path_length(&path_elements, &test_case.inputs) {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Check 2: Sibling order issues
        if let Some(finding) =
            self.check_sibling_order(&path_elements, &path_indices, &test_case.inputs)
        {
            self.stats.findings += 1;
            return Some(finding);
        }

        // Check 3: Multiple valid paths
        let proof_path = ProofPath {
            elements: path_elements,
            witness: test_case.inputs.clone(),
        };

        if let Some(finding) =
            self.check_multiple_paths(&root, &leaf, proof_path, &test_case.inputs)
        {
            self.stats.findings += 1;
            return Some(finding);
        }

        self.stats.observations += 1;
        self.maybe_evict();

        None
    }

    fn name(&self) -> &str {
        "merkle_soundness_oracle"
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Underconstrained
    }

    fn reset(&mut self) {
        self.verified_pairs.clear();
        self.path_lengths.clear();
        self.stats = OracleStats::default();
    }

    fn stats(&self) -> OracleStats {
        let mut stats = self.stats.clone();
        stats.memory_bytes = self.verified_pairs.len() * 128;
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_merkle_test_case(leaf: u64, path_elements: &[u64], path_indices: &[u64]) -> TestCase {
        let mut inputs = vec![FieldElement::from_u64(leaf)];
        for &elem in path_elements {
            inputs.push(FieldElement::from_u64(elem));
        }
        for &idx in path_indices {
            inputs.push(FieldElement::from_u64(idx));
        }
        TestCase {
            inputs,
            expected_output: None,
            metadata: Default::default(),
        }
    }

    #[test]
    fn test_no_issue_normal_proof() {
        let config = OracleConfig::default();
        let mut oracle = MerkleOracle::new(config).with_expected_depth(3);

        let tc = make_merkle_test_case(123, &[1, 2, 3], &[0, 1, 0]);
        let output = vec![FieldElement::from_u64(999)]; // root

        assert!(oracle.check(&tc, &output).is_none());
    }

    #[test]
    fn test_path_length_bypass_detected() {
        let config = OracleConfig::default();
        let mut oracle = MerkleOracle::new(config).with_expected_depth(3);

        // Path with only 2 elements instead of 3
        let tc = make_merkle_test_case(123, &[1, 2], &[0, 1]);
        let output = vec![FieldElement::from_u64(999)];

        let finding = oracle.check(&tc, &output);
        assert!(finding.is_some());
        assert!(finding.unwrap().description.contains("PATH LENGTH"));
    }

    #[test]
    fn test_multiple_paths_detected() {
        let config = OracleConfig::default();
        let mut oracle = MerkleOracle::new(config);

        // Same root, same leaf, different paths
        let tc1 = make_merkle_test_case(100, &[1, 2, 3], &[0, 0, 0]);
        let tc2 = make_merkle_test_case(100, &[4, 5, 6], &[1, 1, 1]);

        // Same output (root)
        let output = vec![FieldElement::from_u64(999)];

        // First should pass
        assert!(oracle.check(&tc1, &output).is_none());

        // Second with different path should detect issue
        let finding = oracle.check(&tc2, &output);
        assert!(finding.is_some());
        assert!(finding.unwrap().description.contains("MULTIPLE"));
    }

    #[test]
    fn test_identical_siblings_warning() {
        let config = OracleConfig::default();
        let mut oracle = MerkleOracle::new(config);

        // Path with identical consecutive siblings
        let tc = make_merkle_test_case(100, &[5, 5, 3], &[0, 1, 0]);
        let output = vec![FieldElement::from_u64(999)];

        let finding = oracle.check(&tc, &output);
        assert!(finding.is_some());
        assert!(finding.unwrap().description.contains("IDENTICAL"));
    }
}
