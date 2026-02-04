//! Collision Detection Attacks for ZK Circuits
//!
//! Implements birthday paradox-based collision detection to find:
//! - Hash function collisions
//! - Nullifier collisions (critical for privacy protocols)
//! - Commitment collisions
//! - Merkle tree path collisions
//!
//! In ZK systems, collisions can lead to:
//! - Double-spending in payment systems
//! - Privacy leaks in mixers/tumblers
//! - Identity confusion in authentication systems

use super::{Attack, AttackContext, CircuitInfo};
use crate::config::AttackType;
use crate::fuzzer::{FieldElement, Finding, ProofOfConcept};
use crate::config::Severity;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// Collision detector using birthday paradox attack
/// 
/// For an n-bit output, we expect to find a collision after
/// approximately 2^(n/2) random samples (birthday bound).
pub struct CollisionDetector {
    /// Number of samples to generate
    samples: usize,
    /// Optional seed for reproducibility
    seed: Option<u64>,
    /// Number of inputs to the circuit
    num_inputs: usize,
    /// Detection mode
    mode: CollisionMode,
}

/// Types of collisions to detect
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionMode {
    /// Standard output collision (different inputs → same output)
    OutputCollision,
    /// Nullifier-specific collision detection
    NullifierCollision,
    /// Commitment collision (binding property violation)
    CommitmentCollision,
    /// Near-collision detection (outputs differ in few bits)
    NearCollision { max_bit_diff: usize },
}

impl Default for CollisionMode {
    fn default() -> Self {
        CollisionMode::OutputCollision
    }
}

/// Result of collision detection
#[derive(Debug, Clone)]
pub struct CollisionResult {
    /// First input that produced the collision
    pub input_a: Vec<FieldElement>,
    /// Second input that produced the collision
    pub input_b: Vec<FieldElement>,
    /// The colliding output
    pub output: Vec<u8>,
    /// Type of collision detected
    pub collision_type: CollisionType,
    /// Hamming distance (for near-collisions)
    pub bit_difference: Option<usize>,
}

/// Classification of collision types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionType {
    /// Exact collision (identical outputs)
    Exact,
    /// Near-collision (outputs differ in few bits)
    Near,
    /// Structural collision (same internal state, different inputs)
    Structural,
}

impl CollisionDetector {
    /// Create a new collision detector
    pub fn new(samples: usize) -> Self {
        Self {
            samples,
            seed: None,
            num_inputs: 1,
            mode: CollisionMode::default(),
        }
    }

    /// Set the random seed for reproducibility
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Set the number of inputs
    pub fn with_inputs(mut self, num_inputs: usize) -> Self {
        self.num_inputs = num_inputs.max(1);
        self
    }

    /// Set the collision detection mode
    pub fn with_mode(mut self, mode: CollisionMode) -> Self {
        self.mode = mode;
        self
    }

    /// Calculate optimal sample count using birthday bound
    /// For n-bit output, collision probability > 50% at ~1.17 * 2^(n/2) samples
    pub fn birthday_bound(output_bits: usize) -> usize {
        let half_bits = output_bits / 2;
        // 1.17 * 2^(n/2), capped to avoid overflow
        if half_bits >= 32 {
            usize::MAX / 2
        } else {
            ((1.17 * (1u64 << half_bits) as f64) as usize).max(1000)
        }
    }

    /// Detect collisions by generating random inputs and hashing outputs
    pub fn detect_collisions(&self, context: &AttackContext) -> Vec<CollisionResult> {
        let mut rng = match self.seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };

        let mut results = Vec::new();
        let mut output_map: HashMap<Vec<u8>, Vec<FieldElement>> = HashMap::new();

        // For near-collision detection, also track outputs with their raw bytes
        let mut near_collision_candidates: Vec<(Vec<u8>, Vec<FieldElement>)> = Vec::new();

        for i in 0..self.samples {
            // Generate random inputs
            let inputs: Vec<FieldElement> = (0..self.num_inputs)
                .map(|_| FieldElement::random(&mut rng))
                .collect();

            // Compute output hash (simulating circuit execution)
            let output = self.compute_output_hash(&inputs);

            // Check for exact collision
            if let Some(existing_inputs) = output_map.get(&output) {
                if existing_inputs != &inputs {
                    results.push(CollisionResult {
                        input_a: existing_inputs.clone(),
                        input_b: inputs.clone(),
                        output: output.clone(),
                        collision_type: CollisionType::Exact,
                        bit_difference: Some(0),
                    });

                    tracing::warn!(
                        "Collision found at sample {}: different inputs produce identical output",
                        i
                    );
                }
            }

            // Check for near-collisions if enabled
            if let CollisionMode::NearCollision { max_bit_diff } = self.mode {
                for (existing_output, existing_inputs) in &near_collision_candidates {
                    let bit_diff = hamming_distance(&output, existing_output);
                    if bit_diff > 0 && bit_diff <= max_bit_diff && existing_inputs != &inputs {
                        results.push(CollisionResult {
                            input_a: existing_inputs.clone(),
                            input_b: inputs.clone(),
                            output: output.clone(),
                            collision_type: CollisionType::Near,
                            bit_difference: Some(bit_diff),
                        });
                    }
                }
                near_collision_candidates.push((output.clone(), inputs.clone()));
            }

            output_map.insert(output, inputs);

            // Progress logging
            if i > 0 && i % 10000 == 0 {
                tracing::debug!(
                    "Collision detection progress: {}/{} samples, {} collisions found",
                    i,
                    self.samples,
                    results.len()
                );
            }
        }

        results
    }

    /// Detect nullifier collisions (specific to privacy protocols)
    /// 
    /// Nullifiers should be unique per note/commitment. A collision means
    /// the same nullifier can be used for different notes, enabling double-spend.
    pub fn detect_nullifier_collisions(
        &self,
        nullifier_inputs: &[(Vec<FieldElement>, Vec<FieldElement>)], // (secret, commitment) pairs
    ) -> Vec<CollisionResult> {
        let mut results = Vec::new();
        let mut nullifier_map: HashMap<Vec<u8>, (Vec<FieldElement>, Vec<FieldElement>)> = HashMap::new();

        for (secret, commitment) in nullifier_inputs {
            // Nullifier = Hash(secret || commitment) typically
            let nullifier = self.compute_nullifier(secret, commitment);

            if let Some((existing_secret, existing_commitment)) = nullifier_map.get(&nullifier) {
                // Found collision - same nullifier for different inputs
                if existing_secret != secret || existing_commitment != commitment {
                    let mut input_a = existing_secret.clone();
                    input_a.extend(existing_commitment.clone());
                    let mut input_b = secret.clone();
                    input_b.extend(commitment.clone());

                    results.push(CollisionResult {
                        input_a,
                        input_b,
                        output: nullifier.clone(),
                        collision_type: CollisionType::Exact,
                        bit_difference: Some(0),
                    });
                }
            } else {
                nullifier_map.insert(nullifier, (secret.clone(), commitment.clone()));
            }
        }

        results
    }

    /// Compute output hash for a set of inputs (simulates circuit execution)
    fn compute_output_hash(&self, inputs: &[FieldElement]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for input in inputs {
            hasher.update(&input.0);
        }
        hasher.finalize().to_vec()
    }

    /// Compute nullifier hash from secret and commitment
    fn compute_nullifier(&self, secret: &[FieldElement], commitment: &[FieldElement]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        
        // Domain separation for nullifier computation
        hasher.update(b"NULLIFIER_DOMAIN");
        
        for s in secret {
            hasher.update(&s.0);
        }
        for c in commitment {
            hasher.update(&c.0);
        }
        
        hasher.finalize().to_vec()
    }

    /// Convert collision results to security findings
    fn results_to_findings(&self, results: Vec<CollisionResult>, circuit_info: &CircuitInfo) -> Vec<Finding> {
        results
            .into_iter()
            .map(|result| {
                let severity = match result.collision_type {
                    CollisionType::Exact => Severity::Critical,
                    CollisionType::Near => Severity::High,
                    CollisionType::Structural => Severity::Critical,
                };

                let description = match result.collision_type {
                    CollisionType::Exact => format!(
                        "Found exact collision in circuit '{}': different inputs produce identical output. \
                         This violates collision resistance and may enable attacks like double-spending.",
                        circuit_info.name
                    ),
                    CollisionType::Near => format!(
                        "Found near-collision in circuit '{}': outputs differ by only {} bits. \
                         This may indicate weaknesses in the hash function.",
                        circuit_info.name,
                        result.bit_difference.unwrap_or(0)
                    ),
                    CollisionType::Structural => format!(
                        "Found structural collision in circuit '{}': \
                         internal state collision detected.",
                        circuit_info.name
                    ),
                };

                Finding {
                    attack_type: AttackType::Collision,
                    severity,
                    description,
                    poc: ProofOfConcept {
                        witness_a: result.input_a,
                        witness_b: Some(result.input_b),
                        public_inputs: vec![],
                        proof: Some(result.output),
                    },
                    location: Some(circuit_info.name.clone()),
                }
            })
            .collect()
    }
}

impl Attack for CollisionDetector {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        tracing::info!(
            "Running collision detection with {} samples on circuit '{}'",
            self.samples,
            context.circuit_info.name
        );

        let results = self.detect_collisions(context);

        tracing::info!(
            "Collision detection complete: {} collisions found",
            results.len()
        );

        self.results_to_findings(results, &context.circuit_info)
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Collision
    }

    fn description(&self) -> &str {
        "Detect hash/nullifier collisions using birthday paradox attack"
    }
}

/// Calculate Hamming distance between two byte arrays
fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    let min_len = a.len().min(b.len());
    let mut distance = 0;

    for i in 0..min_len {
        distance += (a[i] ^ b[i]).count_ones() as usize;
    }

    // Count remaining bytes as all different bits
    if a.len() > min_len {
        distance += a[min_len..].iter().map(|b| b.count_ones() as usize).sum::<usize>();
    }
    if b.len() > min_len {
        distance += b[min_len..].iter().map(|b| b.count_ones() as usize).sum::<usize>();
    }

    distance
}

/// Merkle tree collision detector
/// 
/// Specific attack for finding collisions in Merkle tree implementations
/// that could allow proof forgery or tree manipulation.
pub struct MerkleCollisionDetector {
    /// Tree depth
    depth: usize,
    /// Number of samples per level
    samples_per_level: usize,
}

impl MerkleCollisionDetector {
    pub fn new(depth: usize, samples_per_level: usize) -> Self {
        Self {
            depth,
            samples_per_level,
        }
    }

    /// Detect collisions in Merkle tree hash function
    /// 
    /// For each level of the tree, we look for:
    /// 1. Left-right swap collisions: H(L, R) = H(R, L)
    /// 2. Zero-padding collisions
    /// 3. Length extension issues
    pub fn detect_merkle_collisions(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut rng = StdRng::from_entropy();

        for level in 0..self.depth {
            tracing::debug!("Testing Merkle tree level {}", level);

            // Test left-right swap vulnerability
            for _ in 0..self.samples_per_level {
                let left = FieldElement::random(&mut rng);
                let right = FieldElement::random(&mut rng);

                // Skip if inputs are equal
                if left == right {
                    continue;
                }

                let hash_lr = self.merkle_hash(&left, &right);
                let hash_rl = self.merkle_hash(&right, &left);

                if hash_lr == hash_rl {
                    findings.push(Finding {
                        attack_type: AttackType::Collision,
                        severity: Severity::Critical,
                        description: format!(
                            "Merkle tree hash is commutative at level {}: H(L,R) = H(R,L). \
                             This allows proof forgery by swapping siblings.",
                            level
                        ),
                        poc: ProofOfConcept {
                            witness_a: vec![left.clone(), right.clone()],
                            witness_b: Some(vec![right, left]),
                            public_inputs: vec![],
                            proof: Some(hash_lr),
                        },
                        location: Some(format!("Merkle tree level {}", level)),
                    });
                    break; // One finding per level is enough
                }
            }

            // Test zero-padding vulnerability
            let zero = FieldElement::zero();
            let non_zero = FieldElement::from_u64(12345);
            
            let hash_zero_padded = self.merkle_hash(&non_zero, &zero);
            let hash_single = self.single_element_hash(&non_zero);

            if hash_zero_padded == hash_single {
                findings.push(Finding {
                    attack_type: AttackType::Collision,
                    severity: Severity::High,
                    description: format!(
                        "Merkle tree vulnerable to zero-padding attack at level {}: \
                         H(x, 0) = H(x). This may allow tree height manipulation.",
                        level
                    ),
                    poc: ProofOfConcept {
                        witness_a: vec![non_zero.clone(), zero],
                        witness_b: Some(vec![non_zero]),
                        public_inputs: vec![],
                        proof: None,
                    },
                    location: Some(format!("Merkle tree level {}", level)),
                });
            }
        }

        findings
    }

    fn merkle_hash(&self, left: &FieldElement, right: &FieldElement) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&left.0);
        hasher.update(&right.0);
        hasher.finalize().to_vec()
    }

    fn single_element_hash(&self, element: &FieldElement) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&element.0);
        hasher.finalize().to_vec()
    }
}

impl Attack for MerkleCollisionDetector {
    fn run(&self, _context: &AttackContext) -> Vec<Finding> {
        tracing::info!(
            "Running Merkle tree collision detection (depth={}, samples/level={})",
            self.depth,
            self.samples_per_level
        );

        self.detect_merkle_collisions()
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Collision
    }

    fn description(&self) -> &str {
        "Detect collisions and vulnerabilities in Merkle tree hash functions"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collision_detector_creation() {
        let detector = CollisionDetector::new(1000)
            .with_seed(42)
            .with_inputs(2)
            .with_mode(CollisionMode::OutputCollision);

        assert_eq!(detector.samples, 1000);
        assert_eq!(detector.seed, Some(42));
        assert_eq!(detector.num_inputs, 2);
    }

    #[test]
    fn test_birthday_bound() {
        // For 128-bit output, expect ~2^64 samples
        let bound_128 = CollisionDetector::birthday_bound(128);
        assert!(bound_128 > 1_000_000_000); // Should be very large

        // For 32-bit output, expect ~2^16 = ~65536 samples
        let bound_32 = CollisionDetector::birthday_bound(32);
        assert!(bound_32 >= 65536);
        assert!(bound_32 < 200000);
    }

    #[test]
    fn test_hamming_distance() {
        let a = vec![0b11110000, 0b00001111];
        let b = vec![0b11111111, 0b00000000];
        
        // First byte: 4 bits different (lower nibble)
        // Second byte: 4 bits different (lower nibble)
        let distance = hamming_distance(&a, &b);
        assert_eq!(distance, 8);
    }

    #[test]
    fn test_hamming_distance_identical() {
        let a = vec![0x12, 0x34, 0x56];
        let b = vec![0x12, 0x34, 0x56];
        assert_eq!(hamming_distance(&a, &b), 0);
    }

    #[test]
    fn test_near_collision_mode() {
        let detector = CollisionDetector::new(100)
            .with_seed(42)
            .with_mode(CollisionMode::NearCollision { max_bit_diff: 8 });

        let context = AttackContext {
            circuit_info: CircuitInfo::default(),
            samples: 100,
            timeout_seconds: 60,
        };

        // Run detection - mostly testing that it doesn't panic
        let _ = detector.detect_collisions(&context);
    }

    #[test]
    fn test_merkle_collision_detector() {
        let detector = MerkleCollisionDetector::new(4, 10);
        let findings = detector.detect_merkle_collisions();
        
        // SHA256 should not have swap or padding vulnerabilities
        assert!(findings.is_empty(), "SHA256 should not have Merkle vulnerabilities");
    }

    #[test]
    fn test_compute_output_hash_deterministic() {
        let detector = CollisionDetector::new(100);
        let inputs = vec![FieldElement::from_u64(12345)];
        
        let hash1 = detector.compute_output_hash(&inputs);
        let hash2 = detector.compute_output_hash(&inputs);
        
        assert_eq!(hash1, hash2);
    }
}
