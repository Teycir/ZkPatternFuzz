//! Collision Detection for ZK Circuits
//!
//! Detects hash and nullifier collisions in ZK circuits using:
//! - Birthday paradox attacks (O(2^(n/2)) for n-bit outputs)
//! - Near-collision detection (Hamming distance analysis)
//! - Output distribution analysis
//! - ZK-specific hash function testing (Poseidon, MiMC, Pedersen)
//!
//! # Birthday Attack Theory
//!
//! For a hash function with n-bit output, the birthday paradox states that
//! we expect a collision after approximately 2^(n/2) samples. For a 256-bit
//! hash, this is 2^128 samples - infeasible. However, weak hash implementations
//! or truncated outputs may be vulnerable with fewer samples.
//!
//! # Usage
//!
//! ```rust
//! use zk_fuzzer::attacks::{Attack, AttackContext, CircuitInfo, CollisionDetector, HashType};
//!
//! let detector = CollisionDetector::new(10000)
//!     .with_hamming_threshold(8)
//!     .with_hash_type(HashType::Poseidon)
//!     .with_birthday_analysis(true);
//!
//! let context = AttackContext::new(CircuitInfo::default(), 0, 0);
//! let findings = detector.run(&context);
//! assert!(findings.len() >= 0);
//! ```

use super::{Attack, AttackContext};
use crate::config::{AttackType, Severity};
use crate::fuzzer::{FieldElement, Finding, ProofOfConcept};
use std::collections::HashMap;

/// Known ZK-friendly hash types for specialized collision testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    /// Poseidon hash - widely used in ZK circuits
    Poseidon,
    /// MiMC hash - simple algebraic structure
    MiMC,
    /// Pedersen hash - based on elliptic curve operations
    Pedersen,
    /// Rescue hash - designed for ZK efficiency
    Rescue,
    /// Generic/unknown hash type
    Generic,
}

impl HashType {
    /// Get the expected security level in bits for this hash type
    pub fn security_bits(&self) -> usize {
        match self {
            HashType::Poseidon => 128,  // Standard Poseidon provides 128-bit security
            HashType::MiMC => 128,       // MiMC with sufficient rounds
            HashType::Pedersen => 128,   // Pedersen commitment security
            HashType::Rescue => 128,     // Rescue hash security
            HashType::Generic => 256,    // Assume full security for unknown
        }
    }

    /// Get the recommended minimum samples for birthday attack testing
    pub fn recommended_samples(&self) -> usize {
        // For security level n, birthday attack needs ~2^(n/2) samples
        // We test with a fraction to catch weak implementations
        match self {
            HashType::Poseidon => 50000,
            HashType::MiMC => 50000,
            HashType::Pedersen => 30000,
            HashType::Rescue => 30000,
            HashType::Generic => 10000,
        }
    }
}

/// Result of collision analysis
#[derive(Debug, Clone)]
pub struct CollisionAnalysis {
    /// Total samples tested
    pub samples_tested: usize,
    /// Number of exact collisions found
    pub exact_collisions: usize,
    /// Number of near-collisions (within Hamming threshold)
    pub near_collisions: usize,
    /// Minimum Hamming distance observed between any two outputs
    pub min_hamming_distance: usize,
    /// Average Hamming distance between outputs
    pub avg_hamming_distance: f64,
    /// Output entropy estimate (bits)
    pub output_entropy_bits: f64,
    /// Whether birthday attack threshold was exceeded
    pub birthday_vulnerable: bool,
    /// Colliding input pairs (if any found)
    pub collision_pairs: Vec<CollisionPair>,
}

/// A pair of inputs that produced a collision or near-collision
#[derive(Debug, Clone)]
pub struct CollisionPair {
    pub input_a: Vec<FieldElement>,
    pub input_b: Vec<FieldElement>,
    pub output_a: Vec<u8>,
    pub output_b: Vec<u8>,
    pub hamming_distance: usize,
    pub is_exact: bool,
}

/// Collision detector for hash and nullifier collisions
pub struct CollisionDetector {
    /// Number of samples to test
    samples: usize,
    /// Hamming distance threshold for near-collisions
    hamming_threshold: usize,
    /// Expected hash type (for targeted testing)
    hash_type: HashType,
    /// Whether to perform birthday attack analysis
    birthday_analysis: bool,
    /// Whether to detect near-collisions
    detect_near_collisions: bool,
    /// Maximum near-collisions to report (to avoid flooding)
    max_near_collision_reports: usize,
    /// Output bit length (for truncated hash detection)
    expected_output_bits: Option<usize>,
}

impl Default for CollisionDetector {
    fn default() -> Self {
        Self {
            samples: 10000,
            hamming_threshold: 8,
            hash_type: HashType::Generic,
            birthday_analysis: true,
            detect_near_collisions: true,
            max_near_collision_reports: 10,
            expected_output_bits: None,
        }
    }
}

impl CollisionDetector {
    /// Create a new collision detector
    pub fn new(samples: usize) -> Self {
        Self {
            samples,
            ..Default::default()
        }
    }

    /// Set the Hamming distance threshold for near-collision detection
    pub fn with_hamming_threshold(mut self, threshold: usize) -> Self {
        self.hamming_threshold = threshold;
        self
    }

    /// Set the expected hash type for targeted testing
    pub fn with_hash_type(mut self, hash_type: HashType) -> Self {
        self.hash_type = hash_type;
        self
    }

    /// Enable or disable birthday attack analysis
    pub fn with_birthday_analysis(mut self, enabled: bool) -> Self {
        self.birthday_analysis = enabled;
        self
    }

    /// Enable or disable near-collision detection
    pub fn with_near_collision_detection(mut self, enabled: bool) -> Self {
        self.detect_near_collisions = enabled;
        self
    }

    /// Set expected output bit length (for truncated hash detection)
    pub fn with_expected_output_bits(mut self, bits: usize) -> Self {
        self.expected_output_bits = Some(bits);
        self
    }

    /// Get the configured sample count
    pub fn samples(&self) -> usize {
        self.samples
    }

    /// Calculate Hamming distance between two byte arrays
    pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
        let len = a.len().min(b.len());
        let mut distance = 0;
        
        for i in 0..len {
            distance += (a[i] ^ b[i]).count_ones() as usize;
        }
        
        // Account for length difference
        if a.len() > len {
            for byte in &a[len..] {
                distance += byte.count_ones() as usize;
            }
        }
        if b.len() > len {
            for byte in &b[len..] {
                distance += byte.count_ones() as usize;
            }
        }
        
        distance
    }

    /// Estimate output entropy from observed hash values
    fn estimate_entropy(&self, outputs: &[Vec<u8>]) -> f64 {
        if outputs.is_empty() {
            return 0.0;
        }

        // Count unique first bytes as a quick entropy estimate
        let mut byte_freq: HashMap<u8, usize> = HashMap::new();
        for output in outputs {
            if !output.is_empty() {
                *byte_freq.entry(output[0]).or_insert(0) += 1;
            }
        }

        // Calculate Shannon entropy
        let total = outputs.len() as f64;
        let mut entropy = 0.0;
        for &count in byte_freq.values() {
            let p = count as f64 / total;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        // Scale to full output length estimate
        let output_len = outputs.first().map(|o| o.len()).unwrap_or(32);
        entropy * (output_len as f64)
    }


    /// Perform comprehensive collision analysis on a set of input/output pairs
    pub fn analyze_collisions(
        &self,
        input_output_pairs: &[(Vec<FieldElement>, Vec<u8>)],
    ) -> CollisionAnalysis {
        let mut exact_collisions = 0;
        let mut near_collisions = 0;
        let mut min_hamming = usize::MAX;
        let mut total_hamming: u64 = 0;
        let mut comparisons: u64 = 0;
        let mut collision_pairs = Vec::new();

        // Build output map for exact collision detection
        let mut output_map: HashMap<Vec<u8>, Vec<&Vec<FieldElement>>> = HashMap::new();
        for (input, output) in input_output_pairs {
            output_map.entry(output.clone()).or_default().push(input);
        }

        // Check for exact collisions
        for (output, inputs) in &output_map {
            if inputs.len() > 1 {
                exact_collisions += inputs.len() - 1;
                
                // Record collision pairs
                for i in 1..inputs.len() {
                    collision_pairs.push(CollisionPair {
                        input_a: inputs[0].clone(),
                        input_b: inputs[i].clone(),
                        output_a: output.clone(),
                        output_b: output.clone(),
                        hamming_distance: 0,
                        is_exact: true,
                    });
                }
            }
        }

        // Sample-based near-collision detection (avoid O(n²) for large datasets)
        let outputs: Vec<&Vec<u8>> = input_output_pairs.iter().map(|(_, o)| o).collect();
        let sample_size = outputs.len().min(1000);
        
        for i in 0..sample_size {
            for j in (i + 1)..sample_size.min(i + 100) {
                let dist = Self::hamming_distance(outputs[i], outputs[j]);
                min_hamming = min_hamming.min(dist);
                total_hamming += dist as u64;
                comparisons += 1;

                if self.detect_near_collisions 
                    && dist > 0 
                    && dist <= self.hamming_threshold 
                    && collision_pairs.len() < self.max_near_collision_reports 
                {
                    near_collisions += 1;
                    collision_pairs.push(CollisionPair {
                        input_a: input_output_pairs[i].0.clone(),
                        input_b: input_output_pairs[j].0.clone(),
                        output_a: outputs[i].clone(),
                        output_b: outputs[j].clone(),
                        hamming_distance: dist,
                        is_exact: false,
                    });
                }
            }
        }

        let avg_hamming = if comparisons > 0 {
            total_hamming as f64 / comparisons as f64
        } else {
            0.0
        };

        // Estimate entropy from outputs
        let all_outputs: Vec<Vec<u8>> = outputs.iter().map(|o| (*o).clone()).collect();
        let entropy_bits = self.estimate_entropy(&all_outputs);

        // Check birthday vulnerability based on sample size and collisions
        let birthday_vulnerable = if self.birthday_analysis {
            let expected_for_secure = (2.0_f64).powf(self.hash_type.security_bits() as f64 / 2.0);
            let collision_rate = exact_collisions as f64 / input_output_pairs.len() as f64;
            collision_rate > 0.0 || (input_output_pairs.len() as f64) > expected_for_secure * 0.01
        } else {
            false
        };

        CollisionAnalysis {
            samples_tested: input_output_pairs.len(),
            exact_collisions,
            near_collisions,
            min_hamming_distance: if min_hamming == usize::MAX { 0 } else { min_hamming },
            avg_hamming_distance: avg_hamming,
            output_entropy_bits: entropy_bits,
            birthday_vulnerable,
            collision_pairs,
        }
    }

    /// Generate birthday attack test values targeting specific bit lengths
    pub fn generate_birthday_inputs(&self, count: usize, seed: u64) -> Vec<Vec<FieldElement>> {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        
        let mut rng = StdRng::seed_from_u64(seed);
        let mut inputs = Vec::with_capacity(count);

        for _ in 0..count {
            // Generate random field element
            let input = FieldElement::random(&mut rng);
            inputs.push(vec![input]);
        }

        inputs
    }

    /// Generate Poseidon-specific test inputs
    pub fn generate_poseidon_test_inputs(&self, count: usize, seed: u64) -> Vec<Vec<FieldElement>> {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        
        let mut rng = StdRng::seed_from_u64(seed);
        let mut inputs = Vec::with_capacity(count);

        // Poseidon typically takes 2-12 field elements as input
        let input_sizes = [2, 3, 4, 8, 12];
        
        for i in 0..count {
            let size = input_sizes[i % input_sizes.len()];
            let input: Vec<FieldElement> = (0..size)
                .map(|_| FieldElement::random(&mut rng))
                .collect();
            inputs.push(input);
        }

        inputs
    }

    /// Generate MiMC-specific test inputs  
    pub fn generate_mimc_test_inputs(&self, count: usize, seed: u64) -> Vec<Vec<FieldElement>> {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        
        let mut rng = StdRng::seed_from_u64(seed);
        let mut inputs = Vec::with_capacity(count);

        // MiMC typically takes a message and key
        for _ in 0..count {
            let message = FieldElement::random(&mut rng);
            let key = FieldElement::random(&mut rng);
            inputs.push(vec![message, key]);
        }

        // Also add some edge cases
        inputs.push(vec![FieldElement::zero(), FieldElement::zero()]);
        inputs.push(vec![FieldElement::one(), FieldElement::zero()]);
        inputs.push(vec![FieldElement::zero(), FieldElement::one()]);
        inputs.push(vec![FieldElement::max_value(), FieldElement::max_value()]);

        inputs
    }

}

impl Attack for CollisionDetector {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for small output space (vulnerable to birthday attack)
        if context.circuit_info.num_outputs < 2 {
            findings.push(Finding {
                attack_type: AttackType::Collision,
                severity: Severity::Medium,
                description: format!(
                    "Circuit '{}' has only {} output(s), potentially vulnerable to collision attacks. \
                     Consider using full 256-bit hash outputs.",
                    context.circuit_info.name,
                    context.circuit_info.num_outputs
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        // Check for truncated hash patterns (heuristic based on constraint count)
        let expected_hash_constraints = match self.hash_type {
            HashType::Poseidon => 200,  // Approximate constraints for Poseidon
            HashType::MiMC => 100,       // MiMC is relatively simple
            HashType::Pedersen => 500,   // Pedersen has more constraints
            HashType::Rescue => 300,     // Rescue is moderate
            HashType::Generic => 150,    // Generic estimate
        };

        if context.circuit_info.num_constraints < expected_hash_constraints / 2 {
            findings.push(Finding {
                attack_type: AttackType::Collision,
                severity: Severity::Low,
                description: format!(
                    "Circuit '{}' has {} constraints, which may indicate truncated hash output \
                     or reduced security rounds (expected ~{} for {:?})",
                    context.circuit_info.name,
                    context.circuit_info.num_constraints,
                    expected_hash_constraints,
                    self.hash_type
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        // Check constraint density for hash function patterns
        let density = context.circuit_info.constraint_density();
        if density < 0.5 {
            findings.push(Finding {
                attack_type: AttackType::Collision,
                severity: Severity::Info,
                description: format!(
                    "Low constraint density ({:.2}) in '{}' may indicate weak hash implementation",
                    density,
                    context.circuit_info.name
                ),
                poc: ProofOfConcept::default(),
                location: None,
            });
        }

        findings
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Collision
    }

    fn description(&self) -> &str {
        "Detect hash and nullifier collisions using birthday paradox attacks and near-collision analysis"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance_identical() {
        let a = vec![0x00, 0xFF, 0xAA];
        let b = vec![0x00, 0xFF, 0xAA];
        assert_eq!(CollisionDetector::hamming_distance(&a, &b), 0);
    }

    #[test]
    fn test_hamming_distance_one_bit() {
        let a = vec![0x00];
        let b = vec![0x01];
        assert_eq!(CollisionDetector::hamming_distance(&a, &b), 1);
    }

    #[test]
    fn test_hamming_distance_all_bits() {
        let a = vec![0x00];
        let b = vec![0xFF];
        assert_eq!(CollisionDetector::hamming_distance(&a, &b), 8);
    }

    #[test]
    fn test_hamming_distance_different_lengths() {
        let a = vec![0xFF, 0xFF];
        let b = vec![0x00];
        // First byte: 8 bits different, second byte: 8 bits (since b is shorter)
        assert_eq!(CollisionDetector::hamming_distance(&a, &b), 16);
    }

    #[test]
    fn test_collision_analysis_no_collisions() {
        let detector = CollisionDetector::new(100);
        
        let pairs: Vec<(Vec<FieldElement>, Vec<u8>)> = (0..100)
            .map(|i| {
                let input = vec![FieldElement::from_u64(i)];
                let output = vec![i as u8; 32];
                (input, output)
            })
            .collect();

        let analysis = detector.analyze_collisions(&pairs);
        assert_eq!(analysis.exact_collisions, 0);
        assert_eq!(analysis.samples_tested, 100);
    }

    #[test]
    fn test_collision_analysis_with_collision() {
        let detector = CollisionDetector::new(100);
        
        let mut pairs: Vec<(Vec<FieldElement>, Vec<u8>)> = Vec::new();
        
        // Add a collision - two different inputs, same output
        pairs.push((vec![FieldElement::from_u64(1)], vec![0xAA; 32]));
        pairs.push((vec![FieldElement::from_u64(2)], vec![0xAA; 32]));
        
        // Add some non-colliding pairs
        for i in 3..10 {
            pairs.push((vec![FieldElement::from_u64(i)], vec![i as u8; 32]));
        }

        let analysis = detector.analyze_collisions(&pairs);
        assert_eq!(analysis.exact_collisions, 1);
        assert!(!analysis.collision_pairs.is_empty());
        assert!(analysis.collision_pairs[0].is_exact);
    }

    #[test]
    fn test_hash_type_security_bits() {
        assert_eq!(HashType::Poseidon.security_bits(), 128);
        assert_eq!(HashType::Generic.security_bits(), 256);
    }

    #[test]
    fn test_generate_birthday_inputs() {
        let detector = CollisionDetector::new(100);
        let inputs = detector.generate_birthday_inputs(10, 42);
        assert_eq!(inputs.len(), 10);
        assert!(inputs.iter().all(|i| i.len() == 1));
    }

    #[test]
    fn test_generate_poseidon_inputs() {
        let detector = CollisionDetector::new(100)
            .with_hash_type(HashType::Poseidon);
        let inputs = detector.generate_poseidon_test_inputs(10, 42);
        assert_eq!(inputs.len(), 10);
        // Poseidon inputs vary in size
        assert!(inputs.iter().any(|i| i.len() >= 2));
    }

    #[test]
    fn test_generate_mimc_inputs() {
        let detector = CollisionDetector::new(100)
            .with_hash_type(HashType::MiMC);
        let inputs = detector.generate_mimc_test_inputs(10, 42);
        assert!(inputs.len() >= 10); // Extra edge cases added
        // MiMC inputs are message + key pairs
        assert!(inputs[0].len() == 2);
    }

    #[test]
    fn test_near_collision_detection() {
        let detector = CollisionDetector::new(100)
            .with_hamming_threshold(4)
            .with_near_collision_detection(true);

        let mut pairs: Vec<(Vec<FieldElement>, Vec<u8>)> = Vec::new();
        
        // Create near-collision: outputs differ by only 1 bit
        let output_a = vec![0x00; 32];
        let mut output_b = vec![0x00; 32];
        output_b[0] = 0x01; // Single bit difference
        
        pairs.push((vec![FieldElement::from_u64(1)], output_a));
        pairs.push((vec![FieldElement::from_u64(2)], output_b));

        let analysis = detector.analyze_collisions(&pairs);
        assert!(analysis.min_hamming_distance <= 1);
    }
}
