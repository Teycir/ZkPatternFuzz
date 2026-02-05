//! Structure-Aware Mutations for ZK Circuit DSLs
//!
//! Provides intelligent mutations that understand the structure of ZK circuit
//! inputs, rather than treating them as opaque bytes.

use super::FieldElement;
use crate::config::Framework;
use rand::Rng;
use std::collections::HashMap;

/// Types of structured inputs in ZK circuits
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputStructure {
    /// Single field element
    Field,
    /// Boolean (0 or 1)
    Boolean,
    /// Fixed-width integer with range [0, 2^bits)
    Integer { bits: u32 },
    /// Array of field elements
    Array {
        element_type: Box<InputStructure>,
        length: usize,
    },
    /// Bit decomposition (array of booleans representing a value)
    BitDecomposition { bits: u32 },
    /// Hash input (typically 2 field elements for Poseidon)
    HashPreimage { num_elements: usize },
    /// Merkle path (alternating values and indices)
    MerklePath { depth: usize },
    /// Nullifier components (secret + nonce)
    NullifierPreimage,
    /// Public key point (x, y coordinates)
    PublicKey,
    /// Signature components
    Signature,
}

/// Structure-aware mutator that understands ZK circuit input patterns
pub struct StructureAwareMutator {
    /// Input structure definitions
    structures: Vec<InputStructure>,
    /// Framework-specific knowledge
    framework: Framework,
    /// Learned patterns from execution
    patterns: HashMap<String, Vec<FieldElement>>,
}

impl StructureAwareMutator {
    pub fn new(framework: Framework) -> Self {
        Self {
            structures: Vec::new(),
            framework,
            patterns: HashMap::new(),
        }
    }

    /// Define input structure for intelligent mutation
    pub fn with_structures(mut self, structures: Vec<InputStructure>) -> Self {
        self.structures = structures;
        self
    }

    /// Infer structure from circuit metadata or source
    pub fn infer_structure_from_source(source: &str, framework: Framework) -> Vec<InputStructure> {
        match framework {
            Framework::Circom => Self::infer_circom_structure(source),
            Framework::Noir => Self::infer_noir_structure(source),
            _ => Vec::new(),
        }
    }

    /// Infer structure from Circom source
    fn infer_circom_structure(source: &str) -> Vec<InputStructure> {
        let mut structures = Vec::new();

        for line in source.lines() {
            let trimmed = line.trim();

            // Look for signal declarations with type hints in names
            if trimmed.starts_with("signal input") || trimmed.starts_with("signal private input") {
                let name = Self::extract_signal_name(trimmed);
                let name_lower = name.to_lowercase();

                // Infer type from naming conventions
                let structure = if name_lower.contains("signature") || name_lower.contains("sig") {
                    InputStructure::Signature
                } else if name_lower.contains("pubkey")
                    || name_lower.contains("public_key")
                    || name_lower.contains("publickey")
                {
                    InputStructure::PublicKey
                } else if name_lower.contains("nullifier") || name_lower.contains("preimage") {
                    InputStructure::NullifierPreimage
                } else if name_lower.contains("bit") || name_lower.contains("bool") {
                    InputStructure::Boolean
                } else if name_lower.contains("bits[") {
                    if let Some(len) = Self::extract_array_length(trimmed) {
                        InputStructure::BitDecomposition { bits: len as u32 }
                    } else {
                        InputStructure::Field
                    }
                } else if name_lower.contains("path") || name_lower.contains("merkle") {
                    InputStructure::MerklePath { depth: 20 } // Default Merkle depth
                } else if name_lower.contains("secret") {
                    InputStructure::Field // High-value target
                } else if name_lower.contains("hash") {
                    InputStructure::HashPreimage { num_elements: 2 }
                } else if let Some(len) = Self::extract_array_length(trimmed) {
                    InputStructure::Array {
                        element_type: Box::new(InputStructure::Field),
                        length: len,
                    }
                } else {
                    InputStructure::Field
                };

                structures.push(structure);
            }
        }

        structures
    }

    /// Infer structure from Noir source
    fn infer_noir_structure(source: &str) -> Vec<InputStructure> {
        let mut structures = Vec::new();

        for line in source.lines() {
            let trimmed = line.trim();
            let lowered = trimmed.to_lowercase();

            // Look for function parameters
            if trimmed.contains("fn main(")
                || trimmed.contains(": Field")
                || trimmed.contains(": u")
                || trimmed.contains(": bool")
            {
                // Extract type from Noir type annotations
                if lowered.contains("signature") || lowered.contains("sig") {
                    structures.push(InputStructure::Signature);
                } else if lowered.contains("pubkey")
                    || lowered.contains("public_key")
                    || lowered.contains("publickey")
                {
                    structures.push(InputStructure::PublicKey);
                } else if lowered.contains("nullifier") || lowered.contains("preimage") {
                    structures.push(InputStructure::NullifierPreimage);
                } else if trimmed.contains(": bool") {
                    structures.push(InputStructure::Boolean);
                } else if let Some(bits) = Self::extract_noir_int_type(trimmed) {
                    structures.push(InputStructure::Integer { bits });
                } else if trimmed.contains(": [Field;") {
                    if let Some(len) = Self::extract_noir_array_length(trimmed) {
                        structures.push(InputStructure::Array {
                            element_type: Box::new(InputStructure::Field),
                            length: len,
                        });
                    }
                } else if trimmed.contains(": Field") {
                    structures.push(InputStructure::Field);
                }
            }
        }

        structures
    }

    fn extract_signal_name(line: &str) -> String {
        line.split_whitespace()
            .last()
            .unwrap_or("")
            .trim_end_matches(';')
            .trim_end_matches('[')
            .to_string()
    }

    fn extract_array_length(line: &str) -> Option<usize> {
        if let Some(start) = line.find('[') {
            if let Some(end) = line.find(']') {
                let len_str = &line[start + 1..end];
                return len_str.parse().ok();
            }
        }
        None
    }

    fn extract_noir_int_type(line: &str) -> Option<u32> {
        for width in [8, 16, 32, 64, 128] {
            if line.contains(&format!(": u{}", width)) || line.contains(&format!(": i{}", width)) {
                return Some(width);
            }
        }
        None
    }

    fn extract_noir_array_length(line: &str) -> Option<usize> {
        if let Some(start) = line.find("; ") {
            if let Some(end) = line[start..].find(']') {
                let len_str = &line[start + 2..start + end];
                return len_str.parse().ok();
            }
        }
        None
    }

    /// Mutate inputs based on their structure
    pub fn mutate(&self, inputs: &[FieldElement], rng: &mut impl Rng) -> Vec<FieldElement> {
        if self.structures.is_empty() {
            // Fall back to byte-level mutation with framework-specific heuristics
            return inputs
                .iter()
                .enumerate()
                .map(|(i, fe)| {
                    // Check if we have a learned pattern for this input
                    let pattern_key = format!("input_{}", i);
                    if let Some(pattern) = self.get_pattern(&pattern_key) {
                        // 20% chance to replay learned pattern
                        if rng.gen::<f64>() < 0.2 && !pattern.is_empty() {
                            return pattern[rng.gen_range(0..pattern.len())].clone();
                        }
                    }

                    // Framework-specific mutation hints
                    match self.framework {
                        Framework::Circom | Framework::Noir => {
                            // These use BN254, so bias toward field boundaries
                            if rng.gen::<f64>() < 0.1 {
                                self.interesting_field_value(rng)
                            } else {
                                super::mutate_field_element(fe, rng)
                            }
                        }
                        Framework::Halo2 => {
                            // Halo2 often uses lookup tables, try boundary values
                            if rng.gen::<f64>() < 0.15 {
                                FieldElement::from_u64(rng.gen_range(0..256))
                            } else {
                                super::mutate_field_element(fe, rng)
                            }
                        }
                        _ => super::mutate_field_element(fe, rng),
                    }
                })
                .collect();
        }

        let mut result = inputs.to_vec();
        let idx = rng.gen_range(0..inputs.len().min(self.structures.len()));

        if idx < self.structures.len() {
            result[idx] = self.mutate_structured(&inputs[idx], &self.structures[idx], rng);
        }

        result
    }

    /// Mutate a single input based on its structure
    fn mutate_structured(
        &self,
        input: &FieldElement,
        structure: &InputStructure,
        rng: &mut impl Rng,
    ) -> FieldElement {
        match structure {
            InputStructure::Field => {
                // For field elements, use standard mutations but bias toward interesting values
                if rng.gen::<f64>() < 0.3 {
                    self.interesting_field_value(rng)
                } else {
                    super::mutate_field_element(input, rng)
                }
            }
            InputStructure::Boolean => {
                // Flip boolean
                if *input == FieldElement::zero() {
                    FieldElement::one()
                } else {
                    FieldElement::zero()
                }
            }
            InputStructure::Integer { bits } => self.mutate_integer(input, *bits, rng),
            InputStructure::BitDecomposition { bits } => {
                // Flip a random bit
                self.mutate_bit(input, *bits, rng)
            }
            InputStructure::HashPreimage { .. } => {
                // For hash preimages, try collision-inducing patterns
                if rng.gen::<f64>() < 0.2 {
                    FieldElement::zero() // Try zero preimage
                } else {
                    super::mutate_field_element(input, rng)
                }
            }
            InputStructure::MerklePath { depth } => {
                // For Merkle paths, mutate strategically
                self.mutate_merkle_element(input, *depth, rng)
            }
            InputStructure::NullifierPreimage => {
                // For nullifier preimages, try known attack patterns
                self.mutate_nullifier_input(input, rng)
            }
            _ => super::mutate_field_element(input, rng),
        }
    }

    /// Generate interesting field values for testing
    fn interesting_field_value(&self, rng: &mut impl Rng) -> FieldElement {
        let choice = rng.gen_range(0..10);
        match choice {
            0 => FieldElement::zero(),
            1 => FieldElement::one(),
            2 => FieldElement::max_value(),
            3 => FieldElement::half_modulus(),
            4 => FieldElement::from_u64(u64::MAX),
            5 => FieldElement::from_u64(u32::MAX as u64),
            6 => {
                // Powers of 2
                let power = rng.gen_range(1..64);
                FieldElement::from_u64(1u64 << power)
            }
            7 => {
                // Near powers of 2
                let power = rng.gen_range(1..64);
                FieldElement::from_u64((1u64 << power) - 1)
            }
            8 => {
                // Small primes
                let primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
                FieldElement::from_u64(primes[rng.gen_range(0..primes.len())])
            }
            _ => FieldElement::random(rng),
        }
    }

    /// Mutate an integer within its valid range
    fn mutate_integer(&self, input: &FieldElement, bits: u32, rng: &mut impl Rng) -> FieldElement {
        let max_val = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };

        let mutation_type = rng.gen_range(0..5);
        match mutation_type {
            0 => FieldElement::zero(),
            1 => FieldElement::from_u64(max_val),
            2 => FieldElement::from_u64(max_val / 2),
            3 => {
                // Random within range
                let val = rng.gen_range(0..=max_val);
                FieldElement::from_u64(val)
            }
            _ => {
                // Bit flip within valid range
                let current = self.to_u64(input);
                let bit_to_flip = rng.gen_range(0..bits);
                let flipped = current ^ (1u64 << bit_to_flip);
                FieldElement::from_u64(flipped & max_val)
            }
        }
    }

    /// Mutate a single bit in a bit decomposition
    fn mutate_bit(&self, input: &FieldElement, bits: u32, rng: &mut impl Rng) -> FieldElement {
        let current = self.to_u64(input);
        let bit_to_flip = rng.gen_range(0..bits);
        let max_val = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        FieldElement::from_u64((current ^ (1u64 << bit_to_flip)) & max_val)
    }

    /// Mutate Merkle path elements
    fn mutate_merkle_element(
        &self,
        input: &FieldElement,
        _depth: usize,
        rng: &mut impl Rng,
    ) -> FieldElement {
        let choice = rng.gen_range(0..5);
        match choice {
            0 => FieldElement::zero(), // Empty node
            1 => {
                // Duplicate sibling (path confusion attack)
                input.clone()
            }
            2 => {
                // All zeros (default hash)
                FieldElement::zero()
            }
            _ => super::mutate_field_element(input, rng),
        }
    }

    /// Mutate nullifier inputs (try double-spend patterns)
    fn mutate_nullifier_input(&self, input: &FieldElement, rng: &mut impl Rng) -> FieldElement {
        let choice = rng.gen_range(0..4);
        match choice {
            0 => input.clone(), // Same value (double spend attempt)
            1 => FieldElement::zero(),
            2 => {
                // Small difference (collision attempt)
                let mut bytes = input.0;
                bytes[31] ^= 1;
                FieldElement(bytes)
            }
            _ => super::mutate_field_element(input, rng),
        }
    }

    fn to_u64(&self, fe: &FieldElement) -> u64 {
        let bytes = &fe.0[24..32];
        u64::from_be_bytes(bytes.try_into().unwrap_or([0; 8]))
    }

    /// Add learned patterns from successful inputs
    pub fn learn_pattern(&mut self, name: &str, values: Vec<FieldElement>) {
        self.patterns.insert(name.to_string(), values);
    }

    /// Get a learned pattern for replay
    pub fn get_pattern(&self, name: &str) -> Option<&Vec<FieldElement>> {
        self.patterns.get(name)
    }
}

/// Splicing mutations - combine parts of different test cases
pub struct Splicer;

impl Splicer {
    /// Splice two test cases together
    pub fn splice(a: &[FieldElement], b: &[FieldElement], rng: &mut impl Rng) -> Vec<FieldElement> {
        if a.is_empty() || b.is_empty() {
            return a.to_vec();
        }

        let min_len = a.len().min(b.len());
        let splice_point = rng.gen_range(0..min_len);

        let mut result = Vec::with_capacity(a.len());
        result.extend_from_slice(&a[..splice_point]);
        if splice_point < b.len() {
            result.extend_from_slice(&b[splice_point..]);
        }

        // Pad or truncate to original length
        while result.len() < a.len() {
            result.push(FieldElement::zero());
        }
        result.truncate(a.len());

        result
    }

    /// Insert elements from one test case into another
    pub fn insert(
        target: &[FieldElement],
        source: &[FieldElement],
        rng: &mut impl Rng,
    ) -> Vec<FieldElement> {
        if source.is_empty() || target.is_empty() {
            return target.to_vec();
        }

        let insert_pos = rng.gen_range(0..target.len());
        let source_idx = rng.gen_range(0..source.len());

        let mut result = target.to_vec();
        result[insert_pos] = source[source_idx].clone();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_boolean_mutation() {
        let mutator = StructureAwareMutator::new(Framework::Circom)
            .with_structures(vec![InputStructure::Boolean]);

        let mut rng = StdRng::seed_from_u64(42);
        let zero = FieldElement::zero();
        let result = mutator.mutate_structured(&zero, &InputStructure::Boolean, &mut rng);
        assert_eq!(result, FieldElement::one());
    }

    #[test]
    fn test_integer_mutation_stays_in_range() {
        let mutator = StructureAwareMutator::new(Framework::Circom);
        let mut rng = StdRng::seed_from_u64(42);

        for _ in 0..100 {
            let input = FieldElement::from_u64(100);
            let result = mutator.mutate_integer(&input, 8, &mut rng);
            let value = mutator.to_u64(&result);
            assert!(value <= 255, "8-bit value should be <= 255, got {}", value);
        }
    }

    #[test]
    fn test_circom_structure_inference() {
        let source = r#"
            signal input secret;
            signal input bits[8];
            signal input merkle_path[20];
            signal output nullifier;
        "#;

        let structures = StructureAwareMutator::infer_circom_structure(source);
        assert!(!structures.is_empty());
    }

    #[test]
    fn test_splice() {
        let mut rng = StdRng::seed_from_u64(42);
        let a = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
        let b = vec![FieldElement::from_u64(3), FieldElement::from_u64(4)];

        let result = Splicer::splice(&a, &b, &mut rng);
        assert_eq!(result.len(), 2);
    }
}
