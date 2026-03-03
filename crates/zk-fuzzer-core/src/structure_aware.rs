//! Structure-Aware Mutations for ZK Circuit DSLs
//!
//! Provides intelligent mutations that understand the structure of ZK circuit
//! inputs, rather than treating them as opaque bytes.

use rand::Rng;
use std::collections::HashMap;
use zk_core::{FieldElement, Framework};

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
        let source_lower = source.to_lowercase();
        let mut structures = Vec::new();

        for line in source.lines() {
            let Some((name, array_len)) = Self::parse_circom_input_declaration(line) else {
                continue;
            };
            let usage = Self::collect_usage_lines(&source_lower, &name);

            let inferred = Self::infer_by_usage_and_type(&name, &usage, array_len, None)
                .unwrap_or_else(|| Self::infer_by_name_hint(&name, array_len));
            structures.push(inferred);
        }

        structures
    }

    /// Infer structure from Noir source
    fn infer_noir_structure(source: &str) -> Vec<InputStructure> {
        let source_lower = source.to_lowercase();
        let params = Self::extract_noir_main_params(source);
        let mut structures = Vec::with_capacity(params.len());

        for (name, ty) in params {
            let usage = Self::collect_usage_lines(&source_lower, &name);
            let array_len = Self::extract_noir_array_length(&ty);
            let inferred = Self::infer_by_usage_and_type(&name, &usage, array_len, Some(&ty))
                .unwrap_or_else(|| Self::infer_by_name_hint(&name, array_len));
            structures.push(inferred);
        }

        structures
    }

    fn extract_signal_name(line: &str) -> String {
        let token = line.trim_end_matches(';').trim();
        token
            .split('[')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    fn parse_circom_input_declaration(line: &str) -> Option<(String, Option<usize>)> {
        let without_comment = line.split("//").next().unwrap_or_default().trim();
        if without_comment.is_empty() {
            return None;
        }

        let (prefix, remainder) = if let Some(rest) = without_comment.strip_prefix("signal input") {
            ("signal input", rest)
        } else if let Some(rest) = without_comment.strip_prefix("signal private input") {
            ("signal private input", rest)
        } else {
            return None;
        };
        let _ = prefix;

        let declaration = remainder.trim().trim_end_matches(';').trim();
        if declaration.is_empty() {
            return None;
        }
        let token = declaration.split_whitespace().next().unwrap_or_default();
        let name = Self::extract_signal_name(token).to_lowercase();
        if name.is_empty() {
            return None;
        }
        let array_len = Self::extract_array_length(token);
        Some((name, array_len))
    }

    fn extract_array_length(line: &str) -> Option<usize> {
        if let Some(start) = line.find('[') {
            if let Some(end) = line[start + 1..].find(']') {
                let end = start + 1 + end;
                let len_str = &line[start + 1..end];
                return match len_str.parse() {
                    Ok(len) => Some(len),
                    Err(err) => {
                        tracing::debug!("Invalid Circom array length '{}': {}", len_str, err);
                        None
                    }
                };
            }
        }
        None
    }

    fn extract_noir_int_type(line: &str) -> Option<u32> {
        for width in [8, 16, 32, 64, 128] {
            let unsigned = format!("u{}", width);
            let signed = format!("i{}", width);
            if Self::contains_identifier(line, &unsigned)
                || Self::contains_identifier(line, &signed)
            {
                return Some(width);
            }
        }
        None
    }

    fn extract_noir_array_length(line: &str) -> Option<usize> {
        if let Some((_, len)) = Self::extract_noir_array_type(line) {
            return Some(len);
        }
        None
    }

    fn extract_noir_array_type(ty: &str) -> Option<(String, usize)> {
        let trimmed = ty.trim();
        if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
            return None;
        }
        let inner = &trimmed[1..trimmed.len() - 1];
        let (elem_ty, len_raw) = inner.split_once(';')?;
        let len_str = len_raw.trim();
        match len_str.parse() {
            Ok(len) => Some((elem_ty.trim().to_string(), len)),
            Err(err) => {
                tracing::debug!("Invalid Noir array length '{}': {}", len_str, err);
                None
            }
        }
    }

    fn extract_noir_main_params(source: &str) -> Vec<(String, String)> {
        let Some(main_pos) = source.find("fn main(") else {
            return Vec::new();
        };

        let mut params = String::new();
        let mut depth = 1usize;
        let start = main_pos + "fn main(".len();
        for ch in source[start..].chars() {
            match ch {
                '(' => {
                    depth += 1;
                    params.push(ch);
                }
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                    params.push(ch);
                }
                _ => params.push(ch),
            }
        }

        if depth != 0 {
            return Vec::new();
        }

        let mut result = Vec::new();
        for raw_param in Self::split_top_level_commas(&params) {
            let Some((lhs, rhs)) = raw_param.split_once(':') else {
                continue;
            };
            let Some(name) = lhs.split_whitespace().last() else {
                continue;
            };
            let name = name.trim().to_lowercase();
            if name.is_empty() {
                continue;
            }
            let ty = rhs.trim().to_lowercase();
            if ty.is_empty() {
                continue;
            }
            result.push((name, ty));
        }
        result
    }

    fn split_top_level_commas(input: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut start = 0usize;
        let mut square_depth = 0usize;
        let mut paren_depth = 0usize;
        let mut brace_depth = 0usize;
        let mut angle_depth = 0usize;

        for (idx, ch) in input.char_indices() {
            match ch {
                '[' => square_depth += 1,
                ']' => square_depth = square_depth.saturating_sub(1),
                '(' => paren_depth += 1,
                ')' => paren_depth = paren_depth.saturating_sub(1),
                '{' => brace_depth += 1,
                '}' => brace_depth = brace_depth.saturating_sub(1),
                '<' => angle_depth += 1,
                '>' => angle_depth = angle_depth.saturating_sub(1),
                ',' if square_depth == 0
                    && paren_depth == 0
                    && brace_depth == 0
                    && angle_depth == 0 =>
                {
                    let chunk = input[start..idx].trim();
                    if !chunk.is_empty() {
                        parts.push(chunk.to_string());
                    }
                    start = idx + 1;
                }
                _ => {}
            }
        }

        let tail = input[start..].trim();
        if !tail.is_empty() {
            parts.push(tail.to_string());
        }

        parts
    }

    fn infer_by_usage_and_type(
        input_name: &str,
        usage_lines: &[&str],
        array_len: Option<usize>,
        noir_type: Option<&str>,
    ) -> Option<InputStructure> {
        let noir_type = noir_type.map(str::trim);

        if let Some(ty) = noir_type {
            if ty == "bool" {
                return Some(InputStructure::Boolean);
            }
            if let Some(bits) = Self::extract_noir_int_type(ty) {
                return Some(InputStructure::Integer { bits });
            }
            if let Some((elem_ty, len)) = Self::extract_noir_array_type(ty) {
                let elem_ty = elem_ty.trim().to_lowercase();
                if elem_ty == "bool" {
                    return Some(InputStructure::BitDecomposition {
                        bits: Self::to_bits(len),
                    });
                }
                if Self::has_merkle_usage(usage_lines) {
                    return Some(InputStructure::MerklePath { depth: len });
                }
                if Self::has_hash_usage(usage_lines) {
                    return Some(InputStructure::HashPreimage {
                        num_elements: len.max(1),
                    });
                }
                let element_type = if let Some(bits) = Self::extract_noir_int_type(&elem_ty) {
                    InputStructure::Integer { bits }
                } else {
                    InputStructure::Field
                };
                return Some(InputStructure::Array {
                    element_type: Box::new(element_type),
                    length: len,
                });
            }
        }

        if let Some(len) = array_len {
            if Self::has_boolean_usage(usage_lines, input_name) {
                return Some(InputStructure::BitDecomposition {
                    bits: Self::to_bits(len),
                });
            }
            if Self::has_merkle_usage(usage_lines) {
                return Some(InputStructure::MerklePath { depth: len });
            }
            if Self::has_hash_usage(usage_lines) {
                return Some(InputStructure::HashPreimage {
                    num_elements: len.max(1),
                });
            }
            return Some(InputStructure::Array {
                element_type: Box::new(InputStructure::Field),
                length: len,
            });
        }

        if Self::has_boolean_usage(usage_lines, input_name) {
            return Some(InputStructure::Boolean);
        }
        if Self::has_integer_usage(usage_lines) {
            return Some(InputStructure::Integer { bits: 32 });
        }
        if Self::has_signature_usage(usage_lines) {
            return Some(InputStructure::Signature);
        }
        if Self::has_public_key_usage(usage_lines) {
            return Some(InputStructure::PublicKey);
        }
        if Self::has_nullifier_usage(usage_lines) {
            return Some(InputStructure::NullifierPreimage);
        }
        if Self::has_hash_usage(usage_lines) {
            return Some(InputStructure::HashPreimage { num_elements: 2 });
        }
        if Self::has_merkle_usage(usage_lines) {
            return Some(InputStructure::MerklePath { depth: 20 });
        }

        None
    }

    fn infer_by_name_hint(name_lower: &str, array_len: Option<usize>) -> InputStructure {
        if name_lower.contains("signature")
            || name_lower.starts_with("sig")
            || name_lower.contains("_sig")
            || name_lower.contains("sig_")
        {
            return InputStructure::Signature;
        }
        if name_lower.contains("pubkey")
            || name_lower.contains("public_key")
            || name_lower.contains("publickey")
        {
            return InputStructure::PublicKey;
        }
        if name_lower.contains("nullifier") || name_lower.contains("preimage") {
            return InputStructure::NullifierPreimage;
        }
        if name_lower.contains("bit") || name_lower.contains("bool") {
            if let Some(len) = array_len {
                return InputStructure::BitDecomposition {
                    bits: Self::to_bits(len),
                };
            }
            return InputStructure::Boolean;
        }
        if name_lower.contains("path") || name_lower.contains("merkle") {
            if let Some(depth) = array_len {
                return InputStructure::MerklePath { depth };
            }
            return InputStructure::MerklePath { depth: 20 };
        }
        if name_lower.contains("hash") {
            if let Some(num_elements) = array_len {
                return InputStructure::HashPreimage {
                    num_elements: num_elements.max(1),
                };
            }
            return InputStructure::HashPreimage { num_elements: 2 };
        }
        if let Some(len) = array_len {
            return InputStructure::Array {
                element_type: Box::new(InputStructure::Field),
                length: len,
            };
        }
        InputStructure::Field
    }

    fn collect_usage_lines<'a>(source_lower: &'a str, input_name: &str) -> Vec<&'a str> {
        source_lower
            .lines()
            .map(|line| line.split("//").next().unwrap_or_default().trim())
            .filter(|line| !line.is_empty())
            .filter(|line| {
                !line.starts_with("signal input") && !line.starts_with("signal private input")
            })
            .filter(|line| Self::contains_identifier(line, input_name))
            .collect()
    }

    fn contains_identifier(haystack: &str, ident: &str) -> bool {
        if ident.is_empty() {
            return false;
        }
        let mut offset = 0usize;
        while let Some(pos) = haystack[offset..].find(ident) {
            let start = offset + pos;
            let end = start + ident.len();
            let left_ok = haystack[..start]
                .chars()
                .next_back()
                .map(|ch| !ch.is_ascii_alphanumeric() && ch != '_')
                .unwrap_or(true);
            let right_ok = haystack[end..]
                .chars()
                .next()
                .map(|ch| !ch.is_ascii_alphanumeric() && ch != '_')
                .unwrap_or(true);
            if left_ok && right_ok {
                return true;
            }
            offset = end;
        }
        false
    }

    fn count_identifier_occurrences(haystack: &str, ident: &str) -> usize {
        if ident.is_empty() {
            return 0;
        }
        let mut offset = 0usize;
        let mut count = 0usize;
        while let Some(pos) = haystack[offset..].find(ident) {
            let start = offset + pos;
            let end = start + ident.len();
            let left_ok = haystack[..start]
                .chars()
                .next_back()
                .map(|ch| !ch.is_ascii_alphanumeric() && ch != '_')
                .unwrap_or(true);
            let right_ok = haystack[end..]
                .chars()
                .next()
                .map(|ch| !ch.is_ascii_alphanumeric() && ch != '_')
                .unwrap_or(true);
            if left_ok && right_ok {
                count += 1;
            }
            offset = end;
        }
        count
    }

    fn has_boolean_usage(usage_lines: &[&str], input_name: &str) -> bool {
        usage_lines.iter().any(|line| {
            let occurrences = Self::count_identifier_occurrences(line, input_name);
            let bool_poly = occurrences >= 2 && line.contains('*') && line.contains("- 1");
            let bool_disjunction = line.contains("== 0") && line.contains("== 1");
            let bool_range = line.contains("<= 1") || line.contains("< 2");
            let bool_assert = line.contains("assert")
                && (line.contains("== 0") || line.contains("== 1") || line.contains("<= 1"));
            bool_poly || bool_disjunction || bool_range || bool_assert
        })
    }

    fn has_integer_usage(usage_lines: &[&str]) -> bool {
        usage_lines.iter().any(|line| {
            line.contains("<<")
                || line.contains(">>")
                || line.contains(" & ")
                || line.contains(" % ")
                || line.contains("num2bits")
                || line.contains("range")
        })
    }

    fn has_hash_usage(usage_lines: &[&str]) -> bool {
        Self::has_keyword_usage(
            usage_lines,
            &[
                "poseidon", "mimc", "pedersen", "keccak", "sha", "hash(", "hash2(",
            ],
        )
    }

    fn has_merkle_usage(usage_lines: &[&str]) -> bool {
        Self::has_keyword_usage(
            usage_lines,
            &[
                "merkle",
                "path",
                "sibling",
                "root",
                "proof",
                "path_index",
                "pathindex",
            ],
        )
    }

    fn has_signature_usage(usage_lines: &[&str]) -> bool {
        Self::has_keyword_usage(
            usage_lines,
            &[
                "signature",
                "verify_sig",
                "verifysignature",
                "ecdsa",
                "eddsa",
                "schnorr",
            ],
        )
    }

    fn has_public_key_usage(usage_lines: &[&str]) -> bool {
        Self::has_keyword_usage(
            usage_lines,
            &["pubkey", "public_key", "publickey", "verify_pk", "pk["],
        )
    }

    fn has_nullifier_usage(usage_lines: &[&str]) -> bool {
        Self::has_keyword_usage(
            usage_lines,
            &["nullifier", "commitment", "nonce", "trapdoor", "blinding"],
        )
    }

    fn has_keyword_usage(usage_lines: &[&str], keywords: &[&str]) -> bool {
        usage_lines
            .iter()
            .any(|line| keywords.iter().any(|kw| line.contains(kw)))
    }

    fn to_bits(len: usize) -> u32 {
        len.min(u32::MAX as usize) as u32
    }

    /// Mutate inputs based on their structure
    pub fn mutate(&self, inputs: &[FieldElement], rng: &mut impl Rng) -> Vec<FieldElement> {
        if self.structures.is_empty() {
            // use byte-level mutation with framework-specific heuristics
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
                                crate::mutators::mutate_field_element(fe, rng)
                            }
                        }
                        Framework::Halo2 => {
                            // Halo2 often uses lookup tables, try boundary values
                            if rng.gen::<f64>() < 0.15 {
                                FieldElement::from_u64(rng.gen_range(0..256))
                            } else {
                                crate::mutators::mutate_field_element(fe, rng)
                            }
                        }
                        _ => crate::mutators::mutate_field_element(fe, rng),
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
                    crate::mutators::mutate_field_element(input, rng)
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
                    crate::mutators::mutate_field_element(input, rng)
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
            _ => crate::mutators::mutate_field_element(input, rng),
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
            _ => crate::mutators::mutate_field_element(input, rng),
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
                FieldElement::from_bytes_reduced(&bytes)
            }
            _ => crate::mutators::mutate_field_element(input, rng),
        }
    }

    fn to_u64(&self, fe: &FieldElement) -> u64 {
        let bytes = &fe.0[24..32];
        let bytes: [u8; 8] = match bytes.try_into() {
            Ok(value) => value,
            Err(err) => panic!("FieldElement tail slice is not 8 bytes: {:?}", err),
        };
        u64::from_be_bytes(bytes)
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
#[path = "structure_aware_tests.rs"]
mod tests;
