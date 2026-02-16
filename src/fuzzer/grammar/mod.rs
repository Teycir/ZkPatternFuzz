//! YAML Grammar DSL for ZK Input Generation
//!
//! Provides declarative input specification for ZK circuit fuzzing.
//! Grammars define input structure, constraints, and generation strategies.
//!
//! # Example Grammar
//!
//! ```yaml
//! name: TornadoCashWithdrawal
//! inputs:
//!   - name: secret
//!     type: field
//!     constraints:
//!       - "range: [1, p-1]"
//!       - "entropy: high"
//!   - name: nullifier
//!     type: field
//!     derived_from: "hash(secret)"
//!   - name: pathElements
//!     type: array
//!     element_type: field
//!     length: 20
//! ```

mod generator;
mod parser;
mod types;

pub use generator::GenerationStrategy;
pub use generator::GrammarGenerator;
pub use parser::GrammarParser;

use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zk_core::{FieldElement, TestCase, TestMetadata};

/// Complete input grammar specification
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct InputGrammar {
    /// Grammar name
    pub name: String,
    /// Description
    #[serde(default)]
    pub description: String,
    /// Input specifications
    pub inputs: Vec<InputSpec>,
    /// Global invariants
    #[serde(default)]
    pub invariants: Vec<String>,
    /// Merkle tree configuration (if applicable)
    #[serde(default)]
    pub merkle_config: Option<MerkleConfig>,
}

/// Single input specification
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct InputSpec {
    /// Input name (matches circuit signal name)
    pub name: String,
    /// Input type
    #[serde(rename = "type")]
    pub input_type: InputType,
    /// Constraints on the input
    #[serde(default)]
    pub constraints: Vec<String>,
    /// For array types: length
    #[serde(default)]
    pub length: Option<usize>,
    /// For array types: element type
    #[serde(default)]
    pub element_type: Option<InputType>,
    /// Derivation expression (if derived from other inputs)
    #[serde(default)]
    pub derived_from: Option<String>,
    /// Interesting values to test
    #[serde(default)]
    pub interesting: Vec<String>,
    /// Entropy requirement
    #[serde(default)]
    pub entropy: Option<EntropyLevel>,
}

/// Input type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InputType {
    /// Field element (BN254 scalar)
    Field,
    /// Boolean (0 or 1)
    Bool,
    /// Fixed-length array
    Array,
    /// Merkle proof path
    MerklePath,
    /// Nullifier
    Nullifier,
    /// Commitment
    Commitment,
    /// Signature component
    Signature,
    /// Byte array
    Bytes,
}

/// Entropy requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntropyLevel {
    Low,
    Medium,
    High,
}

/// Merkle tree configuration
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MerkleConfig {
    /// Tree depth
    pub depth: usize,
    /// Hash function to use
    #[serde(default = "default_hash")]
    pub hash_function: String,
}

fn default_hash() -> String {
    "poseidon".to_string()
}

impl InputGrammar {
    /// Load grammar from YAML file
    pub fn from_yaml(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let grammar: InputGrammar = serde_yaml::from_str(&content)?;
        Ok(grammar)
    }

    /// Load grammar from YAML string
    pub fn from_yaml_str(yaml: &str) -> anyhow::Result<Self> {
        let grammar: InputGrammar = serde_yaml::from_str(yaml)?;
        Ok(grammar)
    }

    /// Get total number of inputs
    pub fn input_count(&self) -> usize {
        self.inputs.iter().map(|i| i.flattened_count()).sum()
    }

    /// Generate a valid test case according to grammar
    pub fn generate(&self, rng: &mut impl Rng) -> TestCase {
        let mut inputs = Vec::new();
        let mut context = GenerationContext::new();

        for spec in &self.inputs {
            let values = self.generate_input(spec, rng, &mut context);
            inputs.extend(values);
        }

        TestCase {
            inputs,
            expected_output: None,
            metadata: TestMetadata {
                generation: 0,
                mutation_history: vec![format!("grammar:{}", self.name)],
                coverage_bits: 0,
            },
        }
    }

    /// Generate values for a single input spec
    fn generate_input(
        &self,
        spec: &InputSpec,
        rng: &mut impl Rng,
        context: &mut GenerationContext,
    ) -> Vec<FieldElement> {
        match spec.input_type {
            InputType::Field => {
                let value = self.generate_field(spec, rng);
                context.set(&spec.name, value.clone());
                vec![value]
            }
            InputType::Bool => {
                let value = if rng.gen_bool(0.5) {
                    FieldElement::one()
                } else {
                    FieldElement::zero()
                };
                context.set(&spec.name, value.clone());
                vec![value]
            }
            InputType::Array => {
                let len = match spec.length {
                    Some(value) => value,
                    None => 1,
                };
                let elem_type = match spec.element_type {
                    Some(value) => value,
                    None => InputType::Field,
                };
                (0..len)
                    .map(|_| match elem_type {
                        InputType::Bool => {
                            if rng.gen_bool(0.5) {
                                FieldElement::one()
                            } else {
                                FieldElement::zero()
                            }
                        }
                        _ => self.generate_field(spec, rng),
                    })
                    .collect()
            }
            InputType::MerklePath => {
                let depth = self
                    .merkle_config
                    .as_ref()
                    .map(|c| c.depth)
                    .map(|value| value);
                let depth = match depth {
                    Some(value) => value,
                    None => 20,
                };
                // Generate path elements
                let path_elements: Vec<_> = (0..depth).map(|_| FieldElement::random(rng)).collect();
                // Generate path indices (binary)
                let path_indices: Vec<_> = (0..depth)
                    .map(|_| {
                        if rng.gen_bool(0.5) {
                            FieldElement::one()
                        } else {
                            FieldElement::zero()
                        }
                    })
                    .collect();

                let mut result = path_elements;
                result.extend(path_indices);
                result
            }
            InputType::Nullifier => {
                // Generate high-entropy nullifier
                let value = FieldElement::random(rng);
                context.set(&spec.name, value.clone());
                vec![value]
            }
            InputType::Commitment => {
                // Commitment = hash(secret, blinding_factor)
                let secret = FieldElement::random(rng);
                let blinding = FieldElement::random(rng);
                context.set(&format!("{}_secret", spec.name), secret.clone());
                context.set(&format!("{}_blinding", spec.name), blinding.clone());
                let mut hasher = Sha256::new();
                hasher.update(secret.to_bytes());
                hasher.update(blinding.to_bytes());
                let digest = hasher.finalize();
                vec![FieldElement::from_bytes(&digest)]
            }
            InputType::Signature => {
                // EdDSA signature: (R, s)
                let r = FieldElement::random(rng);
                let s = FieldElement::random(rng);
                vec![r, s]
            }
            InputType::Bytes => {
                let len = match spec.length {
                    Some(value) => value,
                    None => 32,
                };
                let mut bytes = vec![0u8; len];
                rng.fill(&mut bytes[..]);
                // Pack into field elements (32 bytes each)
                bytes.chunks(32).map(FieldElement::from_bytes).collect()
            }
        }
    }

    /// Generate a field element according to constraints
    fn generate_field(&self, spec: &InputSpec, rng: &mut impl Rng) -> FieldElement {
        // Check for interesting values first
        if !spec.interesting.is_empty() && rng.gen_bool(0.3) {
            let idx = rng.gen_range(0..spec.interesting.len());
            if let Ok(fe) = FieldElement::from_hex(&spec.interesting[idx]) {
                return fe;
            }
        }

        // Parse constraints
        for constraint in &spec.constraints {
            if constraint.starts_with("range:") {
                // Parse range constraint (simplified)
                // In a full implementation, would parse [min, max] and generate in range
            }
        }

        // Default: random field element with entropy consideration
        match spec.entropy {
            Some(EntropyLevel::Low) => {
                // Low entropy: small values
                FieldElement::from_u64(rng.gen_range(0..1000))
            }
            Some(EntropyLevel::Medium) => {
                // Medium entropy
                FieldElement::from_u64(rng.gen::<u64>())
            }
            _ => {
                // High entropy: full random
                FieldElement::random(rng)
            }
        }
    }

    /// Apply structure-aware mutation
    pub fn mutate(&self, test_case: &TestCase, rng: &mut impl Rng) -> TestCase {
        let mut new_inputs = test_case.inputs.clone();

        if new_inputs.is_empty() {
            return test_case.clone();
        }

        // Choose mutation type based on grammar structure
        let mutation_type = rng.gen_range(0..5);

        match mutation_type {
            0 => {
                // Flip one input
                let idx = rng.gen_range(0..new_inputs.len());
                new_inputs[idx] = FieldElement::random(rng);
            }
            1 => {
                // Use interesting value
                if let Some(spec) = self.inputs.iter().find(|i| !i.interesting.is_empty()) {
                    let idx = rng.gen_range(0..spec.interesting.len());
                    if let Ok(fe) = FieldElement::from_hex(&spec.interesting[idx]) {
                        let target_idx = rng.gen_range(0..new_inputs.len());
                        new_inputs[target_idx] = fe;
                    }
                }
            }
            2 => {
                // Use boundary value
                let idx = rng.gen_range(0..new_inputs.len());
                let boundary_type = rng.gen_range(0..4);
                new_inputs[idx] = match boundary_type {
                    0 => FieldElement::zero(),
                    1 => FieldElement::one(),
                    2 => FieldElement::max_value(),
                    _ => FieldElement::half_modulus(),
                };
            }
            3 => {
                // Negate a field element
                let idx = rng.gen_range(0..new_inputs.len());
                new_inputs[idx] = new_inputs[idx].neg();
            }
            _ => {
                // Swap two elements
                if new_inputs.len() >= 2 {
                    let idx1 = rng.gen_range(0..new_inputs.len());
                    let idx2 = rng.gen_range(0..new_inputs.len());
                    new_inputs.swap(idx1, idx2);
                }
            }
        }

        TestCase {
            inputs: new_inputs,
            expected_output: None,
            metadata: TestMetadata {
                generation: test_case.metadata.generation + 1,
                mutation_history: {
                    let mut history = test_case.metadata.mutation_history.clone();
                    history.push(format!("grammar_mutate:{}", mutation_type));
                    history
                },
                coverage_bits: 0,
            },
        }
    }
}

impl InputSpec {
    /// Get flattened count (for arrays, includes all elements)
    pub fn flattened_count(&self) -> usize {
        match self.input_type {
            InputType::Array => match self.length {
                Some(value) => value,
                None => 1,
            },
            InputType::MerklePath => {
                // path elements + path indices
                (match self.length {
                    Some(value) => value,
                    None => 20,
                }) * 2
            }
            InputType::Signature => 2, // (R, s)
            _ => 1,
        }
    }
}

/// Context for value generation (tracks generated values for derivation)
struct GenerationContext {
    values: HashMap<String, FieldElement>,
}

impl GenerationContext {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    fn set(&mut self, name: &str, value: FieldElement) {
        self.values.insert(name.to_string(), value);
    }

    #[allow(dead_code)]
    fn get(&self, name: &str) -> Option<&FieldElement> {
        self.values.get(name)
    }
}

/// Standard grammars for common ZK patterns
pub mod standard {
    use super::*;

    /// Tornado Cash withdrawal grammar
    pub fn tornado_cash_withdrawal() -> InputGrammar {
        InputGrammar {
            name: "TornadoCashWithdrawal".to_string(),
            description: "Input grammar for Tornado Cash withdraw circuit".to_string(),
            inputs: vec![
                InputSpec {
                    name: "root".to_string(),
                    input_type: InputType::Field,
                    constraints: vec![],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec![],
                    entropy: Some(EntropyLevel::High),
                },
                InputSpec {
                    name: "nullifierHash".to_string(),
                    input_type: InputType::Nullifier,
                    constraints: vec![],
                    length: None,
                    element_type: None,
                    derived_from: Some("hash(nullifier)".to_string()),
                    interesting: vec![],
                    entropy: Some(EntropyLevel::High),
                },
                InputSpec {
                    name: "recipient".to_string(),
                    input_type: InputType::Field,
                    constraints: vec![],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec![],
                    entropy: Some(EntropyLevel::Medium),
                },
                InputSpec {
                    name: "relayer".to_string(),
                    input_type: InputType::Field,
                    constraints: vec![],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec![],
                    entropy: Some(EntropyLevel::Medium),
                },
                InputSpec {
                    name: "fee".to_string(),
                    input_type: InputType::Field,
                    constraints: vec!["range: [0, 1000000000000000000]".to_string()],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec!["0x0".to_string(), "0x1".to_string()],
                    entropy: Some(EntropyLevel::Low),
                },
                InputSpec {
                    name: "refund".to_string(),
                    input_type: InputType::Field,
                    constraints: vec!["range: [0, 1000000000000000000]".to_string()],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec!["0x0".to_string()],
                    entropy: Some(EntropyLevel::Low),
                },
                InputSpec {
                    name: "nullifier".to_string(),
                    input_type: InputType::Nullifier,
                    constraints: vec![],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec![],
                    entropy: Some(EntropyLevel::High),
                },
                InputSpec {
                    name: "secret".to_string(),
                    input_type: InputType::Field,
                    constraints: vec![],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec![],
                    entropy: Some(EntropyLevel::High),
                },
                InputSpec {
                    name: "pathElements".to_string(),
                    input_type: InputType::Array,
                    constraints: vec![],
                    length: Some(20),
                    element_type: Some(InputType::Field),
                    derived_from: None,
                    interesting: vec![],
                    entropy: None,
                },
                InputSpec {
                    name: "pathIndices".to_string(),
                    input_type: InputType::Array,
                    constraints: vec!["binary".to_string()],
                    length: Some(20),
                    element_type: Some(InputType::Bool),
                    derived_from: None,
                    interesting: vec![],
                    entropy: None,
                },
            ],
            invariants: vec![
                "hash(secret, nullifier) in commitment_set".to_string(),
                "merkle_verify(root, leaf, pathElements, pathIndices) == true".to_string(),
            ],
            merkle_config: Some(MerkleConfig {
                depth: 20,
                hash_function: "pedersen".to_string(),
            }),
        }
    }

    /// Semaphore identity grammar
    pub fn semaphore_identity() -> InputGrammar {
        InputGrammar {
            name: "SemaphoreIdentity".to_string(),
            description: "Input grammar for Semaphore circuit".to_string(),
            inputs: vec![
                InputSpec {
                    name: "identityNullifier".to_string(),
                    input_type: InputType::Nullifier,
                    constraints: vec![],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec![],
                    entropy: Some(EntropyLevel::High),
                },
                InputSpec {
                    name: "identityTrapdoor".to_string(),
                    input_type: InputType::Field,
                    constraints: vec![],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec![],
                    entropy: Some(EntropyLevel::High),
                },
                InputSpec {
                    name: "treePathIndices".to_string(),
                    input_type: InputType::Array,
                    constraints: vec!["binary".to_string()],
                    length: Some(20),
                    element_type: Some(InputType::Bool),
                    derived_from: None,
                    interesting: vec![],
                    entropy: None,
                },
                InputSpec {
                    name: "treeSiblings".to_string(),
                    input_type: InputType::Array,
                    constraints: vec![],
                    length: Some(20),
                    element_type: Some(InputType::Field),
                    derived_from: None,
                    interesting: vec![],
                    entropy: None,
                },
                InputSpec {
                    name: "externalNullifier".to_string(),
                    input_type: InputType::Field,
                    constraints: vec![],
                    length: None,
                    element_type: None,
                    derived_from: None,
                    interesting: vec![],
                    entropy: Some(EntropyLevel::High),
                },
            ],
            invariants: vec![
                "identity_commitment = hash(identityNullifier, identityTrapdoor)".to_string(),
            ],
            merkle_config: Some(MerkleConfig {
                depth: 20,
                hash_function: "poseidon".to_string(),
            }),
        }
    }

    /// Range proof grammar
    pub fn range_proof(bits: usize) -> InputGrammar {
        InputGrammar {
            name: format!("RangeProof{}", bits),
            description: format!("Input grammar for {}-bit range proof", bits),
            inputs: vec![InputSpec {
                name: "value".to_string(),
                input_type: InputType::Field,
                constraints: vec![format!("range: [0, {}]", (1u128 << bits) - 1)],
                length: None,
                element_type: None,
                derived_from: None,
                interesting: vec![
                    "0x0".to_string(),
                    "0x1".to_string(),
                    format!("0x{:x}", (1u128 << bits) - 1),
                    format!("0x{:x}", 1u128 << bits), // Just over boundary
                ],
                entropy: Some(EntropyLevel::Medium),
            }],
            invariants: vec![format!("value < 2^{}", bits)],
            merkle_config: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_grammar() {
        let yaml = r#"
name: TestGrammar
description: Test grammar for unit tests
inputs:
  - name: secret
    type: field
    entropy: high
  - name: pathIndices
    type: array
    length: 5
    element_type: bool
"#;
        let grammar = InputGrammar::from_yaml_str(yaml).unwrap();
        assert_eq!(grammar.name, "TestGrammar");
        assert_eq!(grammar.inputs.len(), 2);
        assert_eq!(grammar.inputs[0].input_type, InputType::Field);
        assert_eq!(grammar.inputs[1].length, Some(5));
    }

    #[test]
    fn test_generate_test_case() {
        let grammar = standard::tornado_cash_withdrawal();
        let mut rng = rand::thread_rng();

        let test_case = grammar.generate(&mut rng);

        // Should have: root(1) + nullifierHash(1) + recipient(1) + relayer(1) +
        // fee(1) + refund(1) + nullifier(1) + secret(1) + pathElements(20) + pathIndices(20)
        assert_eq!(test_case.inputs.len(), 48);
    }

    #[test]
    fn test_mutation() {
        let grammar = standard::tornado_cash_withdrawal();
        let mut rng = rand::thread_rng();

        let original = grammar.generate(&mut rng);

        // Try multiple mutations - at least one should differ
        let mut any_different = false;
        for _ in 0..10 {
            let mutated = grammar.mutate(&original, &mut rng);
            // Should have same length
            assert_eq!(original.inputs.len(), mutated.inputs.len());
            if original.inputs != mutated.inputs {
                any_different = true;
                break;
            }
        }

        // At least one mutation should have produced a different result
        assert!(
            any_different,
            "After 10 attempts, mutation should produce different output"
        );
    }

    #[test]
    fn test_standard_grammars() {
        let tornado = standard::tornado_cash_withdrawal();
        assert_eq!(tornado.input_count(), 48);

        let semaphore = standard::semaphore_identity();
        assert!(semaphore.input_count() > 0);

        let range = standard::range_proof(64);
        assert_eq!(range.input_count(), 1);
    }
}
