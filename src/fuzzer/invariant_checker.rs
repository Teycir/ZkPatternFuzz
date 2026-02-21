//! Fuzz-Continuous Invariant Checking (Phase 2)
//!
//! This module provides per-execution invariant checking for the fuzzing loop.
//! Unlike the one-shot `enforce_invariants()` approach, this checker evaluates
//! invariants against every test case that the circuit accepts, enabling
//! continuous violation detection during fuzzing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     InvariantChecker                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  invariants: Vec<ParsedInvariant>                          │
//! │  input_map: HashMap<String, (usize, usize)>                │
//! │  uniqueness_tracker: HashMap<String, HashSet<Vec<u8>>>     │
//! └─────────────────────────────────────────────────────────────┘
//!           │
//!           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  check(inputs, outputs) → Vec<Violation>                   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Invariant Types
//!
//! - **Range**: `0 <= x < MAX` - checked per-execution
//! - **Uniqueness**: `unique(nullifier) for each (scope, secret)` - stateful tracking
//! - **Constraint**: `y = Poseidon(a, b)` - requires output comparison
//! - **Inequality**: `index < 2^length` - checked per-execution

use crate::config::v2::{
    parse_invariant_relation, Invariant, InvariantAST, InvariantOracle, InvariantType,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use zk_core::FieldElement;

/// A violation of an invariant detected during fuzzing
#[derive(Debug, Clone)]
pub struct Violation {
    /// Name of the violated invariant
    pub invariant_name: String,
    /// The relation that was violated
    pub relation: String,
    /// The witness inputs that caused the violation
    pub witness: Vec<FieldElement>,
    /// The circuit outputs (if available)
    pub outputs: Vec<FieldElement>,
    /// Severity of the violation
    pub severity: String,
    /// Human-readable evidence description
    pub evidence: String,
    /// Whether this was confirmed by circuit accepting the witness
    pub circuit_accepted: bool,
}

/// Parsed invariant ready for fast checking
#[derive(Debug, Clone)]
pub struct ParsedInvariant {
    /// Original invariant name
    pub name: String,
    /// Original relation string
    pub relation: String,
    /// Parsed AST (if successfully parsed)
    pub ast: Option<InvariantAST>,
    /// Type of invariant
    pub invariant_type: InvariantType,
    /// Severity if violated
    pub severity: String,
    /// Input indices this invariant references
    pub input_indices: Vec<usize>,
    /// For range invariants: (lower_bound, upper_bound, is_upper_exclusive)
    pub range_bounds: Option<(FieldElement, FieldElement, bool)>,
    /// For uniqueness invariants: key indices for grouping
    pub uniqueness_key_indices: Vec<usize>,
    /// For uniqueness invariants: value indices to check
    pub uniqueness_value_indices: Vec<usize>,
}

/// Fuzz-continuous invariant checker
///
/// Evaluates invariants against every successful execution in the fuzzing loop.
/// Maintains state for uniqueness invariants (tracking seen values).
pub struct InvariantChecker {
    /// Parsed invariants ready for fast checking
    invariants: Vec<ParsedInvariant>,
    /// Input name to (offset, length) mapping
    input_map: HashMap<String, (usize, usize)>,
    /// For uniqueness invariants: tracks seen values per key
    /// Key: invariant_name + key_hash, Value: set of value_hashes
    uniqueness_tracker: HashMap<String, HashSet<Vec<u8>>>,
}

impl InvariantChecker {
    /// Create a new invariant checker from v2 invariants and input configuration
    pub fn new(invariants: Vec<Invariant>, inputs: &[crate::config::Input]) -> Self {
        let mut input_map = HashMap::new();
        let mut offset = 0usize;
        for input in inputs {
            let len = if input.input_type.starts_with("array") {
                input.length.unwrap_or(1)
            } else {
                1
            };
            input_map.insert(input.name.to_lowercase(), (offset, len));
            offset += len;
        }
        let parsed = invariants
            .into_iter()
            .filter_map(|inv| Self::parse_invariant(&inv, &input_map))
            .collect();

        Self {
            invariants: parsed,
            input_map,
            uniqueness_tracker: HashMap::new(),
        }
    }

    /// Parse a single invariant into a fast-checkable form
    fn parse_invariant(
        invariant: &Invariant,
        input_map: &HashMap<String, (usize, usize)>,
    ) -> Option<ParsedInvariant> {
        // Skip metamorphic invariants (handled separately)
        if invariant.invariant_type == InvariantType::Metamorphic {
            return None;
        }

        // Skip custom/differential/symbolic oracles
        if matches!(
            invariant.oracle,
            InvariantOracle::Custom | InvariantOracle::Differential | InvariantOracle::Symbolic
        ) {
            return None;
        }

        let ast = match parse_invariant_relation(&invariant.relation) {
            Ok(ast) => Some(ast),
            Err(err) => {
                tracing::debug!(
                    "Invariant relation AST parse failed for '{}': {}",
                    invariant.relation,
                    err
                );
                None
            }
        };
        let input_indices = Self::extract_input_indices(&invariant.relation, input_map);

        let range_bounds = if invariant.invariant_type == InvariantType::Range {
            Self::parse_range_bounds(&invariant.relation, ast.as_ref())
        } else {
            None
        };

        let (uniqueness_key_indices, uniqueness_value_indices) =
            if invariant.invariant_type == InvariantType::Uniqueness {
                Self::parse_uniqueness_indices(&invariant.relation, input_map)
            } else {
                (vec![], vec![])
            };

        Some(ParsedInvariant {
            name: invariant.name.clone(),
            relation: invariant.relation.clone(),
            ast,
            invariant_type: invariant.invariant_type.clone(),
            severity: match invariant.severity.clone() {
                Some(value) => value,
                None => "medium".to_string(),
            },
            input_indices,
            range_bounds,
            uniqueness_key_indices,
            uniqueness_value_indices,
        })
    }

    /// Extract input indices referenced in a relation
    fn extract_input_indices(
        relation: &str,
        input_map: &HashMap<String, (usize, usize)>,
    ) -> Vec<usize> {
        let mut indices = Vec::new();
        let tokens = Self::tokenize_relation(relation);

        for token in tokens {
            let lower = token.to_lowercase();
            if let Some(&(offset, len)) = input_map.get(&lower) {
                for i in 0..len {
                    if !indices.contains(&(offset + i)) {
                        indices.push(offset + i);
                    }
                }
            }
        }

        indices
    }

    /// Tokenize a relation string into identifiers
    fn tokenize_relation(relation: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();

        for ch in relation.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                current.push(ch);
            } else if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }

        tokens
    }

    /// Parse range bounds from a relation like "0 <= x < MAX"
    fn parse_range_bounds(
        relation: &str,
        _ast: Option<&InvariantAST>,
    ) -> Option<(FieldElement, FieldElement, bool)> {
        // Try to parse common patterns:
        // "0 <= x < MAX"
        // "x < 2^64"
        // "x >= 0 && x < MAX"

        let relation = relation.trim();

        // Pattern: "0 <= x < MAX" or "0 <= x <= MAX"
        if relation.contains("<=") && relation.contains("<") {
            // Try to extract bounds
            if let Some((lower_part, rest)) = relation.split_once("<=") {
                let lower = Self::parse_field_value(lower_part.trim())?;
                if let Some((_, upper_part)) = rest.split_once('<') {
                    // Check if it's < or <=
                    let is_exclusive = !upper_part.trim_start().starts_with('=');
                    let upper_str = upper_part.trim_start_matches('=').trim();
                    let upper = Self::parse_field_value(upper_str)?;
                    return Some((lower, upper, is_exclusive));
                }
            }
        }

        // Pattern: "x < MAX"
        if let Some((_, upper_part)) = relation.split_once('<') {
            if !upper_part.starts_with('=') {
                let upper = Self::parse_field_value(upper_part.trim())?;
                return Some((FieldElement::zero(), upper, true));
            }
        }

        // Pattern: "x <= MAX"
        if let Some((_, upper_part)) = relation.split_once("<=") {
            let upper = Self::parse_field_value(upper_part.trim())?;
            return Some((FieldElement::zero(), upper, false));
        }

        None
    }

    /// Parse a field value from string (decimal or hex)
    fn parse_field_value(s: &str) -> Option<FieldElement> {
        let s = s.trim();

        // Handle power notation: 2^N
        if let Some((base, exp)) = s.split_once('^') {
            let base: u64 = match base.trim().parse() {
                Ok(base) => base,
                Err(err) => {
                    tracing::debug!("Invalid power base '{}' in '{}': {}", base.trim(), s, err);
                    return None;
                }
            };
            let exp: u32 = match exp.trim().parse() {
                Ok(exp) => exp,
                Err(err) => {
                    tracing::debug!(
                        "Invalid power exponent '{}' in '{}': {}",
                        exp.trim(),
                        s,
                        err
                    );
                    return None;
                }
            };
            if base == 2 && exp <= 253 {
                let mut bytes = [0u8; 32];
                let byte_idx = 31 - (exp / 8) as usize;
                let bit_pos = exp % 8;
                if byte_idx < 32 {
                    bytes[byte_idx] = 1 << bit_pos;
                }
                return Some(FieldElement(bytes));
            }
        }

        // Hex format
        if s.starts_with("0x") || s.starts_with("0X") {
            return match FieldElement::from_hex(s) {
                Ok(value) => Some(value),
                Err(err) => {
                    tracing::debug!("Invalid hex field literal '{}': {}", s, err);
                    None
                }
            };
        }

        // Decimal format
        if let Some(value) = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10) {
            let bytes = value.to_bytes_be();
            if bytes.len() <= 32 {
                let mut buf = [0u8; 32];
                let start = 32 - bytes.len();
                buf[start..].copy_from_slice(&bytes);
                return Some(FieldElement(buf));
            }
        }

        None
    }

    /// Parse uniqueness indices from relation like "unique(nullifier) for each (scope, secret)"
    fn parse_uniqueness_indices(
        relation: &str,
        input_map: &HashMap<String, (usize, usize)>,
    ) -> (Vec<usize>, Vec<usize>) {
        // Parse pattern: "unique(VALUE) for each (KEY1, KEY2)"
        let relation_lower = relation.to_lowercase();

        let value_indices = if let Some(start) = relation_lower.find("unique(") {
            let rest = &relation[start + 7..];
            if let Some(end) = rest.find(')') {
                let value_name = &rest[..end].trim().to_lowercase();
                Self::extract_input_indices(value_name, input_map)
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let key_indices = if let Some(start) = relation_lower.find("for each") {
            let rest = &relation[start + 8..].trim();
            if rest.starts_with('(') {
                if let Some(end) = rest.find(')') {
                    let keys_str = &rest[1..end];
                    Self::extract_input_indices(keys_str, input_map)
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        (key_indices, value_indices)
    }

    /// Check all invariants against a concrete witness
    ///
    /// Called for every test case that the circuit accepts.
    /// Returns a list of violated invariants with evidence.
    pub fn check(
        &mut self,
        inputs: &[FieldElement],
        outputs: &[FieldElement],
        circuit_accepted: bool,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        // Clone the invariants to avoid borrow issues with uniqueness tracking
        let invariants: Vec<_> = self.invariants.clone();
        for invariant in &invariants {
            if let Some(violation) = self.check_single(invariant, inputs, outputs, circuit_accepted)
            {
                violations.push(violation);
            }
        }

        violations
    }

    /// Check a single invariant against inputs/outputs
    fn check_single(
        &mut self,
        invariant: &ParsedInvariant,
        inputs: &[FieldElement],
        outputs: &[FieldElement],
        circuit_accepted: bool,
    ) -> Option<Violation> {
        match invariant.invariant_type {
            InvariantType::Range => self.check_range(invariant, inputs, circuit_accepted),
            InvariantType::Uniqueness => self.check_uniqueness(invariant, inputs, circuit_accepted),
            InvariantType::Constraint => {
                self.check_constraint(invariant, inputs, outputs, circuit_accepted)
            }
            InvariantType::Custom | InvariantType::Metamorphic => None,
        }
    }

    /// Compare two field elements (as big-endian bytes)
    fn field_cmp(a: &FieldElement, b: &FieldElement) -> std::cmp::Ordering {
        a.0.cmp(&b.0)
    }

    /// Check a range invariant
    fn check_range(
        &self,
        invariant: &ParsedInvariant,
        inputs: &[FieldElement],
        circuit_accepted: bool,
    ) -> Option<Violation> {
        let (lower, upper, is_exclusive) = invariant.range_bounds.as_ref()?;

        for &idx in &invariant.input_indices {
            if idx >= inputs.len() {
                continue;
            }

            let value = &inputs[idx];

            // Check lower bound: value >= lower
            if Self::field_cmp(value, lower) == std::cmp::Ordering::Less {
                return Some(Violation {
                    invariant_name: invariant.name.clone(),
                    relation: invariant.relation.clone(),
                    witness: inputs.to_vec(),
                    outputs: vec![],
                    severity: invariant.severity.clone(),
                    evidence: format!(
                        "Input at index {} = {} is below lower bound {}",
                        idx,
                        value.to_hex(),
                        lower.to_hex()
                    ),
                    circuit_accepted,
                });
            }

            // Check upper bound: value < upper (exclusive) or value <= upper (inclusive)
            let cmp = Self::field_cmp(value, upper);
            let upper_violated = if *is_exclusive {
                cmp != std::cmp::Ordering::Less
            } else {
                cmp == std::cmp::Ordering::Greater
            };

            if upper_violated {
                return Some(Violation {
                    invariant_name: invariant.name.clone(),
                    relation: invariant.relation.clone(),
                    witness: inputs.to_vec(),
                    outputs: vec![],
                    severity: invariant.severity.clone(),
                    evidence: format!(
                        "Input at index {} = {} exceeds upper bound {} (exclusive={})",
                        idx,
                        value.to_hex(),
                        upper.to_hex(),
                        is_exclusive
                    ),
                    circuit_accepted,
                });
            }
        }

        None
    }

    /// Check a uniqueness invariant (stateful)
    fn check_uniqueness(
        &mut self,
        invariant: &ParsedInvariant,
        inputs: &[FieldElement],
        circuit_accepted: bool,
    ) -> Option<Violation> {
        if invariant.uniqueness_key_indices.is_empty()
            || invariant.uniqueness_value_indices.is_empty()
        {
            return None;
        }

        // Compute key hash from key indices
        let key_hash = self.compute_hash(&invariant.uniqueness_key_indices, inputs);

        // Compute value hash from value indices
        let value_hash = self.compute_hash(&invariant.uniqueness_value_indices, inputs);

        // Create tracker key: invariant_name + key_hash
        let tracker_key = format!("{}:{}", invariant.name, hex::encode(&key_hash));

        // Check if we've seen this value for this key before
        let seen_values = self.uniqueness_tracker.entry(tracker_key).or_default();

        if seen_values.contains(&value_hash) {
            // Duplicate detected - but this is not necessarily a violation
            // A violation occurs when DIFFERENT key produces SAME value
            // For now, we track this as informational
            return None;
        }

        // Check if this value was seen with a DIFFERENT key
        let value_hex = hex::encode(&value_hash);
        for (other_key, other_values) in &self.uniqueness_tracker {
            if other_key.starts_with(&format!("{}:", invariant.name))
                && other_values.contains(&value_hash)
            {
                // Same value seen with different key - violation!
                return Some(Violation {
                    invariant_name: invariant.name.clone(),
                    relation: invariant.relation.clone(),
                    witness: inputs.to_vec(),
                    outputs: vec![],
                    severity: invariant.severity.clone(),
                    evidence: format!(
                        "Uniqueness violation: value {} seen with different keys",
                        value_hex
                    ),
                    circuit_accepted,
                });
            }
        }

        // Record this value for this key
        let tracker_key = format!("{}:{}", invariant.name, hex::encode(&key_hash));
        self.uniqueness_tracker
            .entry(tracker_key)
            .or_default()
            .insert(value_hash);

        None
    }

    /// Check a constraint invariant
    fn check_constraint(
        &self,
        invariant: &ParsedInvariant,
        inputs: &[FieldElement],
        outputs: &[FieldElement],
        circuit_accepted: bool,
    ) -> Option<Violation> {
        // Constraint checking is more complex and depends on the specific constraint
        // For now, we do basic structural checking
        // Full constraint evaluation would require a constraint solver

        // If we have an AST, try to evaluate it
        if let Some(ast) = &invariant.ast {
            if let Some(violation) =
                self.evaluate_constraint_ast(ast, invariant, inputs, outputs, circuit_accepted)
            {
                return Some(violation);
            }
        }

        None
    }

    /// Evaluate a constraint AST against inputs/outputs
    fn evaluate_constraint_ast(
        &self,
        ast: &InvariantAST,
        invariant: &ParsedInvariant,
        inputs: &[FieldElement],
        outputs: &[FieldElement],
        circuit_accepted: bool,
    ) -> Option<Violation> {
        match ast {
            InvariantAST::Equals(left, right) => {
                let left_val = self.evaluate_expr(left, inputs, outputs)?;
                let right_val = self.evaluate_expr(right, inputs, outputs)?;
                if left_val != right_val {
                    return Some(Violation {
                        invariant_name: invariant.name.clone(),
                        relation: invariant.relation.clone(),
                        witness: inputs.to_vec(),
                        outputs: outputs.to_vec(),
                        severity: invariant.severity.clone(),
                        evidence: format!(
                            "Constraint violated: {} != {}",
                            left_val.to_hex(),
                            right_val.to_hex()
                        ),
                        circuit_accepted,
                    });
                }
            }
            InvariantAST::NotEquals(left, right) => {
                let left_val = self.evaluate_expr(left, inputs, outputs)?;
                let right_val = self.evaluate_expr(right, inputs, outputs)?;
                if left_val == right_val {
                    return Some(Violation {
                        invariant_name: invariant.name.clone(),
                        relation: invariant.relation.clone(),
                        witness: inputs.to_vec(),
                        outputs: outputs.to_vec(),
                        severity: invariant.severity.clone(),
                        evidence: format!(
                            "Constraint violated: {} should not equal {}",
                            left_val.to_hex(),
                            right_val.to_hex()
                        ),
                        circuit_accepted,
                    });
                }
            }
            InvariantAST::LessThan(left, right) => {
                let left_val = self.evaluate_expr(left, inputs, outputs)?;
                let right_val = self.evaluate_expr(right, inputs, outputs)?;
                if Self::field_cmp(&left_val, &right_val) != std::cmp::Ordering::Less {
                    return Some(Violation {
                        invariant_name: invariant.name.clone(),
                        relation: invariant.relation.clone(),
                        witness: inputs.to_vec(),
                        outputs: outputs.to_vec(),
                        severity: invariant.severity.clone(),
                        evidence: format!(
                            "Constraint violated: {} not < {}",
                            left_val.to_hex(),
                            right_val.to_hex()
                        ),
                        circuit_accepted,
                    });
                }
            }
            _ => {}
        }

        None
    }

    /// Evaluate an expression against inputs/outputs
    fn evaluate_expr(
        &self,
        expr: &InvariantAST,
        inputs: &[FieldElement],
        outputs: &[FieldElement],
    ) -> Option<FieldElement> {
        match expr {
            InvariantAST::Identifier(name) => {
                let lower = name.to_lowercase();
                if let Some(&(offset, _)) = self.input_map.get(&lower) {
                    inputs.get(offset).cloned()
                } else if lower.starts_with("output") {
                    // Try to parse output index
                    let idx_str = match lower.strip_prefix("output") {
                        Some(value) => value,
                        None => {
                            panic!(
                                "Invariant identifier unexpectedly lost 'output' prefix: {}",
                                name
                            )
                        }
                    };
                    let idx: usize = match idx_str.trim_start_matches('_').parse() {
                        Ok(parsed) => parsed,
                        Err(err) => {
                            tracing::warn!(
                                "Failed to parse output index from invariant identifier '{}': {}",
                                name,
                                err
                            );
                            return None;
                        }
                    };
                    outputs.get(idx).cloned()
                } else {
                    None
                }
            }
            InvariantAST::Literal(val) => Self::parse_field_value(val),
            _ => None,
        }
    }

    /// Compute a hash of field elements at given indices
    fn compute_hash(&self, indices: &[usize], inputs: &[FieldElement]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for &idx in indices {
            if let Some(fe) = inputs.get(idx) {
                hasher.update(fe.0);
            }
        }
        hasher.finalize().to_vec()
    }

    /// Reset uniqueness tracking state
    pub fn reset_uniqueness_state(&mut self) {
        self.uniqueness_tracker.clear();
    }

    /// Get the number of invariants being checked
    pub fn invariant_count(&self) -> usize {
        self.invariants.len()
    }

    /// Check if there are any uniqueness invariants (which require stateful tracking)
    pub fn has_uniqueness_invariants(&self) -> bool {
        self.invariants
            .iter()
            .any(|inv| inv.invariant_type == InvariantType::Uniqueness)
    }
}
