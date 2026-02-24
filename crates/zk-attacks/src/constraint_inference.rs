//! Constraint Inference Engine
//!
//! Detects **missing** constraints by analyzing circuit semantics and inferring
//! what constraints *should* exist based on common ZK patterns. Then generates
//! inputs that exploit the missing constraints.
//!
//! # Innovation
//!
//! Most fuzzers test existing constraints. This engine infers what constraints
//! *should* exist based on circuit patterns (bit decomposition, Merkle paths,
//! nullifiers, etc.) and generates test cases that violate the missing constraints.
//!
//! # Example
//!
//! ```rust,ignore
//! use zk_fuzzer::oracles::constraint_inference::ConstraintInferenceEngine;
//!
//! let engine = ConstraintInferenceEngine::new()
//!     .with_category(ConstraintCategory::BitDecompositionRoundTrip)
//!     .with_category(ConstraintCategory::MerklePathValidation);
//!
//! let missing = engine.analyze(&inspector)?;
//! for constraint in missing {
//!     println!("Missing: {} (confidence: {:.1}%)", constraint.description, constraint.confidence * 100.0);
//! }
//! ```

use std::collections::{HashMap, HashSet};
use zk_core::{
    AttackType, CircuitExecutor, ConstraintEquation, ConstraintInspector, FieldElement, Finding,
    ProofOfConcept, Severity,
};

/// Categories of constraints that can be inferred
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstraintCategory {
    /// Bit decomposition without recomposition constraint
    BitDecompositionRoundTrip,
    /// Merkle path indices not constrained to binary
    MerklePathValidation,
    /// Nullifier not enforced unique
    NullifierUniqueness,
    /// Range check missing upper/lower bound
    RangeEnforcement,
    /// Hash input/output relation unconstrained
    HashConsistency,
    /// Signature components not on curve
    SignatureValidation,
    /// Commitment binding property missing
    CommitmentBinding,
    /// Public input not properly constrained
    PublicInputValidation,
}

impl ConstraintCategory {
    /// Get all standard categories
    pub fn all() -> Vec<Self> {
        vec![
            Self::BitDecompositionRoundTrip,
            Self::MerklePathValidation,
            Self::NullifierUniqueness,
            Self::RangeEnforcement,
            Self::HashConsistency,
            Self::SignatureValidation,
            Self::CommitmentBinding,
            Self::PublicInputValidation,
        ]
    }

    /// Get description for the category
    pub fn description(&self) -> &'static str {
        match self {
            Self::BitDecompositionRoundTrip => "Bit decomposition without recomposition",
            Self::MerklePathValidation => "Merkle path indices not binary constrained",
            Self::NullifierUniqueness => "Nullifier uniqueness not enforced",
            Self::RangeEnforcement => "Missing range check bounds",
            Self::HashConsistency => "Hash input/output relation missing",
            Self::SignatureValidation => "Signature components not validated",
            Self::CommitmentBinding => "Commitment binding property missing",
            Self::PublicInputValidation => "Public input not properly constrained",
        }
    }

    /// Get severity for missing constraints of this category
    pub fn severity(&self) -> Severity {
        match self {
            Self::BitDecompositionRoundTrip => Severity::Critical,
            Self::MerklePathValidation => Severity::Critical,
            Self::NullifierUniqueness => Severity::Critical,
            Self::RangeEnforcement => Severity::High,
            Self::HashConsistency => Severity::High,
            Self::SignatureValidation => Severity::Critical,
            Self::CommitmentBinding => Severity::High,
            Self::PublicInputValidation => Severity::Medium,
        }
    }
}

/// An implied constraint that should exist but wasn't found
#[derive(Debug, Clone)]
pub struct ImpliedConstraint {
    /// Category of the missing constraint
    pub category: ConstraintCategory,
    /// Human-readable description
    pub description: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Wire indices involved
    pub involved_wires: Vec<usize>,
    /// Suggested constraint expression
    pub suggested_constraint: String,
    /// Violation test case (if generated)
    pub violation_witness: Option<Vec<FieldElement>>,
    /// Execution confirmation status for the violation witness
    pub confirmation: ViolationConfirmation,
}

/// Confirmation status for a violation witness
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationConfirmation {
    /// Not executed/checked yet
    Unchecked,
    /// Executed and constraints were satisfied
    Confirmed,
    /// Executed and constraints were NOT satisfied or execution failed
    Rejected,
    /// Executed but confirmation could not be determined (no constraint checks)
    Inconclusive,
    /// Executed but involves internal wires (cannot be confirmed from inputs)
    UnconfirmedInternal,
}

impl ViolationConfirmation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unchecked => "unchecked",
            Self::Confirmed => "confirmed by execution",
            Self::Rejected => "rejected by execution",
            Self::Inconclusive => "inconclusive (no constraint evaluation)",
            Self::UnconfirmedInternal => "unconfirmed (internal wires involved)",
        }
    }
}

/// Trait for constraint inference rules
pub trait InferenceRule: Send + Sync {
    /// Category this rule detects
    fn category(&self) -> ConstraintCategory;

    /// Analyze constraints and infer missing ones
    fn infer(&self, context: &InferenceContext) -> Vec<ImpliedConstraint>;

    /// Generate a witness that violates the missing constraint
    fn generate_violation(
        &self,
        implied: &ImpliedConstraint,
        num_wires: usize,
    ) -> Option<Vec<FieldElement>>;
}

/// Context for constraint inference
pub struct InferenceContext {
    /// All constraints in the circuit
    pub constraints: Vec<ConstraintEquation>,
    /// Wire labels (if available)
    pub wire_labels: HashMap<usize, String>,
    /// Number of public inputs
    pub num_public_inputs: usize,
    /// Number of private inputs
    pub num_private_inputs: usize,
    /// Total number of wires
    pub num_wires: usize,
}

impl InferenceContext {
    /// Create context from constraint inspector
    pub fn from_inspector(inspector: &dyn ConstraintInspector, num_wires: usize) -> Self {
        let constraints = inspector.get_constraints();
        let labels = inspector.wire_labels();
        let max_from_constraints = constraints
            .iter()
            .flat_map(|c| {
                c.a_terms
                    .iter()
                    .chain(c.b_terms.iter())
                    .chain(c.c_terms.iter())
                    .map(|(w, _)| *w)
            })
            .max();
        let max_from_labels = labels.keys().copied().max();
        let inferred_wires = max_from_constraints
            .into_iter()
            .chain(max_from_labels)
            .max()
            .map(|max_wire| max_wire.saturating_add(1));
        let inferred_wires = match inferred_wires {
            Some(value) => value,
            None => num_wires,
        };

        Self {
            constraints,
            wire_labels: labels,
            num_public_inputs: inspector.num_public_inputs(),
            num_private_inputs: inspector.num_private_inputs(),
            num_wires: num_wires.max(inferred_wires),
        }
    }

    /// Find wires matching a pattern in labels
    pub fn find_wires_by_label(&self, pattern: &str) -> Vec<usize> {
        self.wire_labels
            .iter()
            .filter(|(_, label)| label.to_lowercase().contains(&pattern.to_lowercase()))
            .map(|(idx, _)| *idx)
            .collect()
    }

    /// Check if a constraint exists connecting specific wires
    pub fn has_constraint_on(&self, wires: &[usize]) -> bool {
        let wire_set: HashSet<_> = wires.iter().collect();
        self.constraints.iter().any(|c| {
            let constraint_wires: HashSet<_> = c
                .a_terms
                .iter()
                .chain(c.b_terms.iter())
                .chain(c.c_terms.iter())
                .map(|(w, _)| w)
                .collect();
            wire_set.iter().all(|w| constraint_wires.contains(w))
        })
    }
}

/// Bit decomposition inference rule
pub struct BitDecompositionInference {
    /// Minimum number of "bit" wires to trigger
    min_bits: usize,
}

impl Default for BitDecompositionInference {
    fn default() -> Self {
        Self { min_bits: 4 }
    }
}

impl InferenceRule for BitDecompositionInference {
    fn category(&self) -> ConstraintCategory {
        ConstraintCategory::BitDecompositionRoundTrip
    }

    fn infer(&self, context: &InferenceContext) -> Vec<ImpliedConstraint> {
        let mut implied = Vec::new();

        // Find potential bit arrays (wires with bit-like labels or binary constraints)
        let bit_wires = self.find_bit_wires(context);

        for (base_wire, bit_wires) in bit_wires {
            if bit_wires.len() < self.min_bits {
                continue;
            }

            // Check if recomposition constraint exists
            let has_recomposition = self.check_recomposition(context, base_wire, &bit_wires);

            if !has_recomposition {
                implied.push(ImpliedConstraint {
                    category: self.category(),
                    description: format!(
                        "Bit decomposition of wire {} into {} bits lacks recomposition constraint",
                        base_wire,
                        bit_wires.len()
                    ),
                    confidence: 0.85,
                    involved_wires: std::iter::once(base_wire)
                        .chain(bit_wires.iter().copied())
                        .collect(),
                    suggested_constraint: format!(
                        "sum(bits[i] * 2^i for i in 0..{}) == wire_{}",
                        bit_wires.len(),
                        base_wire
                    ),
                    violation_witness: None,
                    confirmation: ViolationConfirmation::Unchecked,
                });
            }
        }

        implied
    }

    fn generate_violation(
        &self,
        implied: &ImpliedConstraint,
        num_wires: usize,
    ) -> Option<Vec<FieldElement>> {
        if implied.involved_wires.is_empty() {
            return None;
        }

        let mut witness = vec![FieldElement::zero(); num_wires];

        // Set base wire to a value
        let base_wire = implied.involved_wires[0];
        witness[base_wire] = FieldElement::from_u64(42);

        // Set bits to decompose a DIFFERENT value (exploit missing constraint)
        let bit_wires = &implied.involved_wires[1..];
        let different_value = 123u64; // Different from 42

        for (i, &bit_wire) in bit_wires.iter().enumerate() {
            if bit_wire < num_wires {
                let bit_value = different_value.checked_shr(i as u32).unwrap_or_default() & 1;
                witness[bit_wire] = FieldElement::from_u64(bit_value);
            }
        }

        Some(witness)
    }
}

impl BitDecompositionInference {
    fn find_bit_wires(&self, context: &InferenceContext) -> HashMap<usize, Vec<usize>> {
        let mut bit_groups: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut all_bits: Vec<usize> = Vec::new();

        // Look for binary constraints: x * (1 - x) = 0
        for constraint in &context.constraints {
            if let Some(bit_wire) = self.is_binary_constraint(constraint) {
                all_bits.push(bit_wire);
                // Try to associate with a base wire
                // Heuristic: base wire is often constrained elsewhere with these bits
                let base_wire = bit_wire.saturating_sub(1);
                bit_groups.entry(base_wire).or_default().push(bit_wire);
            }
        }

        // If we found many bits but none of the heuristic groups are large,
        // anchor them to a "value" wire label when available.
        let has_large_group = bit_groups.values().any(|bits| bits.len() >= self.min_bits);
        if !all_bits.is_empty() && !has_large_group {
            if let Some(&value_wire) = context.find_wires_by_label("value").first() {
                bit_groups.insert(value_wire, all_bits);
            }
        }

        bit_groups
    }

    fn is_binary_constraint(&self, constraint: &ConstraintEquation) -> Option<usize> {
        // Pattern: x * (1 - x) = 0 expands to x - x^2 = 0
        // In R1CS: a * b = c where one side is x and the other is (1 - x), c = 0
        if !constraint.c_terms.is_empty() {
            return None;
        }

        let check_sides = |single: &Vec<(usize, FieldElement)>,
                           pair: &Vec<(usize, FieldElement)>|
         -> Option<usize> {
            if single.len() != 1 || pair.len() != 2 {
                return None;
            }
            let wire = single[0].0;
            let has_wire = pair.iter().any(|(w, _)| *w == wire);
            let has_const = pair.iter().any(|(w, _)| *w == 0);
            if has_wire && has_const {
                Some(wire)
            } else {
                None
            }
        };

        check_sides(&constraint.a_terms, &constraint.b_terms)
            .or_else(|| check_sides(&constraint.b_terms, &constraint.a_terms))
    }

    fn check_recomposition(
        &self,
        context: &InferenceContext,
        base_wire: usize,
        bit_wires: &[usize],
    ) -> bool {
        // Look for constraint: sum(bits[i] * 2^i) == base
        // Require the base wire and a strong majority of candidate bit wires.
        context.constraints.iter().any(|c| {
            let constraint_wires: HashSet<usize> = c
                .a_terms
                .iter()
                .chain(c.b_terms.iter())
                .chain(c.c_terms.iter())
                .map(|(w, _)| *w)
                .collect();
            if !constraint_wires.contains(&base_wire) {
                return false;
            }

            let bit_overlap = bit_wires
                .iter()
                .filter(|&&wire| constraint_wires.contains(&wire))
                .count();
            let min_required = bit_wires
                .len()
                .saturating_sub(bit_wires.len() / 4)
                .max(self.min_bits.min(bit_wires.len()));
            bit_overlap >= min_required
        })
    }
}

/// Merkle path validation inference rule
pub struct MerklePathInference;

impl InferenceRule for MerklePathInference {
    fn category(&self) -> ConstraintCategory {
        ConstraintCategory::MerklePathValidation
    }

    fn infer(&self, context: &InferenceContext) -> Vec<ImpliedConstraint> {
        let mut implied = Vec::new();

        // Find path index wires
        let path_indices = context.find_wires_by_label("pathIndices");
        let path_index = context.find_wires_by_label("pathIndex");
        let indices = context.find_wires_by_label("index");

        let all_indices: Vec<usize> = path_indices
            .into_iter()
            .chain(path_index)
            .chain(indices)
            .collect();

        for wire in all_indices {
            // Check if this wire has binary constraint
            let has_binary = context.constraints.iter().any(|c| {
                // Look for x * (1-x) = 0 pattern
                c.a_terms.iter().any(|(w, _)| *w == wire)
                    && c.b_terms.iter().any(|(w, _)| *w == wire)
            });

            if !has_binary {
                implied.push(ImpliedConstraint {
                    category: self.category(),
                    description: format!(
                        "Merkle path index wire {} is not constrained to be binary (0 or 1)",
                        wire
                    ),
                    confidence: 0.9,
                    involved_wires: vec![wire],
                    suggested_constraint: format!("wire_{} * (1 - wire_{}) == 0", wire, wire),
                    violation_witness: None,
                    confirmation: ViolationConfirmation::Unchecked,
                });
            }
        }

        implied
    }

    fn generate_violation(
        &self,
        implied: &ImpliedConstraint,
        num_wires: usize,
    ) -> Option<Vec<FieldElement>> {
        if implied.involved_wires.is_empty() {
            return None;
        }

        let mut witness = vec![FieldElement::zero(); num_wires];

        // Set the path index to an invalid value (2 instead of 0 or 1)
        let wire = implied.involved_wires[0];
        witness[wire] = FieldElement::from_u64(2);

        Some(witness)
    }
}

/// Nullifier uniqueness inference rule
pub struct NullifierUniquenessInference;

impl InferenceRule for NullifierUniquenessInference {
    fn category(&self) -> ConstraintCategory {
        ConstraintCategory::NullifierUniqueness
    }

    fn infer(&self, context: &InferenceContext) -> Vec<ImpliedConstraint> {
        let mut implied = Vec::new();

        // Find nullifier wires - only match exact "nullifier" or "nullifierHash" at input level
        let nullifier_wires: Vec<usize> = context
            .wire_labels
            .iter()
            .filter(|(idx, label)| {
                let label_lower = label.to_lowercase();
                // Only match exact nullifier inputs, not intermediate wires
                (label_lower == "nullifier" || label_lower == "nullifierhash")
                    && **idx < context.num_public_inputs + context.num_private_inputs
            })
            .map(|(idx, _)| *idx)
            .collect();

        if nullifier_wires.is_empty() {
            return implied;
        }

        tracing::debug!(
            "Found {} nullifier input wires to check",
            nullifier_wires.len()
        );

        // Check if nullifier is tied to unique input
        let secret_wires = context.find_wires_by_label("secret");

        for null_wire in nullifier_wires {
            let has_binding = context.constraints.iter().any(|c| {
                let wires: HashSet<usize> = c
                    .a_terms
                    .iter()
                    .chain(c.b_terms.iter())
                    .chain(c.c_terms.iter())
                    .map(|(w, _)| *w)
                    .collect();

                wires.contains(&null_wire) && secret_wires.iter().any(|s| wires.contains(s))
            });

            if !has_binding && !secret_wires.is_empty() {
                implied.push(ImpliedConstraint {
                    category: self.category(),
                    description: format!(
                        "Nullifier wire {} is not constrained by secret inputs",
                        null_wire
                    ),
                    confidence: 0.85, // Higher confidence since we're being strict
                    involved_wires: std::iter::once(null_wire)
                        .chain(secret_wires.iter().copied())
                        .collect(),
                    suggested_constraint: "nullifier == hash(secret, ...)".to_string(),
                    violation_witness: None,
                    confirmation: ViolationConfirmation::Unchecked,
                });
            }
        }

        implied
    }

    fn generate_violation(
        &self,
        implied: &ImpliedConstraint,
        num_wires: usize,
    ) -> Option<Vec<FieldElement>> {
        if implied.involved_wires.len() < 2 {
            return None;
        }

        let mut witness = vec![FieldElement::zero(); num_wires];

        // Set nullifier to arbitrary value without following the hash constraint
        let nullifier_wire = implied.involved_wires[0];
        witness[nullifier_wire] = FieldElement::from_u64(0xdeadbeef);

        // Set secret to different value
        if let Some(&secret_wire) = implied.involved_wires.get(1) {
            witness[secret_wire] = FieldElement::from_u64(42);
        }

        Some(witness)
    }
}

/// Range enforcement inference rule
pub struct RangeEnforcementInference;

impl Default for RangeEnforcementInference {
    fn default() -> Self {
        Self
    }
}

impl InferenceRule for RangeEnforcementInference {
    fn category(&self) -> ConstraintCategory {
        ConstraintCategory::RangeEnforcement
    }

    fn infer(&self, context: &InferenceContext) -> Vec<ImpliedConstraint> {
        let mut implied = Vec::new();

        // Find wires that look like they should be range-checked
        let value_wires = context.find_wires_by_label("value");
        let amount_wires = context.find_wires_by_label("amount");
        let balance_wires = context.find_wires_by_label("balance");

        let range_wires: Vec<usize> = value_wires
            .into_iter()
            .chain(amount_wires)
            .chain(balance_wires)
            .collect();

        for wire in range_wires {
            // Heuristic: if wire has "value/amount/balance" but few constraints, likely missing range
            let constraint_count = context
                .constraints
                .iter()
                .filter(|c| {
                    c.a_terms
                        .iter()
                        .chain(c.b_terms.iter())
                        .chain(c.c_terms.iter())
                        .any(|(w, _)| *w == wire)
                })
                .count();

            if constraint_count < 3 {
                implied.push(ImpliedConstraint {
                    category: self.category(),
                    description: format!(
                        "Wire {} may be missing range check constraints (only {} constraints reference it)",
                        wire, constraint_count
                    ),
                    confidence: 0.6,
                    involved_wires: vec![wire],
                    suggested_constraint: format!("0 <= wire_{} < 2^64", wire),
                    violation_witness: None,
                    confirmation: ViolationConfirmation::Unchecked,
                });
            }
        }

        implied
    }

    fn generate_violation(
        &self,
        implied: &ImpliedConstraint,
        num_wires: usize,
    ) -> Option<Vec<FieldElement>> {
        if implied.involved_wires.is_empty() {
            return None;
        }

        let mut witness = vec![FieldElement::zero(); num_wires];

        // Set value to something that would overflow expected range
        let wire = implied.involved_wires[0];
        // Use field prime - 1 (would be negative if range-checked)
        witness[wire] = FieldElement::max_value();

        Some(witness)
    }
}

/// Main constraint inference engine
pub struct ConstraintInferenceEngine {
    rules: Vec<Box<dyn InferenceRule>>,
    confidence_threshold: f64,
    generate_violations: bool,
}

impl Default for ConstraintInferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintInferenceEngine {
    /// Create a new engine with default rules
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(BitDecompositionInference::default()),
                Box::new(MerklePathInference),
                Box::new(NullifierUniquenessInference), // Re-enabled with strict filtering
                Box::new(RangeEnforcementInference),
            ],
            confidence_threshold: 0.7,
            generate_violations: true,
        }
    }

    /// Add an inference rule
    pub fn with_rule(mut self, rule: Box<dyn InferenceRule>) -> Self {
        self.rules.push(rule);
        self
    }

    /// Set confidence threshold
    pub fn with_confidence_threshold(mut self, threshold: f64) -> Self {
        self.confidence_threshold = threshold;
        self
    }

    /// Enable/disable violation generation
    pub fn with_generate_violations(mut self, generate: bool) -> Self {
        self.generate_violations = generate;
        self
    }

    /// Filter to specific categories
    pub fn with_categories(mut self, categories: &[ConstraintCategory]) -> Self {
        let category_set: HashSet<_> = categories.iter().collect();
        self.rules.retain(|r| category_set.contains(&r.category()));
        self
    }

    /// Analyze circuit and find missing constraints
    pub fn analyze(
        &self,
        inspector: &dyn ConstraintInspector,
        num_wires: usize,
    ) -> Vec<ImpliedConstraint> {
        let context = InferenceContext::from_inspector(inspector, num_wires);
        self.analyze_with_context(&context)
    }

    /// Analyze with pre-built context
    pub fn analyze_with_context(&self, context: &InferenceContext) -> Vec<ImpliedConstraint> {
        let mut all_implied: Vec<ImpliedConstraint> = Vec::new();

        tracing::info!(
            "Analyzing {} constraints with {} rules",
            context.constraints.len(),
            self.rules.len()
        );

        for rule in &self.rules {
            let mut implied = rule.infer(context);
            tracing::info!(
                "Rule {:?} found {} implied constraints",
                rule.category(),
                implied.len()
            );

            // Generate violations if enabled
            if self.generate_violations {
                for constraint in &mut implied {
                    constraint.violation_witness =
                        rule.generate_violation(constraint, context.num_wires);
                }
            }

            all_implied.extend(implied);
        }

        // Filter by confidence threshold
        let before_filter = all_implied.len();
        all_implied.retain(|c| c.confidence >= self.confidence_threshold);
        tracing::info!(
            "Filtered {} -> {} constraints by confidence threshold {}",
            before_filter,
            all_implied.len(),
            self.confidence_threshold
        );

        // Sort by confidence descending
        all_implied.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Only keep confirmed violations after execution
        tracing::info!(
            "Returning {} high-confidence implied constraints for confirmation",
            all_implied.len()
        );
        all_implied
    }

    /// Execute violation witnesses to confirm inferred constraints.
    ///
    /// This attempts to run the inferred violation against the executor by
    /// overlaying the violation values onto a base input vector. Confirmation
    /// is marked as:
    /// - Confirmed: execution succeeds and all evaluated constraints are satisfied
    /// - Rejected: execution fails or evaluated constraints are not all satisfied
    /// - Inconclusive: execution succeeds but no constraint evaluation is available
    pub fn confirm_violations(
        &self,
        executor: &dyn CircuitExecutor,
        base_inputs: &[FieldElement],
        implied: &mut [ImpliedConstraint],
        output_wires: &HashSet<usize>,
    ) {
        let num_inputs = executor.num_public_inputs() + executor.num_private_inputs();
        let wire_to_input: Option<HashMap<usize, usize>> =
            executor.constraint_inspector().map(|inspector| {
                let mut ordered = inspector.public_input_indices();
                ordered.extend(inspector.private_input_indices());
                ordered
                    .into_iter()
                    .enumerate()
                    .map(|(idx, wire)| (wire, idx))
                    .collect()
            });
        if num_inputs == 0 {
            tracing::warn!("Cannot confirm violations: circuit has 0 inputs");
            return;
        }

        tracing::info!(
            "Circuit has {} inputs, base_inputs has {} elements",
            num_inputs,
            base_inputs.len()
        );
        let mut seed_inputs = base_inputs.to_vec();
        if seed_inputs.len() < num_inputs {
            seed_inputs.resize(num_inputs, FieldElement::zero());
        } else if seed_inputs.len() > num_inputs {
            seed_inputs.truncate(num_inputs);
        }

        let total = implied.len();
        tracing::info!(
            "Confirming {} violations with {} output wires",
            total,
            output_wires.len()
        );
        for (idx, constraint) in implied.iter_mut().enumerate() {
            let Some(violation) = constraint.violation_witness.as_ref() else {
                constraint.confirmation = ViolationConfirmation::Unchecked;
                continue;
            };

            if idx % 10 == 0 {
                tracing::info!(
                    "Confirming violation {}/{} - executing circuit...",
                    idx + 1,
                    total
                );
                // Force flush to show progress immediately
                use std::io::Write;
                if let Err(err) = std::io::stdout().flush() {
                    tracing::warn!(
                        "Failed to flush stdout during confirmation logging: {}",
                        err
                    );
                }
                if let Err(err) = std::io::stderr().flush() {
                    tracing::warn!(
                        "Failed to flush stderr during confirmation logging: {}",
                        err
                    );
                }
            }

            let mut candidate_inputs = seed_inputs.clone();

            if constraint.involved_wires.is_empty() {
                let copy_len = violation.len().min(candidate_inputs.len());
                for (dst, src) in candidate_inputs
                    .iter_mut()
                    .zip(violation.iter())
                    .take(copy_len)
                {
                    *dst = src.clone();
                }
                if violation.len() > candidate_inputs.len() {
                    tracing::warn!(
                        "Violation witness (len={}) exceeds circuit inputs (len={}); truncating overlay",
                        violation.len(),
                        candidate_inputs.len()
                    );
                }
            } else {
                let mut skipped_wires = 0usize;
                for &wire in &constraint.involved_wires {
                    let input_idx = wire_to_input
                        .as_ref()
                        .and_then(|map| map.get(&wire).copied());
                    let input_idx = match input_idx {
                        Some(value) => value,
                        None => wire,
                    };
                    if input_idx < candidate_inputs.len() && wire < violation.len() {
                        candidate_inputs[input_idx] = violation[wire].clone();
                    } else {
                        skipped_wires = skipped_wires.saturating_add(1);
                    }
                }
                if skipped_wires > 0 {
                    tracing::debug!(
                        "Skipped {} involved wires while overlaying violation witness",
                        skipped_wires
                    );
                }
            }

            let has_internal_wires = constraint.involved_wires.iter().any(|&wire| {
                let is_input = wire_to_input.as_ref().map(|map| map.contains_key(&wire));
                let is_input = match is_input {
                    Some(value) => value,
                    None => wire < num_inputs,
                };
                !is_input && !output_wires.contains(&wire)
            });

            let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                executor.execute_sync(&candidate_inputs)
            })) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Execution panicked during violation confirmation: {:?}", e);
                    constraint.confirmation = ViolationConfirmation::Rejected;
                    continue;
                }
            };

            if !result.success {
                constraint.confirmation = if has_internal_wires {
                    ViolationConfirmation::UnconfirmedInternal
                } else {
                    ViolationConfirmation::Rejected
                };
                continue;
            }

            if has_internal_wires {
                constraint.confirmation = ViolationConfirmation::UnconfirmedInternal;
                constraint.violation_witness = Some(candidate_inputs);
                continue;
            }

            if result.coverage.evaluated_constraints.is_empty() {
                constraint.confirmation = ViolationConfirmation::Inconclusive;
                constraint.violation_witness = Some(candidate_inputs);
                continue;
            }

            let all_satisfied = result.coverage.satisfied_constraints.len()
                == result.coverage.evaluated_constraints.len();
            if all_satisfied {
                constraint.confirmation = ViolationConfirmation::Confirmed;
                constraint.violation_witness = Some(candidate_inputs);
            } else {
                constraint.confirmation = ViolationConfirmation::Rejected;
            }
        }
    }

    /// Convert implied constraints to findings
    pub fn to_findings(&self, implied: &[ImpliedConstraint]) -> Vec<Finding> {
        implied
            .iter()
            .map(|ic| Finding {
                attack_type: AttackType::ConstraintInference,
                severity: ic.category.severity(),
                description: {
                    let mut description = format!(
                        "{} (confidence: {:.0}%)\nSuggested fix: {}",
                        ic.description,
                        ic.confidence * 100.0,
                        ic.suggested_constraint
                    );
                    if ic.confirmation != ViolationConfirmation::Unchecked {
                        description
                            .push_str(&format!("\nViolation check: {}", ic.confirmation.as_str()));
                    }
                    description
                },
                poc: ProofOfConcept {
                    witness_a: ic.violation_witness.clone().unwrap_or_default(),
                    witness_b: None,
                    public_inputs: vec![],
                    proof: None,
                },
                location: None,
                class: None,
            })
            .collect()
    }

    /// Run analysis on executor and return findings
    pub fn run(&self, executor: &dyn CircuitExecutor) -> Vec<Finding> {
        let num_wires = executor.circuit_info().num_public_inputs
            + executor.circuit_info().num_private_inputs
            + 100; // Buffer for intermediate wires

        if let Some(inspector) = executor.constraint_inspector() {
            let implied = self.analyze(inspector, num_wires);
            self.to_findings(&implied)
        } else {
            tracing::warn!("No constraint inspector available for constraint inference");
            vec![]
        }
    }
}

/// Statistics from constraint inference
#[derive(Debug, Clone, Default)]
pub struct ConstraintInferenceStats {
    pub categories_checked: usize,
    pub implied_found: usize,
    pub high_confidence: usize,
    pub violations_generated: usize,
    pub violations_confirmed: usize,
    pub violations_rejected: usize,
    pub violations_inconclusive: usize,
    pub violations_unconfirmed_internal: usize,
}

impl ConstraintInferenceEngine {
    /// Get statistics from analysis
    pub fn stats(&self, implied: &[ImpliedConstraint]) -> ConstraintInferenceStats {
        ConstraintInferenceStats {
            categories_checked: self.rules.len(),
            implied_found: implied.len(),
            high_confidence: implied.iter().filter(|c| c.confidence >= 0.8).count(),
            violations_generated: implied
                .iter()
                .filter(|c| c.violation_witness.is_some())
                .count(),
            violations_confirmed: implied
                .iter()
                .filter(|c| c.confirmation == ViolationConfirmation::Confirmed)
                .count(),
            violations_rejected: implied
                .iter()
                .filter(|c| c.confirmation == ViolationConfirmation::Rejected)
                .count(),
            violations_inconclusive: implied
                .iter()
                .filter(|c| c.confirmation == ViolationConfirmation::Inconclusive)
                .count(),
            violations_unconfirmed_internal: implied
                .iter()
                .filter(|c| c.confirmation == ViolationConfirmation::UnconfirmedInternal)
                .count(),
        }
    }
}

#[cfg(test)]
#[path = "constraint_inference_tests.rs"]
mod tests;
