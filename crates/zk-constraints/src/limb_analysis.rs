//! Limb decomposition detection for non-native arithmetic circuits.
//!
//! This module identifies:
//! - limb-like wires (by naming and bit-width constraints),
//! - reconstruction relations of the form `value = Σ(limb_i * 2^k_i)`.
//!
//! The detector is intentionally conservative and geared toward triage signals
//! for downstream fuzzing/oracle passes.

use crate::constraint_types::{
    AcirOpcode, BlackBoxOp, ExtendedConstraint, LinearCombination, ParsedConstraintSet, WireRef,
};
use num_bigint::BigUint;
use std::collections::{HashMap, HashSet};
use zk_core::FieldElement;

/// Source signal used to classify a limb candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimbSignalSource {
    NamePattern,
    RangeConstraint,
    AcirRangeOpcode,
    AcirBlackBoxRange,
    ReconstructionRelation,
}

/// A detected limb candidate wire.
#[derive(Debug, Clone)]
pub struct DetectedLimb {
    pub wire: WireRef,
    pub bit_width: Option<usize>,
    pub confidence: f32,
    pub sources: Vec<LimbSignalSource>,
}

/// A limb term used in a reconstruction relation.
#[derive(Debug, Clone)]
pub struct LimbTerm {
    pub wire: WireRef,
    pub coefficient: FieldElement,
    pub shift_bits: Option<usize>,
}

/// A relation resembling packed-value reconstruction from limb wires.
#[derive(Debug, Clone)]
pub struct LimbReconstruction {
    pub constraint_index: usize,
    pub full_value_wire: WireRef,
    pub limb_terms: Vec<LimbTerm>,
    pub confidence: f32,
}

/// Output of limb analysis.
#[derive(Debug, Clone, Default)]
pub struct LimbAnalysisReport {
    pub limbs: Vec<DetectedLimb>,
    pub reconstructions: Vec<LimbReconstruction>,
    /// Smallest discovered range-bound per wire (if any).
    pub wire_bit_widths: HashMap<usize, usize>,
}

impl LimbAnalysisReport {
    pub fn limb_by_wire(&self, wire_index: usize) -> Option<&DetectedLimb> {
        self.limbs.iter().find(|limb| limb.wire.index == wire_index)
    }
}

/// Config for limb decomposition analysis.
#[derive(Debug, Clone)]
pub struct LimbAnalysisConfig {
    /// Minimum bit-width to treat a range-bounded wire as limb-like.
    pub min_limb_bits: usize,
    /// Maximum bit-width to treat a range-bounded wire as limb-like.
    pub max_limb_bits: usize,
    /// Minimum terms required in a reconstruction sum.
    pub min_reconstruction_terms: usize,
    /// Minimum number of power-of-two coefficients in reconstruction sum.
    pub min_power_of_two_terms: usize,
}

impl Default for LimbAnalysisConfig {
    fn default() -> Self {
        Self {
            min_limb_bits: 8,
            max_limb_bits: 128,
            min_reconstruction_terms: 2,
            min_power_of_two_terms: 2,
        }
    }
}

/// Analyzer for limb decomposition patterns.
#[derive(Debug, Clone, Default)]
pub struct LimbAnalyzer {
    config: LimbAnalysisConfig,
}

impl LimbAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: LimbAnalysisConfig) -> Self {
        Self { config }
    }

    pub fn analyze(&self, constraints: &[ExtendedConstraint]) -> LimbAnalysisReport {
        self.analyze_with_wire_names(constraints, &HashMap::new())
    }

    pub fn analyze_parsed(&self, parsed: &ParsedConstraintSet) -> LimbAnalysisReport {
        self.analyze(&parsed.constraints)
    }

    pub fn analyze_with_wire_names(
        &self,
        constraints: &[ExtendedConstraint],
        external_wire_names: &HashMap<usize, String>,
    ) -> LimbAnalysisReport {
        let mut wire_names = collect_wire_names(constraints);
        for (idx, name) in external_wire_names {
            wire_names.entry(*idx).or_insert_with(|| name.clone());
        }

        let mut candidates: HashMap<usize, LimbCandidateBuilder> = HashMap::new();
        let mut wire_bit_widths: HashMap<usize, usize> = HashMap::new();

        for (index, name) in &wire_names {
            if looks_like_limb_name(name) {
                mark_candidate(
                    &mut candidates,
                    *index,
                    Some(name.clone()),
                    None,
                    LimbSignalSource::NamePattern,
                    0.35,
                );
            }
        }

        for constraint in constraints {
            match constraint {
                ExtendedConstraint::Range(range) => {
                    register_bit_width(&mut wire_bit_widths, range.wire.index, range.bits);
                    if self.is_limb_bit_width(range.bits) {
                        mark_candidate(
                            &mut candidates,
                            range.wire.index,
                            wire_name_for(&range.wire, &wire_names),
                            Some(range.bits),
                            LimbSignalSource::RangeConstraint,
                            0.50,
                        );
                    }
                }
                ExtendedConstraint::AcirOpcode(AcirOpcode::Range { input, bits }) => {
                    register_bit_width(&mut wire_bit_widths, input.index, *bits);
                    if self.is_limb_bit_width(*bits) {
                        mark_candidate(
                            &mut candidates,
                            input.index,
                            wire_name_for(input, &wire_names),
                            Some(*bits),
                            LimbSignalSource::AcirRangeOpcode,
                            0.50,
                        );
                    }
                }
                ExtendedConstraint::AcirOpcode(AcirOpcode::BlackBox(BlackBoxOp::Range {
                    input,
                    bits,
                })) => {
                    register_bit_width(&mut wire_bit_widths, input.index, *bits);
                    if self.is_limb_bit_width(*bits) {
                        mark_candidate(
                            &mut candidates,
                            input.index,
                            wire_name_for(input, &wire_names),
                            Some(*bits),
                            LimbSignalSource::AcirBlackBoxRange,
                            0.50,
                        );
                    }
                }
                _ => {}
            }
        }

        let mut known_limb_indices: HashSet<usize> = candidates.keys().copied().collect();
        let mut reconstructions = Vec::new();

        for (constraint_index, constraint) in constraints.iter().enumerate() {
            let ExtendedConstraint::R1CS(r1cs) = constraint else {
                continue;
            };

            if is_unit_constant(&r1cs.a) {
                if let Some(reconstruction) = self.detect_reconstruction_relation(
                    constraint_index,
                    &r1cs.b,
                    &r1cs.c,
                    &known_limb_indices,
                    &wire_names,
                ) {
                    for term in &reconstruction.limb_terms {
                        known_limb_indices.insert(term.wire.index);
                        mark_candidate(
                            &mut candidates,
                            term.wire.index,
                            wire_name_for(&term.wire, &wire_names),
                            wire_bit_widths.get(&term.wire.index).copied(),
                            LimbSignalSource::ReconstructionRelation,
                            0.25,
                        );
                    }
                    reconstructions.push(reconstruction);
                }
            }

            if is_unit_constant(&r1cs.b) {
                if let Some(reconstruction) = self.detect_reconstruction_relation(
                    constraint_index,
                    &r1cs.a,
                    &r1cs.c,
                    &known_limb_indices,
                    &wire_names,
                ) {
                    for term in &reconstruction.limb_terms {
                        known_limb_indices.insert(term.wire.index);
                        mark_candidate(
                            &mut candidates,
                            term.wire.index,
                            wire_name_for(&term.wire, &wire_names),
                            wire_bit_widths.get(&term.wire.index).copied(),
                            LimbSignalSource::ReconstructionRelation,
                            0.25,
                        );
                    }
                    reconstructions.push(reconstruction);
                }
            }
        }

        let mut limbs: Vec<DetectedLimb> = candidates
            .into_values()
            .map(|builder| builder.into_detected_limb())
            .collect();
        limbs.sort_by_key(|limb| limb.wire.index);

        LimbAnalysisReport {
            limbs,
            reconstructions,
            wire_bit_widths,
        }
    }

    fn is_limb_bit_width(&self, bits: usize) -> bool {
        bits >= self.config.min_limb_bits && bits <= self.config.max_limb_bits
    }

    fn detect_reconstruction_relation(
        &self,
        constraint_index: usize,
        summation_side: &LinearCombination,
        full_value_side: &LinearCombination,
        known_limb_indices: &HashSet<usize>,
        wire_names: &HashMap<usize, String>,
    ) -> Option<LimbReconstruction> {
        let (sum_terms, sum_constants) = split_linear_combination(summation_side, wire_names);
        let (full_terms, full_constants) = split_linear_combination(full_value_side, wire_names);

        if !sum_constants.is_empty() || !full_constants.is_empty() {
            return None;
        }
        if sum_terms.len() < self.config.min_reconstruction_terms {
            return None;
        }
        if full_terms.len() != 1 || !full_terms[0].1.is_one() {
            return None;
        }

        let full_value_wire = full_terms[0].0.clone();
        let mut limb_terms = Vec::with_capacity(sum_terms.len());
        let mut power_of_two_terms = 0usize;
        let mut known_limb_terms = 0usize;
        let mut name_hint_terms = 0usize;

        for (wire, coefficient) in sum_terms {
            let shift_bits = power_of_two_exponent(&coefficient);
            if shift_bits.is_some() {
                power_of_two_terms += 1;
            }
            if known_limb_indices.contains(&wire.index) {
                known_limb_terms += 1;
            }
            if wire
                .name
                .as_deref()
                .map(looks_like_limb_name)
                .unwrap_or(false)
            {
                name_hint_terms += 1;
            }
            limb_terms.push(LimbTerm {
                wire,
                coefficient,
                shift_bits,
            });
        }

        if power_of_two_terms < self.config.min_power_of_two_terms {
            return None;
        }
        if known_limb_terms == 0 && name_hint_terms == 0 {
            return None;
        }

        limb_terms.sort_by_key(|term| (term.shift_bits.unwrap_or(usize::MAX), term.wire.index));

        let mut confidence = 0.45f32;
        confidence += 0.30f32 * (power_of_two_terms as f32 / limb_terms.len() as f32);
        if known_limb_terms > 0 {
            confidence += 0.15;
        }
        if has_ordered_shifts(&limb_terms) {
            confidence += 0.10;
        }
        confidence = confidence.min(0.99);

        Some(LimbReconstruction {
            constraint_index,
            full_value_wire,
            limb_terms,
            confidence,
        })
    }
}

/// Convenience API with default analyzer configuration.
pub fn detect_limb_decomposition(constraints: &[ExtendedConstraint]) -> LimbAnalysisReport {
    LimbAnalyzer::new().analyze(constraints)
}

#[derive(Debug, Clone)]
struct LimbCandidateBuilder {
    wire_index: usize,
    wire_name: Option<String>,
    bit_width: Option<usize>,
    confidence: f32,
    sources: Vec<LimbSignalSource>,
}

impl LimbCandidateBuilder {
    fn new(wire_index: usize) -> Self {
        Self {
            wire_index,
            wire_name: None,
            bit_width: None,
            confidence: 0.0,
            sources: Vec::new(),
        }
    }

    fn add_signal(
        &mut self,
        wire_name: Option<String>,
        bit_width: Option<usize>,
        source: LimbSignalSource,
        confidence_delta: f32,
    ) {
        if self.wire_name.is_none() {
            self.wire_name = wire_name;
        }
        if let Some(bits) = bit_width {
            match self.bit_width {
                Some(existing) => self.bit_width = Some(existing.min(bits)),
                None => self.bit_width = Some(bits),
            }
        }
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
        self.confidence = (self.confidence + confidence_delta).min(0.99);
    }

    fn into_detected_limb(mut self) -> DetectedLimb {
        self.sources.sort_by_key(|src| *src as u8);
        let wire = match self.wire_name {
            Some(name) => WireRef {
                index: self.wire_index,
                name: Some(name),
            },
            None => WireRef::new(self.wire_index),
        };
        DetectedLimb {
            wire,
            bit_width: self.bit_width,
            confidence: self.confidence.max(0.05),
            sources: self.sources,
        }
    }
}

fn mark_candidate(
    candidates: &mut HashMap<usize, LimbCandidateBuilder>,
    wire_index: usize,
    wire_name: Option<String>,
    bit_width: Option<usize>,
    source: LimbSignalSource,
    confidence_delta: f32,
) {
    candidates
        .entry(wire_index)
        .or_insert_with(|| LimbCandidateBuilder::new(wire_index))
        .add_signal(wire_name, bit_width, source, confidence_delta);
}

fn register_bit_width(wire_bit_widths: &mut HashMap<usize, usize>, wire_index: usize, bits: usize) {
    wire_bit_widths
        .entry(wire_index)
        .and_modify(|existing| *existing = (*existing).min(bits))
        .or_insert(bits);
}

fn wire_name_for(wire: &WireRef, wire_names: &HashMap<usize, String>) -> Option<String> {
    wire.name
        .clone()
        .or_else(|| wire_names.get(&wire.index).cloned())
}

fn canonical_wire(wire: &WireRef, wire_names: &HashMap<usize, String>) -> WireRef {
    match wire_name_for(wire, wire_names) {
        Some(name) => WireRef {
            index: wire.index,
            name: Some(name),
        },
        None => WireRef::new(wire.index),
    }
}

fn split_linear_combination(
    lc: &LinearCombination,
    wire_names: &HashMap<usize, String>,
) -> (Vec<(WireRef, FieldElement)>, Vec<FieldElement>) {
    let mut vars = Vec::new();
    let mut constants = Vec::new();

    for (wire, coeff) in &lc.terms {
        if coeff.is_zero() {
            continue;
        }
        if wire.index == 0 {
            constants.push(coeff.clone());
        } else {
            vars.push((canonical_wire(wire, wire_names), coeff.clone()));
        }
    }

    (vars, constants)
}

fn is_unit_constant(lc: &LinearCombination) -> bool {
    let mut seen_unit = false;
    for (wire, coeff) in &lc.terms {
        if coeff.is_zero() {
            continue;
        }
        if wire.index == 0 && coeff.is_one() && !seen_unit {
            seen_unit = true;
            continue;
        }
        return false;
    }
    seen_unit
}

fn power_of_two_exponent(coeff: &FieldElement) -> Option<usize> {
    let big = coeff.to_biguint();
    let zero = BigUint::from(0u8);
    if big == zero {
        return None;
    }
    let one = BigUint::from(1u8);
    let masked = &big & (&big - &one);
    if masked == zero {
        Some((big.bits().saturating_sub(1)) as usize)
    } else {
        None
    }
}

fn has_ordered_shifts(terms: &[LimbTerm]) -> bool {
    let shifts: Vec<usize> = terms.iter().filter_map(|term| term.shift_bits).collect();
    if shifts.len() < 2 {
        return false;
    }
    shifts.windows(2).all(|window| window[0] <= window[1])
}

fn looks_like_limb_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let has_digit = lower.chars().any(|ch| ch.is_ascii_digit());
    lower.contains("limb")
        || lower.contains("chunk")
        || (lower.contains("word") && has_digit)
        || (lower.contains("part") && has_digit)
        || ((lower.ends_with("_lo") || lower.ends_with("_hi")) && has_digit)
}

fn collect_wire_names(constraints: &[ExtendedConstraint]) -> HashMap<usize, String> {
    let mut names = HashMap::new();

    for constraint in constraints {
        visit_wire_refs(constraint, &mut |wire| {
            if let Some(name) = wire
                .name
                .as_ref()
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
            {
                names.entry(wire.index).or_insert_with(|| name.to_string());
            }
        });
    }

    names
}

fn visit_wire_refs<F>(constraint: &ExtendedConstraint, visit: &mut F)
where
    F: FnMut(&WireRef),
{
    fn visit_lc<F>(lc: &LinearCombination, visit: &mut F)
    where
        F: FnMut(&WireRef),
    {
        for (wire, _) in &lc.terms {
            visit(wire);
        }
    }

    match constraint {
        ExtendedConstraint::R1CS(r1cs) => {
            visit_lc(&r1cs.a, visit);
            visit_lc(&r1cs.b, visit);
            visit_lc(&r1cs.c, visit);
        }
        ExtendedConstraint::PlonkGate(gate) => {
            visit(&gate.a);
            visit(&gate.b);
            visit(&gate.c);
        }
        ExtendedConstraint::CustomGate(custom) => {
            for term in &custom.polynomial.terms {
                for (wire, _) in &term.variables {
                    visit(wire);
                }
            }
        }
        ExtendedConstraint::Lookup(lookup) => {
            visit(&lookup.input);
            for wire in &lookup.additional_inputs {
                visit(wire);
            }
        }
        ExtendedConstraint::Range(range) => {
            visit(&range.wire);
            if let crate::constraint_types::RangeMethod::BitDecomposition { bit_wires } =
                &range.method
            {
                for wire in bit_wires {
                    visit(wire);
                }
            }
        }
        ExtendedConstraint::Polynomial(poly) => {
            for term in &poly.terms {
                for (wire, _) in &term.variables {
                    visit(wire);
                }
            }
        }
        ExtendedConstraint::AcirOpcode(opcode) => match opcode {
            AcirOpcode::Arithmetic { a, b, c, .. } => {
                visit_lc(a, visit);
                visit_lc(b, visit);
                visit_lc(c, visit);
            }
            AcirOpcode::BlackBox(op) => match op {
                BlackBoxOp::SHA256 { inputs, outputs }
                | BlackBoxOp::Blake2s { inputs, outputs }
                | BlackBoxOp::Blake3 { inputs, outputs }
                | BlackBoxOp::Keccak256 { inputs, outputs }
                | BlackBoxOp::Pedersen { inputs, outputs }
                | BlackBoxOp::FixedBaseScalarMul { inputs, outputs }
                | BlackBoxOp::RecursiveAggregation { inputs, outputs } => {
                    for wire in inputs {
                        visit(wire);
                    }
                    for wire in outputs {
                        visit(wire);
                    }
                }
                BlackBoxOp::SchnorrVerify { inputs, output }
                | BlackBoxOp::EcdsaSecp256k1 { inputs, output } => {
                    for wire in inputs {
                        visit(wire);
                    }
                    visit(output);
                }
                BlackBoxOp::Range { input, .. } => visit(input),
            },
            AcirOpcode::MemoryOp { address, value, .. } => {
                visit(address);
                visit(value);
            }
            AcirOpcode::Brillig { inputs, outputs } => {
                for wire in inputs {
                    visit(wire);
                }
                for wire in outputs {
                    visit(wire);
                }
            }
            AcirOpcode::Range { input, .. } => visit(input),
        },
        ExtendedConstraint::AirConstraint(_) => {}
        ExtendedConstraint::Boolean { wire } => visit(wire),
        ExtendedConstraint::Equal { a, b } => {
            visit(a);
            visit(b);
        }
        ExtendedConstraint::Add { a, b, c } | ExtendedConstraint::Mul { a, b, c } => {
            visit(a);
            visit(b);
            visit(c);
        }
        ExtendedConstraint::Constant { wire, .. } => visit(wire),
    }
}

#[cfg(test)]
#[path = "limb_analysis_tests.rs"]
mod tests;
