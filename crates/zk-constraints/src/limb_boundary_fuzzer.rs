//! Limb-boundary fuzz case generation for non-native arithmetic circuits.
//!
//! Generates targeted assignments for:
//! - Individual limb boundaries (`0`, `2^k-1`, `2^k`)
//! - Reconstruction sum overflow candidates (`Σ limb_i*coeff_i > field_modulus`)
//! - Carry propagation edges across adjacent limbs

use crate::limb_analysis::{LimbAnalysisReport, LimbReconstruction};
use num_bigint::BigUint;
use std::collections::{HashMap, HashSet};
use zk_core::constants::bn254_modulus_biguint;
use zk_core::FieldElement;

/// Classification of generated limb-boundary fuzzing cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimbBoundaryCaseKind {
    LimbZero,
    LimbMax,
    LimbOverflow,
    SumOverflow,
    CarryPropagation,
}

/// Single fuzzing assignment for limb-boundary testing.
#[derive(Debug, Clone)]
pub struct LimbBoundaryCase {
    pub kind: LimbBoundaryCaseKind,
    pub description: String,
    pub relation_constraint_index: Option<usize>,
    pub target_wire: Option<usize>,
    pub assignments: HashMap<usize, FieldElement>,
    pub expected_sum_overflow: bool,
}

/// Configuration for limb-boundary fuzz generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimbBoundaryFuzzerConfig {
    /// Field modulus used for overflow checks.
    pub field_modulus: BigUint,
    /// Generate direct limb boundary values (0, max, overflow).
    pub fuzz_individual_boundaries: bool,
    /// Generate reconstruction sum-overflow candidates.
    pub fuzz_sum_overflow: bool,
    /// Generate carry-propagation edge assignments.
    pub fuzz_carry_edges: bool,
}

impl Default for LimbBoundaryFuzzerConfig {
    fn default() -> Self {
        Self {
            field_modulus: bn254_field_modulus(),
            fuzz_individual_boundaries: true,
            fuzz_sum_overflow: true,
            fuzz_carry_edges: true,
        }
    }
}

/// Generator for limb-boundary fuzzing assignments.
#[derive(Debug, Clone, Default)]
pub struct LimbBoundaryFuzzer {
    config: LimbBoundaryFuzzerConfig,
}

impl LimbBoundaryFuzzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: LimbBoundaryFuzzerConfig) -> Self {
        Self { config }
    }

    /// Generate fuzzing cases with empty baseline assignments.
    pub fn generate_cases(&self, analysis: &LimbAnalysisReport) -> Vec<LimbBoundaryCase> {
        self.generate_cases_with_baseline(analysis, &HashMap::new())
    }

    /// Generate fuzzing cases using a baseline assignment map.
    ///
    /// The baseline map is copied into each case then overridden by case-specific
    /// limb assignments.
    pub fn generate_cases_with_baseline(
        &self,
        analysis: &LimbAnalysisReport,
        baseline: &HashMap<usize, FieldElement>,
    ) -> Vec<LimbBoundaryCase> {
        let mut cases = Vec::new();

        if self.config.fuzz_individual_boundaries {
            cases.extend(self.generate_individual_boundary_cases(analysis, baseline));
        }
        if self.config.fuzz_sum_overflow {
            cases.extend(self.generate_sum_overflow_cases(analysis, baseline));
        }
        if self.config.fuzz_carry_edges {
            cases.extend(self.generate_carry_cases(analysis, baseline));
        }

        dedup_cases(cases)
    }

    fn generate_individual_boundary_cases(
        &self,
        analysis: &LimbAnalysisReport,
        baseline: &HashMap<usize, FieldElement>,
    ) -> Vec<LimbBoundaryCase> {
        let mut cases = Vec::new();

        for limb in &analysis.limbs {
            let Some(bits) = limb.bit_width else {
                continue;
            };
            let label = limb
                .wire
                .name
                .clone()
                .unwrap_or_else(|| format!("wire_{}", limb.wire.index));

            let max_big = if bits == 0 {
                BigUint::from(0u8)
            } else {
                (BigUint::from(1u8) << bits) - BigUint::from(1u8)
            };
            let overflow_big = BigUint::from(1u8) << bits;

            if let Some(value) = biguint_to_field_element(&BigUint::from(0u8)) {
                let mut assignments = baseline.clone();
                assignments.insert(limb.wire.index, value);
                cases.push(LimbBoundaryCase {
                    kind: LimbBoundaryCaseKind::LimbZero,
                    description: format!("Set {} ({} bits) to 0", label, bits),
                    relation_constraint_index: None,
                    target_wire: Some(limb.wire.index),
                    assignments,
                    expected_sum_overflow: false,
                });
            }

            if let Some(value) = biguint_to_field_element(&max_big) {
                let mut assignments = baseline.clone();
                assignments.insert(limb.wire.index, value);
                cases.push(LimbBoundaryCase {
                    kind: LimbBoundaryCaseKind::LimbMax,
                    description: format!("Set {} ({} bits) to 2^{}-1", label, bits, bits),
                    relation_constraint_index: None,
                    target_wire: Some(limb.wire.index),
                    assignments,
                    expected_sum_overflow: false,
                });
            }

            if let Some(value) = biguint_to_field_element(&overflow_big) {
                let mut assignments = baseline.clone();
                assignments.insert(limb.wire.index, value);
                cases.push(LimbBoundaryCase {
                    kind: LimbBoundaryCaseKind::LimbOverflow,
                    description: format!("Set {} ({} bits) to 2^{} (overflow)", label, bits, bits),
                    relation_constraint_index: None,
                    target_wire: Some(limb.wire.index),
                    assignments,
                    expected_sum_overflow: false,
                });
            }
        }

        cases
    }

    fn generate_sum_overflow_cases(
        &self,
        analysis: &LimbAnalysisReport,
        baseline: &HashMap<usize, FieldElement>,
    ) -> Vec<LimbBoundaryCase> {
        let mut cases = Vec::new();

        for reconstruction in &analysis.reconstructions {
            if reconstruction.limb_terms.len() < 2 {
                continue;
            }

            let mut assignments = baseline.clone();
            let mut weighted_sum = BigUint::from(0u8);
            let mut used_bits = Vec::new();
            let mut valid_case = true;

            for (idx, term) in reconstruction.limb_terms.iter().enumerate() {
                let Some(bits) = infer_limb_bits(analysis, reconstruction, idx) else {
                    valid_case = false;
                    break;
                };
                used_bits.push(bits);
                let limb_max = if bits == 0 {
                    BigUint::from(0u8)
                } else {
                    (BigUint::from(1u8) << bits) - BigUint::from(1u8)
                };

                let coeff = term.coefficient.to_biguint();
                weighted_sum += coeff * &limb_max;

                let Some(field_value) = biguint_to_field_element(&limb_max) else {
                    valid_case = false;
                    break;
                };
                assignments.insert(term.wire.index, field_value);
            }

            if !valid_case {
                continue;
            }

            let mut expected_sum_overflow = weighted_sum > self.config.field_modulus;

            if !expected_sum_overflow {
                if let Some((first_term, first_bits)) = reconstruction
                    .limb_terms
                    .first()
                    .zip(used_bits.first().copied())
                {
                    let overflow_value = BigUint::from(1u8) << first_bits;
                    let coeff = first_term.coefficient.to_biguint();
                    let candidate_sum = weighted_sum + coeff;
                    if let Some(field_value) = biguint_to_field_element(&overflow_value) {
                        assignments.insert(first_term.wire.index, field_value);
                        expected_sum_overflow = candidate_sum > self.config.field_modulus;
                    }
                }
            }

            cases.push(LimbBoundaryCase {
                kind: LimbBoundaryCaseKind::SumOverflow,
                description: format!(
                    "Reconstruction overflow candidate at constraint {} (expected_overflow={})",
                    reconstruction.constraint_index, expected_sum_overflow
                ),
                relation_constraint_index: Some(reconstruction.constraint_index),
                target_wire: Some(reconstruction.full_value_wire.index),
                assignments,
                expected_sum_overflow,
            });
        }

        cases
    }

    fn generate_carry_cases(
        &self,
        analysis: &LimbAnalysisReport,
        baseline: &HashMap<usize, FieldElement>,
    ) -> Vec<LimbBoundaryCase> {
        let mut cases = Vec::new();

        for reconstruction in &analysis.reconstructions {
            if reconstruction.limb_terms.len() < 2 {
                continue;
            }

            for pair_idx in 0..(reconstruction.limb_terms.len() - 1) {
                let low = &reconstruction.limb_terms[pair_idx];
                let high = &reconstruction.limb_terms[pair_idx + 1];
                let Some(low_bits) = infer_limb_bits(analysis, reconstruction, pair_idx) else {
                    continue;
                };

                let low_max = if low_bits == 0 {
                    BigUint::from(0u8)
                } else {
                    (BigUint::from(1u8) << low_bits) - BigUint::from(1u8)
                };
                let low_overflow = BigUint::from(1u8) << low_bits;
                let Some(low_max_fe) = biguint_to_field_element(&low_max) else {
                    continue;
                };
                let Some(low_overflow_fe) = biguint_to_field_element(&low_overflow) else {
                    continue;
                };

                let mut edge_assignments = baseline.clone();
                zero_out_reconstruction_limbs(&mut edge_assignments, reconstruction);
                edge_assignments.insert(low.wire.index, low_max_fe.clone());
                edge_assignments.insert(high.wire.index, FieldElement::one());
                cases.push(LimbBoundaryCase {
                    kind: LimbBoundaryCaseKind::CarryPropagation,
                    description: format!(
                        "Carry edge at constraint {}: wire {} at max then increment wire {}",
                        reconstruction.constraint_index, low.wire.index, high.wire.index
                    ),
                    relation_constraint_index: Some(reconstruction.constraint_index),
                    target_wire: Some(low.wire.index),
                    assignments: edge_assignments,
                    expected_sum_overflow: false,
                });

                let mut overflow_assignments = baseline.clone();
                zero_out_reconstruction_limbs(&mut overflow_assignments, reconstruction);
                overflow_assignments.insert(low.wire.index, low_overflow_fe);
                cases.push(LimbBoundaryCase {
                    kind: LimbBoundaryCaseKind::CarryPropagation,
                    description: format!(
                        "Carry overflow at constraint {}: wire {} set to 2^{}",
                        reconstruction.constraint_index, low.wire.index, low_bits
                    ),
                    relation_constraint_index: Some(reconstruction.constraint_index),
                    target_wire: Some(low.wire.index),
                    assignments: overflow_assignments,
                    expected_sum_overflow: false,
                });
            }
        }

        cases
    }
}

fn infer_limb_bits(
    analysis: &LimbAnalysisReport,
    reconstruction: &LimbReconstruction,
    term_index: usize,
) -> Option<usize> {
    let term = reconstruction.limb_terms.get(term_index)?;

    if let Some(bits) = analysis.wire_bit_widths.get(&term.wire.index).copied() {
        return Some(bits);
    }

    let term_shift = term.shift_bits?;
    let next_shift = reconstruction
        .limb_terms
        .iter()
        .skip(term_index + 1)
        .filter_map(|next| next.shift_bits)
        .find(|shift| *shift > term_shift)?;

    Some(next_shift - term_shift)
}

fn zero_out_reconstruction_limbs(
    assignments: &mut HashMap<usize, FieldElement>,
    reconstruction: &LimbReconstruction,
) {
    for term in &reconstruction.limb_terms {
        assignments.insert(term.wire.index, FieldElement::zero());
    }
}

fn biguint_to_field_element(value: &BigUint) -> Option<FieldElement> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    Some(FieldElement::from_bytes(&bytes))
}

fn bn254_field_modulus() -> BigUint {
    bn254_modulus_biguint().clone()
}

fn dedup_cases(cases: Vec<LimbBoundaryCase>) -> Vec<LimbBoundaryCase> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for case in cases {
        let mut entries = case
            .assignments
            .iter()
            .map(|(wire, value)| (*wire, value.to_hex()))
            .collect::<Vec<_>>();
        entries.sort_by_key(|(wire, _)| *wire);
        let key = format!(
            "{:?}|{:?}|{:?}|{}",
            case.kind,
            case.relation_constraint_index,
            case.target_wire,
            entries
                .iter()
                .map(|(wire, hex)| format!("{}={}", wire, hex))
                .collect::<Vec<_>>()
                .join(",")
        );

        if seen.insert(key) {
            out.push(case);
        }
    }

    out
}

#[cfg(test)]
#[path = "limb_boundary_fuzzer_tests.rs"]
mod tests;
