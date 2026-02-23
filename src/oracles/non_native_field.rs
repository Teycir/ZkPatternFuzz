//! Non-native field arithmetic oracle.
//!
//! Detects common limb-decomposition bug classes:
//! - Limb overflow (individual limbs exceed declared bit-width)
//! - Reconstruction overflow (`Σ limb_i * coeff_i` wraps modulo field)
//! - Carry propagation/validation failures

use std::collections::HashMap;

use num_bigint::BigUint;
use zk_constraints::{
    ExtendedConstraint, LimbAnalysisReport, LimbBoundaryCase, LimbBoundaryCaseKind,
};
use zk_constraints::{LimbAnalyzer, LimbBoundaryFuzzer, LimbBoundaryFuzzerConfig};
use zk_core::{AttackType, CircuitExecutor, FieldElement, Finding, ProofOfConcept, Severity};

/// Configuration for non-native field oracle execution.
#[derive(Debug, Clone)]
pub struct NonNativeFieldOracleConfig {
    /// Number of base witnesses to mutate.
    pub sample_count: usize,
    /// Maximum number of generated mutation cases per witness.
    pub case_limit: usize,
    /// Maximum number of findings emitted for a single run.
    pub finding_limit: usize,
}

impl Default for NonNativeFieldOracleConfig {
    fn default() -> Self {
        Self {
            sample_count: 16,
            case_limit: 256,
            finding_limit: 32,
        }
    }
}

/// Oracle that applies limb-boundary fuzzing against detected non-native patterns.
#[derive(Debug, Clone, Default)]
pub struct NonNativeFieldOracle {
    config: NonNativeFieldOracleConfig,
}

impl NonNativeFieldOracle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sample_count(mut self, sample_count: usize) -> Self {
        self.config.sample_count = sample_count.max(1);
        self
    }

    pub fn with_case_limit(mut self, case_limit: usize) -> Self {
        self.config.case_limit = case_limit.max(1);
        self
    }

    pub fn with_finding_limit(mut self, finding_limit: usize) -> Self {
        self.config.finding_limit = finding_limit.max(1);
        self
    }

    /// Run non-native arithmetic checks.
    pub fn run(
        &self,
        executor: &dyn CircuitExecutor,
        constraints: &[ExtendedConstraint],
        wire_labels: &HashMap<usize, String>,
        base_witnesses: &[Vec<FieldElement>],
    ) -> Vec<Finding> {
        if constraints.is_empty() || base_witnesses.is_empty() {
            return Vec::new();
        }

        let analyzer = LimbAnalyzer::new();
        let analysis = analyzer.analyze_with_wire_names(constraints, wire_labels);
        if analysis.limbs.is_empty() && analysis.reconstructions.is_empty() {
            return Vec::new();
        }

        let modulus = BigUint::from_bytes_be(&executor.field_modulus());
        if modulus == BigUint::from(0u8) {
            return Vec::new();
        }

        let fuzzer = LimbBoundaryFuzzer::with_config(LimbBoundaryFuzzerConfig {
            field_modulus: modulus,
            ..LimbBoundaryFuzzerConfig::default()
        });

        let mut findings = Vec::new();
        let mut scanned = 0usize;

        for witness in base_witnesses.iter().take(self.config.sample_count) {
            if findings.len() >= self.config.finding_limit {
                break;
            }

            let baseline_result = executor.execute_sync(witness);
            if !baseline_result.success {
                continue;
            }

            let baseline_assignments = witness
                .iter()
                .enumerate()
                .map(|(idx, value)| (idx, value.clone()))
                .collect::<HashMap<_, _>>();
            let cases = fuzzer.generate_cases_with_baseline(&analysis, &baseline_assignments);

            for case in cases.into_iter().take(self.config.case_limit) {
                if findings.len() >= self.config.finding_limit {
                    break;
                }

                scanned += 1;
                let Some(mutated_witness) =
                    apply_assignments_to_witness(witness, &case.assignments)
                else {
                    continue;
                };
                if mutated_witness == *witness {
                    continue;
                }

                let result = executor.execute_sync(&mutated_witness);
                if !result.success {
                    continue;
                }

                if let Some(finding) = self.finding_from_case(
                    executor.name(),
                    &analysis,
                    &case,
                    witness,
                    &mutated_witness,
                    &baseline_result.outputs,
                    &result.outputs,
                ) {
                    findings.push(finding);
                }
            }
        }

        if !findings.is_empty() {
            tracing::info!(
                "Non-native field oracle scanned {} mutation cases and reported {} findings",
                scanned,
                findings.len()
            );
        } else {
            tracing::debug!(
                "Non-native field oracle scanned {} mutation cases with no findings",
                scanned
            );
        }

        findings
    }

    fn finding_from_case(
        &self,
        circuit_name: &str,
        analysis: &LimbAnalysisReport,
        case: &LimbBoundaryCase,
        baseline_witness: &[FieldElement],
        mutated_witness: &[FieldElement],
        baseline_outputs: &[FieldElement],
        mutated_outputs: &[FieldElement],
    ) -> Option<Finding> {
        match case.kind {
            LimbBoundaryCaseKind::LimbOverflow => {
                let target = case.target_wire?;
                let bits = analysis.wire_bit_widths.get(&target).copied()?;
                let assigned = case.assignments.get(&target)?;
                if !value_exceeds_bits(assigned, bits) {
                    return None;
                }

                let mut description = format!(
                    "Non-native limb overflow accepted at wire {} ({} bits): value {}. Circuit accepted out-of-range limb.",
                    target,
                    bits,
                    assigned.to_decimal_string()
                );
                append_cve_hint(&mut description, circuit_name, case.kind);

                Some(Finding {
                    attack_type: AttackType::BitDecomposition,
                    severity: Severity::High,
                    description,
                    poc: ProofOfConcept {
                        witness_a: baseline_witness.to_vec(),
                        witness_b: Some(mutated_witness.to_vec()),
                        public_inputs: mutated_outputs.to_vec(),
                        proof: None,
                    },
                    location: Some(format!("limb_wire:{}", target)),
                    class: None,
                })
            }
            LimbBoundaryCaseKind::SumOverflow => {
                if !case.expected_sum_overflow {
                    return None;
                }
                let mut description = format!(
                    "Non-native reconstruction overflow candidate accepted (constraint {}). Limb sum exceeded field modulus but circuit still accepted.",
                    case.relation_constraint_index.unwrap_or_default()
                );
                append_cve_hint(&mut description, circuit_name, case.kind);

                Some(Finding {
                    attack_type: AttackType::BitDecomposition,
                    severity: Severity::Critical,
                    description,
                    poc: ProofOfConcept {
                        witness_a: baseline_witness.to_vec(),
                        witness_b: Some(mutated_witness.to_vec()),
                        public_inputs: mutated_outputs.to_vec(),
                        proof: None,
                    },
                    location: case
                        .relation_constraint_index
                        .map(|idx| format!("reconstruction_constraint:{}", idx)),
                    class: Some(zk_core::FindingClass::OracleViolation),
                })
            }
            LimbBoundaryCaseKind::CarryPropagation => {
                let target = case.target_wire?;
                let bits = analysis.wire_bit_widths.get(&target).copied().unwrap_or(0);
                let assigned = case.assignments.get(&target).cloned()?;

                let mut description = if bits > 0 && value_exceeds_bits(&assigned, bits) {
                    format!(
                        "Carry overflow accepted at wire {}: value {} exceeds {}-bit limb capacity.",
                        target,
                        assigned.to_decimal_string(),
                        bits
                    )
                } else if mutated_outputs == baseline_outputs {
                    format!(
                        "Carry edge produced unchanged output at wire {}. Possible missing carry propagation/validation in non-native arithmetic.",
                        target
                    )
                } else {
                    return None;
                };
                append_cve_hint(&mut description, circuit_name, case.kind);

                Some(Finding {
                    attack_type: AttackType::BitDecomposition,
                    severity: Severity::High,
                    description,
                    poc: ProofOfConcept {
                        witness_a: baseline_witness.to_vec(),
                        witness_b: Some(mutated_witness.to_vec()),
                        public_inputs: mutated_outputs.to_vec(),
                        proof: None,
                    },
                    location: case
                        .relation_constraint_index
                        .map(|idx| format!("carry_constraint:{}", idx)),
                    class: Some(zk_core::FindingClass::OracleViolation),
                })
            }
            LimbBoundaryCaseKind::LimbZero | LimbBoundaryCaseKind::LimbMax => None,
        }
    }
}

fn value_exceeds_bits(value: &FieldElement, bits: usize) -> bool {
    if bits == 0 {
        return true;
    }
    let bound = BigUint::from(1u8) << bits;
    value.to_biguint() >= bound
}

fn apply_assignments_to_witness(
    witness: &[FieldElement],
    assignments: &HashMap<usize, FieldElement>,
) -> Option<Vec<FieldElement>> {
    if witness.is_empty() {
        return None;
    }
    let mut out = witness.to_vec();
    let mut changed = false;
    for (wire, value) in assignments {
        if *wire >= out.len() {
            continue;
        }
        if out[*wire] != *value {
            changed = true;
            out[*wire] = value.clone();
        }
    }
    if changed {
        Some(out)
    } else {
        None
    }
}

fn append_cve_hint(description: &mut String, circuit_name: &str, kind: LimbBoundaryCaseKind) {
    let lower = circuit_name.to_lowercase();
    let hint = if lower.contains("eddsa")
        && matches!(
            kind,
            LimbBoundaryCaseKind::LimbOverflow | LimbBoundaryCaseKind::CarryPropagation
        ) {
        Some("CVE-2024-42459 (EdDSA malleability) pattern")
    } else if lower.contains("ecdsa")
        && matches!(
            kind,
            LimbBoundaryCaseKind::LimbOverflow
                | LimbBoundaryCaseKind::SumOverflow
                | LimbBoundaryCaseKind::CarryPropagation
        )
    {
        Some("ECDSA s-value overflow pattern")
    } else {
        None
    };

    if let Some(hint) = hint {
        description.push(' ');
        description.push_str("Matches known vulnerability class: ");
        description.push_str(hint);
        description.push('.');
    }
}
