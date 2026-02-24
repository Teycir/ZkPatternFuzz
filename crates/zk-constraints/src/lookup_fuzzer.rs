//! Lookup-focused fuzz case generation.
//!
//! Generates targeted assignments for lookup/range bugs:
//! - Boundary values (table min/max)
//! - Outside-table values
//! - Sparse table gap values

use crate::constraint_types::ParsedConstraintSet;
use crate::lookup_extractor::{LookupExtractionReport, LookupTableExtractor, LookupUsageSource};
use std::collections::{HashMap, HashSet};
use zk_core::FieldElement;

/// Generated lookup fuzz case type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LookupFuzzCaseKind {
    BoundaryMin,
    BoundaryMax,
    OutsideTableRange,
    SparseTableGap,
}

/// Single generated lookup fuzz assignment.
#[derive(Debug, Clone)]
pub struct LookupFuzzCase {
    pub kind: LookupFuzzCaseKind,
    pub description: String,
    pub constraint_index: Option<usize>,
    pub table_id: Option<usize>,
    pub target_wire: Option<usize>,
    pub assignments: HashMap<usize, FieldElement>,
    pub expected_lookup_violation: bool,
}

/// Configuration for lookup fuzz generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupFuzzerConfig {
    pub fuzz_boundary_values: bool,
    pub fuzz_outside_range: bool,
    pub fuzz_sparse_gaps: bool,
    pub max_gap_values_per_usage: usize,
}

impl Default for LookupFuzzerConfig {
    fn default() -> Self {
        Self {
            fuzz_boundary_values: true,
            fuzz_outside_range: true,
            fuzz_sparse_gaps: true,
            max_gap_values_per_usage: 8,
        }
    }
}

/// Lookup fuzz case generator.
#[derive(Debug, Clone, Default)]
pub struct LookupFuzzer {
    config: LookupFuzzerConfig,
}

impl LookupFuzzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: LookupFuzzerConfig) -> Self {
        Self { config }
    }

    pub fn generate_cases(&self, parsed: &ParsedConstraintSet) -> Vec<LookupFuzzCase> {
        self.generate_cases_with_baseline(parsed, &HashMap::new())
    }

    pub fn generate_cases_with_baseline(
        &self,
        parsed: &ParsedConstraintSet,
        baseline: &HashMap<usize, FieldElement>,
    ) -> Vec<LookupFuzzCase> {
        let extraction = LookupTableExtractor::new().extract(parsed);
        self.generate_from_extraction(&extraction, baseline)
    }

    pub fn generate_from_extraction(
        &self,
        extraction: &LookupExtractionReport,
        baseline: &HashMap<usize, FieldElement>,
    ) -> Vec<LookupFuzzCase> {
        let mut cases = Vec::new();

        for usage in &extraction.usages {
            if !matches!(
                usage.source,
                LookupUsageSource::ExplicitLookup | LookupUsageSource::RangeLookup
            ) {
                continue;
            }

            let Some(table_id) = usage.table_id else {
                continue;
            };
            let Some(table) = extraction.lookup_tables.get(&table_id) else {
                continue;
            };
            let Some(target_wire) = usage.input_wires.first().map(|wire| wire.index) else {
                continue;
            };
            let column = usage.table_columns.first().copied().unwrap_or(0);
            if column >= table.num_columns {
                continue;
            }

            let mut numeric_values = table
                .entries
                .iter()
                .filter_map(|row| row.get(column))
                .filter_map(field_to_u64)
                .collect::<Vec<_>>();
            if numeric_values.is_empty() {
                continue;
            }
            numeric_values.sort_unstable();
            numeric_values.dedup();

            let min = numeric_values[0];
            let Some(&max) = numeric_values.last() else {
                continue;
            };
            let present = numeric_values.iter().copied().collect::<HashSet<_>>();

            if self.config.fuzz_boundary_values {
                cases.push(build_case(
                    baseline,
                    usage.enable_wire.as_ref().map(|wire| wire.index),
                    target_wire,
                    min,
                    LookupFuzzCaseKind::BoundaryMin,
                    format!(
                        "Lookup boundary min on wire {} with table {}",
                        target_wire, table_id
                    ),
                    Some(usage.constraint_index),
                    Some(table_id),
                    false,
                ));

                cases.push(build_case(
                    baseline,
                    usage.enable_wire.as_ref().map(|wire| wire.index),
                    target_wire,
                    max,
                    LookupFuzzCaseKind::BoundaryMax,
                    format!(
                        "Lookup boundary max on wire {} with table {}",
                        target_wire, table_id
                    ),
                    Some(usage.constraint_index),
                    Some(table_id),
                    false,
                ));
            }

            if self.config.fuzz_outside_range && max < u64::MAX {
                cases.push(build_case(
                    baseline,
                    usage.enable_wire.as_ref().map(|wire| wire.index),
                    target_wire,
                    max + 1,
                    LookupFuzzCaseKind::OutsideTableRange,
                    format!(
                        "Lookup out-of-range candidate on wire {} with table {} (value={})",
                        target_wire,
                        table_id,
                        max + 1
                    ),
                    Some(usage.constraint_index),
                    Some(table_id),
                    true,
                ));
            }

            if self.config.fuzz_sparse_gaps {
                let mut emitted = 0usize;
                for candidate in min..=max {
                    if present.contains(&candidate) {
                        continue;
                    }
                    cases.push(build_case(
                        baseline,
                        usage.enable_wire.as_ref().map(|wire| wire.index),
                        target_wire,
                        candidate,
                        LookupFuzzCaseKind::SparseTableGap,
                        format!(
                            "Lookup sparse-gap candidate on wire {} with table {} (value={})",
                            target_wire, table_id, candidate
                        ),
                        Some(usage.constraint_index),
                        Some(table_id),
                        true,
                    ));
                    emitted += 1;
                    if emitted >= self.config.max_gap_values_per_usage {
                        break;
                    }
                }
            }
        }

        dedup_cases(cases)
    }
}

fn build_case(
    baseline: &HashMap<usize, FieldElement>,
    enable_wire: Option<usize>,
    target_wire: usize,
    value: u64,
    kind: LookupFuzzCaseKind,
    description: String,
    constraint_index: Option<usize>,
    table_id: Option<usize>,
    expected_lookup_violation: bool,
) -> LookupFuzzCase {
    let mut assignments = baseline.clone();
    assignments.insert(target_wire, FieldElement::from_u64(value));
    if let Some(enable_wire) = enable_wire {
        assignments.insert(enable_wire, FieldElement::one());
    }

    LookupFuzzCase {
        kind,
        description,
        constraint_index,
        table_id,
        target_wire: Some(target_wire),
        assignments,
        expected_lookup_violation,
    }
}

fn field_to_u64(value: &FieldElement) -> Option<u64> {
    let digits = value.to_biguint().to_u64_digits();
    match digits.as_slice() {
        [] => Some(0),
        [single] => Some(*single),
        _ => None,
    }
}

fn dedup_cases(cases: Vec<LookupFuzzCase>) -> Vec<LookupFuzzCase> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

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
            case.constraint_index,
            case.table_id,
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
#[path = "lookup_fuzzer_tests.rs"]
mod tests;
