//! Lookup coverage analysis for lookup/range-check enforcement quality.
//!
//! Detects:
//! - Range-like wires without concrete lookup enforcement
//! - Unresolved lookup table references
//! - Sparse single-column lookup table gaps
//! - Per-wire expected vs observed lookup values from sample assignments

use crate::constraint_types::{ParsedConstraintSet, RangeMethod};
use crate::lookup_extractor::{LookupTableExtractor, LookupUsageSource};
use std::collections::{BTreeSet, HashMap, HashSet};
use zk_core::FieldElement;

/// Analyzer configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupCoverageAnalyzerConfig {
    /// Max enumerated expected values for range-bit expansion.
    pub max_expected_range_values: usize,
    /// Max scanned numeric span for sparse table gap detection.
    pub max_table_gap_scan: usize,
}

impl Default for LookupCoverageAnalyzerConfig {
    fn default() -> Self {
        Self {
            max_expected_range_values: 4096,
            max_table_gap_scan: 4096,
        }
    }
}

/// Issue classes emitted by lookup coverage analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LookupCoverageIssueKind {
    MissingLookupEnforcement,
    MissingLookupTable,
    IncompleteLookupTable,
    UncoveredExpectedValues,
}

/// Single coverage finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupCoverageIssue {
    pub kind: LookupCoverageIssueKind,
    pub message: String,
    pub constraint_index: Option<usize>,
    pub wire_index: Option<usize>,
    pub table_id: Option<usize>,
    pub values: Vec<String>,
}

/// Per-wire expected vs observed value coverage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireLookupCoverage {
    pub wire_index: usize,
    pub expected_values: BTreeSet<String>,
    pub observed_values: BTreeSet<String>,
}

/// Analysis output.
#[derive(Debug, Clone, Default)]
pub struct LookupCoverageReport {
    pub issues: Vec<LookupCoverageIssue>,
    pub per_wire: HashMap<usize, WireLookupCoverage>,
    pub sparse_table_gap_counts: HashMap<usize, usize>,
}

/// Coverage analyzer implementation.
#[derive(Debug, Clone, Default)]
pub struct LookupCoverageAnalyzer {
    config: LookupCoverageAnalyzerConfig,
}

impl LookupCoverageAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: LookupCoverageAnalyzerConfig) -> Self {
        Self { config }
    }

    pub fn analyze(
        &self,
        parsed: &ParsedConstraintSet,
        samples: &[HashMap<usize, FieldElement>],
    ) -> LookupCoverageReport {
        let extraction = LookupTableExtractor::new().extract(parsed);
        let mut report = LookupCoverageReport::default();

        let explicit_lookup_wires: HashSet<usize> = extraction
            .usages
            .iter()
            .filter(|usage| usage.source == LookupUsageSource::ExplicitLookup)
            .flat_map(|usage| usage.input_wires.iter().map(|wire| wire.index))
            .collect();

        for usage in &extraction.usages {
            if matches!(
                usage.source,
                LookupUsageSource::ExplicitLookup | LookupUsageSource::RangeLookup
            ) && !usage.resolved_table
            {
                report.issues.push(LookupCoverageIssue {
                    kind: LookupCoverageIssueKind::MissingLookupTable,
                    message: format!(
                        "Lookup constraint {} references unresolved table {:?}",
                        usage.constraint_index, usage.table_id
                    ),
                    constraint_index: Some(usage.constraint_index),
                    wire_index: usage.input_wires.first().map(|wire| wire.index),
                    table_id: usage.table_id,
                    values: Vec::new(),
                });
            }

            match usage.source {
                LookupUsageSource::RangeLookup
                | LookupUsageSource::PlookupRange
                | LookupUsageSource::CaulkRange => {
                    let Some(wire) = usage.input_wires.first() else {
                        continue;
                    };
                    if !explicit_lookup_wires.contains(&wire.index) {
                        report.issues.push(LookupCoverageIssue {
                            kind: LookupCoverageIssueKind::MissingLookupEnforcement,
                            message: format!(
                                "Wire {} has range/lookup semantics without explicit lookup enforcement",
                                wire.index
                            ),
                            constraint_index: Some(usage.constraint_index),
                            wire_index: Some(wire.index),
                            table_id: usage.table_id,
                            values: Vec::new(),
                        });
                    }
                }
                LookupUsageSource::ExplicitLookup => {}
            }

            if let Some(table_id) = usage.table_id {
                if let Some(table) = extraction.lookup_tables.get(&table_id) {
                    for (wire, col) in usage.input_wires.iter().zip(usage.table_columns.iter()) {
                        if *col >= table.num_columns {
                            continue;
                        }
                        let entry = report.per_wire.entry(wire.index).or_insert_with(|| {
                            WireLookupCoverage {
                                wire_index: wire.index,
                                ..WireLookupCoverage::default()
                            }
                        });
                        for row in &table.entries {
                            if let Some(value) = row.get(*col) {
                                entry.expected_values.insert(value.to_hex());
                            }
                        }
                    }
                }
            }
        }

        self.add_expected_ranges(parsed, &mut report);
        self.add_observed_values(&extraction, samples, &mut report);
        self.detect_sparse_table_gaps(&extraction.lookup_tables, &mut report);
        self.detect_uncovered_values(&mut report);
        dedup_issues(&mut report.issues);
        report
    }

    fn add_expected_ranges(&self, parsed: &ParsedConstraintSet, report: &mut LookupCoverageReport) {
        for constraint in &parsed.constraints {
            let crate::constraint_types::ExtendedConstraint::Range(range) = constraint else {
                continue;
            };

            if !matches!(
                range.method,
                RangeMethod::Lookup { .. } | RangeMethod::Plookup | RangeMethod::Caulk
            ) {
                continue;
            }

            let Some(bound) = range_bound(range.bits, self.config.max_expected_range_values) else {
                continue;
            };

            let entry =
                report
                    .per_wire
                    .entry(range.wire.index)
                    .or_insert_with(|| WireLookupCoverage {
                        wire_index: range.wire.index,
                        ..WireLookupCoverage::default()
                    });

            for value in 0..bound {
                entry
                    .expected_values
                    .insert(FieldElement::from_u64(value).to_hex());
            }
        }
    }

    fn add_observed_values(
        &self,
        extraction: &crate::lookup_extractor::LookupExtractionReport,
        samples: &[HashMap<usize, FieldElement>],
        report: &mut LookupCoverageReport,
    ) {
        for usage in &extraction.usages {
            for sample in samples {
                if let Some(enable_wire) = &usage.enable_wire {
                    let Some(enable_value) = sample.get(&enable_wire.index) else {
                        continue;
                    };
                    if enable_value.is_zero() {
                        continue;
                    }
                }

                for wire in &usage.input_wires {
                    let Some(value) = sample.get(&wire.index) else {
                        continue;
                    };
                    let entry =
                        report
                            .per_wire
                            .entry(wire.index)
                            .or_insert_with(|| WireLookupCoverage {
                                wire_index: wire.index,
                                ..WireLookupCoverage::default()
                            });
                    entry.observed_values.insert(value.to_hex());
                }
            }
        }
    }

    fn detect_sparse_table_gaps(
        &self,
        tables: &HashMap<usize, crate::constraint_types::LookupTable>,
        report: &mut LookupCoverageReport,
    ) {
        for (table_id, table) in tables {
            if table.num_columns != 1 {
                continue;
            }

            let mut values = table
                .entries
                .iter()
                .filter_map(|row| row.first())
                .filter_map(field_to_u64)
                .collect::<Vec<_>>();
            if values.len() < 2 {
                continue;
            }
            values.sort_unstable();
            values.dedup();

            let min = values[0];
            let max = *values.last().expect("values not empty");
            let span = max.saturating_sub(min) as usize;
            if span > self.config.max_table_gap_scan {
                continue;
            }

            let present = values.into_iter().collect::<HashSet<_>>();
            let mut missing = Vec::new();
            for candidate in min..=max {
                if !present.contains(&candidate) {
                    missing.push(candidate);
                }
            }

            if !missing.is_empty() {
                report
                    .sparse_table_gap_counts
                    .insert(*table_id, missing.len());
                report.issues.push(LookupCoverageIssue {
                    kind: LookupCoverageIssueKind::IncompleteLookupTable,
                    message: format!(
                        "Lookup table {} has sparse gaps ({} missing values in [{}, {}])",
                        table_id,
                        missing.len(),
                        min,
                        max
                    ),
                    constraint_index: None,
                    wire_index: None,
                    table_id: Some(*table_id),
                    values: missing.iter().take(32).map(u64::to_string).collect(),
                });
            }
        }
    }

    fn detect_uncovered_values(&self, report: &mut LookupCoverageReport) {
        for coverage in report.per_wire.values() {
            if coverage.expected_values.is_empty() {
                continue;
            }

            let missing = coverage
                .expected_values
                .difference(&coverage.observed_values)
                .cloned()
                .collect::<Vec<_>>();
            if missing.is_empty() {
                continue;
            }

            report.issues.push(LookupCoverageIssue {
                kind: LookupCoverageIssueKind::UncoveredExpectedValues,
                message: format!(
                    "Wire {} is missing {} expected lookup values in observed samples",
                    coverage.wire_index,
                    missing.len()
                ),
                constraint_index: None,
                wire_index: Some(coverage.wire_index),
                table_id: None,
                values: missing.into_iter().take(32).collect(),
            });
        }
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

fn range_bound(bits: usize, max_expected_values: usize) -> Option<u64> {
    if bits >= usize::BITS as usize {
        return None;
    }

    let bound = 1usize << bits;
    if bound > max_expected_values {
        return None;
    }
    Some(bound as u64)
}

fn dedup_issues(issues: &mut Vec<LookupCoverageIssue>) {
    let mut seen = HashSet::new();
    issues.retain(|issue| {
        let key = (
            issue.kind,
            issue.constraint_index,
            issue.wire_index,
            issue.table_id,
            issue.values.clone(),
        );
        seen.insert(key)
    });
}

#[cfg(test)]
#[path = "lookup_coverage_tests.rs"]
mod tests;
