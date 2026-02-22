//! Lookup table extraction from parsed circuit IR.
//!
//! This module normalizes lookup-related constraints into a common
//! representation so downstream analyzers/fuzzers can operate over a single
//! view of table usages.

use crate::constraint_types::{
    ExtendedConstraint, LookupTable, ParsedConstraintSet, RangeMethod, WireRef,
};
use std::collections::HashMap;

/// Origin of a lookup usage within the circuit IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LookupUsageSource {
    /// Explicit lookup constraint (`ExtendedConstraint::Lookup`).
    ExplicitLookup,
    /// Range constraint backed by a concrete lookup table id.
    RangeLookup,
    /// Range constraint using plookup semantics without explicit table id.
    PlookupRange,
    /// Range constraint using caulk semantics without explicit table id.
    CaulkRange,
}

/// Normalized usage record for a lookup-related constraint.
#[derive(Debug, Clone)]
pub struct LookupUsage {
    /// Constraint index in the parsed set.
    pub constraint_index: usize,
    /// Usage source type.
    pub source: LookupUsageSource,
    /// Optional referenced table id.
    pub table_id: Option<usize>,
    /// Input wires participating in the lookup tuple.
    pub input_wires: Vec<WireRef>,
    /// Table columns used by each input wire.
    pub table_columns: Vec<usize>,
    /// Optional enable/selector wire.
    pub enable_wire: Option<WireRef>,
    /// Whether a concrete lookup table was resolved.
    pub resolved_table: bool,
}

impl LookupUsage {
    pub fn input_wire_indices(&self) -> Vec<usize> {
        self.input_wires.iter().map(|wire| wire.index).collect()
    }
}

/// Result of extracting lookup structures from circuit IR.
#[derive(Debug, Clone, Default)]
pub struct LookupExtractionReport {
    /// Resolved lookup tables keyed by table id.
    pub lookup_tables: HashMap<usize, LookupTable>,
    /// Normalized lookup/range-lookup usages.
    pub usages: Vec<LookupUsage>,
    /// Constraint indices for unresolved explicit lookups.
    pub unresolved_lookup_constraints: Vec<usize>,
}

/// Extractor configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupExtractorConfig {
    /// Keep unresolved usages in the output report.
    pub include_unresolved_usages: bool,
}

impl Default for LookupExtractorConfig {
    fn default() -> Self {
        Self {
            include_unresolved_usages: true,
        }
    }
}

/// Extracts lookup metadata from parsed constraints.
#[derive(Debug, Clone, Default)]
pub struct LookupTableExtractor {
    config: LookupExtractorConfig,
}

impl LookupTableExtractor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: LookupExtractorConfig) -> Self {
        Self { config }
    }

    pub fn extract(&self, parsed: &ParsedConstraintSet) -> LookupExtractionReport {
        let mut report = LookupExtractionReport {
            lookup_tables: parsed.lookup_tables.clone(),
            usages: Vec::new(),
            unresolved_lookup_constraints: Vec::new(),
        };

        for (constraint_index, constraint) in parsed.constraints.iter().enumerate() {
            match constraint {
                ExtendedConstraint::Lookup(lookup) => {
                    if let Some(table) = lookup.table.clone() {
                        report.lookup_tables.entry(lookup.table_id).or_insert(table);
                    }

                    let resolved_table = report.lookup_tables.contains_key(&lookup.table_id);
                    if !resolved_table {
                        report.unresolved_lookup_constraints.push(constraint_index);
                        if !self.config.include_unresolved_usages {
                            continue;
                        }
                    }

                    let mut input_wires = vec![lookup.input.clone()];
                    input_wires.extend(lookup.additional_inputs.clone());
                    let table_columns = if lookup.table_columns.is_empty() {
                        (0..input_wires.len()).collect()
                    } else {
                        lookup.table_columns.clone()
                    };

                    report.usages.push(LookupUsage {
                        constraint_index,
                        source: LookupUsageSource::ExplicitLookup,
                        table_id: Some(lookup.table_id),
                        input_wires,
                        table_columns,
                        enable_wire: lookup.enable.clone(),
                        resolved_table,
                    });
                }
                ExtendedConstraint::Range(range) => match &range.method {
                    RangeMethod::Lookup { table_id } => {
                        report.usages.push(LookupUsage {
                            constraint_index,
                            source: LookupUsageSource::RangeLookup,
                            table_id: Some(*table_id),
                            input_wires: vec![range.wire.clone()],
                            table_columns: vec![0],
                            enable_wire: None,
                            resolved_table: report.lookup_tables.contains_key(table_id),
                        });
                    }
                    RangeMethod::Plookup => {
                        report.usages.push(LookupUsage {
                            constraint_index,
                            source: LookupUsageSource::PlookupRange,
                            table_id: None,
                            input_wires: vec![range.wire.clone()],
                            table_columns: vec![0],
                            enable_wire: None,
                            resolved_table: false,
                        });
                    }
                    RangeMethod::Caulk => {
                        report.usages.push(LookupUsage {
                            constraint_index,
                            source: LookupUsageSource::CaulkRange,
                            table_id: None,
                            input_wires: vec![range.wire.clone()],
                            table_columns: vec![0],
                            enable_wire: None,
                            resolved_table: false,
                        });
                    }
                    RangeMethod::BitDecomposition { .. } => {}
                },
                _ => {}
            }
        }

        report
    }
}

#[cfg(test)]
#[path = "lookup_extractor_tests.rs"]
mod tests;
