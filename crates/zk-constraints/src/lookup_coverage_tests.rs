use super::*;
use crate::constraint_types::{
    ExtendedConstraint, LookupConstraint, LookupTable, RangeConstraint, WireRef,
};
use std::collections::HashMap;
use zk_core::FieldElement;

#[test]
fn test_lookup_coverage_flags_missing_lookup_enforcement() {
    let mut parsed = ParsedConstraintSet::default();
    parsed
        .constraints
        .push(ExtendedConstraint::Range(RangeConstraint {
            wire: WireRef::new(5),
            bits: 4,
            method: RangeMethod::Plookup,
        }));

    let sample = HashMap::from([(5usize, FieldElement::from_u64(20))]);
    let report = LookupCoverageAnalyzer::new().analyze(&parsed, &[sample]);

    assert!(report.issues.iter().any(|issue| {
        issue.kind == LookupCoverageIssueKind::MissingLookupEnforcement
            && issue.wire_index == Some(5)
    }));
}

#[test]
fn test_lookup_coverage_detects_sparse_table_gaps() {
    let mut parsed = ParsedConstraintSet::default();
    let mut table = LookupTable::new("sparse", 1);
    table.entries = vec![
        vec![FieldElement::from_u64(0)],
        vec![FieldElement::from_u64(1)],
        vec![FieldElement::from_u64(3)],
    ];
    parsed.lookup_tables.insert(3, table);
    parsed
        .constraints
        .push(ExtendedConstraint::Lookup(LookupConstraint {
            input: WireRef::new(1),
            table_id: 3,
            table: None,
            is_vector_lookup: false,
            additional_inputs: Vec::new(),
            table_columns: Vec::new(),
            enable: None,
        }));

    let report = LookupCoverageAnalyzer::new().analyze(&parsed, &[]);
    let gap_issue = report
        .issues
        .iter()
        .find(|issue| issue.kind == LookupCoverageIssueKind::IncompleteLookupTable)
        .expect("expected sparse-table gap issue");

    assert_eq!(gap_issue.table_id, Some(3));
    assert!(gap_issue.values.iter().any(|value| value == "2"));
}

#[test]
fn test_lookup_coverage_tracks_expected_and_observed_values() {
    let mut parsed = ParsedConstraintSet::default();
    let mut table = LookupTable::new("byte_like", 1);
    table.entries = vec![
        vec![FieldElement::from_u64(0)],
        vec![FieldElement::from_u64(1)],
        vec![FieldElement::from_u64(2)],
    ];
    parsed.lookup_tables.insert(7, table);
    parsed
        .constraints
        .push(ExtendedConstraint::Lookup(LookupConstraint {
            input: WireRef::new(9),
            table_id: 7,
            table: None,
            is_vector_lookup: false,
            additional_inputs: Vec::new(),
            table_columns: Vec::new(),
            enable: None,
        }));

    let samples = vec![
        HashMap::from([(9usize, FieldElement::from_u64(1))]),
        HashMap::from([(9usize, FieldElement::from_u64(2))]),
    ];
    let report = LookupCoverageAnalyzer::new().analyze(&parsed, &samples);

    let wire_coverage = report
        .per_wire
        .get(&9)
        .expect("expected wire coverage for lookup input");
    assert_eq!(wire_coverage.expected_values.len(), 3);
    assert_eq!(wire_coverage.observed_values.len(), 2);
    assert!(wire_coverage
        .observed_values
        .contains(&FieldElement::from_u64(1).to_hex()));
    assert!(wire_coverage
        .observed_values
        .contains(&FieldElement::from_u64(2).to_hex()));
}
