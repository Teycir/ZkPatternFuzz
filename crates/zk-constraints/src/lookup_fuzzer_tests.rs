use super::*;
use crate::constraint_types::{ExtendedConstraint, LookupConstraint, LookupTable, WireRef};
use std::collections::HashMap;
use zk_core::FieldElement;

#[test]
fn test_lookup_fuzzer_generates_boundary_and_outside_cases() {
    let mut parsed = ParsedConstraintSet::default();
    let mut table = LookupTable::new("small", 1);
    table.entries = vec![
        vec![FieldElement::from_u64(0)],
        vec![FieldElement::from_u64(1)],
        vec![FieldElement::from_u64(2)],
    ];
    parsed.lookup_tables.insert(1, table);
    parsed
        .constraints
        .push(ExtendedConstraint::Lookup(LookupConstraint {
            input: WireRef::new(10),
            table_id: 1,
            table: None,
            is_vector_lookup: false,
            additional_inputs: Vec::new(),
            table_columns: Vec::new(),
            enable: None,
        }));

    let baseline = HashMap::from([(10usize, FieldElement::from_u64(1))]);
    let cases = LookupFuzzer::new().generate_cases_with_baseline(&parsed, &baseline);

    assert!(cases
        .iter()
        .any(|case| case.kind == LookupFuzzCaseKind::BoundaryMin));
    assert!(cases
        .iter()
        .any(|case| case.kind == LookupFuzzCaseKind::BoundaryMax));
    assert!(cases
        .iter()
        .any(|case| case.kind == LookupFuzzCaseKind::OutsideTableRange));
}

#[test]
fn test_lookup_fuzzer_generates_sparse_gap_cases() {
    let mut parsed = ParsedConstraintSet::default();
    let mut table = LookupTable::new("sparse", 1);
    table.entries = vec![
        vec![FieldElement::from_u64(0)],
        vec![FieldElement::from_u64(2)],
        vec![FieldElement::from_u64(4)],
    ];
    parsed.lookup_tables.insert(2, table);
    parsed
        .constraints
        .push(ExtendedConstraint::Lookup(LookupConstraint {
            input: WireRef::new(11),
            table_id: 2,
            table: None,
            is_vector_lookup: false,
            additional_inputs: Vec::new(),
            table_columns: Vec::new(),
            enable: None,
        }));

    let fuzzer = LookupFuzzer::with_config(LookupFuzzerConfig {
        max_gap_values_per_usage: 4,
        ..LookupFuzzerConfig::default()
    });
    let cases = fuzzer.generate_cases(&parsed);
    let gap_values = cases
        .iter()
        .filter(|case| case.kind == LookupFuzzCaseKind::SparseTableGap)
        .filter_map(|case| case.assignments.get(&11))
        .filter_map(field_to_u64)
        .collect::<Vec<_>>();

    assert!(!gap_values.is_empty());
    assert!(gap_values.contains(&1));
    assert!(gap_values.contains(&3));
}

#[test]
fn test_lookup_fuzzer_forces_enable_selector() {
    let mut parsed = ParsedConstraintSet::default();
    let mut table = LookupTable::new("selector_table", 1);
    table.entries = vec![vec![FieldElement::from_u64(5)]];
    parsed.lookup_tables.insert(3, table);
    parsed
        .constraints
        .push(ExtendedConstraint::Lookup(LookupConstraint {
            input: WireRef::new(20),
            table_id: 3,
            table: None,
            is_vector_lookup: false,
            additional_inputs: Vec::new(),
            table_columns: Vec::new(),
            enable: Some(WireRef::new(21)),
        }));

    let baseline = HashMap::from([
        (20usize, FieldElement::from_u64(5)),
        (21usize, FieldElement::zero()),
    ]);
    let cases = LookupFuzzer::new().generate_cases_with_baseline(&parsed, &baseline);

    assert!(!cases.is_empty());
    assert!(cases.iter().all(|case| {
        case.assignments
            .get(&21)
            .map(|value| value.is_one())
            .unwrap_or(false)
    }));
}
