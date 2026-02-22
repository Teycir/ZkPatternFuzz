use super::*;
use crate::constraint_types::{LookupConstraint, RangeConstraint};
use zk_core::FieldElement;

#[test]
fn test_extract_lookup_usages_from_lookup_and_range_constraints() {
    let mut parsed = ParsedConstraintSet::default();
    let mut table = LookupTable::new("byte_table", 1);
    table.entries = vec![
        vec![FieldElement::from_u64(0)],
        vec![FieldElement::from_u64(1)],
        vec![FieldElement::from_u64(2)],
    ];
    parsed.lookup_tables.insert(7, table);

    parsed
        .constraints
        .push(ExtendedConstraint::Lookup(LookupConstraint {
            input: WireRef::new(1),
            table_id: 7,
            table: None,
            is_vector_lookup: false,
            additional_inputs: Vec::new(),
            table_columns: Vec::new(),
            enable: None,
        }));
    parsed
        .constraints
        .push(ExtendedConstraint::Range(RangeConstraint {
            wire: WireRef::new(2),
            bits: 8,
            method: RangeMethod::Lookup { table_id: 7 },
        }));
    parsed
        .constraints
        .push(ExtendedConstraint::Range(RangeConstraint {
            wire: WireRef::new(3),
            bits: 8,
            method: RangeMethod::Plookup,
        }));

    let report = LookupTableExtractor::new().extract(&parsed);
    assert_eq!(report.lookup_tables.len(), 1);
    assert_eq!(report.unresolved_lookup_constraints.len(), 0);
    assert_eq!(report.usages.len(), 3);

    let explicit = report
        .usages
        .iter()
        .find(|usage| usage.source == LookupUsageSource::ExplicitLookup)
        .expect("expected explicit lookup usage");
    assert_eq!(explicit.table_id, Some(7));
    assert_eq!(explicit.input_wire_indices(), vec![1]);
    assert!(explicit.resolved_table);

    let range_lookup = report
        .usages
        .iter()
        .find(|usage| usage.source == LookupUsageSource::RangeLookup)
        .expect("expected range lookup usage");
    assert_eq!(range_lookup.table_id, Some(7));
    assert_eq!(range_lookup.input_wire_indices(), vec![2]);

    let plookup = report
        .usages
        .iter()
        .find(|usage| usage.source == LookupUsageSource::PlookupRange)
        .expect("expected plookup usage");
    assert_eq!(plookup.table_id, None);
    assert_eq!(plookup.input_wire_indices(), vec![3]);
    assert!(!plookup.resolved_table);
}

#[test]
fn test_extract_records_unresolved_lookup_constraints() {
    let mut parsed = ParsedConstraintSet::default();
    parsed
        .constraints
        .push(ExtendedConstraint::Lookup(LookupConstraint {
            input: WireRef::new(9),
            table_id: 99,
            table: None,
            is_vector_lookup: false,
            additional_inputs: Vec::new(),
            table_columns: Vec::new(),
            enable: None,
        }));

    let report = LookupTableExtractor::new().extract(&parsed);
    assert_eq!(report.unresolved_lookup_constraints, vec![0]);
    assert_eq!(report.usages.len(), 1);
    assert!(!report.usages[0].resolved_table);

    let report = LookupTableExtractor::with_config(LookupExtractorConfig {
        include_unresolved_usages: false,
    })
    .extract(&parsed);
    assert_eq!(report.unresolved_lookup_constraints, vec![0]);
    assert!(report.usages.is_empty());
}
