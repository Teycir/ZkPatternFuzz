
use super::aggregate_resume_entries;
use crate::chain_fuzzer::ChainCorpusEntry;
use std::collections::HashMap;
use zk_core::FieldElement;

fn mk_entry(
    coverage_bits: u64,
    near_miss_score: f64,
    violation: bool,
    executions: usize,
) -> ChainCorpusEntry {
    let mut inputs = HashMap::new();
    inputs.insert("c".to_string(), vec![FieldElement::from_u64(1)]);
    let mut entry =
        ChainCorpusEntry::new("chain_a", inputs, coverage_bits, 1).with_near_miss(near_miss_score);
    if violation {
        entry = entry.with_violation();
    }
    entry.execution_count = executions;
    entry
}

#[test]
fn test_resume_aggregation_ignores_zero_coverage_bits() {
    let entries = vec![
        mk_entry(0, 0.2, false, 1),
        mk_entry(0, 0.7, true, 2),
        mk_entry(11, 0.3, false, 4),
        mk_entry(11, 0.4, false, 3),
        mk_entry(42, 0.1, false, 1),
    ];
    let refs: Vec<&ChainCorpusEntry> = entries.iter().collect();
    let agg = aggregate_resume_entries(&refs);

    assert_eq!(agg.new_coverage, 2);
    assert!(agg.found_violation);
    assert_eq!(agg.near_miss_score, 0.7);
    assert_eq!(agg.executions, 11);
}
