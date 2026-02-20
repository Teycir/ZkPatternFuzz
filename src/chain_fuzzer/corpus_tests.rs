use super::*;
use tempfile::TempDir;

fn create_test_entry(name: &str, coverage: u64, near_miss: f64) -> ChainCorpusEntry {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Create unique inputs based on name to avoid deduplication
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    let unique_value = hasher.finish();

    let mut inputs = HashMap::new();
    inputs.insert(
        "circuit_a".to_string(),
        vec![FieldElement::from_u64(unique_value)],
    );

    ChainCorpusEntry::new(name, inputs, coverage, 2).with_near_miss(near_miss)
}

#[test]
fn test_add_and_get() {
    let mut corpus = ChainCorpus::new();

    corpus.add(create_test_entry("chain_a", 10, 0.5));
    corpus.add(create_test_entry("chain_b", 20, 0.8));

    assert_eq!(corpus.len(), 2);
    assert_eq!(corpus.entries_for_chain("chain_a").len(), 1);
}

#[test]
fn test_interesting_entries() {
    let mut corpus = ChainCorpus::new();

    corpus.add(create_test_entry("chain_a", 10, 0.9)); // Interesting (high near-miss)
    corpus.add(create_test_entry("chain_b", 0, 0.1)); // Not interesting

    let interesting = corpus.interesting_entries();
    assert_eq!(interesting.len(), 1);
    assert_eq!(interesting[0].spec_name, "chain_a");
}

#[test]
fn test_save_load() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("chain_corpus.json");

    let mut corpus = ChainCorpus::with_storage(&path);
    corpus.add(create_test_entry("chain_a", 10, 0.5));
    corpus.add(create_test_entry("chain_b", 20, 0.8));
    corpus.save().unwrap();

    let loaded = ChainCorpus::load(&path).unwrap();
    assert_eq!(loaded.len(), 2);
}

#[test]
fn test_dedup_is_scoped_per_chain() {
    let mut corpus = ChainCorpus::new();

    let mut shared_inputs = HashMap::new();
    shared_inputs.insert("circuit_a".to_string(), vec![FieldElement::from_u64(42)]);

    corpus.add(ChainCorpusEntry::new(
        "chain_a",
        shared_inputs.clone(),
        1,
        1,
    ));
    corpus.add(ChainCorpusEntry::new("chain_b", shared_inputs, 2, 1));

    assert_eq!(corpus.len(), 2);
}

#[test]
fn test_merge() {
    let mut corpus1 = ChainCorpus::new();
    corpus1.add(create_test_entry("chain_a", 10, 0.5));

    let mut corpus2 = ChainCorpus::new();
    corpus2.add(create_test_entry("chain_b", 20, 0.8));

    corpus1.merge(&corpus2);
    assert_eq!(corpus1.len(), 2);
}

#[test]
fn test_compact() {
    let mut corpus = ChainCorpus::new();

    for i in 0..10 {
        corpus.add(create_test_entry(
            &format!("chain_{}", i),
            i as u64,
            i as f64 * 0.1,
        ));
    }

    corpus.compact(5);
    assert_eq!(corpus.len(), 5);
}

#[test]
fn test_priority_score() {
    let entry_high = create_test_entry("chain_a", 100, 0.9);
    let entry_low = create_test_entry("chain_b", 0, 0.1);

    assert!(entry_high.priority_score() > entry_low.priority_score());
}
