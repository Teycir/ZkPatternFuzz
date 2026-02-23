use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use zk_core::constants::BN254_SCALAR_MODULUS_HEX;

#[test]
fn test_corpus_add() {
    let corpus = Corpus::new(100);

    let entry1 = CorpusEntry::new(
        TestCase {
            inputs: vec![FieldElement::zero()],
            expected_output: None,
            metadata: TestMetadata::default(),
        },
        12345,
    );

    assert!(corpus.add(entry1.clone()));
    assert_eq!(corpus.len(), 1);

    // Duplicate should not be added
    assert!(!corpus.add(entry1));
    assert_eq!(corpus.len(), 1);

    // Different coverage hash should be added
    let entry2 = CorpusEntry::new(
        TestCase {
            inputs: vec![FieldElement::one()],
            expected_output: None,
            metadata: TestMetadata::default(),
        },
        67890,
    );
    assert!(corpus.add(entry2));
    assert_eq!(corpus.len(), 2);
}

#[test]
fn test_corpus_max_size() {
    let corpus = Corpus::new(2);

    for i in 0..5u64 {
        let entry = CorpusEntry::new(
            TestCase {
                inputs: vec![FieldElement::from_u64(i)],
                expected_output: None,
                metadata: TestMetadata::default(),
            },
            i,
        );
        corpus.add(entry);
    }

    assert!(corpus.len() <= 2);
}

#[test]
fn test_corpus_concurrent_add_no_duplicates() {
    // Test that concurrent adds of the same coverage hash don't result in duplicates
    let corpus = Arc::new(Corpus::new(1000));
    let num_threads = 10;
    let entries_per_thread = 100;

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let corpus = Arc::clone(&corpus);
            thread::spawn(move || {
                for i in 0..entries_per_thread {
                    // Use same coverage hash across threads to test deduplication
                    let hash = i as u64;
                    let entry = CorpusEntry::new(
                        TestCase {
                            inputs: vec![FieldElement::from_u64((thread_id * 1000 + i) as u64)],
                            expected_output: None,
                            metadata: TestMetadata::default(),
                        },
                        hash,
                    );
                    corpus.add(entry);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Should have exactly entries_per_thread unique hashes
    // (not num_threads * entries_per_thread duplicates)
    assert_eq!(corpus.len(), entries_per_thread);
}

#[test]
fn test_get_random_with_zero_energy() {
    let corpus = Corpus::new(100);

    // Add entries with zero energy
    for i in 0..5u64 {
        let mut entry = CorpusEntry::new(
            TestCase {
                inputs: vec![FieldElement::from_u64(i)],
                expected_output: None,
                metadata: TestMetadata::default(),
            },
            i,
        );
        entry.energy = 0; // Force zero energy
        corpus.add(entry);
    }

    // Should still be able to select (due to .max(1) guarantee)
    let mut rng = rand::thread_rng();
    let selected = corpus.get_random(&mut rng);
    assert!(selected.is_some());
}

#[test]
fn test_decay_energy_rounds_instead_of_truncating() {
    let corpus = Corpus::new(100);
    let mut entry = CorpusEntry::new(
        TestCase {
            inputs: vec![FieldElement::from_u64(7)],
            expected_output: None,
            metadata: TestMetadata::default(),
        },
        7007,
    );
    entry.energy = 1;
    assert!(corpus.add(entry));

    corpus.decay_energy(0.9);
    let entries = corpus.all_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].energy, 1);
}

#[test]
fn test_load_enforces_max_size() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let temp_dir = PathBuf::from(format!("/tmp/zkpatternfuzz_corpus_load_{nanos}"));

    // Save a corpus larger than the reader's max_size.
    let writer = Corpus::new(10).with_persistence(temp_dir.clone());
    for i in 0..3u64 {
        let entry = CorpusEntry::new(
            TestCase {
                inputs: vec![FieldElement::from_u64(i)],
                expected_output: None,
                metadata: TestMetadata::default(),
            },
            i,
        );
        assert!(writer.add(entry));
    }
    writer.save().expect("writer save should succeed");

    let reader = Corpus::new(2).with_persistence(temp_dir.clone());
    reader.load().expect("reader load should succeed");
    assert!(reader.len() <= 2);

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_serialized_corpus_rejects_non_canonical_inputs() {
    let corpus = SerializableCorpus {
        version: "1.0".to_string(),
        entries: vec![SerializableEntry {
            inputs: vec![format!("0x{}", BN254_SCALAR_MODULUS_HEX)],
            coverage_hash: 123,
            discovered_new_coverage: false,
        }],
    };

    let entries = corpus.to_entries();
    assert!(entries.is_empty());
}
