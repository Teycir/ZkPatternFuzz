use super::*;
use std::sync::Arc;
use std::thread;

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
