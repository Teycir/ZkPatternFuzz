use super::*;
use zk_core::FieldElement;
use zk_core::TestMetadata;

fn make_test_case(inputs: Vec<u64>) -> TestCase {
    TestCase {
        inputs: inputs.into_iter().map(FieldElement::from_u64).collect(),
        expected_output: None,
        metadata: TestMetadata::default(),
    }
}

#[test]
fn test_lock_free_queue_basic() {
    let queue = LockFreeTestQueue::new();
    assert!(queue.is_empty());

    queue.push(make_test_case(vec![1, 2, 3]));
    assert!(!queue.is_empty());
    assert_eq!(queue.len(), 1);

    let tc = queue.pop().unwrap();
    assert_eq!(tc.inputs.len(), 3);
    assert!(queue.is_empty());
}

#[test]
fn test_lock_free_queue_batch() {
    let queue = LockFreeTestQueue::new();

    let batch: Vec<_> = (0..10).map(|i| make_test_case(vec![i])).collect();
    queue.push_batch(batch);

    assert_eq!(queue.len(), 10);

    let popped = queue.pop_batch(5);
    assert_eq!(popped.len(), 5);
    assert_eq!(queue.len(), 5);
}

#[test]
fn test_atomic_coverage_bitmap() {
    let bitmap = AtomicCoverageBitmap::new(100);

    assert!(!bitmap.is_set(50));
    assert!(bitmap.set(50)); // First set returns true
    assert!(bitmap.is_set(50));
    assert!(!bitmap.set(50)); // Second set returns false

    assert_eq!(bitmap.count_set(), 1);
    assert!(bitmap.coverage_percentage() > 0.0);
}

#[test]
fn test_atomic_coverage_bitmap_merge() {
    let bitmap1 = AtomicCoverageBitmap::new(100);
    let bitmap2 = AtomicCoverageBitmap::new(100);

    bitmap1.set(10);
    bitmap1.set(20);
    bitmap2.set(20);
    bitmap2.set(30);

    let new_bits = bitmap1.merge(&bitmap2);

    // Only bit 30 should be new
    assert_eq!(new_bits, 1);
    assert!(bitmap1.is_set(10));
    assert!(bitmap1.is_set(20));
    assert!(bitmap1.is_set(30));
}

#[test]
fn test_lock_free_corpus() {
    let corpus = LockFreeCorpus::new(1000);

    // Add test cases with different coverage
    let tc1 = make_test_case(vec![1]);
    let tc2 = make_test_case(vec![2]);

    assert!(corpus.add(tc1, 12345)); // New coverage
    assert!(!corpus.add(tc2, 12345)); // Same coverage hash

    assert_eq!(corpus.unique_count(), 1);
    assert!(!corpus.is_empty());
}

#[test]
fn test_lock_free_corpus_priority() {
    let corpus = LockFreeCorpus::new(1000);

    // Add test cases with different coverage
    for i in 0..3 {
        let tc = make_test_case(vec![i]);
        corpus.add(tc, i * 12345 + 100); // Different hashes
    }

    let (high, _mid, _low) = corpus.queue_sizes();
    // New coverage goes to high priority
    assert!(high > 0);
}

#[test]
fn test_shared_corpus() {
    let corpus = create_shared_corpus(1000);
    let corpus_clone = Arc::clone(&corpus);

    // Add from one reference
    let tc = make_test_case(vec![42]);
    corpus.add(tc, 99999);

    // Select from clone
    let selected = corpus_clone.select();
    assert!(selected.is_some());
}

#[test]
fn test_coverage_from_hash() {
    let bitmap = AtomicCoverageBitmap::new(1000);

    // Same hash should set same bits
    let new1 = bitmap.set_from_hash(12345);
    let new2 = bitmap.set_from_hash(12345);

    assert!(new1);
    assert!(!new2); // Already set
}

#[test]
fn test_concurrent_access() {
    use std::thread;

    let queue = Arc::new(LockFreeTestQueue::new());

    // Spawn multiple writers
    let mut handles = vec![];
    for i in 0..4 {
        let q = Arc::clone(&queue);
        handles.push(thread::spawn(move || {
            for j in 0..100 {
                q.push(make_test_case(vec![i as u64 * 1000 + j]));
            }
        }));
    }

    // Spawn multiple readers
    for _ in 0..2 {
        let q = Arc::clone(&queue);
        handles.push(thread::spawn(move || {
            let mut _count = 0;
            loop {
                if q.pop().is_some() {
                    _count += 1;
                } else {
                    break;
                }
            }
        }));
    }

    for handle in handles {
        handle
            .join()
            .expect("concurrent access test thread should not panic");
    }

    // Total added should match
    assert_eq!(queue.total_added(), 400);
}
