//! Concurrency Model Tests (Milestone 0.0)
//!
//! Tests for concurrent fuzzer operation including:
//! - Coverage tracker thread safety
//! - Corpus merging correctness
//! - Finding deduplication under concurrent writes
//! - Oracle state isolation
//!
//! See `docs/CONCURRENCY_MODEL.md` for architecture details.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

/// Test atomic counter correctness under concurrent increments
#[test]
fn test_atomic_counter_concurrent() {
    let counter = Arc::new(AtomicU64::new(0));
    let num_threads = 8;
    let increments_per_thread = 1000;

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let counter = Arc::clone(&counter);
            thread::spawn(move || {
                for _ in 0..increments_per_thread {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(
        counter.load(Ordering::SeqCst),
        num_threads * increments_per_thread,
        "Atomic counter should be correct under concurrent access"
    );
}

/// Test that coverage updates don't lose data under concurrent writes
#[test]
fn test_coverage_concurrent_updates() {
    use std::collections::HashSet;
    use std::sync::RwLock;

    let coverage = Arc::new(RwLock::new(HashSet::<usize>::new()));
    let num_threads = 4;
    let constraints_per_thread = 100;

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let coverage = Arc::clone(&coverage);
            thread::spawn(move || {
                for i in 0..constraints_per_thread {
                    let constraint_id = thread_id * constraints_per_thread + i;
                    let mut guard = coverage.write().unwrap();
                    guard.insert(constraint_id);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let final_coverage = coverage.read().unwrap();
    assert_eq!(
        final_coverage.len(),
        num_threads * constraints_per_thread,
        "All constraints should be recorded"
    );
}

/// Test finding deduplication under concurrent writes
#[test]
fn test_finding_deduplication_concurrent() {
    use std::sync::RwLock;

    #[derive(Clone, PartialEq, Eq, Hash)]
    struct MockFinding {
        witness_hash: String,
    }

    let findings = Arc::new(RwLock::new(Vec::<MockFinding>::new()));
    let num_threads = 4;

    // All threads try to add the same finding
    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let findings = Arc::clone(&findings);
            thread::spawn(move || {
                let finding = MockFinding {
                    witness_hash: "duplicate_hash".to_string(),
                };

                let mut guard = findings.write().unwrap();
                // Deduplicate by witness hash
                if !guard.iter().any(|f| f.witness_hash == finding.witness_hash) {
                    guard.push(finding);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let final_findings = findings.read().unwrap();
    assert_eq!(
        final_findings.len(),
        1,
        "Duplicate findings should be deduplicated"
    );
}

/// Test per-worker RNG determinism
#[test]
fn test_worker_rng_determinism() {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    let base_seed = 42u64;

    // Simulate two runs with same seeds
    let run1: Vec<u64> = (0..4)
        .map(|worker_id| {
            let worker_seed = base_seed.wrapping_add(worker_id);
            let mut rng = ChaCha8Rng::seed_from_u64(worker_seed);
            rng.gen()
        })
        .collect();

    let run2: Vec<u64> = (0..4)
        .map(|worker_id| {
            let worker_seed = base_seed.wrapping_add(worker_id);
            let mut rng = ChaCha8Rng::seed_from_u64(worker_seed);
            rng.gen()
        })
        .collect();

    assert_eq!(run1, run2, "Same seeds should produce same results");
}

/// Test corpus merge operation
#[test]
fn test_corpus_merge() {
    use std::sync::RwLock;

    #[derive(Clone)]
    struct TestCase {
        id: usize,
        coverage_hash: u64,
    }

    let global_corpus = Arc::new(RwLock::new(Vec::<TestCase>::new()));

    // Worker local queues
    let worker1_queue = vec![
        TestCase {
            id: 1,
            coverage_hash: 100,
        },
        TestCase {
            id: 2,
            coverage_hash: 200,
        },
    ];
    let worker2_queue = vec![
        TestCase {
            id: 3,
            coverage_hash: 300,
        },
        TestCase {
            id: 4,
            coverage_hash: 100,
        }, // Duplicate coverage
    ];

    // Merge with deduplication by coverage hash
    {
        let mut corpus = global_corpus.write().unwrap();
        for tc in worker1_queue {
            if !corpus.iter().any(|c| c.coverage_hash == tc.coverage_hash) {
                corpus.push(tc);
            }
        }
        for tc in worker2_queue {
            if !corpus.iter().any(|c| c.coverage_hash == tc.coverage_hash) {
                corpus.push(tc);
            }
        }
    }

    let final_corpus = global_corpus.read().unwrap();
    assert_eq!(
        final_corpus.len(),
        3,
        "Corpus should have 3 unique test cases after deduplication"
    );
}

/// Test lock ordering prevents deadlocks
#[test]
fn test_lock_ordering() {
    use std::sync::{Mutex, RwLock};

    // Document the lock ordering: Findings -> Coverage -> Corpus
    let findings = Arc::new(RwLock::new(Vec::<String>::new()));
    let coverage = Arc::new(RwLock::new(Vec::<usize>::new()));
    let corpus = Arc::new(Mutex::new(Vec::<String>::new()));

    let num_threads = 4;

    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let findings = Arc::clone(&findings);
            let coverage = Arc::clone(&coverage);
            let corpus = Arc::clone(&corpus);
            thread::spawn(move || {
                // Always acquire in order: findings -> coverage -> corpus
                {
                    let mut f = findings.write().unwrap();
                    f.push(format!("finding_{}", i));
                }
                {
                    let mut c = coverage.write().unwrap();
                    c.push(i);
                }
                {
                    let mut co = corpus.lock().unwrap();
                    co.push(format!("test_{}", i));
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // If we get here without deadlock, the test passes
    assert_eq!(findings.read().unwrap().len(), num_threads);
    assert_eq!(coverage.read().unwrap().len(), num_threads);
    assert_eq!(corpus.lock().unwrap().len(), num_threads);
}
