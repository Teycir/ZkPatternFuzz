//! Concurrency Stress Tests (Phase 5: Milestone 5.5)
//!
//! Validates the concurrency model under high contention with:
//! - Multiple concurrent workers accessing shared state
//! - High-frequency coverage updates
//! - Corpus merging under load
//! - Oracle state management

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use zk_core::{FieldElement, TestCase};
use zk_fuzzer::corpus::lockfree::{AtomicCoverageBitmap, LockFreeCorpus, LockFreeTestQueue};

/// Test configuration
const NUM_WORKERS: usize = 32;
const OPERATIONS_PER_WORKER: usize = 10_000;
const STRESS_DURATION_SECS: u64 = 10;

// ============================================================================
// Helper Functions
// ============================================================================

fn make_test_case(id: u64) -> TestCase {
    TestCase {
        inputs: vec![FieldElement::from_u64(id)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    }
}

// ============================================================================
// Lock-Free Queue Stress Tests
// ============================================================================

#[test]
fn test_queue_concurrent_push_pop_32_workers() {
    let queue = Arc::new(LockFreeTestQueue::new());
    let push_count = Arc::new(AtomicU64::new(0));
    let pop_count = Arc::new(AtomicU64::new(0));

    let mut handles = vec![];

    // Spawn producer workers
    for worker_id in 0..NUM_WORKERS / 2 {
        let q = Arc::clone(&queue);
        let pc = Arc::clone(&push_count);
        handles.push(thread::spawn(move || {
            for i in 0..OPERATIONS_PER_WORKER {
                let id = (worker_id as u64) * (OPERATIONS_PER_WORKER as u64) + (i as u64);
                q.push(make_test_case(id));
                pc.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Spawn consumer workers
    for _ in 0..NUM_WORKERS / 2 {
        let q = Arc::clone(&queue);
        let pc = Arc::clone(&pop_count);
        handles.push(thread::spawn(move || {
            let mut local_count = 0u64;
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(STRESS_DURATION_SECS) {
                if q.pop().is_some() {
                    local_count += 1;
                } else {
                    thread::yield_now();
                }
            }
            pc.fetch_add(local_count, Ordering::Relaxed);
        }));
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Drain remaining
    let mut remaining = 0u64;
    while queue.pop().is_some() {
        remaining += 1;
    }

    let total_pushed = push_count.load(Ordering::SeqCst);
    let total_popped = pop_count.load(Ordering::SeqCst) + remaining;

    // All pushed items should be accounted for
    assert_eq!(
        total_pushed, total_popped,
        "Push/pop mismatch: pushed={}, popped={}",
        total_pushed, total_popped
    );

    // Verify counts
    assert_eq!(
        queue.total_added(),
        (NUM_WORKERS / 2 * OPERATIONS_PER_WORKER) as u64
    );
}

#[test]
fn test_queue_high_contention_batch_operations() {
    let queue = Arc::new(LockFreeTestQueue::new());
    let mut handles = vec![];

    // Concurrent batch push/pop
    for worker_id in 0..NUM_WORKERS {
        let q = Arc::clone(&queue);
        handles.push(thread::spawn(move || {
            for batch_id in 0..100 {
                // Push batch
                let batch: Vec<_> = (0..100)
                    .map(|i| {
                        make_test_case(
                            (worker_id as u64) * 1_000_000 + (batch_id as u64) * 1_000 + (i as u64),
                        )
                    })
                    .collect();
                q.push_batch(batch);

                // Pop batch
                let _popped = q.pop_batch(50);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Queue should have some items (exact count depends on timing)
    println!(
        "Queue final size: {}, total_added: {}",
        queue.len(),
        queue.total_added()
    );
}

// ============================================================================
// Coverage Bitmap Stress Tests
// ============================================================================

#[test]
fn test_coverage_bitmap_concurrent_updates() {
    const BITMAP_SIZE: usize = 100_000;
    let bitmap = Arc::new(AtomicCoverageBitmap::new(BITMAP_SIZE));
    let new_bits_found = Arc::new(AtomicU64::new(0));
    let mut handles = vec![];

    for worker_id in 0..NUM_WORKERS {
        let bm = Arc::clone(&bitmap);
        let nbf = Arc::clone(&new_bits_found);
        handles.push(thread::spawn(move || {
            let mut local_new = 0u64;
            for i in 0..OPERATIONS_PER_WORKER {
                // Distribute bits across workers to test contention
                let bit = ((worker_id * OPERATIONS_PER_WORKER + i) * 7) % BITMAP_SIZE;
                if bm.set(bit) {
                    local_new += 1;
                }
            }
            nbf.fetch_add(local_new, Ordering::Relaxed);
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let total_new = new_bits_found.load(Ordering::SeqCst);
    let bits_set = bitmap.count_set();

    // The count should match what we tracked
    assert_eq!(
        total_new as usize, bits_set,
        "Bit count mismatch: tracked={}, actual={}",
        total_new, bits_set
    );

    println!(
        "Coverage bitmap: {} bits set out of {} ({:.2}%)",
        bits_set,
        BITMAP_SIZE,
        bitmap.coverage_percentage()
    );
}

#[test]
fn test_coverage_bitmap_merge_concurrent() {
    const BITMAP_SIZE: usize = 10_000;

    let global = Arc::new(AtomicCoverageBitmap::new(BITMAP_SIZE));
    let mut handles = vec![];

    // Each worker creates a local bitmap and merges to global
    for worker_id in 0..NUM_WORKERS {
        let g = Arc::clone(&global);
        handles.push(thread::spawn(move || {
            let local = AtomicCoverageBitmap::new(BITMAP_SIZE);

            // Set some bits locally
            for i in 0..1000 {
                let bit = (worker_id * 1000 + i) % BITMAP_SIZE;
                local.set(bit);
            }

            // Merge to global
            g.merge(&local)
        }));
    }

    let mut total_new = 0;
    for handle in handles {
        total_new += handle.join().expect("Thread panicked");
    }

    println!(
        "Merged {} new bits, global has {} bits set",
        total_new,
        global.count_set()
    );

    // Global should have at least as many bits as unique merges
    assert!(global.count_set() > 0);
}

// ============================================================================
// Lock-Free Corpus Stress Tests
// ============================================================================

#[test]
fn test_corpus_concurrent_add_select() {
    const COVERAGE_BITS: usize = 50_000;
    let corpus = Arc::new(LockFreeCorpus::new(COVERAGE_BITS));
    let adds = Arc::new(AtomicU64::new(0));
    let selects = Arc::new(AtomicU64::new(0));
    let mut handles = vec![];

    // Producer workers
    for worker_id in 0..NUM_WORKERS / 2 {
        let c = Arc::clone(&corpus);
        let a = Arc::clone(&adds);
        handles.push(thread::spawn(move || {
            for i in 0..OPERATIONS_PER_WORKER {
                let id = (worker_id as u64) * (OPERATIONS_PER_WORKER as u64) + (i as u64);
                let coverage_hash = id.wrapping_mul(0x517cc1b727220a95);
                c.add(make_test_case(id), coverage_hash);
                a.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Consumer workers
    for _ in 0..NUM_WORKERS / 2 {
        let c = Arc::clone(&corpus);
        let s = Arc::clone(&selects);
        handles.push(thread::spawn(move || {
            let mut local_selects = 0u64;
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(STRESS_DURATION_SECS) {
                if c.select().is_some() {
                    local_selects += 1;
                } else {
                    thread::yield_now();
                }
            }
            s.fetch_add(local_selects, Ordering::Relaxed);
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let total_adds = adds.load(Ordering::SeqCst);
    let total_selects = selects.load(Ordering::SeqCst);

    println!(
        "Corpus stress test: {} adds, {} selects, {} remaining, {:.2}% coverage",
        total_adds,
        total_selects,
        corpus.len(),
        corpus.coverage_percentage()
    );

    // Adds should match our expectation
    assert_eq!(total_adds, (NUM_WORKERS / 2 * OPERATIONS_PER_WORKER) as u64);
}

#[test]
fn test_corpus_priority_ordering_under_contention() {
    const COVERAGE_BITS: usize = 100_000;
    let corpus = Arc::new(LockFreeCorpus::new(COVERAGE_BITS));
    let mut handles = vec![];

    // Add test cases with varying coverage
    for worker_id in 0..NUM_WORKERS {
        let c = Arc::clone(&corpus);
        handles.push(thread::spawn(move || {
            for i in 0..1000 {
                let id = (worker_id as u64) * 1000 + (i as u64);
                // Use unique hashes to ensure new coverage
                let coverage_hash = id;
                c.add(make_test_case(id), coverage_hash);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let (high, mid, low) = corpus.queue_sizes();
    println!(
        "Priority distribution: high={}, mid={}, low={}",
        high, mid, low
    );

    // Most should be in high priority since all have unique coverage
    assert!(high > 0, "High priority queue should have entries");
}

// ============================================================================
// Long-Running Stress Tests
// ============================================================================

#[test]
// Run with --ignored for extended stress testing
#[ignore = "long-running stress simulation; run manually with -- --ignored"]
fn test_extended_stress_24_hour_simulation() {
    // Simulate 24 hours of fuzzing in compressed time
    const SIMULATION_DURATION_SECS: u64 = 60; // 1 minute = simulated 24 hours
    const COVERAGE_BITS: usize = 1_000_000;

    let corpus = Arc::new(LockFreeCorpus::new(COVERAGE_BITS));
    let total_ops = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let mut handles = vec![];

    for worker_id in 0..NUM_WORKERS {
        let c = Arc::clone(&corpus);
        let ops = Arc::clone(&total_ops);
        handles.push(thread::spawn(move || {
            let mut local_ops = 0u64;
            let mut rng = worker_id as u64;

            while start.elapsed() < Duration::from_secs(SIMULATION_DURATION_SECS) {
                // Simple LCG for random operations
                rng = rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);

                match rng % 10 {
                    0..=6 => {
                        // Add test case (70%)
                        let coverage_hash = rng.wrapping_mul(0x517cc1b727220a95);
                        c.add(make_test_case(local_ops), coverage_hash);
                    }
                    7..=9 => {
                        // Select test case (30%)
                        drop(c.select());
                    }
                    _ => unreachable!(),
                }
                local_ops += 1;
            }
            ops.fetch_add(local_ops, Ordering::Relaxed);
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let total = total_ops.load(Ordering::SeqCst);
    let duration = start.elapsed();
    let ops_per_sec = total as f64 / duration.as_secs_f64();

    println!(
        "Extended stress test: {} total ops in {:.2}s ({:.0} ops/sec)",
        total,
        duration.as_secs_f64(),
        ops_per_sec
    );
    println!(
        "Corpus: {} items, {:.2}% coverage, {} unique",
        corpus.len(),
        corpus.coverage_percentage(),
        corpus.unique_count()
    );

    // Should complete without panics or deadlocks
    assert!(total > 0);
}

// ============================================================================
// Data Integrity Tests
// ============================================================================

#[test]
fn test_no_data_corruption_under_contention() {
    let queue = Arc::new(LockFreeTestQueue::new());
    let corruption_detected = Arc::new(AtomicU64::new(0));
    let mut handles = vec![];

    // Producers: push test cases with known pattern
    for worker_id in 0..NUM_WORKERS / 2 {
        let q = Arc::clone(&queue);
        handles.push(thread::spawn(move || {
            for i in 0..OPERATIONS_PER_WORKER {
                let id = (worker_id as u64) * (OPERATIONS_PER_WORKER as u64) + (i as u64);
                // Magic pattern for verification
                let magic = id ^ 0xDEADBEEF;
                let tc = TestCase {
                    inputs: vec![FieldElement::from_u64(id), FieldElement::from_u64(magic)],
                    expected_output: None,
                    metadata: zk_core::TestMetadata::default(),
                };
                q.push(tc);
            }
        }));
    }

    // Consumers: verify pattern integrity
    for _ in 0..NUM_WORKERS / 2 {
        let q = Arc::clone(&queue);
        let cd = Arc::clone(&corruption_detected);
        handles.push(thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(STRESS_DURATION_SECS) {
                if let Some(tc) = q.pop() {
                    if tc.inputs.len() >= 2 {
                        if let (Some(id), Some(magic)) =
                            (tc.inputs[0].to_u64(), tc.inputs[1].to_u64())
                        {
                            let expected_magic = id ^ 0xDEADBEEF;
                            if magic != expected_magic {
                                cd.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                } else {
                    thread::yield_now();
                }
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let corruptions = corruption_detected.load(Ordering::SeqCst);
    assert_eq!(
        corruptions, 0,
        "Detected {} data corruptions under contention",
        corruptions
    );
}

// ============================================================================
// Throughput Benchmarks
// ============================================================================

#[test]
fn test_throughput_scaling() {
    const OPS: usize = 100_000;
    let queue = Arc::new(LockFreeTestQueue::new());

    // Measure with different worker counts
    for num_workers in [1, 2, 4, 8, 16, 32] {
        let q = Arc::clone(&queue);
        let start = Instant::now();
        let mut handles = vec![];

        let ops_per_worker = OPS / num_workers;

        for worker_id in 0..num_workers {
            let q = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                for i in 0..ops_per_worker {
                    let id = (worker_id * ops_per_worker + i) as u64;
                    q.push(make_test_case(id));
                    assert!(q.pop().is_some(), "queue pop should succeed after push");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        let duration = start.elapsed();
        let ops_per_sec = (ops_per_worker * num_workers * 2) as f64 / duration.as_secs_f64();

        println!(
            "{} workers: {:.0} ops/sec ({:.2}ms)",
            num_workers,
            ops_per_sec,
            duration.as_secs_f64() * 1000.0
        );
    }
}

// ============================================================================
// Race Condition Detection Tests
// ============================================================================

#[test]
fn test_coverage_accuracy_under_contention() {
    const BITMAP_SIZE: usize = 1000;
    const BITS_TO_SET: usize = 500;

    let bitmap = Arc::new(AtomicCoverageBitmap::new(BITMAP_SIZE));
    let bits_to_set: Vec<usize> = (0..BITS_TO_SET).collect();
    let success_count = Arc::new(AtomicU64::new(0));
    let mut handles = vec![];

    // Multiple workers try to set the same bits
    for _ in 0..NUM_WORKERS {
        let bm = Arc::clone(&bitmap);
        let bits = bits_to_set.clone();
        let sc = Arc::clone(&success_count);
        handles.push(thread::spawn(move || {
            let mut local_success = 0u64;
            for &bit in &bits {
                if bm.set(bit) {
                    local_success += 1;
                }
            }
            sc.fetch_add(local_success, Ordering::Relaxed);
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let total_success = success_count.load(Ordering::SeqCst);
    let bits_set = bitmap.count_set();

    // Exactly BITS_TO_SET should be set (each bit set exactly once reports success)
    assert_eq!(
        bits_set, BITS_TO_SET,
        "Expected {} bits set, got {}",
        BITS_TO_SET, bits_set
    );

    // Total successes should also equal BITS_TO_SET (first-wins semantics)
    assert_eq!(
        total_success, BITS_TO_SET as u64,
        "Expected {} successes, got {}",
        BITS_TO_SET, total_success
    );

    // Verify coverage percentage
    let expected_pct = (BITS_TO_SET as f64 / BITMAP_SIZE as f64) * 100.0;
    let actual_pct = bitmap.coverage_percentage();
    assert!(
        (actual_pct - expected_pct).abs() < 0.01,
        "Coverage percentage mismatch: expected {:.2}%, got {:.2}%",
        expected_pct,
        actual_pct
    );
}
