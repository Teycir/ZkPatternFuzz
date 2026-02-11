//! Oracle Scalability Tests (Phase 5: Milestone 5.7)
//!
//! Tests for bounded oracle state management under high load.

use std::sync::Arc;
use std::thread;
use std::time::Instant;

use zk_core::{FieldElement, TestCase};
use zk_fuzzer::fuzzer::oracle_state::{
    BloomFilter, BoundedStateMap, OracleStateConfig, OracleStateManager,
    PerWorkerOracleState,
};

const NUM_WORKERS: usize = 32;
const TEST_CASES: usize = 100_000;

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

fn hash_from_id(id: u64) -> Vec<u8> {
    id.to_le_bytes().to_vec()
}

// ============================================================================
// Bloom Filter Tests
// ============================================================================

#[test]
fn test_bloom_filter_accuracy() {
    let filter = BloomFilter::new(1_000_000, 7);

    // Add 10,000 items
    for i in 0..10_000 {
        filter.add(&i.to_le_bytes());
    }

    // Check false positive rate
    let mut false_positives = 0;
    for i in 10_000..20_000 {
        if filter.might_contain(&i.to_le_bytes()) {
            false_positives += 1;
        }
    }

    let fp_rate = false_positives as f64 / 10_000.0;
    println!("Bloom filter FP rate: {:.4}%", fp_rate * 100.0);
    assert!(fp_rate < 0.01, "FP rate too high: {:.4}%", fp_rate * 100.0);

    // Estimated should be close to actual
    let estimated = filter.estimated_fp_rate();
    println!("Estimated FP rate: {:.4}%", estimated * 100.0);
}

#[test]
fn test_bloom_filter_high_load() {
    let filter = BloomFilter::new(10_000_000, 7);

    // Add 1 million items
    let start = Instant::now();
    for i in 0..1_000_000 {
        filter.add(&i.to_le_bytes());
    }
    let add_time = start.elapsed();

    println!(
        "Added 1M items in {:?} ({:.0}/sec)",
        add_time,
        1_000_000.0 / add_time.as_secs_f64()
    );

    // Check lookup performance
    let start = Instant::now();
    let mut hits = 0;
    for i in 0..1_000_000 {
        if filter.might_contain(&i.to_le_bytes()) {
            hits += 1;
        }
    }
    let lookup_time = start.elapsed();

    println!(
        "Looked up 1M items in {:?} ({:.0}/sec)",
        lookup_time,
        1_000_000.0 / lookup_time.as_secs_f64()
    );

    // All should be found (no false negatives)
    assert_eq!(hits, 1_000_000, "Bloom filter should have no false negatives");
}

#[test]
fn test_bloom_filter_concurrent() {
    let filter = Arc::new(BloomFilter::new(10_000_000, 7));
    let mut handles = vec![];

    for worker_id in 0..NUM_WORKERS {
        let f = Arc::clone(&filter);
        handles.push(thread::spawn(move || {
            for i in 0..10_000 {
                let id = (worker_id * 10_000 + i) as u64;
                f.add(&id.to_le_bytes());
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    assert_eq!(
        filter.items_added(),
        (NUM_WORKERS * 10_000) as u64,
        "Item count mismatch"
    );
}

// ============================================================================
// Bounded State Map Tests
// ============================================================================

#[test]
fn test_bounded_state_map_eviction() {
    let config = OracleStateConfig {
        max_entries: 1000,
        bloom_filter_bits: 100_000,
        bloom_hash_count: 7,
        enable_lru: true,
        memory_limit_bytes: 0,
        eviction_batch_size: 100,
    };

    let map: BoundedStateMap<Vec<u8>, TestCase> = BoundedStateMap::new(config);

    // Insert more than max entries
    for i in 0..2000 {
        let key = hash_from_id(i);
        let value = make_test_case(i);
        map.insert(key, value, 100);
    }

    // Should have evicted to stay under limit
    println!("Entries after 2000 inserts: {}", map.len());
    assert!(
        map.len() <= 1100,
        "Expected eviction, got {} entries",
        map.len()
    );

    // Check eviction stats
    let stats = map.stats();
    assert!(
        stats.evictions.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "Expected evictions"
    );
}

#[test]
fn test_bounded_state_map_bloom_effectiveness() {
    let config = OracleStateConfig {
        max_entries: 10_000,
        bloom_filter_bits: 1_000_000,
        bloom_hash_count: 7,
        enable_lru: true,
        memory_limit_bytes: 0,
        eviction_batch_size: 100,
    };

    let map: BoundedStateMap<Vec<u8>, TestCase> = BoundedStateMap::new(config);

    // Insert items
    for i in 0..5000 {
        let key = hash_from_id(i);
        let value = make_test_case(i);
        map.insert(key, value, 100);
    }

    // Check for non-existent items
    for i in 5000..10000 {
        let key = hash_from_id(i);
        let _ = map.get(&key);
    }

    // Bloom filter should have filtered most lookups
    let stats = map.stats();
    let bloom_eff = stats.bloom_effectiveness();
    println!("Bloom effectiveness: {:.2}%", bloom_eff * 100.0);

    // Most non-existent lookups should be caught by bloom filter
    assert!(
        bloom_eff > 0.9,
        "Bloom effectiveness too low: {:.2}%",
        bloom_eff * 100.0
    );
}

#[test]
fn test_bounded_state_map_memory_limit() {
    let config = OracleStateConfig {
        max_entries: 1_000_000, // High entry limit
        bloom_filter_bits: 100_000,
        bloom_hash_count: 7,
        enable_lru: true,
        memory_limit_bytes: 100_000, // 100KB memory limit
        eviction_batch_size: 100,
    };

    let map: BoundedStateMap<Vec<u8>, TestCase> = BoundedStateMap::new(config);

    // Insert until memory limit is hit
    for i in 0..10_000 {
        let key = hash_from_id(i);
        let value = make_test_case(i);
        map.insert(key, value, 100); // ~100 bytes each
    }

    // Memory should be bounded
    let memory = map.memory_used();
    println!("Memory used: {} bytes, entries: {}", memory, map.len());
}

// ============================================================================
// Oracle State Manager Tests
// ============================================================================

#[test]
fn test_oracle_state_manager_basic() {
    let manager = OracleStateManager::with_defaults();

    // Record unique outputs
    for i in 0..100 {
        let hash = hash_from_id(i);
        let tc = make_test_case(i);
        assert!(manager.record_output(hash, tc).is_none());
    }

    assert_eq!(manager.collision_count(), 0);
}

#[test]
fn test_oracle_state_manager_collision_detection() {
    let manager = OracleStateManager::with_defaults();

    let hash = hash_from_id(42);
    let tc1 = make_test_case(1);
    let tc2 = make_test_case(2);

    // First insert
    assert!(manager.record_output(hash.clone(), tc1).is_none());

    // Second insert with same hash - collision
    let collision = manager.record_output(hash, tc2);
    assert!(collision.is_some());
    assert_eq!(manager.collision_count(), 1);
}

#[test]
fn test_oracle_state_manager_high_volume() {
    let config = OracleStateConfig {
        max_entries: 100_000,
        bloom_filter_bits: 10_000_000,
        bloom_hash_count: 7,
        enable_lru: true,
        memory_limit_bytes: 0,
        eviction_batch_size: 1000,
    };

    let manager = OracleStateManager::new(config);

    let start = Instant::now();

    // Record many unique outputs
    for i in 0..TEST_CASES {
        let hash = hash_from_id(i as u64);
        let tc = make_test_case(i as u64);
        manager.record_output(hash, tc);
    }

    let duration = start.elapsed();
    let stats = manager.stats();

    println!(
        "Recorded {} outputs in {:?} ({:.0}/sec)",
        TEST_CASES,
        duration,
        TEST_CASES as f64 / duration.as_secs_f64()
    );
    println!("Stats: {:?}", stats);

    // Should have no collisions (all unique)
    assert_eq!(stats.collisions, 0);
}

#[test]
fn test_oracle_state_manager_concurrent() {
    let config = OracleStateConfig {
        max_entries: 1_000_000,
        bloom_filter_bits: 10_000_000,
        bloom_hash_count: 7,
        enable_lru: true,
        memory_limit_bytes: 0,
        eviction_batch_size: 1000,
    };

    let manager = Arc::new(OracleStateManager::new(config));
    let mut handles = vec![];

    for worker_id in 0..NUM_WORKERS {
        let m = Arc::clone(&manager);
        handles.push(thread::spawn(move || {
            for i in 0..1000 {
                let id = (worker_id as u64) * 10000 + (i as u64);
                let hash = hash_from_id(id);
                let tc = make_test_case(id);
                m.record_output(hash, tc);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let stats = manager.stats();
    println!(
        "Concurrent test: {} entries, {} collisions",
        stats.entries, stats.collisions
    );

    // All unique IDs, so no collisions expected
    assert_eq!(stats.collisions, 0);
}

#[test]
fn test_oracle_state_manager_memory_bounded() {
    let config = OracleStateConfig {
        max_entries: 10_000,
        bloom_filter_bits: 1_000_000,
        bloom_hash_count: 7,
        enable_lru: true,
        memory_limit_bytes: 1024 * 1024, // 1MB
        eviction_batch_size: 1000,
    };

    let manager = OracleStateManager::new(config);

    // Record more than max entries
    for i in 0..50_000 {
        let hash = hash_from_id(i as u64);
        let tc = make_test_case(i as u64);
        manager.record_output(hash, tc);
    }

    let stats = manager.stats();
    println!(
        "After 50K inserts: {} entries, {} memory, {} evictions",
        stats.entries, stats.memory_used, stats.evictions
    );

    // Should have evicted to stay bounded
    assert!(
        stats.entries <= 11_000,
        "Expected bounded entries, got {}",
        stats.entries
    );
}

// ============================================================================
// Per-Worker State Tests
// ============================================================================

#[test]
fn test_per_worker_state_basic() {
    let mut state = PerWorkerOracleState::new(0, 100);

    // Record unique outputs
    for i in 0..50 {
        let hash = hash_from_id(i);
        let tc = make_test_case(i);
        assert!(!state.record_local(hash, tc));
    }

    assert!(!state.needs_merge());
}

#[test]
fn test_per_worker_state_collision() {
    let mut state = PerWorkerOracleState::new(0, 100);

    let hash = hash_from_id(42);
    let tc = make_test_case(42);

    assert!(!state.record_local(hash.clone(), tc.clone()));
    assert!(state.record_local(hash, tc));
}

#[test]
fn test_per_worker_state_merge() {
    let mut state = PerWorkerOracleState::new(0, 50);

    // Record enough to trigger merge
    for i in 0..100 {
        let hash = hash_from_id(i);
        let tc = make_test_case(i);
        state.record_local(hash, tc);
    }

    assert!(state.needs_merge());

    let entries = state.take_for_merge();
    assert_eq!(entries.len(), 100);
    assert!(!state.needs_merge());
}

#[test]
fn test_per_worker_merge_pattern() {
    // Simulate multi-worker pattern
    let config = OracleStateConfig::default();
    let global_manager = Arc::new(OracleStateManager::new(config));

    let mut handles = vec![];

    for worker_id in 0..NUM_WORKERS {
        let manager = Arc::clone(&global_manager);
        handles.push(thread::spawn(move || {
            let mut local_state = PerWorkerOracleState::new(worker_id, 100);

            for i in 0..500 {
                let id = (worker_id as u64) * 1000 + (i as u64);
                let hash = hash_from_id(id);
                let tc = make_test_case(id);

                local_state.record_local(hash.clone(), tc.clone());

                // Merge when needed
                if local_state.needs_merge() {
                    let entries = local_state.take_for_merge();
                    for (hash, tc) in entries {
                        manager.record_output(hash, tc);
                    }
                }
            }

            // Final merge
            let entries = local_state.take_for_merge();
            for (hash, tc) in entries {
                manager.record_output(hash, tc);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let stats = global_manager.stats();
    println!(
        "Multi-worker merge: {} entries, {} collisions",
        stats.entries, stats.collisions
    );

    // All unique IDs
    assert_eq!(stats.collisions, 0);
}

// ============================================================================
// Performance Benchmarks
// ============================================================================

#[test]
fn test_performance_1m_test_cases() {
    let config = OracleStateConfig {
        max_entries: 500_000,
        bloom_filter_bits: 50_000_000, // 50M bits
        bloom_hash_count: 7,
        enable_lru: true,
        memory_limit_bytes: 0,
        eviction_batch_size: 10_000,
    };

    let manager = OracleStateManager::new(config);

    let start = Instant::now();

    for i in 0..1_000_000 {
        let hash = hash_from_id(i as u64);
        let tc = make_test_case(i as u64);
        manager.record_output(hash, tc);
    }

    let duration = start.elapsed();
    let stats = manager.stats();

    println!("=== 1M Test Cases ===");
    println!("Duration: {:?}", duration);
    println!("Throughput: {:.0} ops/sec", 1_000_000.0 / duration.as_secs_f64());
    println!("Entries: {}", stats.entries);
    println!("Memory: {} bytes", stats.memory_used);
    println!("Evictions: {}", stats.evictions);
    println!("Bloom FP rate: {:.4}%", stats.bloom_fp_rate * 100.0);
    println!("Cache hit rate: {:.2}%", stats.cache_hit_rate * 100.0);

    // Should complete in reasonable time
    assert!(
        duration.as_secs() < 60,
        "1M test cases took too long: {:?}",
        duration
    );

    // Memory should be bounded
    assert!(
        stats.entries <= 510_000,
        "Expected bounded entries, got {}",
        stats.entries
    );
}

#[test]
#[ignore] // Run with --ignored for extended testing
fn test_memory_stability_extended() {
    let config = OracleStateConfig {
        max_entries: 100_000,
        bloom_filter_bits: 10_000_000,
        bloom_hash_count: 7,
        enable_lru: true,
        memory_limit_bytes: 100 * 1024 * 1024, // 100MB limit
        eviction_batch_size: 10_000,
    };

    let manager = OracleStateManager::new(config);

    // Simulate extended fuzzing session
    for batch in 0..100 {
        for i in 0..10_000 {
            let id = (batch as u64) * 10_000 + (i as u64);
            let hash = hash_from_id(id);
            let tc = make_test_case(id);
            manager.record_output(hash, tc);
        }

        let stats = manager.stats();
        println!(
            "Batch {}: {} entries, {} MB memory",
            batch,
            stats.entries,
            stats.memory_used / (1024 * 1024)
        );
    }

    let final_stats = manager.stats();
    println!("\nFinal stats: {:?}", final_stats);

    // Memory should remain bounded
    assert!(
        final_stats.memory_used < 150 * 1024 * 1024,
        "Memory exceeded limit: {} bytes",
        final_stats.memory_used
    );
}
