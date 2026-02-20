use super::*;

fn make_test_case(id: u64) -> TestCase {
    TestCase {
        inputs: vec![FieldElement::from_u64(id)],
        expected_output: None,
        metadata: zk_core::TestMetadata::default(),
    }
}

#[test]
fn test_bloom_filter_basic() {
    let filter = BloomFilter::new(1000, 5);

    let data1 = b"test1";
    let data2 = b"test2";

    assert!(!filter.might_contain(data1));
    filter.add(data1);
    assert!(filter.might_contain(data1));
    assert!(!filter.might_contain(data2)); // Might be false positive, but unlikely
}

#[test]
fn test_bloom_filter_fp_rate() {
    let filter = BloomFilter::new(100_000, 7);

    // Add some items
    for i in 0u64..1000 {
        filter.add(&i.to_le_bytes());
    }

    // Check FP rate
    let fp_rate = filter.estimated_fp_rate();
    assert!(fp_rate < 0.01, "FP rate too high: {}", fp_rate);
}

#[test]
fn test_bounded_state_map() {
    let config = OracleStateConfig {
        max_entries: 100,
        bloom_filter_bits: 1000,
        bloom_hash_count: 5,
        enable_lru: true,
        memory_limit_bytes: 0,
        eviction_batch_size: 10,
    };

    let map: BoundedStateMap<Vec<u8>, u64> = BoundedStateMap::new(config);

    // Insert some entries
    for i in 0u64..50 {
        let key = i.to_le_bytes().to_vec();
        map.insert(key, i, 8);
    }

    assert_eq!(map.len(), 50);

    // Retrieve
    let key = 25u64.to_le_bytes().to_vec();
    assert_eq!(map.get(&key), Some(25));
}

#[test]
fn test_bounded_state_map_eviction() {
    let config = OracleStateConfig {
        max_entries: 50,
        bloom_filter_bits: 1000,
        bloom_hash_count: 5,
        enable_lru: true,
        memory_limit_bytes: 0,
        eviction_batch_size: 10,
    };

    let map: BoundedStateMap<Vec<u8>, u64> = BoundedStateMap::new(config);

    // Insert more than max
    for i in 0u64..100 {
        let key = i.to_le_bytes().to_vec();
        map.insert(key, i, 8);
    }

    // Should have evicted some entries
    assert!(map.len() <= 50 + 10, "Expected eviction, got {}", map.len());
}

#[test]
fn test_oracle_state_manager() {
    let manager = OracleStateManager::with_defaults();

    let tc1 = make_test_case(1);
    let tc2 = make_test_case(2);
    let tc3 = make_test_case(1); // Same as tc1

    let hash1 = vec![1, 2, 3, 4];
    let hash2 = vec![5, 6, 7, 8];
    let hash3 = vec![1, 2, 3, 4]; // Same as hash1

    // First two should not collide
    assert!(manager.record_output(hash1.clone(), tc1).is_none());
    assert!(manager.record_output(hash2, tc2).is_none());

    // Third should collide with first
    let collision = manager.record_output(hash3, tc3);
    assert!(collision.is_some());
    assert_eq!(manager.collision_count(), 1);
}

#[test]
fn test_per_worker_state() {
    let mut state = PerWorkerOracleState::new(0, 100);

    let tc = make_test_case(42);
    let hash = vec![1, 2, 3];

    // First record should not be collision
    assert!(!state.record_local(hash.clone(), tc.clone()));

    // Second record with same hash should be collision
    assert!(state.record_local(hash, tc));
}

#[test]
fn test_per_worker_merge() {
    let mut state = PerWorkerOracleState::new(0, 5);

    for i in 0..10 {
        let hash = vec![i];
        let tc = make_test_case(i as u64);
        state.record_local(hash, tc);
    }

    assert!(state.needs_merge());

    let entries = state.take_for_merge();
    assert_eq!(entries.len(), 10);
    assert!(!state.needs_merge());
}
