use zk_core::{FieldElement, TestCase, TestMetadata};
use zk_fuzzer::fuzzer::oracle_state::{
    BloomFilter, BoundedStateMap, OracleStateConfig, OracleStateManager, PerWorkerOracleState,
};

fn make_test_case(id: u64) -> TestCase {
    TestCase {
        inputs: vec![FieldElement::from_u64(id)],
        expected_output: None,
        metadata: TestMetadata::default(),
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
    assert!(!filter.might_contain(data2));
}

#[test]
fn test_bloom_filter_fp_rate() {
    let filter = BloomFilter::new(100_000, 7);

    for i in 0u64..1000 {
        filter.add(&i.to_le_bytes());
    }

    let fp_rate = filter.estimated_fp_rate();
    assert!(fp_rate < 0.01, "FP rate too high: {}", fp_rate);
}

#[test]
fn test_bounded_state_map_insert_and_get() {
    let config = OracleStateConfig {
        max_entries: 100,
        bloom_filter_bits: 1000,
        bloom_hash_count: 5,
        enable_lru: true,
        memory_limit_bytes: 0,
        eviction_batch_size: 10,
    };

    let map: BoundedStateMap<Vec<u8>, u64> = BoundedStateMap::new(config);

    for i in 0u64..50 {
        map.insert(i.to_le_bytes().to_vec(), i, 8);
    }

    assert_eq!(map.len(), 50);
    assert_eq!(map.get(&25u64.to_le_bytes().to_vec()), Some(25));
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

    for i in 0u64..100 {
        map.insert(i.to_le_bytes().to_vec(), i, 8);
    }

    assert!(map.len() <= 60, "Expected eviction, got {}", map.len());
}

#[test]
fn test_oracle_state_manager_collision_tracking() {
    let manager = OracleStateManager::with_defaults();

    let tc1 = make_test_case(1);
    let tc2 = make_test_case(2);
    let tc3 = make_test_case(1);

    let hash1 = vec![1, 2, 3, 4];
    let hash2 = vec![5, 6, 7, 8];
    let hash3 = vec![1, 2, 3, 4];

    assert!(manager.record_output(hash1.clone(), tc1).is_none());
    assert!(manager.record_output(hash2, tc2).is_none());

    let collision = manager.record_output(hash3, tc3);
    assert!(collision.is_some());
    assert_eq!(manager.collision_count(), 1);

    let stats = manager.stats();
    assert_eq!(stats.collisions, 1);
    assert!(stats.entries >= 2);
}

#[test]
fn test_oracle_state_manager_reset() {
    let manager = OracleStateManager::with_defaults();

    assert!(manager
        .record_output(vec![1, 1, 1], make_test_case(11))
        .is_none());
    assert_eq!(manager.stats().entries, 1);

    manager.reset();

    let stats = manager.stats();
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.collisions, 0);
}

#[test]
fn test_per_worker_state() {
    let mut state = PerWorkerOracleState::new(0, 100);

    let tc = make_test_case(42);
    let hash = vec![1, 2, 3];

    assert!(!state.record_local(hash.clone(), tc.clone()));
    assert!(state.record_local(hash, tc));
}

#[test]
fn test_per_worker_merge() {
    let mut state = PerWorkerOracleState::new(0, 5);

    for i in 0..10 {
        state.record_local(vec![i], make_test_case(i as u64));
    }

    assert!(state.needs_merge());

    let entries = state.take_for_merge();
    assert_eq!(entries.len(), 10);
    assert!(!state.needs_merge());
    assert_eq!(state.worker_id(), 0);
}
