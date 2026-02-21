use super::*;

#[test]
fn test_cache_basic() {
    let cache = ConstraintEvalCache::new();

    let inputs = vec![FieldElement::from_u64(42), FieldElement::from_u64(100)];

    // Miss on first access
    assert!(cache.get(0, &inputs).is_none());

    // Insert and hit
    cache.insert(0, &inputs, ConstraintEvalResult::Satisfied);
    assert_eq!(cache.get(0, &inputs), Some(ConstraintEvalResult::Satisfied));

    let stats = cache.stats();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
}

#[test]
fn test_cache_different_inputs() {
    let cache = ConstraintEvalCache::new();

    let inputs1 = vec![FieldElement::from_u64(1)];
    let inputs2 = vec![FieldElement::from_u64(2)];

    cache.insert(0, &inputs1, ConstraintEvalResult::Satisfied);
    cache.insert(0, &inputs2, ConstraintEvalResult::Violated);

    assert_eq!(
        cache.get(0, &inputs1),
        Some(ConstraintEvalResult::Satisfied)
    );
    assert_eq!(cache.get(0, &inputs2), Some(ConstraintEvalResult::Violated));
}

#[test]
fn test_cache_eviction() {
    let cache = ConstraintEvalCache::new().with_max_size(10);

    // Fill cache
    for i in 0..15 {
        let inputs = vec![FieldElement::from_u64(i)];
        cache.insert(i as usize, &inputs, ConstraintEvalResult::Satisfied);
    }

    let stats = cache.stats();
    assert!(stats.current_size <= 10);
    assert!(stats.evictions > 0);
}

#[test]
fn test_cache_batch() {
    let cache = ConstraintEvalCache::new();

    // Insert batch
    let entries = vec![
        (
            0,
            vec![FieldElement::from_u64(1)],
            ConstraintEvalResult::Satisfied,
        ),
        (
            1,
            vec![FieldElement::from_u64(2)],
            ConstraintEvalResult::Violated,
        ),
    ];
    cache
        .insert_batch(entries)
        .expect("batch insert should succeed");

    // Get batch
    let queries = vec![
        (0, vec![FieldElement::from_u64(1)]),
        (1, vec![FieldElement::from_u64(2)]),
        (2, vec![FieldElement::from_u64(3)]), // Not in cache
    ];
    let results = cache.get_batch(&queries);

    assert_eq!(results[0], Some(ConstraintEvalResult::Satisfied));
    assert_eq!(results[1], Some(ConstraintEvalResult::Violated));
    assert_eq!(results[2], None);

    let stats = cache.stats();
    assert_eq!(stats.hits, 2);
    assert_eq!(stats.misses, 1);
}

#[test]
fn test_cache_invalidation() {
    let cache = ConstraintEvalCache::new();

    let inputs = vec![FieldElement::from_u64(1)];
    cache.insert(0, &inputs, ConstraintEvalResult::Satisfied);
    cache.insert(1, &inputs, ConstraintEvalResult::Violated);

    // Invalidate constraint 0
    cache.invalidate_constraint(0);

    assert!(cache.get(0, &inputs).is_none());
    assert_eq!(cache.get(1, &inputs), Some(ConstraintEvalResult::Violated));
}

#[test]
fn test_shared_cache() {
    let cache = create_shared_cache_with_size(1000);
    let cache_clone = Arc::clone(&cache);

    // Insert in one reference
    let inputs = vec![FieldElement::from_u64(42)];
    cache.insert(0, &inputs, ConstraintEvalResult::Satisfied);

    // Read from clone
    assert_eq!(
        cache_clone.get(0, &inputs),
        Some(ConstraintEvalResult::Satisfied)
    );
}

#[test]
fn test_insert_batch_rejects_oversized_batch() {
    let cache = ConstraintEvalCache::new().with_max_size(2);
    let entries = vec![
        (
            0,
            vec![FieldElement::from_u64(1)],
            ConstraintEvalResult::Satisfied,
        ),
        (
            1,
            vec![FieldElement::from_u64(2)],
            ConstraintEvalResult::Satisfied,
        ),
        (
            2,
            vec![FieldElement::from_u64(3)],
            ConstraintEvalResult::Satisfied,
        ),
    ];

    let err = cache
        .insert_batch(entries)
        .expect_err("oversized batch should fail");

    assert_eq!(
        err,
        ConstraintCacheInsertError::BatchExceedsCapacity {
            batch_size: 3,
            max_size: 2
        }
    );
}

#[test]
fn test_lru_prefers_low_access_count_eviction() {
    let cache = ConstraintEvalCache::new().with_max_size(10);

    for i in 0..10u64 {
        let inputs = vec![FieldElement::from_u64(i)];
        cache.insert(i as usize, &inputs, ConstraintEvalResult::Satisfied);
    }

    let sticky_inputs = vec![FieldElement::from_u64(0)];
    for _ in 0..5 {
        assert_eq!(
            cache.get(0, &sticky_inputs),
            Some(ConstraintEvalResult::Satisfied)
        );
    }

    cache.insert(
        999,
        &[FieldElement::from_u64(999)],
        ConstraintEvalResult::Satisfied,
    );

    assert_eq!(
        cache.get(0, &sticky_inputs),
        Some(ConstraintEvalResult::Satisfied)
    );
}
