
use super::*;
use crate::chain_fuzzer::types::StepSpec;

fn create_test_chains() -> Vec<ChainSpec> {
    vec![
        ChainSpec::new("chain_a", vec![StepSpec::fresh("circuit_a")]),
        ChainSpec::new("chain_b", vec![StepSpec::fresh("circuit_b")]),
        ChainSpec::new("chain_c", vec![StepSpec::fresh("circuit_c")]),
    ]
}

#[test]
fn test_equal_allocation() {
    let chains = create_test_chains();
    let scheduler = ChainScheduler::new(chains, Duration::from_secs(300));
    let allocations = scheduler.allocate();

    assert_eq!(allocations.len(), 3);
    // Each should get roughly 100 seconds
    for alloc in &allocations {
        assert!(alloc.budget >= Duration::from_secs(90));
        assert!(alloc.budget <= Duration::from_secs(110));
    }
}

#[test]
fn test_allocation_never_exceeds_total_budget() {
    let chains = create_test_chains();
    let scheduler = ChainScheduler::new(chains, Duration::from_secs(5))
        .with_min_budget(Duration::from_secs(10));
    let allocations = scheduler.allocate();

    let allocated_ms: u128 = allocations.iter().map(|a| a.budget.as_millis()).sum();
    assert!(allocated_ms <= Duration::from_secs(5).as_millis());
}

#[test]
fn test_priority_update() {
    let chains = create_test_chains();
    let mut scheduler = ChainScheduler::new(chains, Duration::from_secs(300));

    // Update chain_a with a violation
    scheduler.update_priority(&ChainRunStats {
        chain_name: "chain_a".to_string(),
        found_violation: true,
        new_coverage: 10,
        near_miss_score: 0.8,
        executions: 100,
        time_spent: Duration::from_secs(10),
    });

    // chain_a should now have higher priority
    let pa = scheduler.get_priority("chain_a");
    let pb = scheduler.get_priority("chain_b");
    assert!(pa > pb);
}

#[test]
fn test_priority_allocation() {
    let chains = create_test_chains();
    let mut scheduler = ChainScheduler::new(chains, Duration::from_secs(300));

    // Boost chain_a priority
    scheduler.priorities.insert("chain_a".to_string(), 5.0);

    let allocations = scheduler.allocate();

    // chain_a should get more budget
    let alloc_a = allocations
        .iter()
        .find(|a| a.spec.name == "chain_a")
        .unwrap();
    let alloc_b = allocations
        .iter()
        .find(|a| a.spec.name == "chain_b")
        .unwrap();

    assert!(alloc_a.budget > alloc_b.budget);
}

#[test]
fn test_chains_by_priority() {
    let chains = create_test_chains();
    let mut scheduler = ChainScheduler::new(chains, Duration::from_secs(300));

    scheduler.priorities.insert("chain_b".to_string(), 3.0);
    scheduler.priorities.insert("chain_a".to_string(), 1.0);
    scheduler.priorities.insert("chain_c".to_string(), 2.0);

    let sorted = scheduler.chains_by_priority();
    assert_eq!(sorted[0].name, "chain_b");
    assert_eq!(sorted[1].name, "chain_c");
    assert_eq!(sorted[2].name, "chain_a");
}

#[test]
fn test_largest_remainder_allocation_preserves_total_and_fairness() {
    let chains = create_test_chains();
    let mut scheduler = ChainScheduler::new(chains, Duration::from_millis(1001));
    scheduler.priorities.insert("chain_a".to_string(), 3.0);
    scheduler.priorities.insert("chain_b".to_string(), 2.0);
    scheduler.priorities.insert("chain_c".to_string(), 1.0);

    let allocations = scheduler.allocate();
    let total_allocated_ms: u64 = allocations
        .iter()
        .map(|a| a.budget.as_millis() as u64)
        .sum();
    assert_eq!(total_allocated_ms, 1001);

    let alloc_a = allocations
        .iter()
        .find(|a| a.spec.name == "chain_a")
        .expect("chain_a allocation");
    let alloc_b = allocations
        .iter()
        .find(|a| a.spec.name == "chain_b")
        .expect("chain_b allocation");
    let alloc_c = allocations
        .iter()
        .find(|a| a.spec.name == "chain_c")
        .expect("chain_c allocation");

    // Remaining 2ms are split proportionally: 1ms direct to chain_a and 1ms leftover to chain_b.
    assert_eq!(alloc_a.budget, Duration::from_millis(334));
    assert_eq!(alloc_b.budget, Duration::from_millis(334));
    assert_eq!(alloc_c.budget, Duration::from_millis(333));
}
