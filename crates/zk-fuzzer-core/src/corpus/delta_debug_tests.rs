
use super::*;

#[test]
fn test_basic_minimization() {
    // Oracle fails if input contains element 5
    let oracle = |input: &[FieldElement]| {
        if input.iter().any(|fe| fe == &FieldElement::from_u64(5)) {
            OracleResult::Fail
        } else {
            OracleResult::Pass
        }
    };

    let input: Vec<FieldElement> = (0..10).map(FieldElement::from_u64).collect();
    let debugger = DeltaDebugger::new(oracle);

    let (minimized, stats) = debugger.minimize(&input).unwrap();

    assert_eq!(minimized.len(), 1);
    assert_eq!(minimized[0], FieldElement::from_u64(5));
    assert!(stats.reduction_percent > 80.0);
}

#[test]
fn test_multiple_triggers() {
    // Oracle fails if input contains both 3 and 7
    let oracle = |input: &[FieldElement]| {
        let has_3 = input.iter().any(|fe| fe == &FieldElement::from_u64(3));
        let has_7 = input.iter().any(|fe| fe == &FieldElement::from_u64(7));
        if has_3 && has_7 {
            OracleResult::Fail
        } else {
            OracleResult::Pass
        }
    };

    let input: Vec<FieldElement> = (0..10).map(FieldElement::from_u64).collect();
    let debugger = DeltaDebugger::new(oracle);

    let (minimized, stats) = debugger.minimize(&input).unwrap();

    assert_eq!(minimized.len(), 2);
    assert!(minimized.contains(&FieldElement::from_u64(3)));
    assert!(minimized.contains(&FieldElement::from_u64(7)));
    assert!(stats.reduction_percent > 70.0);
}

#[test]
fn test_structured_minimization() {
    // Oracle fails if any group contains 5
    let oracle = |input: &[FieldElement]| {
        if input.iter().any(|fe| fe == &FieldElement::from_u64(5)) {
            OracleResult::Fail
        } else {
            OracleResult::Pass
        }
    };

    let groups = vec![
        (0..5).map(FieldElement::from_u64).collect(),
        (5..10).map(FieldElement::from_u64).collect(),
        (10..15).map(FieldElement::from_u64).collect(),
    ];

    let debugger = DeltaDebugger::new(oracle);
    let (minimized_groups, stats) = debugger.minimize_structured(&groups).unwrap();

    // Should reduce to just the group containing 5
    assert!(stats.reductions > 0);
    let total_elements: usize = minimized_groups.iter().map(|g| g.len()).sum();
    assert!(total_elements < 15);
}

#[test]
fn test_binary_minimize() {
    // Oracle fails for any prefix containing 5
    let oracle = |input: &[FieldElement]| {
        if input.iter().any(|fe| fe == &FieldElement::from_u64(5)) {
            OracleResult::Fail
        } else {
            OracleResult::Pass
        }
    };

    let input: Vec<FieldElement> = (0..100).map(FieldElement::from_u64).collect();
    let (minimized, queries) = binary_minimize(&input, oracle).unwrap();

    // Should find minimal prefix ending at 6 (indices 0-5 inclusive)
    assert_eq!(minimized.len(), 6);
    assert!(queries < 10); // Binary search should be efficient
}

#[test]
fn test_stats() {
    let mut stats = DeltaDebugStats::new(100);
    stats.queries = 50;
    stats.reductions = 10;
    stats.finalize(20, Duration::from_secs(5));

    assert_eq!(stats.original_size, 100);
    assert_eq!(stats.minimized_size, 20);
    assert!((stats.reduction_percent - 80.0).abs() < 0.1);
}
