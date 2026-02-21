use zk_fuzzer::chain_fuzzer::{ChainTrace, DepthMetrics};
use zk_fuzzer::chain_fuzzer::types::{ChainFinding, ChainFindingCore};

fn create_test_finding(l_min: usize) -> ChainFinding {
    ChainFinding {
        finding: ChainFindingCore {
            attack_type: "Underconstrained".to_string(),
            severity: "high".to_string(),
            description: "Test finding".to_string(),
            witness_inputs: vec![],
            location: None,
        },
        chain_length: l_min + 1,
        l_min,
        trace: ChainTrace::new("test_chain"),
        spec_name: "test_chain".to_string(),
        violated_assertion: None,
    }
}

#[test]
fn test_d_mean() {
    let findings = vec![
        create_test_finding(1),
        create_test_finding(2),
        create_test_finding(3),
        create_test_finding(4),
    ];
    let metrics = DepthMetrics::new(findings);

    assert!((metrics.d_mean() - 2.5).abs() < 0.001);
}

#[test]
fn test_p_deep() {
    let findings = vec![
        create_test_finding(1), // Not deep
        create_test_finding(2), // Deep
        create_test_finding(3), // Deep
        create_test_finding(1), // Not deep
    ];
    let metrics = DepthMetrics::new(findings);

    assert!((metrics.p_deep() - 0.5).abs() < 0.001);
}

#[test]
fn test_depth_distribution() {
    let findings = vec![
        create_test_finding(1),
        create_test_finding(1),
        create_test_finding(2),
        create_test_finding(3),
    ];
    let metrics = DepthMetrics::new(findings);

    let dist = metrics.depth_distribution();
    assert_eq!(dist.get(&1), Some(&2));
    assert_eq!(dist.get(&2), Some(&1));
    assert_eq!(dist.get(&3), Some(&1));
}

#[test]
fn test_empty_metrics() {
    let metrics = DepthMetrics::empty();

    assert_eq!(metrics.d_mean(), 0.0);
    assert_eq!(metrics.p_deep(), 0.0);
    assert!(metrics.depth_distribution().is_empty());
}

#[test]
fn test_summary_markdown() {
    let findings = vec![create_test_finding(2), create_test_finding(3)];
    let metrics = DepthMetrics::new(findings);
    let summary = metrics.summary();
    let markdown = summary.to_markdown();

    assert!(markdown.contains("Multi-Step Depth Metrics"));
    assert!(markdown.contains("D (mean L_min)"));
    assert!(markdown.contains("P_deep"));
}
