use zk_core::CoverageMap;
use zk_fuzzer::analysis::DependencyGraph;

#[test]
fn test_dependency_graph_creation() {
    let mut graph = DependencyGraph::new(5, 10);

    graph.add_input_influence(0, 0);
    graph.add_input_influence(0, 1);
    graph.add_input_influence(1, 1);
    graph.add_input_influence(1, 2);

    assert_eq!(graph.constraints_for_input(0).len(), 2);
    assert_eq!(graph.constraints_for_input(1).len(), 2);
    assert_eq!(graph.inputs_for_constraint(1).len(), 2);
}

#[test]
fn test_coverage_stats() {
    let mut graph = DependencyGraph::new(3, 5);

    // Setup: input 0 influences constraints 0,1,2
    for c in 0..3 {
        graph.add_input_influence(0, c);
    }
    // Input 1 influences constraints 3,4
    for c in 3..5 {
        graph.add_input_influence(1, c);
    }

    // Coverage: only constraints 0,1 covered
    let mut coverage = CoverageMap::new();
    coverage.record_hit(0);
    coverage.record_hit(1);
    coverage.max_coverage = 5;

    let stats = graph.coverage_stats(&coverage);

    assert_eq!(stats.covered_constraints, 2);
    assert_eq!(stats.total_constraints, 5);
    assert!((stats.constraint_coverage_percent - 40.0).abs() < 0.1);
}

#[test]
fn test_suggest_inputs() {
    let mut graph = DependencyGraph::new(3, 3);

    graph.add_input_influence(0, 0);
    graph.add_input_influence(1, 0);
    graph.add_input_influence(2, 1);

    let inputs = graph.suggest_inputs_for_coverage(0);
    assert_eq!(inputs.len(), 2);
    assert!(inputs.contains(&0));
    assert!(inputs.contains(&1));
}

#[test]
fn test_dot_export() {
    let mut graph = DependencyGraph::new(2, 3);
    graph.add_input_influence(0, 0);
    graph.add_input_influence(1, 1);
    graph.add_constraint_edge(0, 1);

    let dot = graph.to_dot();

    assert!(dot.contains("digraph DependencyGraph"));
    assert!(dot.contains("input_0"));
    assert!(dot.contains("constraint_0"));
}
