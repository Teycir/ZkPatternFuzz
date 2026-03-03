use zk_fuzzer::analysis::taint::TaintFindingType;
use zk_fuzzer::analysis::TaintAnalyzer;

#[test]
fn test_taint_analyzer_creation() {
    let mut analyzer = TaintAnalyzer::new(2, 3);
    analyzer.initialize_inputs();

    // Check public inputs are labeled
    assert!(analyzer.get_taint(0).unwrap().has_public_taint());
    assert!(analyzer.get_taint(1).unwrap().has_public_taint());

    // Check private inputs are labeled
    assert!(analyzer.get_taint(2).unwrap().has_private_taint());
    assert!(analyzer.get_taint(3).unwrap().has_private_taint());
    assert!(analyzer.get_taint(4).unwrap().has_private_taint());
}

#[test]
fn test_taint_propagation() {
    let mut analyzer = TaintAnalyzer::new(1, 1);
    analyzer.initialize_inputs();

    // Propagate: signal_2 = signal_0 (public) * signal_1 (private)
    analyzer.propagate_constraint(0, &[0, 1], 2);

    let taint = analyzer.get_taint(2).unwrap();
    assert!(taint.has_public_taint());
    assert!(taint.has_private_taint());
}

#[test]
fn test_mixed_flow_detection() {
    let mut analyzer = TaintAnalyzer::new(1, 1);
    analyzer.initialize_inputs();

    // Create mixed flow
    analyzer.propagate_constraint(0, &[0, 1], 2);
    analyzer.mark_as_output(2);

    let findings = analyzer.analyze();
    assert!(!findings.is_empty());
    assert_eq!(findings[0].finding_type, TaintFindingType::MixedFlow);
}

#[test]
fn test_selector_signal_uses_implicit_flow_not_mixed_flow() {
    let mut analyzer = TaintAnalyzer::new(1, 1);
    analyzer.initialize_inputs();
    analyzer.set_selector_signals(&[1]);

    // Signal 1 is treated as selector (private control), signal 0 is public data.
    analyzer.propagate_constraint(0, &[0, 1], 2);
    analyzer.mark_as_output(2);

    let findings = analyzer.analyze();
    assert!(
        findings
            .iter()
            .any(|f| f.finding_type == TaintFindingType::ImplicitFlow),
        "expected implicit-flow finding when private selector controls public data"
    );
    assert!(
        findings
            .iter()
            .all(|f| f.finding_type != TaintFindingType::MixedFlow),
        "selector-only private control should not be reported as mixed explicit flow"
    );
}

#[test]
fn test_selector_label_inference_identifies_halo2_style_selectors() {
    use std::collections::HashMap;

    let mut analyzer = TaintAnalyzer::new(1, 1);
    analyzer.initialize_inputs_with_indices(&[0], &[7]);

    let mut labels = HashMap::new();
    labels.insert(7usize, "q_enable".to_string());
    labels.insert(9usize, "payload".to_string());

    let inferred = analyzer.infer_selector_signals_from_labels(&labels);
    assert_eq!(inferred, 1);

    analyzer.propagate_constraint(1, &[0, 7], 10);
    analyzer.mark_as_output(10);
    let findings = analyzer.analyze();
    assert!(
        findings
            .iter()
            .any(|f| f.finding_type == TaintFindingType::ImplicitFlow)
    );
}
