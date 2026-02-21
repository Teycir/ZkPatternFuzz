#[test]
fn report_generator_preserves_correlation_annotation_guards() {
    let source = include_str!("../src/fuzzer/engine/report_generator.rs");

    assert!(
        source.contains("if !finding.description.contains(\"Correlation: \")"),
        "correlation marker annotation must remain deduplicated"
    );
    assert!(
        source.contains("ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.severity.cmp(&a.1.severity)))"),
        "correlation ranking must prioritize confidence, then severity"
    );
    assert!(
        source.contains("Correlation: {} (groups={}, oracles={}, corroborating={}, sources=[{}])"),
        "correlation marker format must keep group/oracle/corroboration metadata"
    );
}
