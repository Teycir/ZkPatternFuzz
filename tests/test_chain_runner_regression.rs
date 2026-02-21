#[test]
fn chain_resume_aggregation_keeps_zero_coverage_guard() {
    let source = include_str!("../src/fuzzer/engine/chain_runner.rs");

    assert!(
        source.contains("if entry.coverage_bits > 0"),
        "resume aggregation must ignore zero-coverage sentinel entries"
    );
    assert!(
        source.contains("execution_count.max(1)"),
        "resume aggregation must keep minimum execution contribution of 1"
    );
    assert!(
        source.contains("new_coverage: unique_coverage.len() as u64"),
        "resume aggregation must report distinct non-zero coverage bits"
    );
}
