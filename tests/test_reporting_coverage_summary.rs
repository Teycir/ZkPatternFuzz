use zk_fuzzer::reporting::CoverageSummaryBuilder;

#[test]
fn test_coverage_summary_creation() {
    let summary = CoverageSummaryBuilder::new()
        .constraint_coverage(500, 1000)
        .corpus_size(100)
        .findings(5)
        .throughput(1234.5)
        .build();

    assert_eq!(summary.constraint_coverage.covered, 500);
    assert_eq!(summary.constraint_coverage.total, 1000);
    assert!((summary.constraint_coverage.percentage - 50.0).abs() < 0.1);
}

#[test]
fn test_format_number() {
    let summary = CoverageSummaryBuilder::new()
        .constraint_coverage(1_234_567, 2_000_000)
        .build();
    let mut out = Vec::new();
    summary.print_to(&mut out).expect("print_to should succeed");
    let rendered = String::from_utf8(out).expect("valid UTF-8 output");
    assert!(rendered.contains("1,234,567"));
    assert!(rendered.contains("2,000,000"));
}

#[test]
fn test_progress_bar() {
    let summary = CoverageSummaryBuilder::new()
        .constraint_coverage(50, 100)
        .build();
    let mut out = Vec::new();
    summary.print_to(&mut out).expect("print_to should succeed");
    let rendered = String::from_utf8(out).expect("valid UTF-8 output");
    assert!(rendered.contains('█') || rendered.contains('░'));
}

#[test]
fn test_to_markdown() {
    let summary = CoverageSummaryBuilder::new()
        .constraint_coverage(800, 1000)
        .findings(3)
        .build();

    let md = summary.to_markdown();
    assert!(md.contains("## Coverage Summary"));
    assert!(md.contains("800"));
    assert!(md.contains("1000"));
    assert!(md.contains("80.0%"));
}

#[test]
fn test_to_json() {
    let summary = CoverageSummaryBuilder::new()
        .constraint_coverage(100, 200)
        .build();

    let json = summary.to_json();
    assert_eq!(json["constraint_coverage"]["covered"], 100);
    assert_eq!(json["constraint_coverage"]["total"], 200);
}
