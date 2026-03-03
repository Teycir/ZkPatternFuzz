use std::path::Path;

#[test]
fn benchmark_scan_output_root_uses_expected_layout() {
    let path = zk_fuzzer::util::benchmark_scan_output_root(
        Path::new("artifacts/benchmark_runs"),
        "vulnerable_ground_truth",
        "merkle_unconstrained",
        2,
        1042,
    );

    let expected = Path::new("artifacts/benchmark_runs")
        .join("scan_outputs")
        .join("vulnerable_ground_truth")
        .join("merkle_unconstrained")
        .join("trial_2_seed_1042");
    assert_eq!(path, expected);
}

#[test]
fn benchmark_scan_output_root_changes_with_trial_or_seed() {
    let base = Path::new("/tmp/zkbench");
    let p1 = zk_fuzzer::util::benchmark_scan_output_root(base, "suite", "target", 1, 42);
    let p2 = zk_fuzzer::util::benchmark_scan_output_root(base, "suite", "target", 2, 42);
    let p3 = zk_fuzzer::util::benchmark_scan_output_root(base, "suite", "target", 1, 43);

    assert_ne!(p1, p2);
    assert_ne!(p1, p3);
    assert_ne!(p2, p3);
}
