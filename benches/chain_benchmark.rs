//! Mode 3: Chain Fuzzing FP/FN Benchmark
//!
//! Measures precision, recall, and depth metrics on ground truth chain circuits.
//!
//! Run with: `cargo bench --bench chain_benchmark`
//!
//! This benchmark is NOT part of the regular test suite due to execution time.
//! It serves as a regression gate for Mode 3 chain fuzzing quality.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::{Duration, Instant};

/// Result of running the chain benchmark suite
#[derive(Debug, Clone, Default)]
pub struct ChainBenchmarkResult {
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub mean_l_min: f64,
    pub p_deep: f64,
    pub mean_time_to_first: Duration,
}

impl ChainBenchmarkResult {
    pub fn compute_metrics(&mut self) {
        let tp = self.true_positives as f64;
        let fp = self.false_positives as f64;
        let fn_ = self.false_negatives as f64;

        self.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        self.recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
    }

    pub fn to_markdown(&self) -> String {
        format!(
            r#"# Chain Benchmark Results

| Metric | Value |
|--------|-------|
| True Positives | {} |
| False Positives | {} |
| False Negatives | {} |
| Precision | {:.2}% |
| Recall | {:.2}% |
| Mean L_min (D) | {:.2} |
| P_deep | {:.2}% |
| Mean Time to First Finding | {:?} |

## Quality Gates

- Precision >= 90%: {}
- Recall >= 80%: {}
"#,
            self.true_positives,
            self.false_positives,
            self.false_negatives,
            self.precision * 100.0,
            self.recall * 100.0,
            self.mean_l_min,
            self.p_deep * 100.0,
            self.mean_time_to_first,
            if self.precision >= 0.9 { "✅ PASS" } else { "❌ FAIL" },
            if self.recall >= 0.8 { "✅ PASS" } else { "❌ FAIL" },
        )
    }
}

/// Ground truth test case definition
struct GroundTruthCase {
    name: &'static str,
    chain_yaml: &'static str,
    expected_finding: bool,
    expected_assertion: Option<&'static str>,
}

/// Get ground truth cases from tests/ground_truth/chains/
fn get_ground_truth_cases() -> Vec<GroundTruthCase> {
    vec![
        GroundTruthCase {
            name: "nullifier_reuse",
            chain_yaml: "tests/ground_truth/chains/nullifier_reuse/campaign.yaml",
            expected_finding: true,
            expected_assertion: Some("unique(step[*].out[0])"),
        },
        GroundTruthCase {
            name: "root_inconsistency",
            chain_yaml: "tests/ground_truth/chains/root_inconsistency/campaign.yaml",
            expected_finding: true,
            expected_assertion: Some("step[0].out[1] == step[1].in[0]"),
        },
        GroundTruthCase {
            name: "signature_malleability",
            chain_yaml: "tests/ground_truth/chains/signature_malleability/campaign.yaml",
            expected_finding: true,
            expected_assertion: None, // Any finding is valid
        },
        GroundTruthCase {
            name: "clean_deposit_withdraw",
            chain_yaml: "tests/ground_truth/chains/clean_deposit_withdraw/campaign.yaml",
            expected_finding: false, // True negative - should find nothing
            expected_assertion: None,
        },
    ]
}

/// Run a single ground truth case and return (is_positive, l_min, time_to_first)
fn run_ground_truth_case(case: &GroundTruthCase) -> Option<(bool, usize, Duration)> {
    use std::path::Path;
    
    let yaml_path = Path::new(case.chain_yaml);
    if !yaml_path.exists() {
        eprintln!("Ground truth YAML not found: {}", case.chain_yaml);
        return None;
    }

    // In a real implementation, this would:
    // 1. Load the campaign YAML
    // 2. Create a FuzzingEngine
    // 3. Run chain fuzzing
    // 4. Check findings against expected

    // For now, return a placeholder result
    // TODO: Integrate with actual chain fuzzing when circuits are compiled
    Some((false, 0, Duration::from_secs(0)))
}

/// Run the full benchmark suite
fn run_benchmark_suite() -> ChainBenchmarkResult {
    let cases = get_ground_truth_cases();
    let mut result = ChainBenchmarkResult::default();
    let mut l_mins = Vec::new();
    let mut times = Vec::new();

    for case in &cases {
        let start = Instant::now();
        black_box(case.name);
        black_box(case.expected_assertion);
        
        if let Some((found_bug, l_min, time_to_first)) = run_ground_truth_case(case) {
            black_box(start.elapsed());
            
            if case.expected_finding {
                if found_bug {
                    result.true_positives += 1;
                    l_mins.push(l_min);
                    times.push(time_to_first);
                } else {
                    result.false_negatives += 1;
                }
            } else if found_bug {
                result.false_positives += 1;
            } else {
                // True negative - correct behavior, no count needed
            }
        }
    }

    // Compute derived metrics
    result.compute_metrics();

    if !l_mins.is_empty() {
        result.mean_l_min = l_mins.iter().sum::<usize>() as f64 / l_mins.len() as f64;
        let deep_count = l_mins.iter().filter(|&&l| l >= 2).count();
        result.p_deep = deep_count as f64 / l_mins.len() as f64;
    }

    if !times.is_empty() {
        let total_nanos: u128 = times.iter().map(|d| d.as_nanos()).sum();
        result.mean_time_to_first = Duration::from_nanos((total_nanos / times.len() as u128) as u64);
    }

    result
}

fn chain_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_fuzzing");
    
    // Set long measurement time since chain fuzzing is slow
    group.measurement_time(Duration::from_secs(60));
    group.sample_size(10);

    group.bench_function("ground_truth_suite", |b| {
        b.iter(|| {
            let result = run_benchmark_suite();
            black_box(result)
        });
    });

    group.finish();

    // Run once and print results
    let final_result = run_benchmark_suite();
    println!("\n{}", final_result.to_markdown());

    // Write to file
    if std::fs::create_dir_all("reports").is_ok() {
        if let Err(e) = std::fs::write("reports/chain_benchmark.md", final_result.to_markdown()) {
            eprintln!("Failed to write benchmark report: {}", e);
        }
    }

    // Assert quality gates
    assert!(
        final_result.precision >= 0.9,
        "Precision {:.2}% is below 90% threshold",
        final_result.precision * 100.0
    );
    assert!(
        final_result.recall >= 0.8,
        "Recall {:.2}% is below 80% threshold",
        final_result.recall * 100.0
    );
}

criterion_group!(benches, chain_benchmark);
criterion_main!(benches);
