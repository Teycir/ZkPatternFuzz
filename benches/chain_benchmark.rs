//! Mode 3: Chain Fuzzing FP/FN Benchmark
//!
//! Measures precision, recall, and depth metrics on ground truth chain circuits.
//!
//! Run with: `cargo bench --bench chain_benchmark`
//!
//! This benchmark is NOT part of the regular test suite due to execution time.
//! It serves as a regression gate for Mode 3 chain fuzzing quality.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{env, path::Path};
use std::{fmt::Write as _, sync::Arc};
use zk_core::CircuitExecutor;
use zk_fuzzer::chain_fuzzer::{ChainRunner, ChainSpec, CrossStepAssertion, StepSpec};
use zk_fuzzer::executor::FixtureCircuitExecutor;

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
            if self.precision >= 0.9 {
                "✅ PASS"
            } else {
                "❌ FAIL"
            },
            if self.recall >= 0.8 {
                "✅ PASS"
            } else {
                "❌ FAIL"
            },
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

#[derive(Debug, Clone, Copy)]
struct ChainComplexityProfile {
    name: &'static str,
    chain_length: usize,
    wiring_per_step: usize,
    assertions: usize,
}

const CHAIN_COMPLEXITY_PROFILES: [ChainComplexityProfile; 4] = [
    ChainComplexityProfile {
        name: "low",
        chain_length: 2,
        wiring_per_step: 1,
        assertions: 0,
    },
    ChainComplexityProfile {
        name: "medium",
        chain_length: 5,
        wiring_per_step: 2,
        assertions: 2,
    },
    ChainComplexityProfile {
        name: "deep",
        chain_length: 12,
        wiring_per_step: 2,
        assertions: 4,
    },
    ChainComplexityProfile {
        name: "wide_wiring",
        chain_length: 8,
        wiring_per_step: 4,
        assertions: 2,
    },
];

#[derive(Debug, Clone)]
struct ChainComplexitySnapshot {
    profile: ChainComplexityProfile,
    elapsed: Duration,
    succeeded: bool,
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
        result.mean_time_to_first =
            Duration::from_nanos((total_nanos / times.len() as u128) as u64);
    }

    result
}

fn create_fixture_chain_runner(num_circuits: usize, io_width: usize) -> Option<ChainRunner> {
    let mut executors: HashMap<String, Arc<dyn CircuitExecutor>> = HashMap::new();
    for index in 0..num_circuits {
        let name = format!("circuit_{index}");
        let executor = FixtureCircuitExecutor::new(&name, io_width, 0).with_outputs(io_width);
        executors.insert(name, Arc::new(executor));
    }

    match ChainRunner::new(executors) {
        Ok(runner) => Some(runner),
        Err(err) => {
            eprintln!("Skipping complexity benchmark: failed to create chain runner: {err}");
            None
        }
    }
}

fn build_complexity_spec(profile: ChainComplexityProfile, num_circuits: usize) -> ChainSpec {
    let mut steps = vec![StepSpec::fresh("circuit_0")];
    for step_index in 1..profile.chain_length {
        let circuit = format!("circuit_{}", step_index % num_circuits);
        let mapping: Vec<(usize, usize)> = (0..profile.wiring_per_step).map(|i| (i, i)).collect();
        steps.push(StepSpec::from_prior(&circuit, step_index - 1, mapping));
    }

    let mut spec = ChainSpec::new(format!("complexity_{}", profile.name), steps);
    let tail_step = profile.chain_length.saturating_sub(1);
    for assertion_index in 0..profile.assertions {
        let wire = assertion_index % profile.wiring_per_step.max(1);
        let assertion = CrossStepAssertion::new(
            format!("{}_assertion_{assertion_index}", profile.name),
            format!("step[0].out[{wire}] == step[{tail_step}].in[{wire}]"),
        );
        spec = spec.with_assertion(assertion);
    }
    spec
}

fn run_chain_complexity_snapshot() -> Vec<ChainComplexitySnapshot> {
    let Some(runner) = create_fixture_chain_runner(6, 8) else {
        return Vec::new();
    };

    let initial_inputs = HashMap::new();
    CHAIN_COMPLEXITY_PROFILES
        .iter()
        .copied()
        .map(|profile| {
            let spec = build_complexity_spec(profile, 6);
            let start = Instant::now();
            let mut rng = rand::thread_rng();
            let succeeded = runner.execute(&spec, &initial_inputs, &mut rng).completed;
            ChainComplexitySnapshot {
                profile,
                elapsed: start.elapsed(),
                succeeded,
            }
        })
        .collect()
}

fn complexity_snapshot_markdown(samples: &[ChainComplexitySnapshot]) -> String {
    let mut out = String::from(
        "# Chain Complexity Benchmark Snapshot\n\n| Profile | Chain Length | Wiring/Step | Assertions | Single-Run Elapsed | Success |\n|---|---:|---:|---:|---:|---|\n",
    );

    if samples.is_empty() {
        out.push_str("| n/a | 0 | 0 | 0 | n/a | no_data |\n");
        return out;
    }

    for sample in samples {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {:.3}s | {} |",
            sample.profile.name,
            sample.profile.chain_length,
            sample.profile.wiring_per_step,
            sample.profile.assertions,
            sample.elapsed.as_secs_f64(),
            if sample.succeeded { "pass" } else { "fail" }
        );
    }
    out
}

fn chain_benchmark(c: &mut Criterion) {
    let available_cases = get_ground_truth_cases()
        .iter()
        .filter(|case| Path::new(case.chain_yaml).exists())
        .count();
    if available_cases == 0 {
        eprintln!(
            "Skipping chain benchmark: no ground-truth campaign YAMLs were found under tests/ground_truth/chains"
        );
        return;
    }

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

    // Optional quality-gate enforcement for CI/release benchmarks.
    let enforce = env::var("ZKPF_ENFORCE_CHAIN_BENCH_GATES")
        .map(|v| {
            let normalized = v.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false);
    if enforce {
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
    } else if final_result.precision < 0.9 || final_result.recall < 0.8 {
        eprintln!(
            "Chain benchmark quality gates not met (precision={:.2}%, recall={:.2}%) but enforcement is disabled",
            final_result.precision * 100.0,
            final_result.recall * 100.0
        );
    }
}

fn chain_complexity_benchmark(c: &mut Criterion) {
    let Some(runner) = create_fixture_chain_runner(6, 8) else {
        return;
    };

    let mut group = c.benchmark_group("chain_complexity_profiles");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(20);

    let initial_inputs = HashMap::new();
    for profile in CHAIN_COMPLEXITY_PROFILES {
        let spec = build_complexity_spec(profile, 6);
        group.throughput(Throughput::Elements(profile.chain_length as u64));
        group.bench_with_input(
            BenchmarkId::new(profile.name, profile.chain_length),
            &spec,
            |b, spec| {
                b.iter(|| {
                    let mut rng = rand::thread_rng();
                    let result = runner.execute(spec, &initial_inputs, &mut rng);
                    black_box(result)
                });
            },
        );
    }

    group.finish();

    let snapshot = run_chain_complexity_snapshot();
    if std::fs::create_dir_all("reports").is_ok() {
        let markdown = complexity_snapshot_markdown(&snapshot);
        if let Err(e) = std::fs::write("reports/chain_complexity_benchmark.md", markdown) {
            eprintln!("Failed to write chain complexity benchmark snapshot: {e}");
        }
    }
}

criterion_group!(benches, chain_benchmark, chain_complexity_benchmark);
criterion_main!(benches);
