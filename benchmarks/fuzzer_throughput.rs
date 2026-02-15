//! Fuzzer Throughput Benchmarks
//!
//! Measures execution speed across different circuit sizes and configurations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

use zk_core::{CircuitExecutor, FieldElement};
use zk_fuzzer::config::FuzzConfig;
use zk_fuzzer::executor::FixtureCircuitExecutor;
use zk_fuzzer::fuzzer::FuzzingEngine;

/// Create a fixture config for benchmarking
fn create_benchmark_config(name: &str, num_inputs: usize, num_constraints: u64) -> FuzzConfig {
    let yaml = format!(
        r#"
campaign:
  name: "Benchmark: {}"
  version: "1.0"
  target:
    framework: circom
    circuit_path: "./bench_circuit.circom"
    main_component: "main"
  parameters:
    field: bn254
    max_constraints: {}
    timeout_seconds: 60
    additional:
      max_iterations: 1000
      strict_backend: false

attacks:
  - type: underconstrained
    description: "Benchmark attack"
    config:
      witness_pairs: 100

inputs:
{}

reporting:
  output_dir: "./reports/bench"
  formats: ["json"]
"#,
        name,
        num_constraints,
        (0..num_inputs)
            .map(|i| format!(
                "  - name: \"input{}\"\n    type: \"field\"\n    fuzz_strategy: random",
                i
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );

    serde_yaml::from_str(&yaml).expect("Failed to parse benchmark config")
}

/// Benchmark test case generation
fn bench_test_case_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("test_case_generation");
    group.measurement_time(Duration::from_secs(10));

    for num_inputs in [4, 16, 64, 256] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("inputs", num_inputs),
            &num_inputs,
            |b, &num_inputs| {
                let mut rng = rand::thread_rng();
                b.iter(|| {
                    let inputs: Vec<FieldElement> = (0..num_inputs)
                        .map(|_| FieldElement::random(&mut rng))
                        .collect();
                    black_box(inputs)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark fixture circuit execution
fn bench_fixture_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixture_execution");
    group.measurement_time(Duration::from_secs(10));

    for (name, num_inputs, num_outputs) in [("small", 4, 2), ("medium", 32, 8), ("large", 128, 32)]
    {
        let executor =
            FixtureCircuitExecutor::new("bench", num_inputs, 0).with_outputs(num_outputs);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("circuit", name), &executor, |b, exec| {
            let mut rng = rand::thread_rng();
            let inputs: Vec<FieldElement> = (0..num_inputs)
                .map(|_| FieldElement::random(&mut rng))
                .collect();

            b.iter(|| {
                let result = exec.execute_sync(&inputs);
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark engine initialization
fn bench_engine_init(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_initialization");
    group.measurement_time(Duration::from_secs(5));

    for num_inputs in [4, 16, 64] {
        let config = create_benchmark_config("init_bench", num_inputs, 10000);

        group.bench_with_input(
            BenchmarkId::new("inputs", num_inputs),
            &config,
            |b, config| {
                b.iter(|| {
                    let engine = FuzzingEngine::new(config.clone(), Some(42), 1);
                    black_box(engine)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark full fuzzing iteration
fn bench_fuzzing_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("fuzzing_iteration");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(50);

    // Small circuit benchmark
    let small_config = create_benchmark_config("small_circuit", 4, 1000);

    group.throughput(Throughput::Elements(100)); // 100 iterations per sample
    group.bench_function("small_100_iterations", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let mut config = small_config.clone();
                config.campaign.parameters.additional.insert(
                    "max_iterations".to_string(),
                    serde_yaml::Value::Number(100.into()),
                );

                let mut engine = FuzzingEngine::new(config, Some(42), 1).unwrap();
                let report = engine.run(None).await.unwrap();
                black_box(report)
            })
        });
    });

    group.finish();
}

/// Benchmark coverage tracking overhead
fn bench_coverage_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("coverage_tracking");
    group.measurement_time(Duration::from_secs(10));

    use zk_core::CoverageMap;

    // Simulate different coverage map sizes
    for map_size in [100, 1000, 10000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("map_size", map_size),
            &map_size,
            |b, &size| {
                let mut coverage = CoverageMap::default();
                let mut rng = rand::thread_rng();

                // Pre-populate
                for i in 0..size {
                    coverage.record_hit(i);
                }

                b.iter(|| {
                    let idx = rand::Rng::gen_range(&mut rng, 0..size * 2);
                    coverage.record_hit(idx);
                    black_box(coverage.coverage_percentage())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_test_case_generation,
    bench_fixture_execution,
    bench_engine_init,
    bench_fuzzing_iteration,
    bench_coverage_tracking,
);

criterion_main!(benches);
