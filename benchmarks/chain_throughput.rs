//! Chain Fuzzing Throughput Benchmarks
//!
//! Measures execution speed for Mode 3 multi-step chain fuzzing.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use zk_fuzzer::chain_fuzzer::{ChainRunner, ChainSpec, StepSpec};
use zk_fuzzer::executor::MockCircuitExecutor;
use zk_core::{CircuitExecutor, FieldElement};

/// Create chain runner with mock executors
fn create_chain_runner(num_circuits: usize, inputs_per_circuit: usize) -> ChainRunner {
    let mut executors: HashMap<String, Arc<dyn CircuitExecutor>> = HashMap::new();
    
    for i in 0..num_circuits {
        let name = format!("circuit_{}", i);
        let executor = MockCircuitExecutor::new(&name, inputs_per_circuit, 0)
            .with_outputs(inputs_per_circuit);
        executors.insert(name, Arc::new(executor));
    }
    
    ChainRunner::new(executors)
}

/// Create a chain spec with given length
fn create_chain_spec(length: usize) -> ChainSpec {
    let mut steps = vec![StepSpec::fresh("circuit_0")];
    
    for i in 1..length {
        let circuit = format!("circuit_{}", i % 5); // Cycle through 5 circuits
        let step = StepSpec::from_prior(&circuit, i - 1, vec![(0, 0), (1, 1)]);
        steps.push(step);
    }
    
    ChainSpec::new("benchmark_chain", steps)
}

/// Benchmark chain execution for different chain lengths
fn bench_chain_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_execution");
    group.measurement_time(Duration::from_secs(10));

    let runner = create_chain_runner(5, 4);
    
    for chain_length in [2, 5, 10, 20] {
        let spec = create_chain_spec(chain_length);
        
        group.throughput(Throughput::Elements(chain_length as u64));
        group.bench_with_input(
            BenchmarkId::new("chain_length", chain_length),
            &spec,
            |b, spec| {
                let mut rng = rand::thread_rng();
                let initial_inputs = HashMap::new();
                
                b.iter(|| {
                    let result = runner.execute(spec, &initial_inputs, &mut rng);
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark input wiring overhead
fn bench_input_wiring(c: &mut Criterion) {
    let mut group = c.benchmark_group("input_wiring");
    group.measurement_time(Duration::from_secs(10));

    // Test different wiring complexities
    for num_mappings in [1, 4, 16, 64] {
        let runner = create_chain_runner(2, num_mappings * 2);
        
        let mapping: Vec<(usize, usize)> = (0..num_mappings).map(|i| (i, i)).collect();
        let step = StepSpec::from_prior("circuit_1", 0, mapping);
        let spec = ChainSpec::new("wiring_bench", vec![
            StepSpec::fresh("circuit_0"),
            step,
        ]);
        
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("mappings", num_mappings),
            &spec,
            |b, spec| {
                let mut rng = rand::thread_rng();
                let initial_inputs = HashMap::new();
                
                b.iter(|| {
                    let result = runner.execute(spec, &initial_inputs, &mut rng);
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark assertion checking overhead
fn bench_assertion_checking(c: &mut Criterion) {
    use zk_fuzzer::chain_fuzzer::CrossStepAssertion;
    
    let mut group = c.benchmark_group("assertion_checking");
    group.measurement_time(Duration::from_secs(10));

    for num_assertions in [1, 5, 10, 20] {
        let mut spec = ChainSpec::new("assertion_bench", vec![
            StepSpec::fresh("circuit_0"),
            StepSpec::fresh("circuit_1"),
        ]);
        
        for i in 0..num_assertions {
            let assertion = CrossStepAssertion::new(
                &format!("assertion_{}", i),
                &format!("step[0].out[{}] == step[1].in[{}]", i % 4, i % 4),
            );
            spec = spec.with_assertion(assertion);
        }
        
        let runner = create_chain_runner(2, 4);
        
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("assertions", num_assertions),
            &spec,
            |b, spec| {
                let mut rng = rand::thread_rng();
                let initial_inputs = HashMap::new();
                
                b.iter(|| {
                    let result = runner.execute(spec, &initial_inputs, &mut rng);
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark batch chain execution
fn bench_batch_chains(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_chains");
    group.measurement_time(Duration::from_secs(15));

    let runner = create_chain_runner(5, 4);
    
    for batch_size in [10, 50, 100] {
        let specs: Vec<ChainSpec> = (0..batch_size)
            .map(|i| {
                let len = 2 + (i % 5);
                create_chain_spec(len)
            })
            .collect();
        
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("batch_size", batch_size),
            &specs,
            |b, specs| {
                let initial_inputs = HashMap::new();
                
                b.iter(|| {
                    let results = runner.execute_batch(specs, &initial_inputs, 42);
                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_chain_execution,
    bench_input_wiring,
    bench_assertion_checking,
    bench_batch_chains,
);

criterion_main!(benches);
