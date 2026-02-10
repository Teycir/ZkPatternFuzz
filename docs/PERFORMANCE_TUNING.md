# Performance Tuning Guide

**Version:** 1.0  
**Phase:** 4.4 - Performance Optimizations  
**Status:** ✅ Complete

---

## Overview

This document describes performance optimizations implemented in ZkPatternFuzz Phase 4.4. These optimizations target 2-10x speedup on typical circuits.

## Performance Targets

| Metric | Before | After | Target |
|--------|--------|-------|--------|
| Simple circuits | ~1,000 exec/sec | ~2,000 exec/sec | 2x |
| Complex circuits | ~100 exec/sec | ~200 exec/sec | 2x |
| With isolation | ~50 exec/sec | ~100 exec/sec | 2x |
| Cache hit rate | 0% | 50-80% | New |
| Lock contention | High | Low | Reduced |

## Key Optimizations

### 1. Constraint Evaluation Caching

Thread-safe caching of constraint evaluation results:

```rust
use zk_fuzzer::fuzzer::constraint_cache::{
    ConstraintEvalCache, ConstraintEvalResult, create_shared_cache
};

// Create shared cache (thread-safe)
let cache = create_shared_cache_with_size(100_000);

// Before evaluating constraint
if let Some(result) = cache.get(constraint_id, &inputs) {
    // Use cached result
    return result;
}

// Evaluate and cache
let result = evaluate_constraint(constraint_id, &inputs);
cache.insert(constraint_id, &inputs, result.clone());
```

**Features:**
- LRU eviction when cache is full
- Optional TTL-based expiration
- Batch get/insert operations
- Per-constraint invalidation

**Statistics:**
```rust
let stats = cache.stats();
println!("{}", stats);
// Output: Cache: 50000/100000 entries, 75.3% hit rate (150000 hits, 50000 misses, 1000 evictions)
```

### 2. Async Execution Pipeline

Overlap I/O and CPU operations for higher throughput:

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Selection│───>│ Mutation │───>│ Execution│───>│ Results  │
│  Stage   │    │  Stage   │    │  Stage   │    │  Stage   │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │
     │               │               │               │
     ▼               ▼               ▼               ▼
  Corpus         Mutators        Executors      Coverage
  Selection      (4 workers)    (8 workers)     Updates
```

```rust
use zk_fuzzer::fuzzer::async_pipeline::{
    PipelineConfig, AsyncPipeline, PipelineBuilder
};

let config = PipelineConfig {
    select_buffer: 100,      // Selection -> Mutation buffer
    mutate_buffer: 200,      // Mutation -> Execution buffer
    exec_buffer: 100,        // Execution -> Results buffer
    mutation_workers: 4,     // Parallel mutation workers
    execution_workers: 8,    // Parallel execution workers
    mutation_batch_size: 10,
    execution_batch_size: 10,
    execution_timeout: Duration::from_secs(10),
};

let pipeline = PipelineBuilder::new(
    config,
    selector,
    mutator,
    executor,
    result_handler,
);

// Run async pipeline
let stats = Arc::new(tokio::sync::RwLock::new(PipelineStats::default()));
pipeline.run(stats.clone()).await;
```

**Benefits:**
- Selection doesn't block on execution
- Multiple mutations in flight
- Parallel execution with timeout protection

### 3. Lock-Free Data Structures

Replace RwLock-based corpus with lock-free alternatives:

```rust
use zk_fuzzer::corpus::lockfree::{
    LockFreeTestQueue, AtomicCoverageBitmap, LockFreeCorpus,
    create_shared_corpus
};

// Lock-free test case queue
let queue = LockFreeTestQueue::new();
queue.push(test_case);
let tc = queue.pop();  // Non-blocking

// Atomic coverage bitmap
let coverage = AtomicCoverageBitmap::new(10_000);
let is_new = coverage.set(constraint_id);  // Returns true if newly covered
println!("Coverage: {:.1}%", coverage.coverage_percentage());

// Complete lock-free corpus
let corpus = create_shared_corpus(10_000);
let is_interesting = corpus.add(test_case, coverage_hash);
let next_case = corpus.select();  // Priority-based selection
```

**Features:**
- Lock-free queue for test cases
- Atomic coverage bitmap
- Priority-based corpus (high/mid/low queues)
- Batch operations

**Benefits:**
- No lock contention in hot paths
- Predictable latency
- Better multi-core scaling

### 4. Batch Execution

Amortize overhead with batch processing:

```rust
use zk_fuzzer::fuzzer::async_pipeline::BatchExecutor;

let batch_executor = BatchExecutor::new(
    batch_size: 100,
    timeout: Duration::from_secs(30),
);

// Execute batch in parallel
let results = batch_executor.execute_batch(inputs, |input| {
    executor.execute(input)
});

// With progress callback
let results = batch_executor.execute_with_progress(
    inputs,
    |input| executor.execute(input),
    |completed, total| {
        println!("Progress: {}/{}", completed, total);
    },
);
```

## Configuration Guide

### For High Throughput

```rust
// Constraint cache: maximize size
let cache = ConstraintEvalCache::new()
    .with_max_size(500_000)
    .with_ttl(0);  // No expiry

// Pipeline: maximize parallelism
let pipeline_config = PipelineConfig {
    mutation_workers: num_cpus::get(),
    execution_workers: num_cpus::get() * 2,
    ..Default::default()
};

// Corpus: lock-free with large coverage bitmap
let corpus = create_shared_corpus(100_000);
```

### For Memory Constrained Environments

```rust
// Constraint cache: smaller size with TTL
let cache = ConstraintEvalCache::new()
    .with_max_size(10_000)
    .with_ttl(300);  // 5 minute expiry

// Pipeline: reduce buffers
let pipeline_config = PipelineConfig {
    select_buffer: 50,
    mutate_buffer: 100,
    exec_buffer: 50,
    ..Default::default()
};
```

### For Low Latency

```rust
// Constraint cache: small but fast
let cache = ConstraintEvalCache::new()
    .with_max_size(50_000);

// Pipeline: reduce batch sizes
let pipeline_config = PipelineConfig {
    mutation_batch_size: 5,
    execution_batch_size: 5,
    execution_timeout: Duration::from_secs(5),
    ..Default::default()
};
```

## Profiling

### Enable Tracing

```bash
RUST_LOG=zk_fuzzer=debug cargo run -- run campaign.yaml
```

### CPU Profiling

```bash
# Using perf
perf record -g cargo run --release -- run campaign.yaml
perf report

# Using flamegraph
cargo flamegraph -- run campaign.yaml
```

### Memory Profiling

```bash
# Using heaptrack
heaptrack cargo run --release -- run campaign.yaml
heaptrack_gui heaptrack.zk-fuzzer.*.gz
```

## Benchmarks

### Constraint Cache Impact

```
Benchmark: constraint_cache_hit
  Without cache: 100,000 evals in 5.2s (19,230 eval/sec)
  With cache:    100,000 evals in 1.8s (55,555 eval/sec)
  Speedup: 2.9x

Benchmark: constraint_cache_large
  Circuit: 100K constraints
  Cache size: 100K entries
  Hit rate: 78%
  Speedup: 2.4x
```

### Lock-Free Corpus Impact

```
Benchmark: corpus_contention_4_workers
  RwLock corpus: 50,000 ops in 2.3s (21,739 ops/sec)
  Lock-free:     50,000 ops in 0.8s (62,500 ops/sec)
  Speedup: 2.9x

Benchmark: corpus_contention_8_workers
  RwLock corpus: 50,000 ops in 4.1s (12,195 ops/sec)
  Lock-free:     50,000 ops in 1.1s (45,454 ops/sec)
  Speedup: 3.7x
```

### Pipeline Impact

```
Benchmark: pipeline_vs_sequential
  Sequential: 10,000 execs in 45s (222 exec/sec)
  Pipeline:   10,000 execs in 12s (833 exec/sec)
  Speedup: 3.75x
```

## Troubleshooting

### Low Cache Hit Rate

**Symptoms:** Cache stats show <30% hit rate

**Causes:**
1. Input space too large
2. Constraints have high entropy
3. Cache too small

**Solutions:**
1. Increase cache size
2. Use constraint grouping
3. Consider structure-aware caching

### Pipeline Backpressure

**Symptoms:** One stage consistently full, others idle

**Causes:**
1. Execution stage too slow
2. Imbalanced worker counts
3. Buffer sizes too small

**Solutions:**
1. Increase execution workers
2. Increase slow stage's buffer
3. Use batch processing

### Memory Growth

**Symptoms:** Memory usage grows unbounded

**Causes:**
1. Cache not evicting
2. Corpus accumulating
3. Coverage bitmap too large

**Solutions:**
1. Set cache TTL
2. Enable corpus minimization
3. Reduce coverage bitmap size

## Integration Example

Complete example combining all optimizations:

```rust
use std::sync::Arc;
use std::time::Duration;

// 1. Create shared constraint cache
let cache = Arc::new(ConstraintEvalCache::new()
    .with_max_size(100_000));

// 2. Create lock-free corpus
let corpus = create_shared_corpus(10_000);

// 3. Configure pipeline
let pipeline_config = PipelineConfig {
    mutation_workers: 4,
    execution_workers: 8,
    ..Default::default()
};

// 4. Create fuzzing engine with optimizations
let mut engine = FuzzingEngine::new(config, seed, workers)?;
engine.set_constraint_cache(cache);
engine.set_corpus(corpus);
engine.set_pipeline_config(pipeline_config);

// 5. Run with all optimizations
let report = engine.run(Some(&progress)).await?;
```

## See Also

- [SYMBOLIC_OPTIMIZATION.md](SYMBOLIC_OPTIMIZATION.md) - Symbolic execution optimizations
- [CONCURRENCY_MODEL.md](CONCURRENCY_MODEL.md) - Multi-worker architecture
- [TARGETED_SYMBOLIC.md](TARGETED_SYMBOLIC.md) - Bug-directed execution
