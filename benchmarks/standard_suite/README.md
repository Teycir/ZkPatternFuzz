# ZkPatternFuzz Benchmark Suite

Standard benchmark suite for measuring fuzzer performance across different circuit sizes and complexity levels.

## Purpose

- Measure throughput (executions/second)
- Compare performance across circuit sizes
- Identify performance bottlenecks
- Track performance regressions

## Categories

### Small Circuits (1K-10K constraints)
- Range proofs (8-64 bit)
- Simple hash computations
- Basic arithmetic circuits

### Medium Circuits (10K-100K constraints)
- Merkle tree proofs (depth 10-20)
- EdDSA signature verification
- Multi-input commitments

### Large Circuits (100K-1M constraints)
- zkEVM state transition
- Complex DeFi protocols
- Batch verification

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench fuzzer_throughput

# Run with HTML report
cargo bench -- --save-baseline main
```

## Target Metrics

| Circuit Size | Target exec/sec | Current |
|--------------|-----------------|---------|
| Small (1K)   | 10,000+         | TBD     |
| Medium (10K) | 1,000+          | TBD     |
| Large (100K) | 100+            | TBD     |

## Comparison

Benchmark against:
- Circomspect (static analysis)
- Ecne (constraint analysis)
- Manual fuzzing baseline
