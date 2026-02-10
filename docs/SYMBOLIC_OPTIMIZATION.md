# Symbolic Execution Optimization Guide

**Version:** 1.0  
**Phase:** 4 - Symbolic Execution Deep Dive  
**Status:** ✅ Complete

---

## Overview

This document describes the advanced symbolic execution optimizations implemented in ZkPatternFuzz Phase 4. These optimizations enable KLEE-level symbolic execution depth for ZK circuits.

## Performance Targets

| Metric | Before (v1) | After (v2) | Improvement |
|--------|-------------|------------|-------------|
| Max Paths | 1,000 | 10,000 | 10x |
| Max Depth | 50 | 1,000 | 20x |
| Solver Timeout | 5s | 30s (adaptive to 60s) | 6-12x |
| Cache Hit Rate | 0% | 50-80% | ∞ |
| Path Explosion | Unmitigated | Merging + Pruning | 5-10x |

## Key Optimizations

### 1. Path Explosion Mitigation

#### Path Merging (`MergeStrategy`)

Combines similar symbolic states at program points to reduce explosion:

```rust
use zk_symbolic::symbolic_v2::{PathMerger, MergeStrategy};

let mut merger = PathMerger::new(MergeStrategy::ProgramPoint)
    .with_threshold(4)      // Merge after 4 states accumulate
    .with_similarity(0.7);  // 70% similarity threshold

// Submit states for potential merging
if let Some(merged) = merger.submit(state) {
    // Process merged state
}
```

**Available Strategies:**
- `None` - Traditional execution (no merging)
- `ProgramPoint` - Merge at same constraint index
- `ConstraintSimilarity` - Merge by constraint structure
- `PrefixMerge` - Merge states with common prefix
- `Veritesting` - Merge at convergence points

#### Path Pruning (`PruningStrategy`)

Intelligent pruning to avoid unproductive paths:

```rust
use zk_symbolic::enhanced::{PathPruner, PruningStrategy};

let pruner = PathPruner::new(PruningStrategy::CoverageGuided)
    .with_max_depth(1000)
    .with_max_paths(10000)
    .with_loop_bound(10);

if pruner.should_prune(&state, explored_count) {
    // Skip this path
}
```

**Available Strategies:**
- `None` - Explore all paths
- `DepthBounded` - Prune at max depth
- `ConstraintBounded` - Prune by constraint count
- `CoverageGuided` - Prune low-coverage paths
- `RandomSampling` - Random path selection
- `LoopBounded` - Limit loop iterations
- `SimilarityBased` - Skip similar paths
- `SubsumptionBased` - Skip subsumed paths

### 2. Constraint Caching

Thread-safe caching of solver results:

```rust
use zk_symbolic::symbolic_v2::ConstraintCache;

let cache = ConstraintCache::new()
    .with_max_size(100_000)
    .with_ttl(3600);  // 1 hour TTL

// Check cache before solving
if let Some(cached) = cache.get(&path_condition) {
    return cached;
}

// Solve and cache result
let result = solver.solve(&path_condition);
cache.insert(&path_condition, result.clone());
```

**Features:**
- LRU eviction
- TTL-based expiration
- Unsat caching (fast rejection)
- Subproblem caching

### 3. Incremental Solving

Build on previous solver sessions:

```rust
use zk_symbolic::enhanced::IncrementalSolver;

let solver = IncrementalSolver::new()
    .with_timeout(30_000)  // 30 seconds
    .with_random_seed(Some(42));

// Solve base path
let result = solver.solve(&base_path);

// Incrementally add constraints
let new_result = solver.solve_incremental(&base_path, &new_constraints);
```

### 4. Path Prioritization

Vulnerability-targeted path ordering:

```rust
use zk_symbolic::symbolic_v2::{PathPriority, VulnerabilityTargetPattern};

let patterns = vec![
    VulnerabilityTargetPattern::underconstrained(),
    VulnerabilityTargetPattern::nullifier_reuse(),
    VulnerabilityTargetPattern::arithmetic_overflow(),
];

let priority = PathPriority::compute(&state, &coverage_bitmap, &patterns);
// priority.score determines exploration order
```

### 5. Adaptive Timeout

Scale solver timeout with constraint complexity:

```rust
// Base: 30s
// < 10 constraints: 30s
// < 50 constraints: 60s
// < 100 constraints: 90s
// >= 100 constraints: 120s (max)
```

## V2 Symbolic Executor

The `SymbolicV2Executor` combines all optimizations:

```rust
use zk_symbolic::symbolic_v2::{SymbolicV2Executor, SymbolicV2Config};

let config = SymbolicV2Config {
    max_paths: 10_000,
    max_depth: 1_000,
    solver_timeout_ms: 30_000,
    adaptive_timeout: true,
    merge_strategy: MergeStrategy::ProgramPoint,
    pruning_strategy: PruningStrategy::CoverageGuided,
    enable_caching: true,
    simplify_constraints: true,
    incremental_solving: true,
    ..Default::default()
};

let mut executor = SymbolicV2Executor::with_config(5, config);
executor.set_coverage_bitmap(current_coverage);

let test_cases = executor.explore();
let stats = executor.stats();

println!("Explored {} paths, generated {} test cases", 
    stats.paths_explored, stats.test_cases_generated);
println!("Cache hit rate: {:.1}%", stats.cache_hit_rate * 100.0);
```

## Configuration Defaults

### SymbolicV2Config

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_paths` | 10,000 | Maximum paths to explore |
| `max_depth` | 1,000 | Maximum constraint depth |
| `solver_timeout_ms` | 30,000 | Base solver timeout (30s) |
| `max_adaptive_timeout_ms` | 60,000 | Maximum adaptive timeout |
| `merge_strategy` | ProgramPoint | Path merging strategy |
| `pruning_strategy` | CoverageGuided | Path pruning strategy |
| `enable_caching` | true | Enable constraint caching |
| `simplify_constraints` | true | Enable constraint simplification |
| `incremental_solving` | true | Use incremental solver |
| `solutions_per_path` | 3 | Solutions to generate per path |
| `loop_bound` | 10 | Loop iteration limit |

## Statistics Tracking

The executor provides detailed statistics:

```rust
pub struct SymbolicV2Stats {
    pub paths_explored: u64,
    pub paths_pruned: u64,
    pub states_merged: u64,
    pub states_eliminated: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
    pub solver_time_ms: u64,
    pub avg_solver_time_ms: f64,
    pub test_cases_generated: u64,
    pub max_depth_reached: usize,
    pub execution_time_ms: u64,
}
```

## Best Practices

### For Large Circuits (>100K constraints)

1. Enable aggressive pruning:
   ```rust
   config.pruning_strategy = PruningStrategy::CoverageGuided;
   ```

2. Use path merging:
   ```rust
   config.merge_strategy = MergeStrategy::PrefixMerge;
   ```

3. Enable constraint caching:
   ```rust
   config.enable_caching = true;
   ```

4. Use adaptive timeout:
   ```rust
   config.adaptive_timeout = true;
   config.max_adaptive_timeout_ms = 120_000;  // 2 minutes max
   ```

### For Vulnerability Hunting

1. Add targeted patterns:
   ```rust
   config.vuln_patterns = vec![
       VulnerabilityTargetPattern::underconstrained(),
       VulnerabilityTargetPattern::nullifier_reuse(),
   ];
   ```

2. Consider bug-directed execution (see `TARGETED_SYMBOLIC.md`)

### For Regression Testing

1. Use differential symbolic execution (see `TARGETED_SYMBOLIC.md`)
2. Compare constraint sets between versions

## Integration with Fuzzing Engine

The V2 symbolic executor integrates with the main fuzzing engine:

```rust
// In FuzzingEngine
let symbolic = SymbolicV2Executor::with_config(num_inputs, SymbolicV2Config::default());
let coverage_bitmap = self.coverage_tracker.get_bitmap();
symbolic.set_coverage_bitmap(coverage_bitmap);

let symbolic_tests = symbolic.explore();
for test in symbolic_tests {
    self.corpus.add(TestCase::new(test));
}
```

## Troubleshooting

### High Cache Miss Rate

- Increase cache size: `cache.with_max_size(500_000)`
- Check constraint variation (randomized constraints cache poorly)

### Path Explosion Despite Merging

- Lower merge threshold: `merger.with_threshold(2)`
- Use more aggressive pruning strategy
- Reduce max_paths limit

### Solver Timeouts

- Increase timeout: `config.solver_timeout_ms = 60_000`
- Enable adaptive timeout
- Enable constraint simplification

## See Also

- [TARGETED_SYMBOLIC.md](TARGETED_SYMBOLIC.md) - Bug-directed and differential execution
- [PERFORMANCE_TUNING.md](PERFORMANCE_TUNING.md) - General performance optimization
- [CONCURRENCY_MODEL.md](CONCURRENCY_MODEL.md) - Multi-worker execution model
