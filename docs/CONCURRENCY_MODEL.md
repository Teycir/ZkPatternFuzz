# ZkPatternFuzz Concurrency Model

**Version:** 1.0  
**Date:** February 2026  
**Status:** Phase 0 Documentation

---

## Overview

ZkPatternFuzz uses a multi-worker architecture for parallel fuzzing. This document specifies the concurrency model to prevent race conditions and ensure correct operation.

## Architecture

```
                    ┌─────────────────────┐
                    │   FuzzingEngine     │
                    │  (Main Coordinator) │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
        ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
        │  Worker 1 │    │  Worker 2 │    │  Worker N │
        │   (RNG)   │    │   (RNG)   │    │   (RNG)   │
        └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
              │                │                │
              └────────────────┼────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
        ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
        │  Shared   │    │  Shared   │    │  Shared   │
        │  Corpus   │    │ Coverage  │    │ Findings  │
        └───────────┘    └───────────┘    └───────────┘
```

## Shared State Components

### 1. Coverage Tracker

**Location:** `crates/zk-fuzzer-core/src/coverage.rs`

**Concurrency Strategy:** Lock-free read, RwLock for writes

```rust
pub struct CoverageTracker {
    /// Constraint hit counts - RwLock for concurrent access
    constraint_hits: Arc<RwLock<HashMap<usize, u64>>>,
    
    /// Atomic counters for fast reads
    total_constraints: usize,
    new_coverage_count: AtomicU64,
}
```

**Access Pattern:**
- **Reads:** Frequent, lock-free via atomic counters where possible
- **Writes:** Per-execution, use RwLock with short critical sections
- **Contention Mitigation:** 
  - Batch constraint updates when possible
  - Use atomic increment for `new_coverage_count`

### 2. Corpus

**Location:** `src/corpus/mod.rs`

**Concurrency Strategy:** Per-worker queues with periodic merging

```
┌─────────────────────────────────────────────────┐
│                 Global Corpus                    │
│  (Arc<RwLock<Vec<TestCase>>>)                   │
└─────────────────────┬───────────────────────────┘
                      │ Periodic Merge
    ┌─────────────────┼─────────────────┐
    │                 │                 │
┌───▼───┐         ┌───▼───┐         ┌───▼───┐
│Worker1│         │Worker2│         │WorkerN│
│ Queue │         │ Queue │         │ Queue │
│(local)│         │(local)│         │(local)│
└───────┘         └───────┘         └───────┘
```

**Merge Policy:**
- Workers add interesting test cases to local queue
- Merge to global corpus every 100 executions or when local queue > 50
- Deduplication happens during merge (by coverage hash)

### 3. Findings

**Location:** `src/fuzzer/engine.rs`

**Concurrency Strategy:** Arc<RwLock> with immediate write

```rust
findings: Arc<RwLock<Vec<Finding>>>,
```

**Access Pattern:**
- **Writes:** Immediate on finding discovery (rare, < 0.1% of executions)
- **Reads:** At report generation only
- **Deduplication:** By witness hash at insertion time

### 4. Oracle State

**Location:** `crates/zk-fuzzer-core/src/oracle.rs`

**Concurrency Strategy:** Per-worker oracle instances OR DashMap for shared state

**For Stateful Oracles (e.g., UnderconstrainedOracle):**

```rust
pub struct UnderconstrainedOracle {
    /// Option 1: Per-worker instances (no sharing)
    /// Each worker has its own oracle, findings merged at end
    
    /// Option 2: Shared state with DashMap (lock-free concurrent HashMap)
    pub output_history: Arc<DashMap<Vec<u8>, TestCase>>,
}
```

**Recommendation:** Per-worker instances for most oracles. Only use shared state when cross-worker collision detection is required.

## Worker Model

### Worker Initialization

```rust
// Each worker gets:
// 1. Unique RNG seed for deterministic reproduction
// 2. Clone of executor (stateless, safe to share)
// 3. Reference to shared coverage/corpus/findings
// 4. Own oracle instances (stateful oracles)

let worker_seed = base_seed + worker_id;
let worker_rng = ChaCha8Rng::seed_from_u64(worker_seed);
```

### Execution Loop

```
for each iteration:
    1. Select test case from corpus (read lock)
    2. Mutate test case (worker-local RNG)
    3. Execute circuit (worker-local executor)
    4. Update coverage (write lock, short critical section)
    5. Check oracles (worker-local state)
    6. If new coverage: add to local queue
    7. If finding: write to shared findings
    8. Every N iterations: merge local queue to corpus
```

## Thread Pool

**Implementation:** Rayon thread pool (cached per engine)

```rust
thread_pool: Option<Arc<rayon::ThreadPool>>,
```

**Benefits:**
- Avoids thread creation overhead per attack
- Consistent worker count across attacks
- Better cache locality

## Synchronization Primitives

| Component | Primitive | Reason |
|-----------|-----------|--------|
| Coverage | `RwLock<HashMap>` | Many reads, few writes |
| Corpus | `RwLock<Vec>` | Periodic batch updates |
| Findings | `RwLock<Vec>` | Rare writes, bulk read at end |
| Counters | `AtomicU64` | Lock-free fast incrementing |
| Oracle State | `DashMap` or per-worker | Depends on oracle needs |

## Race Condition Mitigations

### 1. Corpus Selection Race

**Problem:** Multiple workers select same test case simultaneously
**Solution:** Acceptable behavior - different mutations produce different results

### 2. Coverage Update Race

**Problem:** Two workers discover same new coverage simultaneously
**Solution:** Both add to corpus, deduplicate during merge

### 3. Finding Deduplication Race

**Problem:** Same finding reported by multiple workers
**Solution:** Deduplicate by witness hash in `push_finding()`

### 4. Oracle State Corruption

**Problem:** Stateful oracles shared across workers
**Solution:** Per-worker oracle instances (default) or DashMap for required sharing

## Process Isolation

**Location:** `src/executor/isolated.rs`

For real backends (Circom, Noir, Halo2, Cairo), each execution runs in a subprocess:

```rust
pub struct IsolatedExecutor {
    inner: Arc<dyn CircuitExecutor>,
    timeout_ms: u64,
    worker_exe: PathBuf,
}
```

**Benefits:**
- Backend crash doesn't kill fuzzer
- Hard timeout enforcement
- Memory isolation

**Trade-off:** 2-10x slower than in-process execution

**Usage:**
```rust
// Automatically enabled for real backends in evidence mode
if config.evidence_mode {
    executor = IsolatedExecutor::new(executor, ...);
}
```

## Performance Characteristics

| Workers | Throughput Scaling | Contention |
|---------|-------------------|------------|
| 1 | 1x (baseline) | None |
| 2-4 | 1.8-3.5x | Low |
| 5-8 | 4-7x | Medium |
| 9+ | 7-10x | High (diminishing returns) |

**Bottlenecks:**
- Coverage write lock (mitigated by short critical sections)
- Corpus merge (mitigated by batching)
- I/O for subprocess isolation

## Debugging Concurrency Issues

### Enable Debug Logging

```bash
RUST_LOG=zk_fuzzer=debug cargo run ...
```

### Check for Deadlocks

The codebase uses consistent lock ordering:
1. Findings lock
2. Coverage lock  
3. Corpus lock

Never hold multiple locks simultaneously except in documented order.

### Reproduce Deterministically

```bash
# Same seed + same worker count = deterministic execution
cargo run --release -- evidence campaign.yaml --seed 42 --workers 4
```

## Future Improvements

- [ ] Lock-free coverage bitmap (like AFL++)
- [ ] NUMA-aware memory allocation
- [ ] Distributed fuzzing across machines
- [ ] GPU-accelerated constraint checking

---

*This document is part of Phase 0: Correctness Fixes*
