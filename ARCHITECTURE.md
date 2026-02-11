# ZkPatternFuzz Architecture

## Overview

ZkPatternFuzz is a modular security testing framework for zero-knowledge circuits. This document describes the internal architecture, design decisions, and extension points.

## Core Components

### 1. Fuzzing Engine (`src/fuzzer/engine.rs`)

The central orchestrator that coordinates all fuzzing activities.

**Key Responsibilities:**
- Test case generation and mutation
- Coverage-guided exploration
- Worker coordination
- Statistics collection

**Design Pattern:** Producer-Consumer with shared state

```rust
FuzzingEngine
├── Corpus (shared, lock-free)
├── Coverage Tracker (shared, atomic)
├── Power Scheduler (energy-based selection)
├── Structure Mutator (ZK-aware mutations)
└── Bug Oracles (vulnerability detection)
```

### 2. Executor Abstraction (`src/executor/`)

Provides a unified interface for different ZK backends.

**Trait Hierarchy:**
```rust
CircuitExecutor (trait)
├── execute(&self, inputs) -> outputs
├── prove(&self, witness) -> proof
└── verify(&self, proof, public) -> bool

Implementations:
├── MockCircuitExecutor (testing)
├── CircomTarget (via targets module)
├── NoirTarget (via targets module)
├── Halo2Target (via targets module)
└── CairoTarget (via targets module)
```

**Factory Pattern:**
```rust
ExecutorFactory::create(framework, path, component)
  -> Arc<dyn CircuitExecutor>
```

### 3. Attack Modules (`src/attacks/`)

Specialized vulnerability detectors implementing the `Attack` trait.

**Attack Types:**

| Attack | Detection Method | Complexity |
|--------|------------------|------------|
| Underconstrained | Witness pair comparison | O(n²) |
| Soundness | Proof forgery attempts | O(n) |
| Arithmetic | Boundary value testing | O(1) |
| Witness | Consistency checking | O(n) |
| Verification | Malformed proof testing | O(n) |

**Extension Point:**
```rust
pub trait Attack {
    fn run(&self, context: &AttackContext) -> Vec<Finding>;
}
```

### 4. Corpus Management (`src/corpus/`)

Efficient storage and retrieval of interesting test cases.

**Data Structures:**
- `CorpusEntry`: Individual test case with metadata
- `SharedCorpus`: Thread-safe corpus with bounded size
- `Minimizer`: Reduces corpus while preserving coverage

**Eviction Strategy:**
1. Calculate coverage contribution per test case
2. Remove cases with lowest unique coverage
3. Preserve cases that found bugs

### 5. Coverage Tracking (`src/executor/coverage.rs`)

Monitors which constraints have been exercised.

**Implementation:**
- Bitmap-based tracking (1 bit per constraint)
- Atomic operations for thread safety
- Efficient diff computation for new coverage

**Metrics:**
- Total constraints
- Covered constraints
- Coverage percentage
- Unique paths explored

### 6. Power Scheduling (`src/fuzzer/power_schedule.rs`)

Assigns energy to test cases for prioritized selection.

**Algorithms:**

| Schedule | Strategy | Best For |
|----------|----------|----------|
| FAST | Favor fast executions | Large circuits |
| COE | Cut-off exponential | Balanced |
| EXPLORE | Maximize new paths | Deep exploration |
| MMOPT | Min-max optimal | General purpose |
| RARE | Focus on rare cases | Edge cases |
| SEEK | Active coverage seeking | Targeted fuzzing |

**Energy Formula:**
```
energy = base_energy * schedule_factor(exec_time, coverage, rarity)
```

### 7. Structure-Aware Mutation (`src/fuzzer/structure_aware.rs`)

Understands ZK-specific data structures for intelligent mutations.

**Recognized Structures:**
- Merkle paths (maintain tree structure)
- Signatures (preserve format)
- Nullifiers (maintain uniqueness properties)
- Public keys (coordinate pairs)
- Hash preimages

**Mutation Strategies:**
- Bit flips (random corruption)
- Arithmetic (add/sub/mul)
- Splicing (combine test cases)
- Structure-preserving (maintain validity)

### 8. Symbolic Execution (`src/analysis/symbolic.rs`)

Uses Z3 SMT solver for constraint-guided test generation.

**Workflow:**
1. Extract constraints from circuit
2. Build symbolic expressions
3. Query solver for satisfying assignments
4. Generate concrete test cases

**Configuration:**
```rust
SymbolicConfig {
    max_paths: 100,           // Path explosion limit
    max_depth: 20,            // Recursion depth
    solver_timeout_ms: 2000,  // Per-query timeout
    generate_boundary_tests: true,
    solutions_per_path: 2,
}
```

### 9. Taint Analysis (`src/analysis/taint.rs`)

Tracks information flow from inputs to outputs.

**Taint Sources:**
- Private inputs (should not leak)
- Secret witnesses

**Taint Sinks:**
- Public outputs
- Proof components

**Detection:**
- Direct flow: private → public
- Indirect flow: private → intermediate → public

### 10. Backend Targets (`src/targets/`)

Framework-specific integrations.

#### Circom (`circom.rs`)
- Compiles `.circom` → R1CS + WASM
- Uses snarkjs for proving/verification
- Parses constraint count from R1CS

#### Noir (`noir.rs`)
- Compiles via `nargo`
- Executes via Barretenberg backend
- Supports ACIR format

#### Halo2 (`halo2.rs`)
- Rust-based circuits
- Compiles via `cargo build`
- Mock mode for testing

#### Cairo (`cairo.rs`)
- Supports Cairo 0 and Cairo 1
- Uses stone-prover for STARK proofs
- Tracks execution steps

### 11. Process Isolation & Command Timeouts

Hardened execution and evidence tooling to avoid hangs and crashes.

**Components:**
- `IsolatedExecutor` (`src/executor/isolated.rs`): runs backends in a subprocess with hard per-exec timeouts.
- `command_timeout` (`src/reporting/command_timeout.rs`): wrapper used by proof generation to time out external tools.

**Behavior:**
- Evidence mode prefers per-exec isolation for hang safety.
- Proof generation for Circom/Noir/Cairo uses timeouts to avoid indefinite stalls.

### 12. Distributed Fuzzing (`src/distributed/`)

Optional local-only coordinator/worker mode.

**Defaults:**
- Binds to `127.0.0.1` by default (local only).
- Enforces a maximum message size to avoid memory exhaustion.

**Note:** Remote/distributed use is not enabled by default.

## Data Flow

### Fuzzing Loop

```
┌─────────────────────────────────────────────────────────┐
│                    Start Campaign                       │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Analyze Circuit Complexity                 │
│  • Count constraints                                    │
│  • Calculate degrees of freedom                         │
│  • Identify optimization opportunities                  │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                 Seed Initial Corpus                     │
│  • Interesting values (0, 1, p-1)                       │
│  • Random samples                                       │
│  • Symbolic execution seeds                             │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Run Configured Attacks                     │
│  • Underconstrained detection                           │
│  • Soundness testing                                    │
│  • Arithmetic overflow checks                           │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │   Coverage-Guided      │
        │   Fuzzing Loop         │
        └────────┬───────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
    ▼                         ▼
┌────────┐              ┌──────────┐
│ Select │              │ Parallel │
│  Test  │──────────────│ Workers  │
│  Case  │              └──────────┘
└───┬────┘                    │
    │                         │
    │  ┌──────────────────────┘
    │  │
    ▼  ▼
┌─────────────┐
│   Mutate    │
│  Test Case  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Execute   │
│   Circuit   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Check     │
│   Oracles   │
└──────┬──────┘
       │
       ▼
┌─────────────┐      Yes    ┌──────────┐
│ New         │─────────────▶│   Add    │
│ Coverage?   │              │ to Corpus│
└──────┬──────┘              └──────────┘
       │ No
       │
       ▼
┌─────────────┐      Yes    ┌──────────┐
│ Bug         │─────────────▶│  Record  │
│ Found?      │              │ Finding  │
└──────┬──────┘              └──────────┘
       │ No
       │
       ▼
┌─────────────┐      No     ┌──────────┐
│ Timeout or  │─────────────│ Continue │
│ Max Iters?  │             │  Loop    │
└──────┬──────┘             └──────────┘
       │ Yes
       ▼
┌─────────────────────────────────────────┐
│          Generate Report                │
│  • Findings with severity               │
│  • Coverage statistics                  │
│  • Proof-of-concept test cases          │
│  • Recommendations                      │
└─────────────────────────────────────────┘
```

## Concurrency Model

### Thread Safety

**Shared State:**
- `SharedCorpus`: `Arc<RwLock<Vec<CorpusEntry>>>`
- `SharedCoverageTracker`: `Arc<RwLock<CoverageTracker>>`
- `Findings`: `Arc<RwLock<Vec<Finding>>>`

**Lock-Free Operations:**
- Execution counter: `AtomicU64`
- Statistics: Atomic updates where possible

**Worker Model:**
```rust
// Main thread
let engine = FuzzingEngine::new(config, seed, workers);

// Spawn workers
(0..workers).into_par_iter().for_each(|worker_id| {
    let mut local_rng = StdRng::seed_from_u64(seed + worker_id);
    
    loop {
        // 1. Select test case (read lock on corpus)
        let test_case = corpus.select(&mut local_rng);
        
        // 2. Mutate (no locks)
        let mutated = mutate(test_case, &mut local_rng);
        
        // 3. Execute (no locks)
        let result = executor.execute(&mutated);
        
        // 4. Update coverage (write lock)
        if coverage.update(&result) {
            corpus.add(mutated);
        }
        
        // 5. Check oracles (no locks)
        if let Some(bug) = check_oracles(&result) {
            findings.write().push(bug);
        }
    }
});
```

## Extension Points

### Adding a New Backend

1. Implement `TargetCircuit` trait in `src/targets/`:

```rust
pub struct MyBackendTarget {
    // Backend-specific state
}

impl TargetCircuit for MyBackendTarget {
    fn framework(&self) -> Framework { Framework::MyBackend }
    fn execute(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>> {
        // Call backend CLI or library
    }
    fn prove(&self, witness: &[FieldElement]) -> Result<Vec<u8>> {
        // Generate proof
    }
    fn verify(&self, proof: &[u8], public: &[FieldElement]) -> Result<bool> {
        // Verify proof
    }
}
```

2. Add to `ExecutorFactory`:

```rust
Framework::MyBackend => {
    let target = MyBackendTarget::new(path)?;
    Ok(Arc::new(target))
}
```

3. Update `Framework` enum in `src/config/mod.rs`

### Adding a New Attack

1. Create module in `src/attacks/`:

```rust
pub struct MyAttack {
    config: MyAttackConfig,
}

impl Attack for MyAttack {
    fn run(&self, context: &AttackContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Implement attack logic
        for _ in 0..self.config.iterations {
            if let Some(bug) = self.check_vulnerability(context) {
                findings.push(bug);
            }
        }
        
        findings
    }
}
```

2. Register in attack dispatcher

3. Add configuration schema to YAML

### Adding a New Mutation Strategy

1. Implement in `src/fuzzer/mutators.rs`:

```rust
pub fn my_mutation(input: &[FieldElement], rng: &mut impl Rng) -> Vec<FieldElement> {
    // Custom mutation logic
}
```

2. Add to mutation selection in `FuzzingEngine`

## Performance Considerations

### Bottlenecks

1. **Circuit Execution**: Dominates runtime (90%+)
   - Mitigation: Parallel workers, fast mock mode

2. **Corpus Lock Contention**: High with many workers
   - Mitigation: Read-heavy workload, batch updates

3. **Coverage Bitmap Updates**: Atomic operations
   - Mitigation: Per-worker bitmaps, periodic merge

### Optimization Strategies

**For Light Circuits (<1000 constraints):**
- Use 8+ workers
- Aggressive mutation rate
- Shorter timeouts

**For Heavy Circuits (>100k constraints):**
- Use 2-4 workers
- Conservative mutations
- Longer timeouts
- Enable symbolic execution

## Testing Strategy

### Unit Tests
- Individual components in isolation
- Mock dependencies
- Fast execution (<1s per test)

### Integration Tests
- End-to-end fuzzing campaigns
- Real backend integration (marked `#[ignore]`)
- Deterministic with fixed seeds

### Realistic Tests
- Known vulnerable circuits
- Regression tests for found bugs
- Performance benchmarks

## Future Enhancements

1. **Distributed Fuzzing**: Corpus sharing across machines
2. **Machine Learning**: Learn mutation strategies from successful cases
3. **Formal Verification Integration**: Combine fuzzing with proofs
4. **Custom DSL**: Domain-specific language for attack patterns
5. **Real-time Dashboard**: Web UI for campaign monitoring
