# Plan: Mode 3 — Multi-Step Deepest Fuzzer Module

**Date:** 2026-02-09
**Status:** IMPLEMENTED — all critical gaps fixed
**Goal:** Add a self-contained, modular `chain_fuzzer` module that implements real multi-step event-chain fuzzing (Mode 3) on top of the existing engine.

## Implementation Status

| Step | Description | Status | Notes |
|------|-------------|--------|-------|
| 1 | Performance wins (rayon pool, HashMap capacity, etc.) | ✅ Done | 1a ✅ pool reuse, 1b ✅ HashMap capacity, 1c ✅ clone eliminated via indexed results, 1d N/A — inspector returns `&dyn`, caching unnecessary (already cheap) |
| 2 | Core types (`types.rs`) | ✅ Done | 645 lines, all types defined |
| 3 | Chain runner (`runner.rs`) | ✅ Done | Multi-circuit support via `circuits` config map + `CircuitPathConfig` |
| 4 | Cross-step invariant checker (`invariants.rs`) | ✅ Done | 526 lines, all assertion patterns implemented |
| 5 | Chain mutator (`mutator.rs`) | ✅ Done | 464 lines, all 5 mutation strategies |
| 6 | Chain shrinker (`shrinker.rs`) | ✅ Done | 327 lines, prefix/dropout/input minimization |
| 7 | Depth metrics (`metrics.rs`) | ✅ Done | 307 lines, D, P_deep, distribution |
| 8 | YAML schema extension | ✅ Done | ChainConfig/StepConfig/InputWiringConfig + CircuitPathConfig + parse_chains() |
| 9 | Chain scheduler (`scheduler.rs`) | ✅ Done | 310 lines, budget allocation |
| 10 | Engine integration (`run_chains()`) | ✅ Done | Multi-circuit loading, coverage_bits computed from traces |
| 11 | Reporting extension | ✅ Done | JSON + markdown chain reports in main.rs |
| 12 | CLI integration (`chains` subcommand) | ✅ Done | `zk-fuzzer chains <yaml>` with --iterations/--timeout/--resume |
| 13 | Campaign template | ✅ Done | `campaigns/templates/deepest_multistep.yaml` exists |
| 14 | Chain corpus persistence (`corpus.rs`) | ✅ Done | Save/load works with real coverage_bits from chain traces |
| 15 | Ground truth chain circuits | ✅ Done | 4 circuit pairs in `tests/ground_truth/chains/`, test file exists |
| 16 | FP/FN benchmark harness | ✅ Done | `benches/chain_benchmark.rs` with criterion, quality gates |

## Resolved Critical Gaps

1. ✅ **Multi-circuit executor loading** (Step 3) — Added `CircuitPathConfig` to `ChainConfig.circuits` map. `run_chains()` now calls `collect_circuit_configs()` and loads executors per unique circuit_ref using `ExecutorFactory::create_with_options()`.
2. ✅ **Coverage feedback** (Steps 10, 14) — Added `compute_chain_coverage_bits()` helper that hashes constraint coverage from all steps in a trace. Corpus entries now have real coverage data for prioritization.
3. ✅ **Inspector caching** (Step 1d) — Removed dead `cached_inspector` field. The trait returns `&dyn ConstraintInspector` (a cheap borrow), so caching via `Arc` is unnecessary and impossible without a trait change.
4. ✅ **FP/FN benchmark** (Step 16) — Created `benches/chain_benchmark.rs` with criterion harness, ground truth test cases, precision/recall metrics, and quality gates (90% precision, 80% recall).
5. ✅ **tc.clone() eliminated** (Step 1c) — Refactored underconstrained and collision attacks to use `indexed_results: Vec<(usize, ExecutionResult)>` and reference test_cases by index, avoiding clones in the hot path.

---

## Design Principles

1. **New module, no rewrites.** Everything lives under `src/chain_fuzzer/`. Existing engine, orchestrator, and config code are extended, never modified destructively.
2. **Composable.** Each sub-module (types, runner, invariants, shrinker, metrics, YAML) is independently testable.
3. **Reuse existing plumbing.** Uses `CircuitExecutor`, `InvariantChecker`, `FuzzingEngine`, `FuzzReport`, and `Finding` as-is.
4. **YAML-driven.** Chains are defined in campaign YAML under a new `chains:` key; no code changes needed to define new scenarios.

---

## Module Layout

```
src/chain_fuzzer/
├── mod.rs              # public API, re-exports
├── types.rs            # ChainSpec, StepSpec, ChainTrace, StepTrace, ChainFinding
├── runner.rs           # ChainRunner — executes a chain spec against executors
├── invariants.rs       # CrossStepInvariantChecker — evaluates assertions over ChainTrace
├── shrinker.rs         # ChainShrinker — minimizes chain to L_min
├── mutator.rs          # ChainMutator — mutates chains (step-swap, input-tweak, step-drop)
├── metrics.rs          # Depth metrics: L_min, D, P_deep per scan_metrics.md
└── scheduler.rs        # ChainScheduler — budget allocation across chain scenarios
```

---

## Step-by-Step Implementation Plan

### Step 1: Low-effort performance wins (chain-critical)

Chain fuzzing multiplies execution cost by chain length. A 5-step chain at 100 exec/sec = 20 exec/sec effective throughput. These optimizations are low-risk, no-refactor, and directly benefit Mode 3 disproportionately.

**1a. Reuse rayon thread pool across attacks (~30 min)**

Currently `engine.rs` creates a new `rayon::ThreadPoolBuilder::new().build()` per attack invocation (lines 1774, 2201). Chain runner will call many attacks in sequence. Fix: build the pool once in `FuzzingEngine::new()`, store as a field, reuse everywhere.

```rust
// Before (per-attack):
let pool = rayon::ThreadPoolBuilder::new().num_threads(self.workers).build()?;

// After (once at init):
// In FuzzingEngine struct:
pool: rayon::ThreadPool,
// In new():
pool: rayon::ThreadPoolBuilder::new().num_threads(workers).build()?,
// In each attack:
self.pool.install(|| { ... })
```

Risk: none. Rayon pools are thread-safe and reentrant.

**1b. Pre-size HashMaps with `with_capacity` (~20 min)**

Multiple hot-path HashMaps are created with `HashMap::new()` then filled with known-size data (e.g., output_map in underconstrained attack at line 1792, collision map at line 2218). Pre-sizing avoids rehashing.

```rust
// Before:
let mut output_map: HashMap<Vec<u8>, Vec<TestCase>> = HashMap::new();

// After:
let mut output_map: HashMap<Vec<u8>, Vec<TestCase>> = HashMap::with_capacity(num_pairs / 2);
```

Risk: none. Worst case wastes a few KB.

**1c. Avoid `tc.clone()` in parallel collect (~20 min)**

Lines 1770, 1784, 2197, 2211 clone every `TestCase` just to pair it with its result. For chains this is amplified N times per step. Fix: use indexed access instead.

```rust
// Before:
test_cases.par_iter().map(|tc| {
    let result = executor.execute_sync(&tc.inputs);
    (tc.clone(), result)  // unnecessary clone
}).collect()

// After:
test_cases.par_iter().enumerate().map(|(i, tc)| {
    let result = executor.execute_sync(&tc.inputs);
    (i, result)
}).collect()
// Then index into test_cases[i] when needed
```

Risk: none. Pure refactor, same semantics.

**1d. Cache `constraint_inspector()` result (~15 min)**

`self.executor.constraint_inspector()` is called in multiple places (seed generation, constraint slice, taint analysis). If the inspector does any work on each call, cache it once.

```rust
// In FuzzingEngine struct:
cached_inspector: Option<Arc<dyn ConstraintInspector>>,
// In new():
cached_inspector: executor.constraint_inspector().map(Arc::from),
```

Risk: very low. Inspector is read-only.

**Total effort:** ~1.5 hours
**Expected impact:** 10–30% throughput gain on chain fuzzing (compounds across steps).
**Risk:** zero — all are mechanical, no logic changes.

**Depends on:** nothing.
**Tests:** existing `cargo test` covers all paths. Run `test_parallel_performance` before/after to measure.

---

### Step 2: Core types (`types.rs`)

Define the data model that every other sub-module depends on.

```rust
// What a chain scenario looks like (parsed from YAML)
pub struct ChainSpec {
    pub name: String,
    pub steps: Vec<StepSpec>,
    pub assertions: Vec<CrossStepAssertion>,
}

pub struct StepSpec {
    pub circuit_ref: String,          // name or path of circuit
    pub input_wiring: InputWiring,    // how to derive inputs
    pub label: Option<String>,
}

pub enum InputWiring {
    Fresh,                                     // fuzz from scratch
    FromPriorOutput { step: usize, mapping: Vec<(usize, usize)> },  // output[i] → input[j]
    Mixed { prior: Vec<(usize, usize, usize)>, fresh_indices: Vec<usize> },
}

pub struct CrossStepAssertion {
    pub name: String,
    pub relation: String,           // e.g. "step[0].out[0] == step[1].in[2]"
    pub severity: String,
}

// Runtime trace of a chain execution
pub struct ChainTrace {
    pub spec_name: String,
    pub steps: Vec<StepTrace>,
    pub success: bool,
}

pub struct StepTrace {
    pub step_index: usize,
    pub circuit_ref: String,
    pub inputs: Vec<FieldElement>,
    pub outputs: Vec<FieldElement>,
    pub success: bool,
    pub constraints_hit: HashSet<usize>,
}

// A finding with chain depth metadata
pub struct ChainFinding {
    pub finding: Finding,
    pub chain_length: usize,    // total steps
    pub l_min: usize,           // minimum steps to reproduce
    pub trace: ChainTrace,
}
```

**Depends on:** `zk_core::FieldElement`, `zk_core::Finding`
**Tests:** unit tests for serialization, `InputWiring` resolution logic.

---

### Step 3: Chain runner (`runner.rs`)

Executes a `ChainSpec` against a set of named `CircuitExecutor`s, producing a `ChainTrace`.

```rust
pub struct ChainRunner {
    executors: HashMap<String, Arc<dyn CircuitExecutor>>,
    timeout_per_step: Duration,
}

impl ChainRunner {
    pub fn new(executors: HashMap<String, Arc<dyn CircuitExecutor>>) -> Self;

    pub fn execute(
        &self,
        spec: &ChainSpec,
        initial_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> ChainTrace;
}
```

Key behaviors:
- Resolves `InputWiring` per step to derive inputs from prior outputs + fresh fuzz values.
- Records full `StepTrace` for every step (inputs, outputs, constraint hits).
- Stops on first step failure but still returns partial trace (needed for shrinker).
- Respects per-step timeout using `IsolatedExecutor` when in evidence mode.

**Depends on:** `types.rs`, existing `CircuitExecutor` trait, `IsolatedExecutor`.
**Tests:** unit test with `MockCircuitExecutor`; chain of 3 mock circuits; verify trace correctness.

---

### Step 4: Cross-step invariant checker (`invariants.rs`)

Evaluates `CrossStepAssertion`s over a completed `ChainTrace`.

```rust
pub struct CrossStepInvariantChecker {
    assertions: Vec<CrossStepAssertion>,
}

impl CrossStepInvariantChecker {
    pub fn from_spec(spec: &ChainSpec) -> Self;

    pub fn check(&self, trace: &ChainTrace) -> Vec<CrossStepViolation>;
}

pub struct CrossStepViolation {
    pub assertion_name: String,
    pub relation: String,
    pub step_indices: Vec<usize>,
    pub actual_values: Vec<FieldElement>,
    pub severity: String,
}
```

Supported assertion patterns (parsed from `relation` string):
- `step[i].out[j] == step[k].in[m]` — wiring consistency
- `unique(step[*].out[j])` — no duplicate outputs across steps
- `step[i].out[j] != step[k].out[m]` — distinctness
- `step[i].success == true` — step must succeed

**Depends on:** `types.rs`.
**Tests:** unit tests for each assertion pattern; violated and satisfied cases.

---

### Step 5: Chain mutator (`mutator.rs`)

Mutates chain inputs for coverage-guided exploration.

```rust
pub struct ChainMutator {
    field_mutator: StructureAwareMutator,
}

impl ChainMutator {
    pub fn mutate_inputs(
        &self,
        spec: &ChainSpec,
        prior_inputs: &HashMap<String, Vec<FieldElement>>,
        rng: &mut impl Rng,
    ) -> HashMap<String, Vec<FieldElement>>;
}
```

Mutation strategies:
1. **Single-step input tweak** — pick a step with `Fresh` or `Mixed` wiring, mutate its fresh inputs.
2. **Initial-input cascade** — mutate step 0 inputs, let wiring propagate changes downstream.
3. **Step reorder** — swap two steps (if wiring allows).
4. **Step duplication** — repeat a step to test re-entrancy.
5. **Boundary injection** — inject 0, 1, p-1 at random fresh-input positions.

**Depends on:** `types.rs`, existing `StructureAwareMutator`.
**Tests:** verify each strategy produces valid mutated inputs.

---

### Step 6: Chain shrinker (`shrinker.rs`)

Minimizes a violation-triggering chain to compute `L_min`.

```rust
pub struct ChainShrinker {
    runner: ChainRunner,
    checker: CrossStepInvariantChecker,
    max_attempts: usize,
}

impl ChainShrinker {
    pub fn minimize(
        &self,
        spec: &ChainSpec,
        inputs: &HashMap<String, Vec<FieldElement>>,
        violation: &CrossStepViolation,
    ) -> (ChainSpec, usize); // (minimized spec, L_min)
}
```

Minimization strategies (applied in order):
1. **Prefix truncation** — try removing trailing steps.
2. **Step dropout** — try removing individual intermediate steps (delta-debug style).
3. **Input minimization** — for each step, try replacing non-wired inputs with zeros.

`L_min` = number of steps in the smallest chain that still triggers the same assertion violation.

**Depends on:** `runner.rs`, `invariants.rs`, `types.rs`.
**Tests:** chain of 5 steps where violation only needs steps 0,2,4 → verify `L_min == 3`.

---

### Step 7: Depth metrics (`metrics.rs`)

Computes Mode 3 metrics per `scan_metrics.md`.

```rust
pub struct DepthMetrics {
    pub findings: Vec<ChainFinding>,
}

impl DepthMetrics {
    pub fn d_mean(&self) -> f64;       // mean(L_min) over confirmed findings
    pub fn p_deep(&self) -> f64;       // P(L_min >= 2)
    pub fn depth_distribution(&self) -> HashMap<usize, usize>;  // L_min → count
}
```

**Depends on:** `types.rs`.
**Tests:** known set of findings → verify metric values.

---

### Step 8: YAML schema extension (`config/v2.rs` addition)

Add `chains:` key to `FuzzConfigV2`:

```yaml
chains:
  - name: "deposit_then_withdraw"
    steps:
      - circuit_ref: "deposit"
        input_wiring: fresh
      - circuit_ref: "withdraw"
        input_wiring:
          from_prior_output:
            step: 0
            mapping:
              - [0, 2]   # deposit.out[0] → withdraw.in[2]
              - [1, 3]   # deposit.out[1] → withdraw.in[3]
    assertions:
      - name: "nullifier_uniqueness"
        relation: "unique(step[*].out[0])"
        severity: "critical"
      - name: "root_consistency"
        relation: "step[0].out[1] == step[1].in[3]"
        severity: "high"
```

Implementation:
- Add `chains: Vec<ChainConfig>` field to `FuzzConfigV2` (with `#[serde(default)]`).
- Add `ChainConfig`, `StepConfig`, `InputWiringConfig`, `AssertionConfig` serde structs.
- Add parser function `parse_chains(yaml) → Vec<ChainSpec>` that converts config → runtime types.
- Add readiness rule: "chains defined but no assertions" → warning.

**Depends on:** `types.rs`, existing `config/v2.rs`.
**Tests:** parse sample YAML → verify `ChainSpec` correctness.

---

### Step 9: Chain scheduler (`scheduler.rs`)

Allocates budget across chain scenarios within a campaign.

```rust
pub struct ChainScheduler {
    chains: Vec<ChainSpec>,
    budget: Duration,
}

impl ChainScheduler {
    pub fn allocate(&self) -> Vec<(ChainSpec, Duration)>;
    pub fn update_priority(&mut self, chain_name: &str, result: &ChainRunResult);
}
```

Priority heuristics:
- Chains with near-miss violations get more budget.
- Chains with no coverage gain get de-prioritized.
- New/untested chains get a minimum baseline budget.

**Depends on:** `types.rs`.
**Tests:** verify budget allocation with mock results.

---

### Step 10: Integration — wire into engine (`engine.rs` extension)

Add a `run_chains()` method to `FuzzingEngine` (or a standalone `ChainFuzzingEngine`):

```rust
impl FuzzingEngine {
    pub async fn run_chains(
        &mut self,
        chains: &[ChainSpec],
        progress: Option<&ProgressReporter>,
    ) -> Vec<ChainFinding>;
}
```

Flow:
1. Parse `chains:` from config.
2. For each chain, in a loop until budget exhausted:
   a. Generate/mutate inputs via `ChainMutator`.
   b. Execute via `ChainRunner`.
   c. Check cross-step invariants via `CrossStepInvariantChecker`.
   d. On violation: shrink via `ChainShrinker` to get `L_min`.
   e. Record `ChainFinding`.
3. Compute `DepthMetrics`.
4. Merge chain findings into `FuzzReport`.

**Depends on:** all previous steps.
**Tests:** integration test with mock circuits, known-buggy chain → verify finding produced with correct `L_min`.

---

### Step 11: Reporting extension

Add chain-specific sections to `FuzzReport` and markdown/JSON output:

- `chain_findings: Vec<ChainFinding>` field on `FuzzReport`.
- Markdown section: "## Multi-Step Findings" with per-finding: chain name, steps, L_min, assertion violated, witness per step, repro command.
- Metrics section: D, P_deep, depth distribution histogram.
- Evidence bundle: include full `ChainTrace` as JSON attachment.

**Depends on:** `types.rs`, `metrics.rs`, existing `reporting/`.
**Tests:** verify markdown output contains expected sections.

---

### Step 12: CLI integration

Add `--mode deepest` or `--chains` flag to CLI:

- When `chains:` is present in YAML and mode is evidence, automatically run `run_chains()` after (or instead of) standard fuzzing.
- Add `zk-fuzzer chains <campaign.yaml>` subcommand for chain-only runs.

**Depends on:** step 10, `src/main.rs`.

---

### Step 13: Campaign template

Create `campaigns/templates/deepest_multistep.yaml` — a ready-to-use template for Mode 3 with example chains, assertions, and documentation comments.

---

### Step 14: Chain corpus persistence

Multi-step chains are expensive to execute. Losing coverage state between runs is unacceptable at Mode 3 budgets.

```rust
pub struct ChainCorpus {
    entries: Vec<ChainCorpusEntry>,
    storage_path: PathBuf,
}

pub struct ChainCorpusEntry {
    pub spec_name: String,
    pub inputs: HashMap<String, Vec<FieldElement>>,
    pub coverage_bits: u64,
    pub depth_reached: usize,
    pub near_miss_score: f64,
}

impl ChainCorpus {
    pub fn save(&self) -> anyhow::Result<()>;
    pub fn load(path: &Path) -> anyhow::Result<Self>;
    pub fn merge(&mut self, other: &ChainCorpus);
}
```

Implementation:
- Serialize chain corpus entries to `<output_dir>/chain_corpus/` as JSON.
- On startup, if `chain_corpus/` exists, load and seed the chain mutator with prior entries.
- Add `--resume-chains` CLI flag that loads prior corpus + skips already-covered chains.
- Prioritize entries with high near-miss scores and novel coverage for re-mutation.

**Depends on:** `types.rs`, existing `corpus/storage.rs` patterns.
**Tests:** save corpus → load corpus → verify entries match; merge two corpora → verify dedup.

---

### Step 15: Ground truth chain circuits

Mode 3 is useless without proof that it catches real multi-step bugs. Build a minimal set of intentionally-vulnerable chain scenarios.

Target circuits (Circom, placed in `tests/ground_truth/chains/`):

| Circuit Pair | Bug Class | Expected Finding |
|-------------|-----------|-----------------|
| `deposit.circom` + `withdraw.circom` | Nullifier reuse across steps | `unique(step[*].out[0])` violated |
| `update_root.circom` + `verify_root.circom` | Inconsistent Merkle root propagation | `step[0].out[1] == step[1].in[0]` violated |
| `sign.circom` + `verify.circom` | Signature malleability (s vs p-s) | Both steps succeed with different witnesses for same message |
| `clean_deposit.circom` + `clean_withdraw.circom` | No bug (true negative) | Zero findings |

Each ground truth case includes:
- The Circom source (minimal, <50 lines each).
- A chain campaign YAML.
- Expected outcome: CONFIRMED or CLEAN.
- A test in `tests/chain_ground_truth.rs` that asserts the outcome.

Success criteria:
- 100% detection rate on known-buggy chains.
- 0% false positive rate on clean chains.
- `D > 1` across the buggy set (proves multi-step depth).

**Depends on:** steps 10 (engine integration), 11 (reporting).
**Tests:** `cargo test --test chain_ground_truth` — hard CI gate.

---

### Step 16: FP/FN rate measurement

Add a benchmark harness that runs all ground truth chains and computes:

```rust
pub struct ChainBenchmarkResult {
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub precision: f64,       // TP / (TP + FP)
    pub recall: f64,          // TP / (TP + FN)
    pub mean_l_min: f64,      // D metric
    pub p_deep: f64,          // P(L_min >= 2)
    pub mean_time_to_first: Duration,
}
```

- Runs as `cargo bench --bench chain_benchmark` (not in regular test suite — too slow).
- Outputs a markdown table to `reports/chain_benchmark.md`.
- Tracked in CI as a regression gate: precision must not drop below 0.9, recall must not drop below 0.8.

**Depends on:** step 15 (ground truth circuits).
**Tests:** the benchmark itself is the test.

---

## Dependency Graph

```
Step 1 (perf wins) ← no dependencies, do first so chain runner benefits immediately
  │
  ▼
Step 2 (types)
  ├── Step 3 (runner)
  │     └── Step 6 (shrinker) ← also needs Step 4
  ├── Step 4 (invariants)
  ├── Step 5 (mutator)
  ├── Step 7 (metrics)
  ├── Step 8 (YAML schema)
  └── Step 9 (scheduler)
        │
        ▼
Step 10 (engine integration) ← needs 3,4,5,6,7,8,9
  ├── Step 11 (reporting)
  ├── Step 12 (CLI)
  ├── Step 13 (template)
  └── Step 14 (chain corpus persistence)
        │
        ▼
Step 15 (ground truth chains) ← needs 10,11
  └── Step 16 (FP/FN benchmark) ← needs 15
```

Step 1 should be completed first so all subsequent chain work benefits from improved throughput.
Steps 3, 4, 5, 7, 8, 9 can be built in parallel after Step 2.
Steps 11, 12, 13, 14 can be built in parallel after Step 10.

---

## Estimated Effort

| Step | Effort | Can Parallelize With |
|------|--------|---------------------|
| 1. perf wins (a–d) | 1.5 hours | — (do first) |
| 2. types | 2–3 hours | — |
| 3. runner | 4–6 hours | 4, 5, 7, 8, 9 |
| 4. invariants | 3–4 hours | 3, 5, 7, 8, 9 |
| 5. mutator | 3–4 hours | 3, 4, 7, 8, 9 |
| 6. shrinker | 4–6 hours | 7, 8, 9 |
| 7. metrics | 1–2 hours | 3, 4, 5, 6, 8, 9 |
| 8. YAML schema | 3–4 hours | 3, 4, 5, 6, 7, 9 |
| 9. scheduler | 2–3 hours | 3, 4, 5, 6, 7, 8 |
| 10. engine integration | 4–6 hours | — |
| 11. reporting | 2–3 hours | 12, 13 |
| 12. CLI | 1–2 hours | 11, 13 |
| 13. template | 1 hour | 11, 12, 14 |
| 14. chain corpus persistence | 3–4 hours | 11, 12, 13 |
| 15. ground truth chains | 4–6 hours | — |
| 16. FP/FN benchmark | 2–3 hours | — |
| **Total** | **~5–7 days** | |

---

## Validation Criteria

| # | Criterion | How to verify |
|---|-----------|---------------|
| 1 | Perf: no new thread pool allocations per attack | grep for `ThreadPoolBuilder` — single callsite |
| 2 | Chain of 3 mock circuits executes, trace recorded | Unit test in `runner.rs` |
| 3 | Cross-step assertion violation detected | Unit test in `invariants.rs` |
| 4 | Shrinker reduces 5-step chain to L_min=3 | Unit test in `shrinker.rs` |
| 5 | YAML with `chains:` parses correctly | Unit test in `config/v2.rs` |
| 6 | `D > 1` and `P_deep > 0` on chain findings | Unit test in `metrics.rs` |
| 7 | Integration: mock campaign produces `ChainFinding` with correct L_min | Integration test |
| 8 | Evidence mode: chain finding includes full trace + repro command | Integration test |
| 9 | Chain corpus saves/loads correctly across runs | Unit test in `chain_corpus.rs` |
| 10 | Ground truth: 100% TP detection, 0% FP on clean chains | `cargo test --test chain_ground_truth` |
| 11 | Benchmark: precision >= 0.9, recall >= 0.8 | `cargo bench --bench chain_benchmark` |
| 12 | `cargo test` passes, `cargo check` clean | CI gate |
