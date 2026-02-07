# ZkPatternFuzz: Remaining Work

**Status:** In Progress (Phase 4/5 + 0‑Day Workflow Readiness)  
**Remaining:** 2-4 weeks  
**Priority:** 0‑Day Workflow Readiness  
**Last Updated:** 2026-02-07

---

## Single Success Metric (Non-Negotiable)

**Only one thing matters:** **discoveries on the provided target set**  
`/media/elements/Repos/zk0d`

Every task below must directly improve our ability to produce **evidence-backed findings**
on zk0d circuits. If a task does not support this metric, it is out of scope.

---

## ✅ CRITICAL FINDINGS - ALL RESOLVED

### Original Blockers (All Fixed)

1. **[FIXED]** No Coverage-Guided Fuzzing Loop → Continuous phase implemented
2. **[FIXED]** Broken Underconstrained Oracle → Stateful with `&mut self`
3. **[FIXED]** Output-Hash-Only Coverage → Engine uses `satisfied_constraints`
4. **[FIXED]** 5 Unimplemented Attacks → All dispatchers implemented
5. **[FIXED]** Wrong Underconstrained Sampling → Public inputs held constant
6. **[FIXED]** Hard-Coded BN254 Field → Per-backend `field_modulus()`
7. **[FIXED]** Semantic Oracles Unused → Wired via config

---

## Phase 0: Fix Core Infrastructure ✅ COMPLETE

- [x] Stateful `BugOracle` with `&mut self`
- [x] Continuous fuzzing loop with CLI flags
- [x] Fixed underconstrained sampling
- [x] Semantic oracles wired
- [x] All 5 novel attack dispatchers
- [x] Per-backend field modulus

---

## Phase 1: Backend Constraint Coverage ✅ COMPLETE

- [x] Engine calls `coverage.record_execution(satisfied_constraints)` (engine.rs:223,261)
- [x] Backends return `satisfied_constraints` in results
- [x] Noir constraint extraction (ACIR)
- [x] Halo2 constraint extraction (PLONK)
- [x] Wire labels for Circom/Noir
- [x] Coverage tests on real circuits (Circom/Noir multiplier + Halo2 real-circuit check run manually)

---

## Phase 2: YAML v2 (1-2 weeks)

- [x] `src/config/v2.rs` - YAML includes, profiles, invariants
- [x] `templates/traits/*.yaml` - Merkle/Range/Hash/Nullifier/Signature
- [x] `src/config/generator.rs` - Auto-detect patterns
- [x] `src/fuzzer/phased_scheduler.rs` - Phased execution

---

## Phase 3: Reality Check & Observability (1 week)

- [x] `docs/CAPABILITY_MATRIX.md` - Feature status
- [x] Update README.md with actual capabilities
- [x] `src/analysis/dependency.rs` - Witness-dependency graph
- [x] `src/reporting/coverage_summary.rs` - Enhanced CLI
- [x] Update `FuzzStatistics` with new metrics

---

## Phase 4: Novel Oracle Enhancement (2-3 weeks)

### A. Constraint Inference
- [x] Basic implementation
- [x] Execute violation witnesses for confirmation
- [x] Add Halo2/Cairo label sources
- [ ] Validate on real circuits (zk0d)

### B. Metamorphic Oracles
- [x] Basic implementation
- [x] Circuit-specific relations

### C. Constraint Slice
- [x] Basic implementation
- [ ] Validate on real circuits (zk0d)

### D. Spec Inference
- [x] Basic implementation
- [x] Remove 100-sample cap
- [x] Reduce false positives

### E. Witness Collision
- [x] Basic implementation
- [ ] Enhance heuristics (public input scoping by backend)

### F. Differential
- [ ] Enhance cross-backend detection (coverage/timing mismatch signal tuning)

---

## Phase 5: AI YAML & Adaptive (1-2 weeks)

- [x] `docs/CLAUDE_PROMPT.md` - Opus prompt for manual‑analysis → YAML
- [x] `docs/AI_ASSISTED_WORKFLOW.md` - Manual analysis → YAML → fuzz loop
- [x] `scripts/validate_yaml.*` - YAML validator/sanitizer
- [x] `scripts/run_ai_campaign.*` - Batch runner for target list
- [x] `docs/TARGETS.md` - zk0d target list with main components

---

## Timeline

| Phase | Status | Remaining |
|-------|--------|-----------|
| 0. Fix Core | ✅ COMPLETE | - |
| 1. Backend Coverage | ✅ COMPLETE | - |
| 2. YAML v2 | ✅ COMPLETE | - |
| 3. Reality Check | ✅ COMPLETE | - |
| 4. Novel Oracles | IN PROGRESS | 1-2 weeks |
| 5. AI & Adaptive | ✅ COMPLETE | - |

**Total:** 2-4 weeks

---

## Success Metrics

### Phase 0 ✅ PASSED
1. [x] Underconstrained oracle detects collisions
2. [x] Fuzzing loop runs >1000 iterations
3. [x] Semantic oracles instantiate from config
4. [x] All 5 novel attacks dispatch
5. [x] Public inputs held constant

### Phase 1 ✅ PASSED
1. [x] Engine calls `record_execution()` with constraints
2. [x] Backends return `satisfied_constraints`
3. [x] Coverage uses actual constraints (not hashes)

### Phase 4 (In Progress)
1. [ ] Constraint inference detects missing constraints
2. [ ] >80% constraint coverage on benchmarks
3. [ ] <60s time-to-bug
4. [ ] <5% false positives

### Phase 5 ✅ PASSED
1. [x] Manual analysis → YAML flow documented
2. [x] YAML validation gate before fuzzing
3. [x] Batch runner over zk0d targets

---

## Immediate Next Steps (Concrete)

### 0-Day Workflow Readiness (Priority)
1. [x] Fix constraint slice output mapping (wire -> output index)  
   DoD: slice comparisons use real output indices, not wire indices; add a focused unit test that would fail under the current mapping.
2. [x] Guard constraint inference confirmation for internal‑wire constraints  
   DoD: only mark "confirmed" when mutated wires are public inputs or explicitly labeled outputs; otherwise downgrade to "unconfirmed_internal".
3. [x] Backend‑aware public input scoping for witness collisions  
   DoD: use backend metadata to map public inputs; findings include exact public input indices used.
4. [ ] AI prompt template for manual-analysis -> YAML  
   DoD: `docs/CLAUDE_PROMPT.md` with schema, example invariants, example YAML output.
5. [x] YAML validator + batch runner for zk0d target list  
   DoD: validator fails on missing invariants/labels; batch runner executes all targets and writes per-target reports.

### Validation on zk0d (Once Ready)
1. [ ] Run on Tornado withdraw (circom)
2. [ ] Run on Semaphore (circom)
3. [x] Run on Iden3 authV3 (circom)  
   Result (2026-02-07): evidence run completed, **0 findings**. Reports in `reports/zk0d/iden3_authv3/`.
4. [ ] Expand to cat2/cat4 targets

---

## Discovery Execution (Step-by-Step)
1. [x] Run skimmer on zk0d  
   DoD: `scripts/run_skimmer.sh --root /media/elements/Repos/zk0d --max-files 200` produces `reports/zk0d/skimmer/skimmer_summary.md`.
2. [x] Select most promising circuit from skimmer summary  
   DoD: pick top candidate with highest hint score + manual review notes.
3. [x] Manual invariant analysis for selected circuit  
   DoD: 3-10 invariants written in v2 YAML with exact input names.
4. [x] Evidence run on selected circuit  
   DoD: `evidence` mode produces PoCs and reproducible report.
   Selected: `AuthV3` (Iden3). Evidence: `campaigns/zk0d/iden3_authv3.yaml`, candidates: `campaigns/zk0d/candidate_invariants.yaml`.

### Machine Optimization for the 0-Day Flow (Concrete)
1. [ ] Use release builds for campaigns  
   DoD: run `cargo build --release` and execute `./target/release/zk-fuzzer ...` for all zk0d campaigns.
2. [ ] Set worker count to saturate CPU  
   DoD: use `--workers <nproc>` on the CLI; verify run logs show the configured worker count.
3. [ ] Reduce overhead in long runs  
   DoD: use `--simple-progress` and `--quiet` for batch runs; enable `--verbose` only for triage.
4. [ ] Bound campaigns deterministically  
   DoD: always pass `--seed`, `--iterations`, and `--timeout` per campaign; record these in the campaign log.
5. [ ] Preflight before long runs  
   DoD: `zk-fuzzer validate <campaign.yaml>` and `--dry-run` succeed before any long campaign.

---

## Evidence + Deep-Custom Fuzz Plan (Step-by-Step)

### Phase 0: Preconditions (Must Pass)
1. [ ] Circuit compiles (circom/noir/halo2) and runs with baseline inputs  
   DoD: `zk-fuzzer validate` passes for the campaign.
2. [ ] Manual invariants written (v2 YAML `invariants:` present)  
   DoD: at least 3 invariants with explicit target inputs.
3. [ ] Invariant targets are mapped to input names  
   DoD: invariants reference actual input names, not generic placeholders.

### Phase 1: Evidence Run (Deterministic)
1. [ ] Run evidence mode with fixed seed  
   DoD: `cargo run --release -- evidence <campaign.yaml> --seed 42 --iterations 50000 --timeout 1800 --simple-progress`
2. [ ] Capture outputs + reports  
   DoD: `report.json` / `report.md` saved and include violations with PoCs.
3. [ ] Triage each violation  
   DoD: reproduce from witness and record “confirmed / needs fix / false alarm”.

### Phase 2: Deep Custom Fuzz (Unexpected Edge Cases)
1. [ ] Add custom invariants for “bricking” cases  
   DoD: invariants for zero/nullifier collisions, boundary overflow, path index abuse, malformed signature points.
2. [ ] Add focused mutations for bricking scenarios  
   DoD: custom mutators or yaml constraints targeting: all-zero inputs, max field value, non-binary path indices, duplicated roots.
3. [ ] Run custom fuzz campaign  
   DoD: `cargo run --release -- evidence <custom.yaml> --seed 1337 --iterations 100000 --timeout 3600`
4. [ ] Minimize PoCs  
   DoD: minimal witness saved; reproduction command documented in report.

### Phase 3: Evidence Package (Publishable)
1. [ ] Bundle PoC artifacts per finding  
   DoD: witness, repro YAML, circuit path, and invariant violated.
2. [ ] Write a short root-cause note  
   DoD: 3-5 bullet explanation of why constraint missed and impact.
3. [ ] Add “confirmed evidence” entries to validation report  
   DoD: no hints-only claims in the report.

---

## AI Pentest Rules (Required Reading)
1. [ ] Follow `docs/AI_PENTEST_RULES.md` for skimmer -> evidence -> deep custom phases  
   DoD: no hints reported as confirmed; every confirmed finding includes PoC + repro command.

---

## Deep Custom Fuzz Checklist (Ready-to-Run Template)
1. [ ] Base YAML includes v2 invariants
2. [ ] Custom YAML includes targeted mutations for edge cases
3. [ ] Evidence mode enabled
4. [ ] Deterministic seed and fixed iteration/time budget
5. [ ] Findings saved + reproduced

---

## What's Complete ✅

### Core Infrastructure
- ✅ Continuous fuzzing loop with CLI flags
- ✅ Stateful oracles with cross-execution tracking
- ✅ 12 attack types (all dispatchers implemented)
- ✅ Semantic oracles wired via config
- ✅ Per-backend field modulus
- ✅ Constraint-level coverage (not hash-only)
- ✅ Wire labels for Circom/Noir

### Features
- ✅ Power scheduling (6 strategies)
- ✅ Structure-aware mutations
- ✅ Symbolic execution (Z3)
- ✅ Taint analysis
- ✅ Constraint-guided seeds
- ✅ Differential framework
- ✅ Multi-circuit composition
- ✅ Benchmarking suite
- ✅ PoC generator
- ✅ Delta debugging
- ✅ CI workflows
- ✅ JSON/Markdown/SARIF reports

### Needs Enhancement
- ⚠️ Constraint inference (needs zk0d validation)
- ⚠️ Constraint slice (needs zk0d validation)
- ⚠️ Witness collision (public input scoping by backend)
- ⚠️ Differential (signal tuning for coverage/timing)

### Complete ✅
- ✅ YAML v2 with includes, profiles, invariants

---

## 0‑Day Workflow (Manual Analysis → YAML → Fuzz)

This is the intended path to uncover complex vulnerabilities:

1. **Manual Analysis**: Identify invariants and likely break paths
2. **Generate YAML**: Encode invariants, targets, and attack focus (v2)
3. **Validate YAML**: Sanity‑check inputs, invariants, and schedules
4. **Run Fuzzer**: Execute against zk0d targets and collect findings
5. **Triage & Iterate**: Refine invariants and attack focus based on results

```rust
// Intended API surface for the 0‑day flow (not fully wired yet)
use zk_fuzzer::fuzzer::FuzzingEngine;
use zk_fuzzer::config::FuzzConfig;

let config = FuzzConfig::from_yaml("generated_campaign.yaml")?;
let mut engine = FuzzingEngine::new(config, Some(42), 4)?;
let report = tokio::runtime::Runtime::new()?.block_on(async { engine.run(None).await })?;
```

**Focus:** 0‑day workflow readiness over breadth. Build correctness, then scale.

## 0-Day Runbook (Concrete Commands)

1. Produce campaign YAML from manual analysis (using the Claude Opus prompt template once available).
2. Validate the YAML before any long run:

```bash
./target/release/zk-fuzzer validate path/to/campaign.yaml
./target/release/zk-fuzzer --config path/to/campaign.yaml --dry-run
```

3. Launch a bounded, reproducible fuzzing run:

```bash
./target/release/zk-fuzzer run path/to/campaign.yaml \
  --workers 8 \
  --seed 42 \
  --iterations 50000 \
  --timeout 1800 \
  --simple-progress
```

4. Triage findings, update the YAML, and re-run with adjusted invariants.
