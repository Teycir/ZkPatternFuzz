# ZkPatternFuzz: Remaining Work

**Status:** 60% Complete (Code Review: Critical Gaps Found)  
**Remaining:** 6-10 weeks  
**Priority:** Fix Core Infrastructure FIRST

---

## ⚠️ CRITICAL FINDINGS (Code Review 2024)

### Blockers Preventing 0-Day Discovery

1. **No Coverage-Guided Fuzzing Loop** - `run()` executes attacks once and exits (no continuous exploration)
2. **Broken Underconstrained Oracle** - Uses `&self`, never records outputs, can't detect collisions
3. **Output-Hash-Only Coverage** - Noir/Halo2 don't provide constraint-level feedback
4. **5 Unimplemented Attacks** - ConstraintInference/Metamorphic/ConstraintSlice/SpecInference/WitnessCollision hit "not implemented"
5. **Wrong Underconstrained Sampling** - Doesn't fix public inputs (tests wrong hypothesis)
6. **Hard-Coded BN254 Field** - Breaks non-BN254 circuits
7. **Semantic Oracles Unused** - Nullifier/Merkle/Range implemented but never instantiated

---

## Phase 0: Fix Core Infrastructure (1-2 weeks) 🚨 CRITICAL

### A. Fix Underconstrained Oracle (2 days)
- [ ] Change `BugOracle::check()` to `&mut self` in `zk-fuzzer-core/src/oracle.rs`
- [ ] Add `record_output()` to `UnderconstrainedOracle`
- [ ] Wire into `FuzzingEngineCore::execute_and_learn()`

### B. Implement Fuzzing Loop (3-4 days)
- [ ] Add `continuous_fuzzing_phase()` after attacks in `FuzzingEngine::run()`
- [ ] Loop: `select_from_corpus() → mutate() → execute_and_learn()`
- [ ] Add `--iterations` and `--timeout` CLI flags

### C. Fix Underconstrained Sampling (1 day)
- [ ] Fix `run_underconstrained_attack()` to hold public inputs constant
- [ ] Generate multiple private witnesses for same public inputs

### D. Wire Semantic Oracles (1 day)
- [ ] Read `FuzzConfig.oracles` in `FuzzingEngine::new()`
- [ ] Instantiate nullifier/merkle/range oracles based on config

### E. Implement Attack Dispatchers (2 days)
- [ ] Add dispatch logic for ConstraintInference/Metamorphic/ConstraintSlice/SpecInference/WitnessCollision
- [ ] Remove "not implemented" warnings

### F. Fix Field Modulus (1 day)
- [ ] Add `field_modulus()` to `CircuitExecutor` trait
- [ ] Replace hard-coded `bn254_modulus_bytes()` calls

---

## Phase 1: Backend Constraint Coverage (1-2 weeks)

- [ ] Add `constraint_inspector()` to Noir (extract from ACIR)
- [ ] Add `constraint_inspector()` to Halo2 (extract from PLONK)
- [ ] Return `satisfied_constraints: Vec<usize>` from `execute_sync()`
- [ ] Call `coverage.record_execution()` with actual constraints

---

## Phase 2: YAML v2 (1-2 weeks)

- [ ] `src/config/v2.rs` - YAML includes, profiles, invariants
- [ ] `templates/traits/*.yaml` - Merkle/Range/Hash/Nullifier/Signature patterns
- [ ] `src/config/generator.rs` - Auto-detect circuit patterns
- [ ] `src/fuzzer/phased_scheduler.rs` - Phased execution

---

## Phase 3: Reality Check & Observability (1 week)

### A. Capability Matrix (2 hours)
- [ ] `docs/CAPABILITY_MATRIX.md` - Honest feature status
- [ ] Update README.md with actual capabilities

### B. Observability
- [ ] `src/analysis/dependency.rs` - Witness-dependency graph
- [ ] `src/reporting/coverage_summary.rs` - Enhanced CLI
- [ ] Update `FuzzStatistics` with new metrics

---

## Phase 4: Novel Oracles (2-3 weeks)

### A. Constraint Inference (4-5 days)
**Finds missing constraints**

```rust
// src/attacks/constraint_inference.rs (NEW)
pub struct ConstraintInferenceEngine {
    inference_rules: Vec<Box<dyn InferenceRule>>,
}
```

- [ ] Implement `src/attacks/constraint_inference.rs`

### B. Metamorphic Oracles (3-4 days)
**Test invariants via transformations**

- [ ] Implement `src/attacks/metamorphic.rs`

### C. Constraint Slice (3 days)
**Mutate within dependency cones**

- [ ] Implement `src/attacks/constraint_slice.rs`

### D. Spec Inference (3-4 days)
**Auto-learn properties, generate violations**

- [ ] Implement `src/attacks/spec_inference.rs`

### E. Witness Collision (2 days)
- [ ] Enhance existing `src/attacks/witness_collision.rs`

### F. Differential (2 days)
- [ ] Enhance `src/differential/executor.rs`

---

## Phase 5: AI YAML & Adaptive (1-2 weeks)

### A. AI-Assisted YAML (2-3 days)
- [ ] `templates/ai_assisted/*.yaml` - Templates
- [ ] `docs/CLAUDE_PROMPT.md` - Prompt
- [ ] `docs/AI_WORKFLOW.md` - Guide

### B. Adaptive Scheduler (1 week)
- [ ] `src/fuzzer/adaptive_attack_scheduler.rs`
- [ ] `src/fuzzer/near_miss.rs`
- [ ] `src/config/suggester.rs`

---

## Timeline

| Phase | Duration | Priority |
|-------|----------|----------|
| **0. Fix Core** | **1-2 weeks** | **🚨 CRITICAL** |
| 1. Backend Coverage | 1-2 weeks | HIGH |
| 2. YAML v2 | 1-2 weeks | MEDIUM |
| 3. Reality Check | 1 week | HIGH |
| 4. Novel Oracles | 2-3 weeks | HIGH |
| 5. AI & Adaptive | 1-2 weeks | MEDIUM |

**Total:** 6-10 weeks

---

## Success Metrics

### Phase 0 (Must Pass)
1. Underconstrained oracle detects collision in test
2. Fuzzing loop runs >1000 iterations
3. Semantic oracles instantiate from config
4. All 5 novel attacks dispatch without warnings

### Phase 4
1. Constraint inference detects missing constraints
2. >80% constraint coverage on benchmarks
3. <60s time-to-bug on known issues
4. <5% false positives

---

## Immediate Next Steps (Week 1-2)

### Week 1
1. **Day 1-2:** Fix underconstrained oracle (stateful)
2. **Day 3-6:** Implement fuzzing loop
3. **Day 7:** Fix sampling + wire semantic oracles

### Week 2
1. **Day 8-9:** Implement attack dispatchers
2. **Day 10-12:** Backend constraint coverage
3. **Day 13-14:** Capability matrix + docs

---

## What's Actually Complete ✅

### Working
- ✅ Mock backend with constraint coverage
- ✅ Power scheduling (6 strategies)
- ✅ Structure-aware mutations
- ✅ Symbolic execution (Z3 seed generation)
- ✅ Taint analysis
- ✅ Constraint-guided seeds (R1CS/ACIR)
- ✅ Differential framework
- ✅ Multi-circuit composition
- ✅ Benchmarking suite
- ✅ PoC generator
- ✅ Delta debugging
- ✅ CI workflows
- ✅ JSON/Markdown/SARIF reports

### Partially Working (Need Fixes)
- ⚠️ 7 attacks work, 5 unimplemented
- ⚠️ Underconstrained detection (broken oracle)
- ⚠️ Coverage (mock works, real backends hash-only)
- ⚠️ Semantic oracles (exist but not wired)

### Not Working
- ❌ Coverage-guided fuzzing loop
- ❌ Constraint coverage for Noir/Halo2
- ❌ Stateful cross-execution oracles
- ❌ Field-specific arithmetic

---

**Focus:** Phase 0 must complete before novel oracles can work. The fuzzing loop and stateful oracles are prerequisites for 0-day discovery.
