# ZkPatternFuzz: Remaining Work

**Status:** 75% Complete (Phase 0 mostly done)  
**Remaining:** 4-7 weeks  
**Priority:** Backend constraint coverage + validation

---

## ⚠️ CRITICAL FINDINGS (Code Review 2024)

### Blockers Preventing 0-Day Discovery

1. **[FIXED] No Coverage-Guided Fuzzing Loop** - Continuous fuzzing phase added
2. **[FIXED] Broken Underconstrained Oracle** - Stateful oracle now records outputs
3. **[OPEN] Output-Hash-Only Coverage** - Real backends still lack constraint-level feedback
4. **[FIXED] 5 Unimplemented Attacks** - Dispatchers added for all novel attacks
5. **[FIXED] Wrong Underconstrained Sampling** - Public inputs now held constant
6. **[PARTIAL] Hard-Coded BN254 Field** - Circom/Noir/Halo2 now override; Cairo/Mock still default
7. **[FIXED] Semantic Oracles Unused** - Wired via config and adapter

---

## Phase 0: Fix Core Infrastructure (DONE) 🚨

### A. Fix Underconstrained Oracle (DONE)
- [x] Change `BugOracle::check()` to `&mut self` in `zk-fuzzer-core/src/oracle.rs`
- [x] Add `record_output()` to `UnderconstrainedOracle`
- [x] Wire into `FuzzingEngineCore::execute_and_learn()`
- [x] Regression test: collisions scoped to identical public inputs

### B. Implement Fuzzing Loop ✅ COMPLETE
- [x] Add `continuous_fuzzing_phase()` after attacks in `FuzzingEngine::run()`
- [x] Loop: `select_from_corpus() → mutate() → execute_and_learn()`
- [x] Add YAML params `fuzzing_iterations` / `fuzzing_timeout_seconds`
- [x] Add `--iterations` and `--timeout` CLI flags (in `run` subcommand)

### C. Fix Underconstrained Sampling (DONE)
- [x] Fix `run_underconstrained_attack()` to hold public inputs constant
- [x] Generate multiple private witnesses for same public inputs

### D. Wire Semantic Oracles (DONE)
- [x] Read `FuzzConfig.oracles` in `FuzzingEngine::new()`
- [x] Instantiate nullifier/merkle/range oracles based on config

### E. Implement Attack Dispatchers (DONE)
- [x] Add dispatch logic for ConstraintInference/Metamorphic/ConstraintSlice/SpecInference/WitnessCollision
- [x] Remove "not implemented" warnings

### F. Fix Field Modulus (DONE, Cairo/Mock pending)
- [x] Add `field_modulus()` to `CircuitExecutor` trait
- [x] Replace hard-coded `bn254_modulus_bytes()` calls
- [x] Wire executor-specific moduli for Circom/Noir/Halo2
- [ ] Add Cairo/Mock field overrides if needed

---

## Phase 1: Backend Constraint Coverage (1-2 weeks)

- [x] Noir `constraint_inspector()` available (ACIR)
- [x] Halo2 `constraint_inspector()` extraction (PLONK) + wire labels
- [x] Return `satisfied_constraints: Vec<usize>` from `execute_sync()`
- [x] Call `coverage.record_execution()` with actual constraints
- [x] Add wire labels for Cairo/Halo2 if possible
- [x] Validate coverage with real circuits (non-mock) (Circom + Noir multiplier coverage tests)

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

- [x] Implement `src/attacks/constraint_inference.rs`
- [ ] Execute violation witnesses to confirm acceptance
- [ ] Add label sources for Halo2/Cairo to improve pattern hits

### B. Metamorphic Oracles (3-4 days)
**Test invariants via transformations**

- [x] Implement `src/attacks/metamorphic.rs`
- [ ] Add circuit-specific relations/templates

### C. Constraint Slice (3 days)
**Mutate within dependency cones**

- [x] Implement `src/attacks/constraint_slice.rs`
- [ ] Validate on real circuits with correct output indices

### D. Spec Inference (3-4 days)
**Auto-learn properties, generate violations**

- [x] Implement `src/attacks/spec_inference.rs`
- [ ] Use full `sample_count` (not capped at 100) and reduce false positives

### E. Witness Collision (2 days)
- [x] Implement basic `src/attacks/witness_collision.rs`
- [ ] Enhance heuristics and reporting

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
1. [x] Underconstrained oracle detects collision in test
2. [x] Fuzzing loop runs >1000 iterations
3. [x] Semantic oracles instantiate from config
4. [x] All 5 novel attacks dispatch without warnings
5. [x] Collisions are scoped to identical public inputs

### Phase 4
1. Constraint inference detects missing constraints
2. >80% constraint coverage on benchmarks
3. <60s time-to-bug on known issues
4. <5% false positives

---

## Immediate Next Steps (Week 1-2)

### Week 1
1. **Day 1-2:** Implement real constraint coverage for Circom/Noir/Halo2
2. **Day 3:** Add CLI flags for `--iterations` / `--timeout`
3. **Day 4-5:** Add Cairo/Mock field overrides if needed
4. **Day 6-7:** Validate coverage on at least one real circuit

### Week 2
1. **Day 8-10:** Execute constraint-inference violations for confirmation
2. **Day 11-12:** Add wire labels for Halo2/Cairo (if available)
3. **Day 13-14:** Capability matrix + docs refresh

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
- ✅ Continuous fuzzing loop
- ✅ Stateful underconstrained oracle + public input scoping
- ✅ Semantic oracles wired via config
- ✅ Novel attack dispatchers implemented
- ✅ Field-specific modulus overrides (Circom/Noir/Halo2)
- ✅ Wire labels for Circom/Noir (constraint inference)

### Partially Working (Need Fixes)
- ⚠️ Coverage (mock works, real backends hash-only)
- ⚠️ Constraint inference heuristics (needs violation confirmation + more labels)
- ⚠️ Spec inference sample usage capped at 100
- ⚠️ Metamorphic relations are generic (need circuit-specific)
- ⚠️ Field-specific arithmetic still default for Cairo/Mock

### Not Working
- ❌ Real constraint coverage for Halo2/Cairo (and coverage-guided exploration on real circuits)

---

**Focus:** Phase 1 coverage + validation are now the bottleneck for real 0‑day discovery.
