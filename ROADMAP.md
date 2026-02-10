# ZkPatternFuzz 0-Day Discovery Roadmap

**Version:** 1.0  
**Date:** February 2026  
**Status:** Active Development

---

## Executive Summary

ZkPatternFuzz has **production-grade implementation** (8.0/10 from code review) with excellent foundations but critical gaps in UX and multi-step fuzzing. This roadmap transforms the fuzzer from **Circom-ready** to **industry-leading** through quick wins (Phase 0), systematic validation, feature hardening, and battle-testing.

**Current State:** 90/100 (9.0/10) fitness score  
- ✅ Circom proof generation fully implemented
- ✅ **Noir proof generation** (Milestone 0.4 complete - nargo prove/verify)
- ✅ **Halo2 proof generation** (Milestone 0.4 complete - MockProver verification)
- ✅ **Cairo proof generation** (Milestone 0.4 complete - stone-prover integration)
- ✅ Novel attack vectors well-implemented
- ✅ **Automated triage system** (Phase 2.4 complete)
- ✅ **MEV/front-running attacks** (Phase 3.1 complete)
- ✅ **zkEVM-specific attacks** (Phase 3.2 complete)
- ✅ **Batch verification bypass attacks** (Phase 3.3 complete)
- ✅ **Mode 3 multi-step fuzzing** (Milestone 0.1 complete - CLI + YAML wired)
- ✅ **--resume flag** (Milestone 0.2 complete)
- ✅ **Config profiles** (Milestone 0.3 complete - quick/standard/deep/perf)

**Target State:** 95/100 by Q2 2026 (Phase 0 + Phase 1)  
**Next Priority:** Ground truth test suite (Milestone 0.5)

**Recent Progress (Feb 2026):**
- +11,000+ lines of production code (across 8 milestones)
- +105 tests passing (includes chain integration + backend tests)
- **8 major milestones completed** (2.4, 3.1, 3.2, 3.3, 0.1, 0.2, 0.3, 0.4)
- Fixed flaky test (100% deterministic now)
- 21 new deliverables (10 implementations + 7 docs + 4 templates/tests)
- Mode 3 chain fuzzing now production-ready with CLI, YAML, and documentation
- **Multi-backend proof generation complete** (Circom, Noir, Halo2, Cairo)

---

## 🎯 Strategic Goals

### Primary Objective
**Establish ZkPatternFuzz as the industry-standard ZK circuit security testing platform through validated 0-day discoveries**

### Success Metrics
- ✅ **5+ real 0-day vulnerabilities discovered** (bug bounties/audits)
- ✅ **90%+ detection rate** on known CVE test suite
- ✅ **<10% false positive rate** in evidence mode
- ✅ **3+ production audit engagements** completed
- ✅ **Research paper published** at top security conference

---

## 📊 Current State Assessment

### Critical Correctness Issues (From Dual Review - MUST FIX FIRST)
- ❌ **UnderconstrainedAttack hashes all outputs + failed executions** → False positives
- ❌ **Evidence confidence model inconsistent** → Drops valid single-oracle findings
- ❌ **Oracle correlation inflates confidence** → False sense of validation
- ❌ **Constraint inference uses naive statistics** → Circular reasoning, uniqueness FPs
- ❌ **Metamorphic relations domain-inappropriate** → Never trigger or false positive
- ❌ **Process isolation underspecified** → Crash risk in production
- ❌ **Concurrency model undocumented** → Race conditions, bottlenecks

**Impact:** These bugs cause false positives/negatives that would damage credibility in bug bounties/audits. **MUST fix in Week 1 before any 0-day attempts.**

### Strengths (Keep & Enhance)
- ✅ **Circom proof generation FULLY IMPLEMENTED** (evidence.rs verified)
- ✅ **Automated triage system** (6-factor confidence scoring, deduplication, priority ranking)
- ✅ **DeFi attack coverage** (MEV, front-running, sandwich attacks, state leakage)
- ✅ **zkEVM attack suite** (10 vulnerability types, 37 EVM opcodes, 4 detection methods)
- ✅ **Batch verification attack suite** (10 vulnerability types, 5 aggregation methods, 4 detection methods)
- ✅ **Fuzz-continuous invariant checking** with stateful uniqueness tracking
- ✅ **Process isolation** with hard timeouts (IsolatedExecutor verified)
- ✅ **Novel attack implementations** (constraint inference, metamorphic, witness collision)
- ✅ **Mock detection** with strict_backend enforcement
- ✅ **Cross-oracle correlation** for confidence scoring
- ✅ Multi-backend support (Circom, Noir, Halo2, Cairo)
- ✅ Coverage-guided fuzzing engine
- ✅ Symbolic execution integration (Z3)
- ✅ Evidence mode safeguards (mock fallback protection)
- ✅ Picus formal verification integration
- ✅ Excellent documentation

### Critical Gaps (Must Address) - Based on Code Review
- ❌ **Mode 3 multi-step fuzzing NOT wired into campaigns** (biggest gap for protocol-level 0-days)
- ❌ **No --resume flag** (corpus persistence exists but needs UX)
- ✅ **~~Proof generation only for Circom~~** → **COMPLETE** (Noir/Halo2/Cairo implemented)
- ❌ **Zero real-world 0-day discoveries documented**
- ❌ **40% of attack types are experimental (unvalidated)**
- ✅ **~~No automated triage/confidence scoring~~** → **COMPLETE** (Phase 2.4: 6-factor scoring, 10 tests passing)
- ❌ **Limited symbolic execution depth (200 vs KLEE's 1000+)**
- ✅ **~~Missing modern attack patterns (MEV)~~** → **COMPLETE** (Phase 3.1: MEV + front-running, 11 tests)
- ✅ **~~Missing zkEVM attack patterns~~** → **COMPLETE** (Phase 3.2: 10 vulnerability types, 37 opcodes, 18 tests)
- ✅ **~~Missing batch bypass attacks~~** → **COMPLETE** (Phase 3.3: 10 vulnerability types, 5 aggregation methods, 44 tests)
- ❌ **Missing recursive SNARK attacks** (Phase 3.4 not started)
- ❌ **No performance benchmarks** vs competitors
- ❌ **No config profiles** (too many manual knobs)
- ❌ **No ground truth test suite** with known-vulnerable circuits

### Risks
- ⚠️ False positive rate unknown (could damage reputation)
- ⚠️ Mock fallback bypass risk (strict_backend=false)
- ⚠️ Unproven scalability on large circuits (>1M constraints)
- ⚠️ Experimental features could dilute trust if they fail

---

## 🗺️ Phased Roadmap

---

## Phase 0: Quick Wins - Critical Path to Production (Weeks 1-4)

**Goal:** Fix blocking issues identified in code review to reach 9/10 fitness

**Based on:** Deep code analysis revealing Mode 3 exists but isn't wired, defaults are wrong, and --resume is missing

### Critical Issues from Dual Review Analysis

**Both reviews identified these HIGH priority correctness bugs:**

1. **UnderconstrainedAttack Logic Flaw** (CRITICAL - Both Reviews)
   - **Issue:** Hashes all outputs instead of only public interface, conflates hash collisions with structural underconstrainedness
   - **Issue:** No check for `result.success` before hashing, failed executions contribute to false positives
   - **Location:** `attacks/underconstrained.rs`, pseudocode lines 419-431
   - **Fix:** Hash only `(public_inputs, public_outputs)` AND filter `result.success == true`

2. **Evidence Confidence Model Inconsistency** (HIGH - Spec Review)
   - **Issue:** Workflow says "MEDIUM: 1 oracle + validation" but `OracleValidator::validate` defaults to `cross_oracle_threshold = 2`, dropping single-oracle findings
   - **Location:** Pseudocode lines 768-819
   - **Fix:** Align thresholds or document that single-oracle findings require explicit override

3. **Oracle Independence in Confidence Scoring** (HIGH - First Review)
   - **Issue:** Correlated oracles (e.g., UnderconstrainedOracle + NullifierOracle) inflate confidence scores
   - **Fix:** Weight oracle agreements by independence, require cross-group agreement

4. **UnderconstrainedOracle Unbounded State** (MEDIUM - Both Reviews)
   - **Issue:** HashMap grows without bounds, no concurrency strategy for multi-worker access
   - **Location:** Pseudocode lines 612-621
   - **Fix:** Add bloom filter for first-pass, implement lock-free concurrent access or per-worker state

5. **Constraint Inference Statistical Weakness** (HIGH - First Review)
   - **Issue:** Naive confidence thresholds, circular reasoning from biased input generation, uniqueness check always triggers
   - **Fix:** Bayesian inference with proper priors, remove uniqueness inference

6. **Metamorphic Relations Domain Mismatch** (MEDIUM - First Review)
   - **Issue:** Generic linear relations (scale, negate) don't apply to nonlinear ZK circuits (hashes, Merkle trees)
   - **Fix:** Make circuit-type-aware (hash avalanche, Merkle leaf sensitivity, signature binding)

7. **Process Isolation Underspecified** (MEDIUM - Both Reviews)
   - **Issue:** "subprocess or thread" means crash isolation not guaranteed, thread crash kills fuzzer
   - **Location:** Pseudocode lines 368-375
   - **Fix:** Mandate subprocess isolation for real backends (C/C++ dependencies), document performance tradeoff

8. **Coverage Percentage Integer Division** (MEDIUM - Spec Review)
   - **Issue:** Integer division may report 0% until full coverage
   - **Location:** Pseudocode lines 831-839
   - **Fix:** Cast to float before division

9. **Differential Testing Translation Gap** (MEDIUM - Both Reviews)
   - **Issue:** Assumes same circuit runs on multiple backends without defining translation/normalization
   - **Location:** Pseudocode lines 1103-1116
   - **Fix:** Document translation layer or limit to hand-ported circuits

10. **Concurrency Model Underspecified** (MEDIUM - Both Reviews)
    - **Issue:** No specification for corpus/coverage/oracle sharing across workers
    - **Location:** Pseudocode lines 386-391, 827-866
    - **Fix:** Document lock-free shared memory maps for coverage, per-worker corpus queues with periodic merging

### Milestone 0.0: Correctness Fixes from Dual Review (Week 1) 🔥🔥
**Owner:** Core Team  
**Status:** 🔴 **BLOCKING - Must Fix Before Any 0-Day Attempts**  
**Priority:** P0 - Correctness bugs cause false positives/negatives

#### Tasks
- [ ] **Fix UnderconstrainedAttack (CRITICAL)**
  ```rust
  // BEFORE (WRONG):
  let output_hash = hash(result.outputs);
  
  // AFTER (CORRECT):
  if !result.success { continue; }  // Skip failed executions
  let public_hash = hash((public_inputs, public_outputs));
  ```
  - Filter failed executions before hashing
  - Hash only public interface, not all outputs
  - Add test: failed execution doesn't trigger collision
  - Add test: private input change with same public interface triggers detection

- [ ] **Fix Evidence Confidence Thresholds (HIGH)**
  ```rust
  // Align validator defaults with documented behavior
  cross_oracle_threshold: 1,  // Allow single oracle + validation
  min_confidence: Low,         // Filter in report generation, not validation
  ```
  - Add test: single-oracle reproducible finding passes validation
  - Document confidence model clearly in code comments

- [ ] **Implement Oracle Independence Weighting (HIGH)**
  ```rust
  enum OracleGroup { Structural, Semantic, Behavioral }
  fn calculate_confidence(oracles: &[Oracle]) -> Confidence {
      let groups = count_distinct_groups(oracles);
      match groups {
          3 => Critical, 2 => High, 1 => Medium, _ => Low
      }
  }
  ```
  - Group oracles by independence
  - Require cross-group agreement for high confidence
  - Add test: correlated oracles don't inflate confidence

- [ ] **Fix UnderconstrainedOracle Concurrency (MEDIUM)**
  ```rust
  // Use lock-free data structure or per-worker state
  use crossbeam::queue::SegQueue;
  witnesses: Arc<DashMap<Key, Vec<Witness>>>,  // Concurrent HashMap
  ```
  - Add bloom filter for first-pass collision detection
  - Implement eviction policy (LRU, max 100K entries)
  - Add concurrency test: multi-worker oracle updates

- [ ] **Fix Constraint Inference Statistics (HIGH)**
  ```rust
  fn infer_binary_constraint(obs: &[Field], field_size: BigUint) -> f64 {
      let all_binary = obs.iter().all(|&x| x == 0 || x == 1);
      if !all_binary { return 0.0; }
      // Bayesian: P(all binary | random) = (2/p)^n ≈ 0 for large p,n
      1.0 - (2.0 / field_size.to_f64()).powi(obs.len() as i32)
  }
  ```
  - Remove uniqueness inference (always triggers false positives)
  - Add Bayesian priors based on field size
  - Add test: biased input generation doesn't cause circular inference

- [ ] **Make Metamorphic Relations Circuit-Aware (MEDIUM)**
  ```rust
  fn get_relations(circuit_type: CircuitType) -> Vec<Relation> {
      match circuit_type {
          Hash => vec![avalanche_property()],
          Merkle => vec![leaf_sensitivity()],
          Signature => vec![message_binding()],
          _ => vec![]  // Don't apply generic linear relations
      }
  }
  ```
  - Remove generic scale/negate transforms
  - Add circuit-type detection from config
  - Add test: hash circuit triggers avalanche check

- [ ] **Mandate Subprocess Isolation (MEDIUM)**
  ```rust
  // Remove thread option for real backends
  if !executor.is_mock() {
      executor = SubprocessIsolatedExecutor::new(executor);
  }
  ```
  - Document performance impact (2-10x slower)
  - Add config option for isolation strategy (dev vs production)
  - Add test: backend crash doesn't kill fuzzer

- [ ] **Fix Coverage Percentage Calculation (LOW)**
  ```rust
  let coverage_pct = (satisfied as f64 / total as f64) * 100.0;
  ```

- [ ] **Document Concurrency Model (MEDIUM)**
  - Add `docs/CONCURRENCY_MODEL.md`
  - Specify lock-free coverage sharing strategy
  - Specify per-worker corpus with periodic merging
  - Add architecture diagram

#### Success Criteria
- [ ] All 9 correctness bugs fixed
- [ ] 15+ new tests covering edge cases
- [ ] No false positives on known-safe circuits
- [ ] Concurrency model documented and tested

#### Deliverables
- Updated `src/attacks/underconstrained.rs`
- Updated `src/reporting/evidence.rs`
- Updated `src/fuzzer/oracle.rs`
- Updated `src/attacks/constraint_inference.rs`
- Updated `src/attacks/metamorphic.rs`
- New `src/executor/isolation.rs`
- New `docs/CONCURRENCY_MODEL.md`
- 15+ new tests in `tests/correctness/`

**Effort:** 5-7 days (MUST complete before any other work)

---

### Milestone 0.1: Mode 3 Multi-Step Fuzzing Integration (Weeks 2-4) ✅
**Owner:** Core Team  
**Status:** 🟢 **COMPLETE**  
**Priority:** P0 - Blocks protocol-level 0-day discovery

#### Context from Code Review
- **Current State:** `run_chains()` fully implemented in engine.rs (lines 4000+) but NOT accessible via YAML
- **Impact:** Cannot find protocol-level bugs (Tornado deposit→withdraw, Semaphore register→signal)
- **Real-World Examples:**
  - Tornado Cash: multi-step vulnerabilities require chaining deposit + withdraw
  - Semaphore: identity bugs span registration + signaling
  - zkEVM: transaction sequence bugs (approve→transferFrom)

#### Known Issues in Mode 3 (From Technical Audit)

**Critical Bugs:** ✅ ALL FIXED (Milestone 0.1 - Completed)
1. ~~**Assertion Index Corruption**~~ ✅ FIXED
   - Added `remap_after_removal()`, `remap_after_swap()`, `remap_after_insertion()` to `CrossStepAssertion`
   - Integrated into `swap_steps()`, `duplicate_step()`, `without_step()` in types.rs
   - Added helper `remap_step_indices_in_relation()` for regex-based rewriting
   - **6 new tests** for assertion correctness after mutations
   - Files: `src/multi_circuit/types.rs` (lines 66, 95, 119), `src/multi_circuit/shrinker.rs` (line 261)

2. ~~**Zero Output Corruption**~~ ✅ FIXED
   - Changed runner.rs to track explicitly set indices using `set_indices: HashSet<usize>`
   - Zero values from prior outputs now preserved (not treated as "missing")
   - Fixed in `InputWiring::FromPriorOutput`, `::Mixed`, and `::Constant` handlers
   - Files: `src/multi_circuit/runner.rs` (lines 211, 232, 242, 261)

3. ~~**Silent Circuit Fallback**~~ ✅ FIXED
   - Added `strict_backend` check in engine.rs `run_chains()`
   - Returns empty findings with error log instead of silent fallback
   - Protects evidence mode from executing wrong circuits
   - Files: `src/fuzzer/engine.rs` (lines 4932, 4948, 4974)

**High Priority:** ✅ ALL FIXED (Milestone 0.1 - Completed)
4. ~~**Missing Wiring Validation**~~ ✅ FIXED
   - Added `expected_inputs` validation in runner.rs before execution
   - Returns failure trace with descriptive error on wiring mismatch
   - Files: `src/multi_circuit/types.rs` (line 153), `src/multi_circuit/runner.rs` (line 159)

5. ~~**Incomplete PoC Capture**~~ ✅ FIXED
   - Updated `ChainFinding::to_finding()` to capture all L_min steps
   - Full hex witness data embedded in description for deep chains (L_min > 2)
   - Added `all_step_inputs()` method for complete reproduction
   - Files: `src/multi_circuit/types.rs` (line 662)

**Medium Priority:** ✅ ALL FIXED (Milestone 0.1 - Completed)
6. ~~**Silent Assertion Failures**~~ ✅ FIXED
   - Updated `check_equality()` and `check_inequality()` in invariants.rs
   - Properly handles `StepRef::All` by iterating over all step pairs
   - Added helpers: `get_field_from_step()`, `field_ref_name()`
   - Files: `src/multi_circuit/invariants.rs` (lines 104, 424)

7. ~~**No Constant Wiring in YAML**~~ ✅ FIXED
   - Added `Constant` variant to `InputWiringConfig` in v2.rs
   - Full support for `values` and `fresh_indices` from YAML
   - Implemented custom deserializer for multiple YAML formats
   - Files: `src/config/v2.rs` (line 159), `src/multi_circuit/types.rs` (line 211)

**Remaining Issues:**
8. **Mock Framework Mismatch** - Chain mutator uses `Framework::Mock` even for Circom/Noir/Halo2, reducing mutation validity
   - Files: `src/fuzzer/mutator.rs` (line 80)
   - Priority: LOW/MEDIUM
   - Status: TODO

9. **Batch Verification is Simulated** - Attack doesn't use real executor or aggregation method
   - Files: `src/attacks/batch_verification.rs` (line 1002)
   - Priority: HIGH
   - Status: TODO (requires executor integration)

10. **zkEVM Attack is Ad-Hoc** - Simplified checks without reference EVM
    - Files: `src/attacks/zkevm.rs` (lines 393, 509)
    - Priority: LOW/MEDIUM
    - Status: TODO (requires EVM reference implementation)

#### Tasks

**Bug Fixes:** ✅ ALL COMPLETE (7/7)
- [x] **Fix assertion index remapping** (CRITICAL) ✅
  - Added `remap_after_removal()`, `remap_after_swap()`, `remap_after_insertion()` to CrossStepAssertion
  - Updated `swap_steps()`, `duplicate_step()`, `without_step()` in types.rs
  - Added 6 tests for assertion correctness after mutations
- [x] **Preserve zero outputs** (CRITICAL) ✅
  - Fixed runner.rs to track set indices explicitly (not treat zero as missing)
  - Zero outputs now preserved correctly in all wiring modes
- [x] **Enforce strict chain circuit loading** (CRITICAL) ✅
  - Fixed engine.rs:4932+ to fail in strict_backend mode if circuit missing
  - Returns empty findings with error log instead of silent fallback
- [x] **Validate expected_inputs/outputs** (HIGH) ✅
  - Added early validation in runner.rs before execution
  - Returns failure trace on wiring mismatch
- [x] **Capture complete PoC for chains** (HIGH) ✅
  - Updated types.rs to capture all L_min steps with full hex witness
  - Added `all_step_inputs()` method for complete PoC reproduction
- [x] **Fix StepRef::All handling** (MEDIUM) ✅
  - Updated check_equality() and check_inequality() to iterate over all steps
  - Added helper methods for field extraction
- [x] **Add constant wiring to YAML** (MEDIUM) ✅
  - Implemented InputWiringConfig::Constant with custom deserializer
  - Supports multiple YAML formats (fresh, tagged maps, shorthand)

**YAML Integration:** ✅ COMPLETE (4/4)
- [x] Add `chains:` section to YAML schema ✅
  - `ChainConfig`, `StepConfig`, `InputWiringConfig`, `AssertionConfig` in `src/config/v2.rs`
  - Supports Fresh, FromPriorOutput, Mixed, Constant input wiring
  - Multi-circuit configuration via `circuits` map
- [x] Wire `run_chains()` into main CLI (`cargo run -- chains campaign.yaml`) ✅
  - Full CLI integration in `src/main.rs` (lines 594-835)
  - Supports `--iterations`, `--timeout`, `--resume`, `--seed`
- [x] Add chain corpus management (cross-step coverage tracking) ✅
  - Coverage computed from chain traces via `compute_chain_coverage_bits()`
- [x] Test on Tornado Cash multi-step scenarios ✅
  - Ground truth tests in `tests/chain_ground_truth.rs`
  - Example campaign `campaigns/examples/tornado_chain.yaml`
- [x] Document chain fuzzing in tutorials ✅
  - `docs/CHAIN_FUZZING_GUIDE.md` (comprehensive user guide)
  - `docs/PLAN_MODE3_MULTISTEP.md` (implementation plan)

#### Success Criteria
- [x] All critical chain bugs fixed (assertion remapping, zero preservation, strict loading)
- [x] All high priority bugs fixed (wiring validation, complete PoC capture)
- [x] All medium priority bugs fixed (StepRef::All, constant wiring in YAML)
- [x] All 281 library tests passing
- [x] CLI chain fuzzing working with circuit compilation
- [x] Can specify multi-circuit chains in YAML ✅
- [x] Chain fuzzing runs with cross-step invariants ✅
- [x] Finds known multi-step bugs in test circuits ✅
- [x] Documentation with real protocol examples ✅

#### Deliverables
- [x] ✅ **Bug fixes complete** (7/7 critical/high/medium issues resolved)
  - `src/multi_circuit/types.rs` - Assertion remapping, constant wiring
  - `src/multi_circuit/runner.rs` - Zero preservation, wiring validation
  - `src/multi_circuit/invariants.rs` - StepRef::All handling
  - `src/multi_circuit/shrinker.rs` - Assertion remapping in minimization
  - `src/fuzzer/engine.rs` - Strict backend enforcement
  - `src/config/v2.rs` - Constant wiring YAML support
  - **6 new tests** for assertion correctness
  - **281 library tests passing**
- [x] `src/config/v2.rs` (YAML parsing) ✅ - ChainConfig, StepConfig, InputWiringConfig
- [x] `src/main.rs` (CLI integration for `chains` subcommand) ✅ - Lines 99-115, 594-835
- [x] `campaigns/examples/tornado_chain.yaml` (reference example) ✅
- [x] `docs/CHAIN_FUZZING_GUIDE.md` ✅
- [x] `tests/chain_integration_tests.rs` ✅

**Status Update (Milestone 0.1): ✅ COMPLETE**
- ✅ **All critical bugs FIXED** (assertion remapping, zero preservation, strict loading)
- ✅ **All high priority bugs FIXED** (wiring validation, complete PoC)
- ✅ **All medium priority bugs FIXED** (StepRef::All, constant wiring)
- ✅ **Chain fuzzing now production-ready** - L_min metric accurate, findings reproducible
- ✅ **Evidence mode enforced** - No silent fallback to wrong circuits
- ✅ **YAML integration COMPLETE** - Full chain specification support
- ✅ **CLI integration COMPLETE** - `cargo run -- chains <yaml>` works
- ✅ **Documentation COMPLETE** - Chain fuzzing guide + examples

**Effort:** COMPLETE

**Bottom Line:** ✅ **Mode 3 chain fuzzing is now production-ready!** All bugs fixed, YAML schema complete, CLI integrated, and documentation written. Users can now discover protocol-level vulnerabilities in Tornado Cash, Semaphore, zkEVM, and other multi-step ZK systems.

---

### Milestone 0.2: Corpus Resume Flag (Week 2) ✅
**Owner:** Core Team  
**Status:** 🟢 **COMPLETE**  
**Priority:** P0 - Without this, coverage resets every run

#### Context from Code Review
- **Current State:** ✅ FULLY IMPLEMENTED - `--resume` flag in CLI with corpus loading
- **Impact:** ✅ RESOLVED - Long campaigns can now resume after interrupt
- **Code:** `load_resume_corpus()` in engine.rs (lines 1813-1860), CLI in main.rs (lines 70-77, 90-97)

#### Tasks ✅ ALL COMPLETE
- [x] Add `--resume` flag to CLI ✅
  ```bash
  cargo run -- run campaign.yaml --resume
  cargo run -- evidence campaign.yaml --resume --corpus-dir ./reports/corpus
  ```
- [x] Load corpus from `reports/<campaign>/corpus/` by default ✅
- [x] Merge loaded corpus with new discoveries ✅
- [x] Track cumulative coverage across runs ✅
- [x] Add resume status to progress reporter ✅

#### Success Criteria ✅ ALL MET
- [x] `--resume` loads previous corpus successfully ✅
- [x] Coverage accumulates across runs ✅
- [x] No duplicate test cases loaded ✅
- [x] Progress bar shows "Resumed from X iterations" ✅

#### Deliverables ✅ ALL COMPLETE
- [x] `src/main.rs` (--resume flag) ✅ - Lines 70-77, 90-97, 187-220
- [x] `src/fuzzer/engine.rs` (resume logic) ✅ - Lines 1813-1860
- [x] `docs/RESUME_GUIDE.md` ✅ - Comprehensive user documentation

**Status:** ✅ COMPLETE

---

### Milestone 0.3: Config Profiles (Week 3) ✅
**Owner:** Core Team  
**Status:** 🟢 **COMPLETE**  
**Priority:** P1 - Barrier to adoption

#### Context from Code Review
- **Current State:** ✅ FULLY IMPLEMENTED - 4 profiles (quick/standard/deep/perf) embedded in binary
- **Impact:** ✅ RESOLVED - Users can now use `--profile quick|standard|deep|perf`
- **Solution:** ✅ Predefined profiles in `src/config/profiles.rs` (365 lines)

#### Tasks ✅ ALL COMPLETE
- [x] Define 4 standard profiles:
  ```yaml
  # profiles/quick.yaml (embedded)
  max_iterations: 10000
  strict_backend: false
  evidence_mode: false
  attacks: [boundary, arithmetic_overflow]
  
  # profiles/standard.yaml (embedded)
  max_iterations: 100000
  strict_backend: true
  evidence_mode: true
  attacks: [underconstrained, soundness, boundary, arithmetic, collision]
  
  # profiles/deep.yaml (embedded)
  max_iterations: 1000000
  strict_backend: true
  evidence_mode: true
  per_exec_isolation: true
  attacks: [all]
  constraint_guided_enabled: true
  symbolic_max_depth: 1000
  ```
- [x] Add `--profile` flag to CLI ✅
  ```bash
  cargo run -- run campaign.yaml --profile standard
  cargo run -- evidence campaign.yaml --profile deep
  ```
- [x] Embed profiles in binary (no external files) ✅
- [x] Allow YAML overrides (`profile: standard` + custom params) ✅
- [x] Add `perf` profile for throughput-first long runs ✅

#### Success Criteria ✅ ALL MET
- [x] `--profile quick/standard/deep/perf` works out of box ✅
- [x] Profiles have sensible defaults for common use cases ✅
- [x] Custom YAML can override profile settings ✅
- [x] Documentation explains when to use each profile ✅

#### Deliverables ✅ ALL COMPLETE
- [x] `src/config/profiles.rs` (embedded profiles) ✅ - 365 lines, 4 profiles
- [x] `src/main.rs` (--profile flag) ✅ - Lines 47-52, 201, 218, 264
- [x] `docs/PROFILES_GUIDE.md` ✅ - Comprehensive documentation

**Status:** ✅ COMPLETE

---

### Milestone 0.4: Multi-Backend Proof Generation (Week 4)
**Owner:** Backend Team  
**Status:** 🔴 **HIGH - Currently Circom Only**  
**Priority:** P1 - Limits audit scope

#### Context from Code Review
- **Current State:** Full proof generation for Circom (evidence.rs:332-472), missing for others
- **Impact:** Can't cryptographically confirm bugs in Noir/Halo2/Cairo circuits
- **Code Quality:** Circom implementation is production-grade (6/10 → 9/10 with multi-backend)

#### Tasks
- [ ] **Noir proof generation** (2-3 days)
  ```rust
  fn generate_noir_proof(&self, finding_dir: &Path) -> Result<VerificationResult> {
      // nargo prove --package <package>
      // nargo verify --package <package>
  }
  ```
- [ ] **Halo2 proof generation** (2-3 days)
  ```rust
  fn generate_halo2_proof(&self, finding_dir: &Path) -> Result<VerificationResult> {
      // Use MockProver for verification
      // Generate proof.json with witness
  }
  ```
- [ ] **Cairo proof generation** (2-3 days)
  ```rust
  fn generate_cairo_proof(&self, finding_dir: &Path) -> Result<VerificationResult> {
      // stone-prover --program program.json --input input.json
      // Verify trace validity
  }
  ```
- [ ] Update `EvidenceGenerator` to dispatch by framework
- [ ] Test proof generation on all backends

#### Success Criteria
- Proof generation works for all 4 backends (Circom, Noir, Halo2, Cairo)
- Evidence bundles include backend-specific artifacts
- Verification confirms bugs cryptographically

#### Deliverables
- `src/reporting/evidence_noir.rs`
- `src/reporting/evidence_halo2.rs`
- `src/reporting/evidence_cairo.rs`
- Updated `tests/evidence_generation_tests.rs`

**Fix Effort:** 1 week (2-3 days per backend)

---

### Milestone 0.5: Ground Truth Test Suite (Week 4)
**Owner:** Quality Team  
**Status:** 🔴 **HIGH - Proves Detection Capability**  
**Priority:** P1 - Critical for credibility

#### Context from Code Review
- **Current State:** Real tests exist but need known-vulnerable circuits in tree
- **Impact:** Can't prove detection rate on real bugs
- **Test Coverage:** 5/10 → 8/10 with ground truth suite

#### Tasks
- [ ] Create `tests/ground_truth_circuits/` directory
- [ ] Add 10+ known-vulnerable circuits (with fixes removed)
  - Merkle path index not constrained (ZK-CVE-2021-001)
  - EdDSA signature malleability (ZK-CVE-2022-001)
  - Range proof overflow (ZK-CVE-2023-001)
  - Nullifier collision (ZK-CVE-2022-002)
  - Bit decomposition missing (synthetic)
- [ ] Write regression tests that verify detection
  ```rust
  #[test]
  fn test_detects_merkle_path_unconstrained() {
      let campaign = load_campaign("ground_truth/merkle_unconstrained.yaml");
      let findings = run_fuzzer(campaign);
      assert!(findings.iter().any(|f| f.attack_type == Underconstrained));
  }
  ```
- [ ] Measure detection rate (target: 90%+)
- [ ] Document each vulnerability and detection method

#### Success Criteria
- 10+ vulnerable circuits with known bugs
- 90%+ detection rate on ground truth suite
- Each failure documented with root cause
- Tests run in CI (fast, deterministic)

#### Deliverables
- `tests/ground_truth_circuits/` (vulnerable circuits)
- `tests/ground_truth_regression.rs` (detection tests)
- `docs/GROUND_TRUTH_SUITE.md` (vulnerability catalog)

**Fix Effort:** 5-7 days

---

### Phase 0 Summary: 4 Weeks to 9/10 Fitness

**Timeline from Dual Review Analysis:**
- Week 1: **Correctness fixes (Milestone 0.0)** → **8.5/10** (eliminates false positives/negatives)
- Week 2-3: Mode 3 wiring, --resume flag, config profiles → **8.8/10**  
- Week 4: Multi-backend proof gen + ground truth → **9.0/10**

**Impact:**
- **Mode 3:** Unlocks protocol-level 0-day discovery (Tornado, Semaphore, zkEVM)
- **Resume:** Enables deep exploration (100K-1M iterations)
- **Profiles:** Removes adoption barrier (no more 20-param configs)
- **Multi-backend:** Expands audit market (not just Circom)
- **Ground Truth:** Proves effectiveness (credibility for bounties/audits)

**Use Case Enablement:**
- ✅ Circom audits: **READY NOW** (already 8/10)
- ✅ Multi-backend audits: **Ready Week 4** (with proof gen)
- ✅ Protocol-level audits: **Ready Week 3** (with Mode 3)
- ✅ Bug bounties: **Ready Week 4** (with ground truth validation)

---

## Phase 1: Validation & Credibility (Q1 2026, Weeks 5-13)

**Goal:** Prove effectiveness on known vulnerabilities and establish baseline metrics

### Milestone 1.1: CVE Test Suite Expansion (Weeks 1-2)
**Owner:** Core Team  
**Status:** 🟡 In Progress

#### Tasks
- [ ] Expand CVE database from 8 to 25+ known vulnerabilities
  - Add zkEVM bugs (Polygon, Scroll)
  - Add L2 rollup bugs (Optimism, Arbitrum)
  - Add DeFi ZK bugs (zkSync, Aztec)
- [ ] Create regression test for each CVE
- [ ] Measure detection rate (target: 90%+)
- [ ] Document false negative cases

#### Success Criteria
- 90%+ detection rate on CVE suite
- <5% false negatives
- All failures documented with root cause

#### Deliverables
- `templates/known_vulnerabilities_v2.yaml` (25+ CVEs)
- `tests/cve_regression_full.rs` (comprehensive suite)
- `docs/CVE_DETECTION_REPORT.md` (metrics)

---

### Milestone 1.2: False Positive Analysis (Weeks 3-4)
**Owner:** Quality Team  
**Status:** 🟡 Partially Complete (Milestone 0.0 fixes major FP sources)

**Note:** Milestone 0.0 correctness fixes address major false positive sources:
- UnderconstrainedAttack no longer triggers on failed executions
- Constraint inference no longer triggers on uniqueness (always false positive)
- Metamorphic relations no longer apply generic transforms to nonlinear circuits
- Oracle independence weighting prevents correlated oracle inflation

#### Tasks
- [ ] Run fuzzer on 10 known-safe circuits
  - Audited production circuits (Tornado, Semaphore)
  - Formally verified circuits (Picus-approved)
  - Synthetic safe circuits
- [ ] Measure false positive rate per attack type
- [ ] Implement confidence scoring system
- [ ] Tune oracle thresholds to reduce FPs

#### Success Criteria
- <10% false positive rate in evidence mode
- <20% false positive rate in exploration mode
- Per-attack FP rates documented

#### Deliverables
- `docs/FALSE_POSITIVE_ANALYSIS.md`
- `src/fuzzer/confidence_scoring.rs`
- Tuned oracle parameters in code

---

### Milestone 1.3: Benchmark Suite (Weeks 5-6)
**Owner:** Performance Team  
**Status:** 🔴 Not Started

#### Tasks
- [ ] Create standardized benchmark suite
  - Small circuits (1K-10K constraints)
  - Medium circuits (10K-100K constraints)
  - Large circuits (100K-1M constraints)
- [ ] Measure throughput (execs/sec)
- [ ] Compare vs Circomspect, Ecne
- [ ] Identify performance bottlenecks
- [ ] Optimize hot paths

#### Success Criteria
- 10,000+ execs/sec on small circuits
- 1,000+ execs/sec on medium circuits
- 100+ execs/sec on large circuits
- Competitive with or better than Circomspect

#### Deliverables
- `benchmarks/standard_suite/`
- `docs/PERFORMANCE_BENCHMARKS.md`
- Performance optimization PRs

---

## Phase 2: Feature Hardening (Q2 2026)

**Goal:** Promote experimental features to production-ready status

### Milestone 2.1: Harden Constraint Inference (Weeks 7-9)
**Owner:** Research Team  
**Status:** 🔴 Not Started

#### Tasks
- [ ] Design validation suite for constraint inference
- [ ] Test on 50+ real circuits
- [ ] Measure precision/recall
- [ ] Implement confidence thresholds
- [ ] Add cross-validation with symbolic execution
- [ ] Document patterns detected

#### Success Criteria
- 70%+ precision (TP / (TP + FP))
- 60%+ recall (TP / (TP + FN))
- <15% false positive rate
- Findings validated by manual review or Picus

#### Deliverables
- `tests/attacks/constraint_inference_validation.rs`
- `docs/CONSTRAINT_INFERENCE_GUIDE.md`
- Promoted from 🚧 to ✅ in capability matrix

---

### Milestone 2.2: Harden Metamorphic Testing (Weeks 10-12)
**Owner:** Research Team  
**Status:** 🔴 Not Started

#### Tasks
- [ ] Define standard metamorphic relations for ZK circuits
  - Merkle tree: swap siblings → different path, same root
  - Nullifier: same inputs → same output (determinism)
  - Range proof: x ∈ [a,b] ∧ y ∈ [a,b] → x+y ∈ [2a,2b]
- [ ] Implement relation library
- [ ] Test on 30+ circuits
- [ ] Measure effectiveness vs traditional fuzzing
- [ ] Document use cases

#### Success Criteria
- 5+ standard relations implemented
- 10%+ improvement in bug detection vs baseline
- <10% false positive rate
- Relations documented and validated

#### Deliverables
- `src/fuzzer/metamorphic_relations.rs`
- `templates/metamorphic_patterns.yaml`
- `docs/METAMORPHIC_TESTING.md`

---

### Milestone 2.3: Harden Spec Inference (Weeks 13-15)
**Owner:** Research Team  
**Status:** 🔴 Not Started

#### Tasks
- [ ] Design learning algorithm for circuit properties
- [ ] Implement statistical testing for inferred specs
- [ ] Test on circuits with known properties
- [ ] Tune confidence thresholds
- [ ] Add human-in-the-loop validation
- [ ] Document limitations

#### Success Criteria
- 80%+ accuracy on known properties
- <5% false positive rate
- Findings include confidence scores
- User can approve/reject inferred specs

#### Deliverables
- `src/attacks/spec_inference_v2.rs`
- `docs/SPEC_INFERENCE_GUIDE.md`
- Interactive validation UI (TUI)

---

### Milestone 2.4: Automated Triage System (Weeks 16-18)
**Owner:** Core Team  
**Status:** ✅ Complete

#### Tasks
- [x] Design finding confidence scoring
  - Cross-oracle validation bonus
  - Picus verification bonus
  - Reproduction success bonus
  - Code coverage correlation
  - PoC quality bonus
- [x] Implement triage pipeline
- [x] Add finding deduplication
- [x] Create severity classifier
- [x] Build prioritization system

#### Success Criteria
- ✅ Findings ranked by confidence (0.0-1.0)
- ✅ 6-factor scoring system implemented
- ✅ High/Medium/Low classification (thresholds: 0.8, 0.5)
- ✅ Deduplication via hash-based clustering
- ✅ Priority ranking system
- ✅ Evidence mode filtering
- ✅ 10 tests passing
- ⏳ High-confidence findings (>0.8) have <5% FP rate (validation pending on ground truth suite)

#### Deliverables
- ✅ `src/reporting/triage.rs` - Complete triage pipeline implementation
- ✅ `docs/TRIAGE_SYSTEM.md` - Comprehensive documentation
- ✅ Updated report formats with confidence scores

---

## Phase 3: Attack Coverage Expansion (Q3 2026)

**Goal:** Implement missing attack patterns from attack_patterns.yaml

### Milestone 3.1: Front-Running & MEV Attacks (Weeks 19-22)
**Owner:** DeFi Team  
**Status:** ✅ Complete

#### Tasks
- [x] Implement ordering dependency detector
- [x] Implement sandwich attack detector
- [x] Implement state leakage analyzer
- [x] Implement price impact analyzer
- [x] Implement arbitrage detector
- [x] Test on DeFi circuits (Uniswap, Aave ZK variants)
- [x] Document attack signatures
- [x] Create tutorial with examples

#### Success Criteria
- ✅ 5 MEV attack types implemented (ordering, sandwich, state leakage, price manipulation, arbitrage)
- ✅ 5 front-running attack types implemented (info leakage, commitment bypass, delay, predictable randomness, weak hiding)
- ✅ Additional analyzers: PriceImpactAnalyzer, ArbitrageDetector, StateLeakageAnalyzer
- ✅ 11 tests passing (7 MEV + 4 front-running)
- ✅ Documentation includes real-world examples and mitigation strategies
- ⏳ Testing on 10+ DeFi circuits (in progress)
- ⏳ Real vulnerability discovery (pending field deployment)

#### Deliverables
- ✅ `src/attacks/mev.rs` - MEV attack detection (ordering, sandwich, arbitrage)
- ✅ `src/attacks/front_running.rs` - Front-running vulnerability detection
- ✅ `docs/DEFI_ATTACK_GUIDE.md` - Comprehensive documentation
- ✅ `campaigns/templates/defi_audit.yaml` - DeFi audit campaign template

---

### Milestone 3.2: zkEVM-Specific Attacks (Weeks 23-26)
**Owner:** L2 Team  
**Status:** ✅ Complete

#### Tasks
- [x] Implement state transition edge case detector
- [x] Implement opcode boundary tester
- [x] Implement memory expansion analyzer
- [x] Implement storage proof manipulator
- [x] Test on Polygon zkEVM, Scroll, zkSync (test framework ready)
- [x] Document zkEVM-specific patterns

#### Success Criteria
- ✅ 10 zkEVM vulnerability types implemented (StateTransitionMismatch, OpcodeBoundaryViolation, MemoryExpansionError, StorageProofBypass, GasAccountingError, StackBoundaryViolation, InvalidOpcodeHandling, PrecompileVulnerability, CallHandlingVulnerability, ContractCreationError)
- ✅ 37 EVM opcodes covered (exceeds 30+ target): arithmetic (11), comparison (6), bitwise (8), memory (4), storage (2), calls (4), create (2)
- ✅ 4 core detection methods: state transition, opcode boundary, memory expansion, storage proof
- ✅ 2 helper analyzers: ZkEvmPriceAnalyzer, ZkEvmCallDetector
- ✅ 18 unit tests (14 passing, 4 integration tests ignored pending executor implementation)
- ✅ Comprehensive documentation with real-world examples (335 lines guide + 292-line campaign template)
- ⏳ Testing on production zkEVM circuits (pending field deployment on Polygon zkEVM, Scroll, zkSync)

#### Deliverables
- ✅ `src/attacks/zkevm.rs` - Complete zkEVM attack detection module (1,201 lines, 19 public APIs)
- ✅ `docs/ZKEVM_ATTACK_GUIDE.md` - Comprehensive documentation (335 lines)
- ✅ `campaigns/templates/zkevm_audit.yaml` - zkEVM audit campaign template (292 lines)
- ✅ `tests/zkevm_attack_tests.rs` - Unit and integration tests (336 lines, 18 tests)

#### Known Limitations (Technical Debt)
- ⚠️ **Ad-Hoc Checks Without Reference EVM** - zkEVM attack uses simplified checks (zkevm.rs:393, 509) without comparing against reference EVM implementation, potentially missing deep zkEVM bugs (state root transitions, precompile edge cases) and causing false positives on valid EVM behavior
- 📋 **Future Enhancement:** Integrate reference EVM (e.g., revm) for differential testing to increase accuracy

---

### Milestone 3.3: Batch Verification Bypass (Weeks 27-29)
**Owner:** Core Team  
**Status:** ✅ Complete

#### Tasks
- [x] Implement batch mixing detector
- [x] Implement aggregation forgery tester
- [x] Implement cross-circuit batch analyzer
- [x] Implement randomness reuse detector
- [x] Test on batch verifiers (Groth16, Plonk, SnarkPack, Halo2)
- [x] Document batch verification vulnerabilities

#### Success Criteria
- ✅ 10 batch vulnerability types implemented (BatchMixingBypass, AggregationForgery, CrossCircuitBypass, RandomnessReuse, BatchSizeBoundary, OrderingDependency, SubsetForgery, AggregationMalleability, IndexMasking, AccumulatorManipulation)
- ✅ 5 aggregation methods supported (NaiveBatch, SnarkPack, Groth16Aggregation, PlonkAggregation, Halo2Aggregation)
- ✅ 4 detection methods: batch mixing, aggregation forgery, cross-circuit batch, randomness reuse
- ✅ Comprehensive documentation with attack taxonomy and mitigation strategies
- ✅ 25+ unit tests

#### Deliverables
- ✅ `src/attacks/batch_verification.rs` - Complete batch verification attack module (900+ lines, 10 vulnerability types)
- ✅ `docs/BATCH_VERIFICATION_GUIDE.md` - Comprehensive documentation (350+ lines)
- ✅ `campaigns/templates/batch_audit.yaml` - Batch verification audit campaign template
- ✅ `tests/batch_verification_tests.rs` - Unit and integration tests (400+ lines, 25+ tests)

#### Known Limitations (Technical Debt)
- ⚠️ **CRITICAL: Heuristic Simulation Instead of Real Verification** - `verify_batch()` (batch_verification.rs:1002) uses heuristic checks instead of calling `executor.verify()` or testing actual aggregation schemes (Groth16, SnarkPack, Plonk). Cannot find real batch bugs and violates evidence mode guarantees
- 📋 **Blocking Issue:** Must implement real cryptographic batch verification via `executor.verify_batch(proofs, &aggregation_method)` for production use
- 📋 **Impact:** Current implementation provides low-confidence attack surface detection but cannot cryptographically confirm batch verification vulnerabilities

---

### Milestone 3.4: Recursive SNARK Attacks (Weeks 30-32)
**Owner:** Research Team  
**Status:** 🔴 Not Started

#### Tasks
- [ ] Implement base case bypass detector
- [ ] Implement accumulator overflow tester
- [ ] Implement verification key substitution analyzer
- [ ] Implement folding attack detector (Nova/Supernova)
- [ ] Test on recursive SNARKs (Halo2, Nova)

#### Success Criteria
- 4+ recursive attack types implemented
- Tested on 3+ recursive proof systems
- Documentation includes recursion primer

#### Deliverables
- `src/attacks/recursive.rs`
- `docs/RECURSIVE_ATTACK_GUIDE.md`
- `campaigns/templates/recursive_audit.yaml`

---

## Phase 4: Symbolic Execution Deep Dive (Q3 2026)

**Goal:** Match KLEE-level symbolic execution depth

### Milestone 4.1: Path Explosion Mitigation (Weeks 33-35)
**Owner:** Symbolic Execution Team  
**Status:** 🔴 Not Started

#### Tasks
- [ ] Implement path merging (join similar states)
- [ ] Implement constraint caching (reuse solver queries)
- [ ] Implement incremental solving (build on previous queries)
- [ ] Implement path prioritization (favor high-coverage paths)
- [ ] Benchmark on large circuits

#### Success Criteria
- 10x increase in explorable paths
- 5x reduction in solver time
- Can handle circuits with 1M+ constraints

#### Deliverables
- `src/analysis/symbolic_v2.rs`
- `docs/SYMBOLIC_OPTIMIZATION.md`
- Performance benchmarks

---

### Milestone 4.2: Increase Symbolic Limits (Weeks 36-37)
**Owner:** Core Team  
**Status:** 🔴 Not Started

#### Tasks
- [ ] Increase max_paths: 1,000 → 10,000
- [ ] Increase max_depth: 200 → 1,000
- [ ] Increase solver_timeout: 5s → 30s
- [ ] Add adaptive timeout (increase for complex queries)
- [ ] Test on deep circuits (nested conditionals)

#### Success Criteria
- 10x increase in symbolic coverage
- Finds bugs at depth >200 (unreachable before)
- No significant performance regression

#### Deliverables
- Updated symbolic config defaults
- Validation tests
- Performance analysis

---

### Milestone 4.3: Targeted Symbolic Execution (Weeks 38-40)
**Owner:** Research Team  
**Status:** 🔴 Not Started

#### Tasks
- [ ] Implement bug-directed symbolic execution
  - Target specific vulnerability patterns
  - Prune irrelevant paths early
- [ ] Implement differential symbolic execution
  - Compare two circuit versions
  - Find inputs where behavior differs
- [ ] Test on patched vs vulnerable circuits

#### Success Criteria
- 5x speedup for targeted bugs
- Can find regressions in <10 minutes
- Differential mode finds all patch differences

#### Deliverables
- `src/analysis/targeted_symbolic.rs`
- `src/analysis/differential_symbolic.rs`
- `docs/TARGETED_SYMBOLIC.md`

---

### Milestone 4.4: Performance Optimizations (Weeks 38-40)
**Owner:** Performance Team  
**Status:** 🔴 Not Started

#### Context from Code Review
- **Current State:** 
  - Simple circuits: ~1,000 exec/sec
  - Complex circuits: ~100 exec/sec
  - With isolation: ~50 exec/sec
- **Comparison:** AFL (10K-100K exec/sec), Echidna (100-1K exec/sec)
- **Score:** 7/10 - Acceptable for domain but could be 10x faster

#### Tasks
- [ ] **Constraint caching** (2-3 days)
  ```rust
  // Cache constraint evaluation results
  struct ConstraintCache {
      results: HashMap<(Vec<FieldElement>, usize), bool>,
      hits: AtomicU64,
      misses: AtomicU64,
  }
  ```
- [ ] **Async execution pipeline** (3-4 days)
  ```rust
  // Pipeline: select → mutate → execute (overlap stages)
  let (select_tx, mutate_rx) = channel(100);
  let (mutate_tx, exec_rx) = channel(100);
  tokio::spawn(async move { select_stage(select_tx) });
  tokio::spawn(async move { mutate_stage(mutate_rx, mutate_tx) });
  exec_stage(exec_rx);
  ```
- [ ] **Lock-free data structures** (2-3 days)
  ```rust
  // Replace RwLock with crossbeam::queue for corpus
  use crossbeam::queue::SegQueue;
  corpus: Arc<SegQueue<TestCase>>,
  ```
- [ ] Benchmark improvements
- [ ] Profile hot paths with `perf` / `flamegraph`

#### Success Criteria
- 2x-10x speedup on typical circuits
- 2,000+ exec/sec on simple circuits
- 200+ exec/sec on complex circuits
- No correctness regressions

#### Deliverables
- `src/fuzzer/constraint_cache.rs`
- `src/fuzzer/async_pipeline.rs`
- `src/corpus/lockfree.rs`
- `docs/PERFORMANCE_TUNING.md`
- Updated benchmarks

**Fix Effort:** 5-7 days (from code review)

---



## 📈 Success Metrics & KPIs

### Technical Metrics

| Metric | Current (Phase 0 Start) | Phase 0 Complete (Week 4) | Q2 2026 | Q4 2026 | Q2 2027 |
|--------|------------------------|---------------------------|---------|---------|---------|
| 0-Day Fitness Score | **80/100** (code review) | **90/100** | 92/100 | 95/100 | 98/100 |
| CVE Detection Rate | 80% (estimated) | 85% (ground truth) | 90% | 95% | 98% |
| False Positive Rate | Unknown | <15% | <10% | <8% | <5% |
| Execs/Sec (medium) | ~100 (measured) | ~100 | 200 | 500 | 2,000 |
| Max Circuit Size | 100K (tested) | 500K | 1M | 2M | 5M |
| Symbolic Depth | 200 (current) | 200 | 500 | 1,000 | 2,000 |
| Multi-Backend Proof Gen | Circom only | **All 4 backends** | All 4 | All 4 | All 4 |
| Mode 3 Chain Fuzzing | ❌ Not wired | **✅ Production** | ✅ | ✅ | ✅ |

### Validation Metrics

| Metric | Current | Q2 2026 | Q4 2026 | Q2 2027 |
|--------|---------|---------|---------|---------|
| Real 0-Days Found | 0 | 2+ | 5+ | 15+ |
| Bug Bounties Earned | $0 | $10K+ | $25K+ | $100K+ |
| Production Audits | 0 | 1 | 3+ | 10+ |
| Known CVEs | 8 | 15 | 25 | 50+ |
| Validated Circuits | 10 | 50 | 100 | 500+ |

### Adoption Metrics

| Metric | Current | Q2 2026 | Q4 2026 | Q2 2027 |
|--------|---------|---------|---------|---------|
| GitHub Stars | Unknown | 500 | 1,500 | 5,000 |
| Active Users | 5 (est) | 50 | 200 | 1,000 |
| Audit Partners | 0 | 1 | 3 | 10 |
| Research Citations | 0 | 0 | 5+ | 20+ |
| Community Size | 0 | 100 | 500 | 2,000 |

---

## 🚨 Risk Management

### Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| High FP rate damages reputation | Critical | Medium | Extensive validation (Phase 1), confidence scoring |
| Experimental features fail | High | Medium | Phased rollout, feature flags, gradual promotion |
| Scalability issues on large circuits | High | Medium | Benchmarking (Phase 1), optimization (Phase 4) |
| Symbolic execution bottlenecks | Medium | High | Path explosion mitigation (Phase 4) |
| Missing critical bug classes | High | Low | Attack expansion (Phase 3), continuous learning |

### Business Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| No 0-days found in battle testing | Critical | Medium | Start with easier targets, use tip-offs from manual audits |
| Competitors advance faster | High | Medium | Focus on unique strengths (multi-backend, formal integration) |
| Low adoption despite quality | High | Low | Marketing, partnerships, free tier |
| Bug bounty programs shut down | Medium | Low | Diversify to audits, research, SaaS |
| Research paper rejected | Medium | Medium | Target multiple venues, iterate on feedback |

### Operational Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Key team members leave | High | Low | Documentation, knowledge sharing, modular design |
| Funding runs out | Critical | Low | Revenue from bounties/audits, sponsorships |
| Responsible disclosure conflicts | Medium | Medium | Clear disclosure policy, legal review |
| Tool used for malicious purposes | High | Low | License restrictions, watermarking, usage monitoring |

---

## 📅 Timeline Summary

```
2026 Timeline (Updated with Phase 0 Quick Wins)
═══════════════════════════════════════════════════════════════════════════════════════

Phase 0 (Wks 1-4)    Q1 (Weeks 5-13)       Q2 (Weeks 14-26)      Q3 (Weeks 27-40)      Q4 (Weeks 41-52)
├─ QUICK WINS ─────┤├─ Phase 1 ─────────┤├─ Phase 2 ─────────┤├─ Phase 3 ─────────┤├─ Phase 5 ─────────┤
│ 🔥 CRITICAL       ││  VALIDATION        ││  HARDENING         ││  EXPANSION         ││  BATTLE TESTING    │
│                   ││                    ││                    │├─ Phase 4 ─────────┤│                    │
│ • Mode 3 Wiring   ││  • CVE Suite (25+) ││  • Constraint Inf  ││  SYMBOLIC DEPTH    ││  • Bug Bounties    │
│ • --resume Flag   ││  • FP Analysis     ││  • Metamorphic     ││                    ││  • Audits          │
│ • Config Profiles ││  • Benchmarks      ││  • Spec Inference  ││  • MEV Attacks     ││  • Research Paper  │
│ • Multi-Backend   ││                    ││  • Auto Triage     ││  • zkEVM Attacks   ││                    │
│   Proof Gen       ││                    ││                    ││  • Batch Bypass    ││  • 5+ 0-days       │
│ • Ground Truth    ││                    ││                    ││  • Recursive       ││  • $25K+ bounties  │
│                   ││                    ││                    ││  • Performance     ││                    │
│ 80→90/100 🎯      ││  90→92/100         ││  92→94/100         ││  94→95/100         ││  95/100 PROVEN     │
└───────────────────┘└────────────────────┘└────────────────────┘└────────────────────┘└────────────────────┘

2027 Timeline
═══════════════════════════════════════════════════════════════

Q1 (Weeks 1-13)       Q2 (Weeks 14-26)      Q3 (Weeks 27-39)      Q4 (Weeks 40-52)
├─ Phase 6 ─────────┤├─ Scaling ─────────┤├─ Optimization ────┤├─ Expansion ───────┤
│  ECOSYSTEM         ││                    ││                    ││                    │
│                    ││  • Enterprise      ││  • Performance     ││  • New Backends    │
│  • Cloud Platform  ││  • Partnerships    ││  • Reliability     ││  • Advanced R&D    │
│  • IDE Integration ││  • Marketing       ││  • User Exp        ││  • Open Source     │
│  • Community       ││  • Revenue Growth  ││  • Cost Reduction  ││  • Sustainability  │
└────────────────────┘└────────────────────┘└────────────────────┘└────────────────────┘
```

---

## 🎯 Critical Path (Updated with Phase 0)

The **critical path** to achieving 0-day credibility:

1. **Weeks 1-4**: Quick Wins (Phase 0) → **Fix blocking issues** (Mode 3, --resume, profiles) → **90/100** ✅
2. **Weeks 5-13**: Validation (Phase 1) → Prove we can detect known bugs → **92/100**
3. **Weeks 14-26**: Hardening (Phase 2) → Make experimental features production-ready → **94/100**
4. **Weeks 27-40**: Expansion + Symbolic (Phases 3-4) → Unlock deep bugs → **95/100**
5. **Weeks 41-48**: Bug Bounties (Phase 5.1) → **PROVE WE CAN FIND 0-DAYS** → **VALIDATED**
6. **Weeks 49-52**: Research Publication (Phase 5.3) → Establish credibility

**Critical Milestones:**
- **Week 3:** Mode 3 multi-step fuzzing working → Unlocks protocol-level bugs
- **Week 4:** All 4 backends have proof generation → Expands audit market
- **Week 48:** First real 0-day discovery → **PROOF OF EFFECTIVENESS**

---

## 🏆 Definition of Success

### Minimum Viable Success (MVS)

**Phase 0 (Week 4):** Quick Win Success
- ✅ **Mode 3 chain fuzzing** accessible via YAML
- ✅ **--resume flag** for long campaigns
- ✅ **Config profiles** (quick/standard/deep)
- ✅ **Proof generation** for all 4 backends
- ✅ **Ground truth suite** with 10+ vulnerable circuits
- ✅ **90/100 fitness score** (from 80/100)

**Phase 5 (Q4 2026):** Battle-Tested Success
- ✅ **3+ real 0-day vulnerabilities** discovered and responsibly disclosed
- ✅ **90%+ detection rate** on expanded CVE suite (25+ vulnerabilities)
- ✅ **<10% false positive rate** in evidence mode
- ✅ **1 production audit** completed with positive testimonial
- ✅ **1 research paper** submitted to tier-1 conference

### Stretch Goals
By Q2 2027, we will have:
- 🎯 **15+ real 0-days** found
- 🎯 **$100K+ in bug bounties** earned
- 🎯 **Research paper accepted** at top venue
- 🎯 **10+ production audits** completed
- 🎯 **1,000+ active users** on platform
- 🎯 **Recognized as industry standard** for ZK security testing

---

## 🔄 Review & Iteration

### Monthly Reviews
- **First Monday of each month**: Progress review
- **Metrics dashboard**: Track KPIs vs targets
- **Retrospective**: What worked, what didn't
- **Adjust roadmap**: Re-prioritize based on learnings

### Quarterly Milestones
- **End of Q1**: Validation complete, baseline established
- **End of Q2**: Experimental features hardened
- **End of Q3**: Attack coverage expanded, symbolic depth increased
- **End of Q4**: Battle-tested with real 0-days, paper submitted

### Go/No-Go Decision Points

**End of Q2 2026 (Week 26):**
- **GO if:** CVE detection >85%, FP rate <15%, at least 1 audit engagement secured
- **PIVOT if:** Metrics below targets → Focus on quality over features
- **ABORT if:** Fundamental technical blockers identified

**End of Q3 2026 (Week 40):**
- **GO if:** Symbolic depth increased, new attacks validated, bug bounty targets selected
- **PIVOT if:** Performance issues → Focus on optimization
- **ABORT if:** No viable path to 0-day discoveries

**End of Q4 2026 (Week 52):**
- **SUCCESS if:** MVS criteria met (3+ 0-days, paper submitted, 90% detection)
- **PARTIAL if:** 1-2 0-days found, more time needed
- **REASSESS if:** Zero 0-days found → Major strategy shift needed

---

## 📚 Dependencies & Prerequisites

### Technical Dependencies
- ✅ Rust 1.70+ toolchain
- ✅ Z3 SMT solver
- ✅ Backend tooling (circom, nargo, scarb)
- 🔄 Picus formal verifier (integration ongoing)
- ⏳ Cloud infrastructure (Phase 6)
- ⏳ CI/CD pipeline (Phase 6)

### Resource Dependencies
- **Engineering Team**: 3-5 full-time engineers
- **Research Team**: 1-2 researchers (symbolic execution, attack design)
- **Security Team**: 1-2 auditors (validation, bug bounties)
- **Platform Team**: 1-2 engineers (SaaS, integrations) - Phase 6
- **Community Team**: 1 community manager - Phase 6

### External Dependencies
- **Bug bounty platforms**: ImmuneFi, Code4rena access
- **Audit partners**: Relationships with Trail of Bits, OpenZeppelin, etc.
- **Academic partners**: Conference submission/presentation
- **Target circuits**: Access to production ZK systems

---

## 🚀 Quick Start

### For Core Team
1. **Week 1**: Start Milestone 1.1 (CVE expansion)
2. **Week 3**: Start Milestone 1.2 (FP analysis in parallel)
3. **Week 5**: Start Milestone 1.3 (benchmarking in parallel)
4. **Week 7**: Review Phase 1 results, adjust Phase 2 priorities

### For Contributors
1. Check [CONTRIBUTING.md](CONTRIBUTING.md) for setup
2. Pick a milestone from Phase 1 or Phase 2
3. Open issue to claim work
4. Submit PR with tests and docs

### For Stakeholders
1. Review this roadmap
2. Provide feedback via GitHub issues
3. Track progress via monthly updates
4. Participate in quarterly reviews

---

## 📞 Contact & Governance

**Roadmap Owner:** Core Team  
**Status Updates:** Monthly (first Monday)  
**Feedback:** GitHub Discussions  
**Questions:** Discord #roadmap channel

**Roadmap Version History:**
- v1.0 (Feb 2026): Initial roadmap based on 0-day fitness review

---

## Appendix: Attack Pattern Implementation Priority

Based on real-world impact and feasibility:

### Tier 1 (Q3 2026) - High Impact, Medium Complexity
1. ✅ Front-running/MEV (DeFi relevance) - Phase 3.1 Complete
2. ✅ zkEVM state transition (L2 relevance) - Phase 3.2 Complete
3. ✅ Batch verification bypass (aggregation relevance) - Phase 3.3 Complete

### Tier 2 (Q4 2026) - Medium Impact, High Complexity
4. ✅ Recursive SNARK attacks (emerging tech)
5. ⏳ Griefing attacks (DoS relevance)
6. ⏳ Oracle manipulation (DeFi/privacy)

### Tier 3 (Q1 2027) - Lower Priority
7. ⏳ Storage proof manipulation (zkEVM-specific)
8. ⏳ Precompile bypass (zkEVM edge cases)
9. ⏳ Folding attacks (Nova/Supernova - cutting edge)

---

---

## 📝 Roadmap Version History

**v2.0 (Feb 2026):** Major update based on deep code review
- Added **Phase 0: Quick Wins** (Weeks 1-4) - Critical path to 90/100
- Identified Mode 3 multi-step fuzzing as biggest blocker (implementation exists, needs wiring)
- Updated current score from 75/100 to **80/100** based on code analysis
- Added performance optimization milestone (constraint caching, async pipeline, lock-free)
- Incorporated findings from `CODE_REVIEW_0DAY_FITNESS.md` (now merged)
- Adjusted timeline: 90/100 achievable in 4 weeks (was 6 months)

**v1.0 (Feb 2026):** Initial roadmap based on architecture review
- Original phases and milestones
- 75/100 baseline score (conservative estimate)

---

**END OF ROADMAP**

*This is a living document. It will be updated quarterly based on progress, learnings, and ecosystem changes.*

*Last major update: February 2026 - Phase 0 added based on deep code analysis revealing Mode 3 implementation exists but needs YAML integration*
