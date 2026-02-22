# ZkPatternFuzz Production Roadmap

Date: 2026-02-22  
Status: Active  
Primary goal: make the scanner production-grade for real multi-target runs with high recall and high runtime stability, and drive every supported circuit framework to a measurable 5/5 maturity score.

---

## 📊 Status Overview (2026-02-22)

### Phase Implementation Progress
- ✅ Phase 0: Reliability Blockers (implementation completed)
- ✅ Phase 1: Detection Recall Upgrade (implementation completed)
- ✅ Phase 2: Real Backend Internalization (implementation completed)
- ✅ Phase 3: Multi-Target Execution Engine (implementation completed)
- ✅ Phase 3A: Logic Correctness Hardening (implementation completed)
- ✅ Phase 4: Validation/Stats tooling (implementation completed)
- ✅ Phase 5: Release Hardening (implementation completed)
- ✅ Phase 6: Full Non-Circom Circuit-Type Readiness (implementation completed)
- 🟡 Phase 7: Semantic Analysis & Complex Bug Detection (partially implemented, release-deferred)
- 🟡 Phase 8: 5/5 Circuit Maturity Program (in progress)

### Exit Criteria Progress
- ✅ Phase 0 exit criteria (met on 20-run fast matrix: attack-stage reach 100%, no output-lock failures)
- ✅ Phase 1 exit criteria (met: selector hit-rate 90%, recall uplift +80pp over non-dry-run baseline, safe high-confidence FPR 0%)
- ✅ Phase 2 exit criteria (met: fresh-clone bootstrap matrix passes and keygen preflight is green)
- ✅ Phase 3 exit criteria (met on 10-target serial-vs-parallel benchmark with zero collisions and 1.884x speedup)
- ✅ Phase 3A exit criteria (met with backend-heavy and timeout/Noir-throughput validations)
- ✅ Phase 4 exit criteria (met on latest fast matrix: recall 80%, safe high-confidence FPR 0%, miss reason coverage 100%)
- ✅ Phase 5 exit criteria (release candidate gates pass twice consecutively)
- ✅ Phase 6 exit criteria (met: non-Circom readiness lanes pass with zero runtime/preflight/missing-outcome regressions)
- ⏳ Phase 8 exit criteria (pending: Circom/Noir/Cairo/Halo2 sustained at 5.0/5.0 for 14 consecutive daily scorecards)

### Definition of Done Progress
- ✅ Stability: >=95% scan completion on the latest 20-run benchmark matrix (`100%`)
- ✅ Multi-target: 10+ target matrix with `jobs=2`/`workers=2` without collisions
- ✅ Detection: measurable recall uplift on known vulnerable targets
- ✅ Operability: single bootstrap path validated on fresh environments
- ✅ Quality gates: nightly regression dashboard with pass/fail by failure class
- ⏳ 5/5 maturity: Circom/Noir/Cairo/Halo2 each sustain 5.0/5.0 across release-gated scorecard runs

---

## 🎯 Phase 0: Reliability Blockers

**Goal:** Stop easy breakage before tuning detection quality.

### Implementation Tasks
- [x] Add per-run output root isolation for parallel scans
- [x] Classify run outcomes explicitly (completed, locked_output, keygen_failed, etc.)
- [x] Add preflight for toolchain/keygen readiness
- [x] Preserve output schema while adding stable reason codes
- [x] Remove panic-based lock handling in Circom backend
- [x] Add timeout-wrapped external command execution
- [x] Add collision-safe automatic scan run-root allocation
- [x] Add backend preflight hardening for Circom key setup
- [x] Add `zk-fuzzer preflight` command for readiness checks

### Exit Criteria
- [x] 20-run matrix on 5 local targets has 0 output-lock failures
- [x] >=90% runs reach attack execution stage (not blocked in setup)

**Current Status:** ✅ Met on latest fast 20-run matrix (`artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`): attack-stage reach `100%`, completion `100%`, and no output-lock failures

---

## 🔍 Phase 1: Detection Recall Upgrade

**Goal:** Reduce missed true positives while keeping YAML workflow.

### Implementation Tasks
- [x] Extend YAML selector semantics with weighted regex groups
- [x] Add `k-of-n` matching support
- [x] Add lexical normalization before regex matching
- [x] Support optional synonym bundles per pattern family
- [x] Make recall bias defaults profile-controlled
- [x] Keep summary output focused on matched pattern IDs
- [x] Add selector-policy regression tests
- [x] Add selector normalization/synonym regression tests

### Exit Criteria
- [x] Selector hit-rate >=90% on intended target set
- [x] Recall improves by >=20 percentage points over baseline
- [x] High-confidence false positives remain bounded (<=5% on safe suite)

**Current Status:** ✅ Recall uplift confirmed by `scripts/validate_recall_uplift.py`: baseline `benchmark_20260219_151048` recall `0%` to latest `benchmark_20260219_212657` recall `80%` (`+80pp`), with safe high-confidence FPR `0%`

---

## 🔧 Phase 2: Real Backend Internalization

**Goal:** Avoid environment fragility across circuits.

### Implementation Tasks
- [x] Add `bins bootstrap` command for circom/snarkjs/ptau acquisition
- [x] Implement SHA-256 digest verification for downloads
- [x] Standardize include-path and binary-path resolution to local `bins/`
- [x] Add ptau discovery policy with deterministic precedence
- [x] Add deterministic ptau autodiscovery regression tests
- [x] Ensure local binary assets remain untracked by git

### Exit Criteria
- [x] Fresh clone + bootstrap can run 5-target matrix without manual tool installation (`artifacts/fresh_clone_validation/latest_report.json`)
- [x] Keygen readiness preflight passes on at least 4/5 baseline targets (`artifacts/keygen_preflight/latest_report.json`)

**Current Status:** ✅ Phase 2 exit criteria are met: fresh-clone bootstrap matrix passes with zero Circom compilation failures and baseline keygen preflight passes on 5/5 targets

---

## 🚀 Phase 3: Multi-Target Execution Engine

**Goal:** Make large real-world test campaigns predictable and parallel-safe.

### Implementation Tasks
- [x] Build matrix runner for target lists with bounded parallelism
- [x] Separate process parallelism (`jobs`) from scan worker parallelism (`--workers`)
- [x] Add guardrails for parallel execution
- [x] Emit per-target outcome table and aggregate campaign scorecard
- [x] Add `zk0d_matrix` multi-target runner
- [x] Add default matrix config template
- [x] Add target-matrix usage docs

### Exit Criteria
- [x] 10-target run completes with zero filesystem collisions
- [x] Parallel run wall-clock speedup >=1.7x over serial baseline

**Current Status:** ✅ Met on latest speedup run (`artifacts/benchmark_runs_speedup_v2/speedup_report.json`): zero collisions and `1.884x` speedup (`jobs=2` vs `jobs=1`)

---

## 🛡️ Phase 3A: Logic Correctness Hardening

**Goal:** Close audit-confirmed semantic bugs before scaling campaign volume.

### Implementation Tasks
- [x] Make adaptive orchestrator enforce scheduler allocations per attack phase
- [x] Add hard timeout wrappers to proof forgery `snarkjs` subprocesses
- [x] Normalize allocation fractions post-clamp to match total budget exactly
- [x] Fix Cairo execution fallback/coverage behavior
- [x] Cache Noir constraints (OnceLock) to remove repeated disk parse overhead
- [x] Replace runtime global env mutation paths with startup-time configuration
- [x] Fix hardcoded seed=42 in adaptive orchestrator phases
- [x] Remove `.max(1)` floor on new_coverage in adaptive orchestrator
- [x] Replace Hamming distance with arithmetic distance in near-miss detector
- [x] Add min_value boundary check in near-miss detector
- [x] Apply largest-remainder method to chain scheduler budget allocation

### Exit Criteria
- [x] `AdaptiveOrchestrator` integration tests validate allocation enforcement
- [x] Proof forgery detector cannot hang indefinitely on subprocesses (`artifacts/phase3a_timeout_noir_validation/phase3a_timeout_noir_report.json`)
- [x] Cairo backend can execute and report non-empty coverage/failure semantics
- [x] Noir backend execution throughput improves measurably on repeated runs (`artifacts/phase3a_timeout_noir_validation/noir_throughput_report.json`)

**Current Status:** ✅ Phase 3A exit criteria are met with dedicated timeout/noir evidence (`artifacts/phase3a_timeout_noir_validation/phase3a_timeout_noir_report.json`), including proof-forgery timeout hardening and measured Noir warm-run speedup

---

## 📈 Phase 4: Validation And Statistical Confidence

**Goal:** Prove detection quality with statistically meaningful results.

### Implementation Tasks
- [x] Curate vulnerable matrix (minimum 5 known vulnerable targets)
- [x] Curate safe matrix (minimum 5 clean targets)
- [x] Implement repeated trials with fixed seeds
- [x] Add confidence intervals for recall/precision
- [x] Add regression gates that fail on recall/stability regression
- [x] Publish detection reasons for misses
- [x] Add CI benchmark regression gates
- [x] Add nightly benchmark trend artifacts
- [x] Add explicit environment config separation (dev/prod profiles)
- [x] Add scan/report contract compatibility assertions
- [x] Add reason-code aggregation in `zk0d_batch`

### Exit Criteria
- [x] Vulnerable-set recall >=80%
- [x] Safe-set high-confidence FPR <=5%
- [x] Every miss has machine-readable root-cause category

**Current Status:** ✅ Recall `80%`, safe high-confidence FPR `0%`, and miss reason coverage `100%` (`2/2`) on latest matrix (`artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`, `artifacts/benchmark_runs_fast/benchmark_20260219_212657/miss_reason_coverage.json`)

---

## 🎁 Phase 5: Release Hardening

**Goal:** Production operations and predictable upgrades.

### Implementation Tasks
- [x] Add release checklist (toolchain, regression matrix, docs, migration notes)
- [x] Freeze public scan/report contract and add compatibility tests
- [x] Add troubleshooting playbook for keygen, includes, lock contention, timeout tuning
- [x] Add nightly CI matrix (fast smoke + deep scheduled)
- [x] Add production release checklist document
- [x] Add release-candidate consecutive-pass gate script
- [x] Add rollback validation script
- [x] Add dedicated manual release validation workflow
- [x] Add release-validation invocation docs
- [x] Add README "Release Ops" section
- [x] Add nightly failure-class dashboard generation
- [x] Add configurable failure-class threshold overrides

### Exit Criteria
- [x] Versioned release candidate passes all gates twice consecutively (`artifacts/release_candidate_validation/release_candidate_report.json`)
- [x] Rollback strategy documented and tested (`docs/RELEASE_CHECKLIST.md`, `artifacts/release_candidate_validation/rollback_validation.log`)

**Current Status:** ✅ Two consecutive release-gate attempts pass (`artifacts/release_candidate_validation/release_candidate_report.json`) on the default benchmark root with fresh passing evidence (`artifacts/benchmark_runs/benchmark_20260220_221614/summary.json`, `artifacts/benchmark_runs/benchmark_20260220_222045/summary.json`), and remain valid on fast benchmark evidence (`artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`).

---

## 🧩 Phase 6: Full Non-Circom Circuit-Type Readiness

**Goal:** Make all non-Circom backends first-class at full capacity, with priority order Noir -> Cairo -> Halo2, and release-gated across representative circuit types.

### Scope (Backend Readiness Matrix)
| Backend | Current Status | Known Gaps |
|---|---|---|
| Noir | In progress (setup stabilized) | Needs full-capacity breadth gating and higher completed-rate on matching templates |
| Cairo | In progress (default breadth-gated) | Runtime-error blocker cleared; completion-rate is still below full-capacity target |
| Halo2 | Partial (mixed breadth outcomes) | Local JSON-spec reconciliation is fixed; scaffold path still needs completion-rate lift |

### Implementation Tasks
- [x] Add backend-specific readiness profiles in `targets/fuzzer_registry.prod.yaml` for Noir, Halo2, and Cairo circuit families
- [x] Add Noir preflight hardening for package-resolution and ABI artifact-path variants
- [x] Add selector-mismatch synthetic outcome classification in `zk0d_batch` to eliminate validation-skip `run_outcome_missing` gaps
- [x] Add Noir end-to-end prove/verify smoke and fuzz parity tests for external `Nargo.toml` projects
- [x] Add Cairo breadth-target suite to `zk0d_matrix` default validation set (not optional backend-heavy-only checks) (`targets/zk0d_matrix_breadth.yaml`)
- [x] Add Cairo full-capacity regression suite with stable coverage/failure semantics on external and local targets
- [x] Add Cairo JSON/metadata input reconciliation fallback (wire-label/index compatibility) (`src/executor/mod.rs`)
- [x] Add Halo2 JSON-spec input reconciliation normalizer (wire-label/index compatibility) (`src/executor/mod.rs`)
- [x] Add Halo2 scaffold execution stability checks under nightly toolchain with deterministic fixture inputs
- [x] Reduce `run_outcome_missing` on non-Circom targets to <=5% by enforcing explicit reason-code closure in matrix summaries
- [x] Add per-backend release gates in `scripts/release_candidate_gate.sh` (Noir/Halo2/Cairo must each satisfy minimum completion and setup-success thresholds)
- [x] Publish backend readiness dashboard artifact (`artifacts/backend_readiness/latest_report.json`) on every benchmark/release run
- [x] Add dedicated Noir readiness matrix + runner (`targets/zk0d_matrix_noir_readiness.yaml`, `scripts/run_noir_readiness.sh`)
- [x] Add dedicated Cairo readiness matrix + runner (`targets/zk0d_matrix_cairo_readiness.yaml`, `scripts/run_cairo_readiness.sh`)
- [x] Add dedicated Halo2 readiness matrix + runner (`targets/zk0d_matrix_halo2_readiness.yaml`, `scripts/run_halo2_readiness.sh`)

### Execution Plan (Priority: Noir -> Cairo -> Halo2 -> Other Non-Circom)
- [x] Noir full-capacity lane: rerun roadmap steps `066-069` plus external Noir targets at release settings and reach >=90% completed outcomes on selector-matching templates
- [x] Cairo full-capacity lane: promote Cairo from optional backend-heavy checks to default breadth gating with full integration tests
- [x] Halo2 full-capacity lane: stabilize real-circuit execution path and clear runtime/spec reconciliation failures on canonical fixtures
- [x] Cross-backend lane: run 50+ target collision stress tests and enforce aggregate non-Circom readiness thresholds in release gates

### Test Coverage Gaps
- [x] Cairo full integration tests
- [x] Halo2 real-circuit validation suite
- [x] Noir constraint coverage edge cases
- [x] Multi-target collision stress tests (50+ targets)

### Documentation
- [x] Noir backend troubleshooting guide
- [x] Cairo integration tutorial
- [x] Halo2 migration guide from mock mode
- [x] Attack DSL specification

### Formal Verification Bridge
- [x] Export fuzzing findings to formal tools
- [x] Import formal invariants as fuzzing oracles
- [x] Hybrid fuzzing+proof workflow

### Exit Criteria
- [x] Noir: `backend_preflight_failed=0` on roadmap breadth/follow-up target sets and >=90% completed outcomes
- [x] Cairo: >=90% completed outcomes on designated Cairo breadth targets with non-empty run outcome classification
- [x] Halo2: `runtime_error=0` for canonical local specs and >=90% completed outcomes on scaffold/spec targets
- [x] Cross-backend: non-Circom `run_outcome_missing` <=5% in aggregate follow-up report
- [x] Release gate fails automatically when any non-Circom backend drops below readiness thresholds

**Current Status:** ✅ Complete for Phase 6 readiness scope. Noir release-settings rerun is now complete on the dedicated readiness matrix (local + external targets) with `completed=3`, `selector_mismatch=15`, `run_outcome_missing=0`, and `matrix.exit_code=0` (`artifacts/backend_readiness/noir/latest_report.json`, `artifacts/backend_readiness/noir/summary_20260220_205242.tsv`). Noir selector-matching completion gate passes at `1.000` (>=0.90) with `runtime_error=0`, `backend_preflight_failed=0`, and `run_outcome_missing_rate=0.000` on consecutive reruns (`artifacts/backend_readiness/noir_release_settings_dashboard.json`). Full unskipped release-settings backend lanes now pass in enforced mode for Noir/Cairo/Halo2 (`artifacts/backend_readiness/latest_report.json`, generated `2026-02-20T21:48:40Z`) with aggregate non-Circom `run_outcome_missing_rate=0.000` and selector-matching completion `1.000` per backend, after integration-test infra classification hardening in `tests/backend_integration_tests.rs`. Halo2 breadth recheck remains stable at `runtime_error=0` on canonical fixtures (`artifacts/roadmap_step_tests_recheck4/summary/step_069__local_halo2_minimal_json_spec_.tsv`), Cairo default-breadth step `070` remains classified and runtime-clean (`artifacts/roadmap_step_tests_recheck5/summary/step_070__local_cairo_multiplier_.tsv`), and cross-backend collision stress passes for 54 non-Circom targets (`artifacts/non_circom_collision_stress/latest_report.json`).

---

## 🏁 Phase 8: 5/5 Circuit Maturity Program (All Frameworks)

**Goal:** reach and sustain `5.0/5.0` maturity for Circom, Noir, Cairo, and Halo2 using a single, release-gated scorecard.
**Track:** active parallel execution track for backend maturity closure while Phase 7 semantic-analysis work remains planned.

### Baseline Snapshot (2026-02-22)
- Noir: `4.0/5.0`
- Halo2: `3.1/5.0`
- Cairo: `2.8/5.0`
- Circom: `4.5/5.0` (finalized in Week 1 scorecard freeze)
- Cross-backend readiness: `4.2/5.0`

### 8.1 Maturity Rubric (5 points total)
1. `Execution fidelity (1.0)`: deterministic outputs + no infra-skip on required targets.
2. `Proof lifecycle fidelity (1.0)`: setup/prove/verify is fully supported and reproducible.
3. `Constraint coverage fidelity (1.0)`: production lanes use real backend constraints; no heuristic-only pass paths.
4. `Breadth readiness (1.0)`: >=95% completion with `runtime_error=0`, `backend_preflight_failed=0`, `run_outcome_missing=0`.
5. `Operational hardening (1.0)`: release gates pass with sandbox enforced and performance/flake thresholds satisfied.

### 8.2 Shared Workstream (Week 1-2)
- [x] Add a backend scorecard generator (`scripts/backend_maturity_scorecard.sh`) and publish `artifacts/backend_maturity/latest_scorecard.json`.
- [x] Add CI/release gate that fails when any backend score drops below target (`>=4.5` initially, `==5.0` at cutover).
- [x] Expand readiness matrices to include at least 5 enabled representative targets per backend (local + external).
- [x] Enforce tool sandbox for all readiness/release lanes (`--enforce-tool-sandbox`) and archive gate evidence.
- [x] Add backend maturity history + consecutive-day streak gate (`scripts/backend_maturity_scorecard.sh`, `scripts/release_candidate_gate.sh`) to enforce 14-day `5.0` closures with runtime-error constraints.

### 8.3 Backend-Specific Closure Plans (Release-Critical)

#### Noir -> 5/5
- [x] Expand Noir matrix coverage to `>=25` selector-matching classified runs per release cycle.
- [x] Add compatibility matrix tests for supported `nargo` versions and artifact layouts.
- [x] Add hard proof artifact contract tests (path + format + deterministic verify inputs).
- Tracking note: 14-day `5.0` streak is enforced by the scorecard history gate, not a separate manual checklist item.

#### Halo2 -> 5/5
- [x] Implement key setup path in `Halo2Target::setup_keys` (or a strict canonical adapter with equivalent guarantees).
- [x] Add canonical execution/prove/verify integration that is not dependent on ad-hoc custom CLI flags in target binaries.
- [x] Replace metadata-only success fallbacks with strict production behavior in readiness lanes.
- [x] Expand Halo2 matrix to at least 5 targets (JSON specs + real circuits + external circuits).
- Tracking note: `runtime_error=0` and 14-day `5.0` streak remain enforced by release-gate thresholds.

#### Cairo -> 5/5
- [x] Replace source-assertion-only coverage fallback with trace/AIR-backed production coverage.
- [x] Normalize Cairo1 proof handling to a structured, reproducible artifact contract (not execution-id-only payload semantics).
- [x] Gate both Cairo0 and Cairo1 canonical paths where applicable.
- [x] Expand Cairo matrix to at least 5 targets (local + external) with stone/scarb prove-verify gates.
- Tracking note: Cairo 14-day `5.0` closure is scorecard-gated and does not need duplicate manual tracking.

#### Circom -> 5/5
- [x] Add long-horizon flake gate (14-day consecutive pass requirement) for Circom keygen/compile/prove/verify lanes.
- [ ] Add hermetic include/path validation in release lanes for deterministic toolchain resolution.
- [ ] Add large-circuit memory and throughput fitness gates in release validation.
- Tracking note: once the two items above land, the same 14-day scorecard gate enforces sustained closure.

### 8.4 Milestones (Informational)
- `M0 (Week 1)`: complete (`>=4.5` gate + scorecard freeze).
- `M1 (Week 3)`: in progress (critical implementation gaps closed; all backends `>=4.5`).
- `M2 (Week 5)`: planned (coverage-fidelity hardening to `>=4.8`).
- `M3 (Week 7)`: planned (all backends sustained at `5.0/5.0` for 14 consecutive daily runs).

### 8.5 Global Exit Criteria (Release Gate)
- [ ] Zero unresolved backend-specific release blockers.
- [ ] Release candidate gate enforces and archives 5/5 evidence bundles (including 14-day consecutive scorecard thresholds).

---

## 🧠 Phase 7: Semantic Analysis & Complex Bug Detection

**Goal:** Bridge the gap between syntax-level fuzzing and semantic property violations. Enable detection of protocol-level bugs that constraint-level analysis misses.

**Scope update (2026-02-22):** keep only high-leverage, near-term semantic tasks active while Phase 8 release closure is in progress; move long-horizon research tasks into deferred backlog tracking.

### 7.1 Completed Foundation (Merged)
- [x] Semantic invariant DSL + parser/validator + semantic oracle + violation reporting (`docs/INVARIANT_SPEC_SCHEMA.md`, `crates/zk-core/src/invariants.rs`, `src/fuzzer/invariant_checker.rs`).
- [x] Non-native field/limb arithmetic oracle with CVE-backed regressions (`crates/zk-constraints/src/limb_analysis.rs`, `tests/halo2_specs/affine.json`, signature fixtures).
- [x] Witness extension attack mode with constraint-subset strategies and SMT solving (`crates/zk-symbolic/src/enhanced.rs`).
- [x] Lookup-analysis core implemented (lookup semantics, extractor, analyzer, fuzzer) (`crates/zk-constraints/src/constraint_types.rs` and related analysis modules).

### 7.2 Active Remaining Work (Useful Now)
- [ ] Add Halo2-specific lookup integration tests to validate Plookup coverage end to end.
- [ ] Publish one semantic-analysis operator guide (invariants, witness extension, lookup workflows) with reproducible commands.

### 7.3 Deferred Backlog (Post-5/5 Cutover, Non-Blocking)
- Reference implementation differential (former 7.5).
- Constraint cluster collective enforcement (former 7.6).
- Information leakage active distinguisher (former 7.7).
- Stretch targets after reactivation:
  - Expand invariant catalog to `>=5` production vulnerability patterns.
  - Raise lookup detection coverage to `>=80%` on Halo2 Plookup fixtures.

### 7.4 Tracking Rule
- Phase 7 items are non-blocking while Phase 8 maturity closure remains the active release track.
- Promote deferred items back to active only with an assigned owner, fixture plan, and explicit release impact.

**Current Status:** 🟡 Partially implemented. Core P0/P1 engines are merged; remaining active work is limited to Halo2 lookup integration tests and operator documentation.

---

## 🔬 Audit Intake (2026-02-18)

Source: 2026-02-18 logic audit snapshot (13 findings: High=3, Medium=5, Low=3, Info=2)

### P0 (Must-Fix Before Broader Tuning)
- [x] Wire adaptive scheduler allocations into engine execution (H-2)
- [x] Add timeout-wrapped external command execution in proof forgery detector (H-3)

### P1 (Next Correctness/Stability Wave)
- [x] Normalize adaptive budget allocations to exact total budget (H-1)
- [x] Fix Cairo executor always-fail coverage path (M-3)
- [x] Cache Noir constraints to avoid per-exec disk reloads (M-4)
- [x] Remove runtime `std::env::set_var` hazards in multi-threaded paths (M-2)

### P2/P3 (Defensive + Maintainability)
- [x] Remove panic fallback in `engagement_dir_name` and env parsing panic paths (M-1, L-2)
- [x] Improve zero-day confirmation matching from category-only to content-aware (L-3)
- [x] Document/contain dynamic log file routing edge window (M-5)
- [x] CLI modularization and run lifecycle deduplication (I-1, I-2)

---

## 🏗️ Architecture Improvements (Completed)

### Backend Hardening
- [x] Remove panic-based lock handling in compile/setup/prove/verify/witness paths
- [x] Replace unbounded external command executions with timeout-wrapped execution
- [x] Improve backend failure diagnostics with richer command-failure context
- [x] Bounded ptau `curl` download with timeout + explicit command-failure diagnostics
- [x] Hardened ptau validation to reject truncated/corrupt files

### CLI Modularization
- [x] Extract run lifecycle helpers into dedicated module
- [x] Extract stale-run and early-failure helpers
- [x] Extract output-lock failure helper
- [x] Extract lifecycle initialization helper
- [x] Extract scan summary append helper
- [x] Extract pattern-only YAML validation
- [x] Wire to dedicated selector module
- [x] Extract scan campaign materialization
- [x] Extract selector gating + mismatch diagnostics
- [x] Extract family-resolution policy
- [x] Extract scan-target construction
- [x] Extract shared scan-mode progress wrapper
- [x] Extract family-run dispatch orchestration
- [x] Extract scan-preparation orchestration
- [x] Isolate scan-run orchestration into dedicated runner module
- [x] Extract campaign bootstrap helpers
- [x] Extract run identity and path helpers
- [x] Extract log context, interrupt hooks, and process cleanup
- [x] Extract chain-mode corpus/helpers and UI presentation
- [x] Extract chain quality-gate evaluation
- [x] Extract chain report construction/writes
- [x] Extract chain-results console rendering
- [x] Extract completion status/doc assembly
- [x] Extract corpus metric loading
- [x] Extract forced chain-mode runtime overrides
- [x] Extract engagement-threshold loading
- [x] Extract standard report persistence
- [x] Extract startup/preflight orchestration
- [x] Extract engine execution orchestration
- [x] Extract bundled chain report persistence
- [x] Extract quality/summary assessment
- [x] Extract report context construction
- [x] Extract failure-wrapped report persistence
- [x] Extract completion finalization and enforcement
- [x] Introduce shared run context
- [x] Extract run-level corpus metric staging
- [x] Extract full chain campaign flow module

### Test Organization
- [x] Separate production and test concerns for CLI selector/command regressions
- [x] Enforce strict repository-wide separation of test bodies from production source
- [x] Enforce stricter config test separation under dedicated config-test module boundary
- [x] Document hard no-mixing policy: production modules (`src/**`, `crates/**`) must not import, re-export, or depend on test-only modules/helpers
- [x] Document hard placement policy: test bodies belong only in `tests/**`; no `#[cfg(test)]` modules or `*_tests.rs` files in production trees
- [x] Add CI guard that fails if production modules expose test-only symbols/re-exports

### Attack Coverage
- [x] Wire previously non-executed attack families into runtime dispatch
- [x] Add direct engine dispatch for TrustedSetup, ConstraintBypass, Malleability, etc.
- [x] Add runtime wrappers for MEV/front-running/zkEVM/batch-verification
- [x] Extend phased scheduler string parsing for broader attack-type aliases
- [x] Add core/runtime support for SidechannelAdvanced, QuantumResistance, PrivacyAdvanced, DefiAdvanced
- [x] Implement dedicated advanced attack modules in `zk-attacks`
- [x] Add static-first Circom lint lane and fail-fast severity gating
- [x] Add generator-driven adoption and static-evidence handling
- [x] Add first-class trusted-setup module

### Tooling & Infrastructure
- [x] Add batch run reason-code aggregation in `zk0d_batch`
- [x] Add collision-safe automatic scan run-root allocation
- [x] Add `zk-fuzzer preflight` command
- [x] Add regex selector policy controls
- [x] Add selector synonym bundles
- [x] Add `zk-fuzzer bins bootstrap` command
- [x] Add deterministic ptau autodiscovery precedence
- [x] Add `zk0d_matrix` multi-target runner
- [x] Add retry-on-transient-setup policy in `zk0d_batch`
- [x] Add repeated-trial benchmark harness (`zk0d_benchmark`)
- [x] Add CI benchmark regression gates
- [x] Add explicit environment config separation (dev/prod profiles)

### Code Quality
- [x] Remove `?` from regex safety validator dangerous quantifier list
- [x] Replace O(n) Vec::remove(0) with Vec::drain(0..1) in range oracle hot path
- [x] Change kill_existing_instances to use `pgrep -x` instead of `pgrep -f`
- [x] Delete legacy attack-module and mode naming surfaces

---

## 🚧 Current Blockers

### Critical Issues
1. **Noir/Cairo/Halo2 readiness gate closure**
   - Evidence: aggregated dashboard pass with selector-matching completion gate and zero runtime/preflight/missing-outcome regressions (`artifacts/backend_readiness/latest_report.json`)
   - Impact: non-Circom readiness gating is now enforced in release flow
   - Status: ✅ Closed

2. **Cairo default-breadth enforcement**
   - Evidence: Cairo breadth step is runtime-clean and explicitly classified (`artifacts/roadmap_step_tests_recheck5/summary/step_070__local_cairo_multiplier_.tsv`)
   - Impact: Cairo participates in required breadth readiness coverage
   - Status: ✅ Closed

3. **Halo2 canonical fixture stability**
   - Evidence: Halo2 step `069` recheck is runtime-clean with explicit reason-code closure (`artifacts/roadmap_step_tests_recheck4/summary/step_069__local_halo2_minimal_json_spec_.tsv`)
   - Impact: Halo2 readiness lane is release-gate eligible
   - Status: ✅ Closed

4. **Release rollback evidence in consecutive gate validation**
   - Evidence: two-pass release validation with rollback pass (`artifacts/release_candidate_validation/release_candidate_report.json`, `artifacts/release_candidate_validation/rollback_validation.log`)
   - Impact: release hardening claim is evidence-backed on default benchmark root
   - Status: ✅ Closed

---

## 📋 Immediate Action Items

### Top Priority (P0)
- [x] Implement Phase 6 backend readiness matrix runner and publish `artifacts/backend_readiness/latest_report.json`
- [x] Fix Noir target setup path for Aztec example projects (steps `066`/`067`) and rerun breadth follow-up (`artifacts/roadmap_step_tests_recheck2/summary/step_066__cat3_privacy_aztec_docs_examples_circuits_hello_circuit_.tsv`, `artifacts/roadmap_step_tests_recheck2/summary/step_067__cat3_privacy_barretenberg_docs_examples_fixtures_main_.tsv`)
- [x] Promote Cairo from backend-heavy optional validation into required breadth readiness gates and publish completion metrics (`targets/zk0d_matrix_breadth.yaml`, `artifacts/roadmap_step_tests_recheck5/summary/step_070__local_cairo_multiplier_.tsv`)
- [x] Fix Halo2 minimal JSON spec input reconciliation (`tests/halo2_specs/minimal.json`) with metadata-only wire-label fallback (`src/executor/mod.rs`)
- [x] Rerun step `069` and capture updated Halo2 readiness outcomes after input-reconciliation fix (`artifacts/roadmap_step_tests_recheck4/summary/step_069__local_halo2_minimal_json_spec_.tsv`)
- [x] Reduce non-Circom aggregate `run_outcome_missing` to <=5% on follow-up suite
- [x] Add CI gate that blocks release when Noir/Halo2/Cairo readiness thresholds fail (`.github/workflows/release_validation.yml`, `scripts/run_backend_readiness_lanes.sh`)

### High Priority (P1)
- [x] Add automated fresh clone + bootstrap validation script (`scripts/fresh_clone_bootstrap_validate.sh`)
- [x] Run fresh clone + bootstrap validation and capture summary artifacts (`artifacts/fresh_clone_validation/latest_report.json`)
- [x] Fix clean-clone `zk-backends` build blockers (`fixture`/`util` module resolution) so bootstrap validation can reach benchmark stage
- [x] Ensure `circomlib` include availability in fresh-clone bootstrap path and eliminate `circom_compilation_failed` (`artifacts/fresh_clone_validation/latest_report.json`)
- [x] Add automated keygen preflight matrix validator (`scripts/keygen_preflight_validate.sh`)
- [x] Run baseline keygen preflight matrix and capture pass-count report (`artifacts/keygen_preflight/latest_report.json`)
- [x] Add serial-vs-parallel speedup benchmark automation (`scripts/benchmark_parallel_speedup.sh`)
- [x] Execute 10-target wall-clock benchmark and capture speedup evidence
- [x] Add automated Phase 3A validation script (`scripts/phase3a_validate.sh`)
- [x] Run backend-heavy Phase 3A integrated checks (Cairo/Noir) and capture evidence (`artifacts/phase3a_validation_backend_heavy/phase3a_report.json`)
- [x] Add dedicated Phase 3A timeout+Noir throughput validator (`scripts/phase3a_timeout_noir_validate.sh`, `src/bin/zk0d_noir_throughput.rs`)
- [x] Run dedicated proof-forgery timeout and Noir throughput checks (`artifacts/phase3a_timeout_noir_validation/phase3a_timeout_noir_report.json`)
- [x] Achieve measurable recall (target >=80%) (`artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`)
- [x] Validate safe FPR remains <=5% (`artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`)

### Medium Priority (P2)
- [x] Add rollback-integrated release gate invocation (`scripts/release_candidate_gate.sh --stable-ref <ref>`)
- [x] Add automated two-attempt release-candidate validator (`scripts/release_candidate_validate_twice.sh`)
- [x] Run release candidate validation twice consecutively (`artifacts/release_candidate_validation/release_candidate_report.json`)
- [x] Execute rollback validation in release gate and archive evidence (`artifacts/release_candidate_validation/rollback_validation.log`)
- [x] Document remaining edge cases in troubleshooting playbook (`docs/TROUBLESHOOTING_PLAYBOOK.md` section `5B`)

---

## 📊 Latest Benchmark Evidence (2026-02-19)

### Fresh Clone Validation (Bootstrap Operability)
- **Command:** `scripts/fresh_clone_bootstrap_validate.sh --bootstrap-mode dry-run --suite safe_regression,vulnerable_ground_truth --trials 1 --jobs 1 --batch-jobs 1 --workers 1 --iterations 50 --timeout 10 --report-out artifacts/fresh_clone_validation/latest_report.json`
- **Report:** `artifacts/fresh_clone_validation/latest_report.json`
- **Outcome:** `passes=true`, `overall_completion_rate=0.30`, `overall_attack_stage_reach_rate=1.00`, `circom_compilation_failed=0`, `completed_runs=3`
- **Resolved blocker:** clean-clone compile failure from missing `zk-backends` modules (`fixture`/`util`) is fixed, and clean-clone Circom include resolution no longer fails benchmark runs
- **Observed blocker:** completion/quality gates are still below target despite stable bootstrap operability
- **Status:** Phase 2 dependency-availability blocker is closed; remaining blockers are completion and detection-quality gates

### Fresh Clone Circom Compilation Root-Cause Analysis
- **Command:** `python3 scripts/analyze_circom_compilation_failures.py --outcomes artifacts/fresh_clone_validation/fresh_clone_20260219_203942_outcomes.json --summary artifacts/fresh_clone_validation/fresh_clone_20260219_203942_summary.json --repo-root . --json-out artifacts/fresh_clone_validation/fresh_clone_20260219_203942_circom_compilation_analysis.json`
- **Report:** `artifacts/fresh_clone_validation/fresh_clone_20260219_203942_circom_compilation_analysis.json`
- **Outcome:** all six fresh-clone compilation failures map to circuits importing `circomlib/*` (`poseidon.circom`, `comparators.circom`, `bitify.circom`)
- **Follow-up:** rerun at current head (`artifacts/fresh_clone_validation/latest_report.json`) shows `circom_compilation_failed=0`
- **Status:** Phase 2 dependency-availability gap is resolved; this RCA remains as historical root-cause evidence

### Baseline Keygen Readiness Preflight (5-target matrix)
- **Command:** `scripts/keygen_preflight_validate.sh --suite safe_regression --profile dev --required-passes 4 --report-out artifacts/keygen_preflight/latest_report.json`
- **Report:** `artifacts/keygen_preflight/latest_report.json`
- **Outcome:** `passes=true`, `passed_targets=5`, `failed_targets=0`, `required_passes=4`
- **Status:** Phase 2 keygen-readiness exit gate is met on baseline suite

### Release Candidate Validation (Two Consecutive Attempts)
- **Command:** `scripts/release_candidate_validate_twice.sh --bench-root artifacts/benchmark_runs_fast --required-passes 1 --output-dir artifacts/release_candidate_validation --enforce`
- **Report:** `artifacts/release_candidate_validation/release_candidate_report.json`
- **Outcome:** attempt #1 `pass`, attempt #2 `pass`, overall `PASS`
- **Status:** Phase 5 release criteria are now met on the current branch

### Phase 3A Backend-Heavy Integrated Validation
- **Command:** `scripts/phase3a_validate.sh --output-dir artifacts/phase3a_validation_backend_heavy --run-backend-heavy --enforce`
- **Report:** `artifacts/phase3a_validation_backend_heavy/phase3a_report.json`
- **Outcome:** required checks `PASS`; optional backend-heavy checks `PASS` (`cairo_backend_integration`, `noir_constraint_coverage`)
- **Status:** backend-heavy execution evidence is captured and remains green

### Phase 3A Dedicated Timeout + Noir Throughput Validation
- **Command:** `scripts/phase3a_timeout_noir_validate.sh --output-dir artifacts/phase3a_timeout_noir_validation --noir-project tests/noir_projects/multiplier --noir-runs 20 --min-improvement-ratio 1.05 --enforce`
- **Report:** `artifacts/phase3a_timeout_noir_validation/phase3a_timeout_noir_report.json`
- **Outcome:** required checks `PASS` (`proof_forgery_timeout_hardening`, `noir_repeated_run_throughput`), Noir cold/warm ratio `1.97x` (`cold_first_us=214399`, `warm_median_us=108626`)
- **Status:** Phase 3A timeout and Noir-throughput exit criteria are now closed with dedicated evidence

### Run 1: Permission-Denied Blocker
- **Command:** `cargo run --quiet --bin zk0d_benchmark -- --config-profile dev --suite safe_regression,vulnerable_ground_truth --trials 2 --jobs 1 --batch-jobs 1 --workers 1 --output-dir artifacts/benchmark_runs`
- **Summary:** `artifacts/benchmark_runs/benchmark_20260219_145841/summary.json`
- **Results:**
  - Total runs: 20
  - Overall completion rate: 0.0%
  - Vulnerable recall: 0.0%
  - Safe false-positive rate: 0.0%
- **Observation:** Run failures were setup/permission-bound (`Failed to reserve batch scan run root ... Permission denied`)

### Run 2: Panic Blocker (After Writable-Root Fix)
- **Command:** `cargo run --quiet --bin zk0d_benchmark -- --config-profile dev --suite safe_regression,vulnerable_ground_truth --trials 2 --jobs 4 --batch-jobs 1 --workers 1 --iterations 200 --timeout 15 --output-dir artifacts/benchmark_runs`
- **Fix Applied:** Set child `zk0d_batch` environment under benchmark output root to avoid host-home permission failures
- **Outcome:** Permission-denied setup blocker cleared, but runs hit panic blocker `Missing required 'command' in run document` during evidence/report mirroring
- **Status:** Phase 0/1 remain unmet

### Panic Regression Validation (20-Run Matrix)
- **Command:** `python3 scripts/validate_artifact_mirror_panics.py --outcomes artifacts/benchmark_runs_fast/benchmark_20260219_182723/outcomes.json --json-out artifacts/benchmark_runs_fast/benchmark_20260219_182723/artifact_mirror_panic_report.json --enforce`
- **Report:** `artifacts/benchmark_runs_fast/benchmark_20260219_182723/artifact_mirror_panic_report.json`
- **Outcome:** `passes=true`, `panic_occurrences=0` across `20` runs
- **Status:** Prior panic class is no longer observed on the latest 20-run matrix

### Phase 1 Recall Uplift Validation
- **Command:** `python3 scripts/validate_recall_uplift.py --baseline-summary artifacts/benchmark_runs/benchmark_20260219_151048/summary.json --candidate-summary artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json --min-uplift-pp 20 --max-safe-high-conf-fpr 0.05 --json-out artifacts/benchmark_runs_fast/benchmark_20260219_212657/recall_uplift_report.json --enforce`
- **Report:** `artifacts/benchmark_runs_fast/benchmark_20260219_212657/recall_uplift_report.json`
- **Outcome:** `baseline_recall=0.0`, `candidate_recall=0.8`, `recall_uplift_pp=80.0`, `safe_high_confidence_false_positive_rate=0.0`, `passes=true`
- **Status:** Phase 1 recall-uplift criterion is now evidence-backed and met

---

## 🎯 Product Principles

1. ✅ YAML-first scanning remains the primary interface
2. ✅ Pattern matching is target-agnostic and regex-driven, not tied to exact CVE strings
3. ✅ Real backend execution is required for evidence (circom and other supported frameworks)
4. ✅ Report/output schemas and output roots remain stable unless explicitly approved
5. ✅ Recall-first tuning is allowed in scan mode (slightly higher low-confidence false positives to reduce misses)

---

## 📚 Documentation

- **[TUTORIAL.md](docs/TUTORIAL.md)** - Step-by-step guide
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Internal design
- **[RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)** - Production release gate checklist
- **[TROUBLESHOOTING_PLAYBOOK.md](docs/TROUBLESHOOTING_PLAYBOOK.md)** - Keygen/includes/locks/timeouts playbook
- **[TRIAGE_SYSTEM.md](docs/TRIAGE_SYSTEM.md)** - Automated triage
- **[SECURITY_THREAT_MODEL.md](docs/SECURITY_THREAT_MODEL.md)** - Security assumptions and trust boundaries
- **[DEFI_ATTACK_GUIDE.md](docs/DEFI_ATTACK_GUIDE.md)** - MEV/front-running detection
- **[TARGETS.md](docs/TARGETS.md)** - Target matrix and benchmark usage
- **[ROADMAP_TARGET_TESTS.md](docs/ROADMAP_TARGET_TESTS.md)** - Breadth target checklist with per-target remarks
- **[ROADMAP_TARGET_TESTS_FOLLOWUP.md](docs/ROADMAP_TARGET_TESTS_FOLLOWUP.md)** - Focused follow-up rerun summary

---

## 🔄 Validation Commands

### Compile Checks
```bash
cargo check -q
cargo check -q --workspace
cargo check -q --bin zk-fuzzer
cargo check -q --bin zk0d_matrix
cargo check -q --bin zk0d_batch
cargo check -q --bin zk0d_benchmark
```

### Regression Tests
```bash
# Selector/command regression
cargo test -q run_doc_command_extraction_ -- --test-threads=1
cargo test -q scan_selector_tests::scan_selector_regex_safety_ -- --test-threads=1

# Engagement-dir panic-path regression
cargo test -q engagement_dir_name_invalid_run_id_never_panics -- --test-threads=1

# Scan/report contract compatibility
cargo test -q --test mode123_nonregression mode123_cli_smoke_non_regression -- --test-threads=1

# Chain scheduler regression
cargo test -q chain_fuzzer::scheduler::tests::test_largest_remainder_allocation_preserves_total_and_fairness -- --test-threads=1

# Near-miss detector regression
cargo test -q fuzzer::near_miss::tests::test_range_near_miss_detects_min_boundary_proximity -- --test-threads=1
cargo test -q fuzzer::near_miss::tests::test_range_near_miss_uses_arithmetic_distance_not_bit_hamming -- --test-threads=1

# Adaptive orchestrator regression
cargo test -q adaptive_orchestrator::tests:: -- --test-threads=1
```

### Benchmark & Gate Validation
```bash
# Dry run benchmark
cargo run --quiet --bin zk0d_benchmark -- --dry-run --trials 1 --jobs 1 --batch-jobs 1 --workers 1

# Full benchmark run (dev profile)
cargo run --quiet --bin zk0d_benchmark -- --config-profile dev --suite safe_regression,vulnerable_ground_truth --trials 2 --jobs 4 --batch-jobs 1 --workers 1 --iterations 200 --timeout 15 --output-dir artifacts/benchmark_runs

# Local gate check
./scripts/ci_benchmark_gate.sh

# Failure dashboard generation
python3 scripts/benchmark_failure_dashboard.py --benchmark-root artifacts/benchmark_runs --output-dir artifacts/benchmark_trends

# Dashboard unit tests
python3 -m unittest -q tests/test_benchmark_failure_dashboard.py

# Cross-backend throughput comparison (Noir/Cairo/Halo2)
./scripts/benchmark_cross_backend_throughput.sh --runs 2 --iterations 20 --timeout 20 --workers 2 --batch-jobs 1 --enforce

# Large-circuit memory profiling (Noir/Cairo/Halo2)
./scripts/profile_large_circuit_memory.sh --max-targets 6 --max-targets-per-framework 2 --iterations 20 --timeout 20

# zkevm-circuits upstream release tracking (strict; requires release metadata)
python3 scripts/track_zkevm_releases.py --repo-path circuits/zkevm-circuits --releases-json /tmp/zkevm_releases_fixture.json --release-commit "$(git -C circuits/zkevm-circuits rev-list -n 1 v0.10.0)" --output artifacts/dependency_tracking/zkevm_upstream_latest.json

# arkworks 0.5 upgrade-path evaluation (workspace-scoped)
python3 scripts/evaluate_arkworks_upgrade_path.py --output artifacts/dependency_tracking/arkworks_upgrade_path.json

# Z3 solver compatibility matrix (strict dynamic + static lanes)
python3 scripts/build_z3_compatibility_matrix.py --output artifacts/dependency_tracking/z3_compatibility_matrix.json
```

### Release Validation
```bash
# Release candidate gate (requires 2 consecutive passes)
MAX_SAFE_HIGH_CONF_FPR=0.05 ./scripts/release_candidate_gate.sh --stable-ref <stable-ref>

# Rollback validation
./scripts/rollback_validate.sh <stable-ref>

# Manual release validation workflow
gh workflow run "Release Validation" --ref main -f required_passes=2 -f stable_ref=<tag>
gh run watch
```

---

## 🐛 Capacity & Fitness Bug Fixes (2026-02-20)

### Critical (P0)
- [x] **Bug 1**: Fix `insert_batch` infinite loop in `src/fuzzer/constraint_cache.rs`
  - Issue: When `needed_space > max_size`, loop never terminates
  - Fix: Add guard `if needed_space > max_size { return Err(...) }` before loop

### High Priority (P1)
- [x] **Bug 2**: Fix LRU eviction in `src/fuzzer/constraint_cache.rs`
  - Issue: `access_count` never incremented in `get()`, eviction is FIFO not LRU
  - Fix: Add `entry.access_count += 1` in `get()` method

- [x] **Bug 4**: Add size cap to `unsat_cache` in `crates/zk-symbolic/src/symbolic_v2.rs`
  - Issue: Unbounded `HashSet<u64>` causes memory exhaustion
  - Fix: Add `max_unsat_cache_size` and evict oldest entries when exceeded

- [x] **Bug 5**: Fix `coe_energy` i32 overflow in `crates/zk-fuzzer-core/src/power_schedule.rs`
  - Issue: Silent narrowing overflow for `selection_count > 2^31`
  - Fix: Use `.saturating_sub(CUT_OFF).min(i32::MAX as u32) as i32` or switch to f64

- [x] **Bug 6**: Enforce `max_size` in `corpus.load()` in `crates/zk-fuzzer-core/src/corpus/mod.rs`
  - Issue: Resume bypasses capacity limit
  - Fix: Add size check and truncate/evict when `entries.len() > max_size`

### Medium Priority (P2)
- [x] **Bug 3**: Count cache misses for absent keys in `src/fuzzer/constraint_cache.rs`
  - Issue: Only TTL-expired hits counted as misses, genuine misses untracked
  - Fix: Add `else { self.misses += 1 }` branch for absent keys

- [x] **Bug 7**: Fix energy decay truncation in `crates/zk-fuzzer-core/src/corpus/mod.rs`
  - Issue: `usize` cast truncates to zero prematurely (e.g., `1 * 0.9 = 0.9 → 0`)
  - Fix: Use `((entry.energy as f64) * factor).round() as usize`
  - Also fix in `EnergyScheduler::calculate_energy` (coverage.rs:362)

### Low Priority (P3)
- [x] **Bug 8**: Handle empty-input mutation in `crates/zk-fuzzer-core/src/engine.rs`
  - Issue: Silent no-op when `inputs.is_empty()`, returns unmutated clone
  - Fix: Add early return or generate new random input when empty

---

## 🔍 Code Quality Tasks (2026-02-20)

### P0 - Replace Panic Calls with Error Handling
- [x] `src/fuzzer/engine/config_helpers.rs` - Invalid power_schedule panic
- [x] `src/fuzzer/engine/corpus_manager.rs` - Invalid indexed input suffix panic
- [x] `src/fuzzer/oracle_correlation.rs` - Empty correlation group panic
- [x] `src/fuzzer/oracle_state.rs` - Lock poisoning panics (2 instances)
- [x] `src/reporting/sarif.rs` - Invalid SARIF location panics (3 instances)
- [x] `src/executor/isolation_hardening.rs` - UNIX_EPOCH panics (2 instances)

### P1 - Fix Clippy Warnings
- [x] Apply `cargo clippy --fix` for auto-fixable issues
- [x] Refactor `src/run_lifecycle.rs:306` (8 args → config struct)
- [x] Refactor `src/run_outcome_docs.rs:150` (8 args → config struct)
- [x] Refactor `src/run_outcome_docs.rs:175` (9 args → config struct)
- [x] Refactor `src/scan_runner.rs:5` (10 args → config struct)
- [x] Refactor `src/main.rs:193` (8 args → config struct)
- [x] Fix `only_used_in_recursion` in `crates/zk-backends/src/noir/mod.rs:654`
- [x] Remove needless `Ok()` wrapper in `crates/zk-backends/src/noir/mod.rs:325`

### P2 - Documentation & Safety
- [x] Add safety comments to `src/reporting/command_timeout.rs:13-19,30`
- [x] Add safety comments to `src/executor/isolation_hardening.rs:332,335`
- [x] Complete AI implementation in `src/ai/invariant_generator.rs`

### P3 - Concurrency Hardening
- [x] Add deadlock detection for high-concurrency paths
- [x] Add integration tests for concurrent code paths

---

## 📌 Remaining Backlog

### Non-Circom Backend Production Parity (Priority Order: Noir -> Cairo -> Halo2)
- [x] Noir: enforce local real-circuit prove/verify smoke gate (`test_noir_local_prove_verify_smoke`, wired in `scripts/run_noir_readiness.sh`)
- [x] Noir: barretenberg integration hardening for external `bb`-coupled projects (explicit `bb`-missing diagnostics + robust proof artifact path resolution in evidence flow)
- [x] Cairo: enforce real-circuit proving support for local Cairo0 fixture (`test_cairo_stone_prover_prove_verify_smoke`)
- [x] Cairo: enforce Stone prover integration gate in readiness lane (`scripts/run_cairo_readiness.sh`)
- [x] Cairo: Cairo1 proof/verify pipeline via `scarb prove --execute` + `scarb verify --execution-id` (strict execution-id tracking)
- [x] Halo2: mock to real-circuit execution promotion in release lanes (release workflow now installs Noir/Cairo toolchains and runs unskipped backend readiness lanes with dashboard enforcement)
- [x] Halo2: production circuit integration breadth/throughput uplift (`test_halo2_scaffold_production_throughput` enforced in `run_halo2_readiness.sh`)

### Product Surface And Ecosystem Tracking
- [x] Custom attack pattern DSL (`docs/ATTACK_DSL_SPEC.md`)
- [x] Track `zkevm-circuits` upstream releases (`scripts/track_zkevm_releases.py`, `tests/test_track_zkevm_releases.py`)
- [x] Evaluate `arkworks` 0.5 upgrade path (`scripts/evaluate_arkworks_upgrade_path.py`, `tests/test_evaluate_arkworks_upgrade_path.py`, `artifacts/dependency_tracking/arkworks_upgrade_path.json`)
- [x] Build Z3 solver compatibility matrix (`scripts/build_z3_compatibility_matrix.py`, `tests/test_build_z3_compatibility_matrix.py`, `artifacts/dependency_tracking/z3_compatibility_matrix.json`)

### Security Hardening Follow-Up (From Manual Review)
- [x] Replace unmaintained `bincode 1.3` in ACIR bytecode decoding path (`crates/zk-constraints/Cargo.toml`, `crates/zk-constraints/src/constraint_types.rs`, `crates/zk-constraints/src/constraint_types_tests.rs`) with a maintained serialization strategy and regression tests
- [x] Add CI panic-surface gate for production code to block new `.unwrap()`/`.expect()` outside tests/docs, with an explicit allowlist for proven invariants (`scripts/check_panic_surface.py`, `config/panic_surface_allowlist.txt`, `.github/workflows/ci.yml`)
- [x] Add strict external-tool sandbox execution mode (namespace/seccomp wrapper) for backend commands (`circom`, `snarkjs`, `nargo`, `scarb`, `cargo`) and enforce it in release readiness lanes (`crates/zk-backends/src/util.rs`, `src/reporting/command_timeout.rs`, `scripts/run_backend_readiness_lanes.sh`, `.github/workflows/release_validation.yml`)
- [x] Publish an explicit security assumptions and threat model document for fuzzing/evidence flows and backend toolchain trust boundaries (`docs/SECURITY_THREAT_MODEL.md`)

### External Assessment Follow-Up (2026-02-21)
- [x] Refactor oversized engine files by responsibility boundary:
  - [x] extract findings post-processing/storage into dedicated module (`src/fuzzer/engine/finding_pipeline.rs`) and remove duplicated evidence-mode policy logic from `attack_runner.rs`
  - [x] extract static/source scan attack handlers into dedicated module (`src/fuzzer/engine/attack_runner_static.rs`) and reduce `attack_runner.rs` size without behavior drift
  - [x] extract advanced runtime attack handlers into dedicated module (`src/fuzzer/engine/attack_runner_advanced.rs`) for sidechannel/privacy/defi attack family isolation
  - [x] extract protocol/economic attack handlers into dedicated module (`src/fuzzer/engine/attack_runner_protocol.rs`) for mev/front-running/zkevm/batch-verification family isolation
  - [x] extract Phase-4 novel oracle attack handlers into dedicated module (`src/fuzzer/engine/attack_runner_novel.rs`) for constraint-inference/metamorphic/constraint-slice/spec-inference/witness-collision isolation
  - [x] extract deterministic attack budget/floor helpers into dedicated module (`src/fuzzer/engine/attack_runner_budget.rs`) to share cap/floor logic across attack-family modules
  - [x] extract lifecycle orchestration helpers + run loop into dedicated module (`src/fuzzer/engine/run_lifecycle.rs`) so `mod.rs` remains initialization-focused
  - [x] extract startup/bootstrap orchestration into dedicated module (`src/fuzzer/engine/run_bootstrap.rs`) so run lifecycle flow is separated from pre-attack initialization
  - [x] extract attack-dispatch execution loop into dedicated module (`src/fuzzer/engine/run_dispatch.rs`) so run lifecycle orchestration is separated from per-attack dispatch mechanics
  - [x] extract post-dispatch continuation/timeout orchestration into dedicated module (`src/fuzzer/engine/run_continuation.rs`) so continuous phase control is isolated from lifecycle entrypoint
  - [x] extract static pattern witness-selection/recording into dedicated module (`src/fuzzer/engine/run_pattern.rs`) to isolate selector/materialization flow from run orchestration
  - [x] extract report/evidence finalization into dedicated module (`src/fuzzer/engine/run_reporting.rs`) so run orchestration and reporting paths are isolated
  - [x] split `src/fuzzer/engine/attack_runner.rs` into attack-family dispatch modules + shared execution helpers
  - [x] split `src/fuzzer/engine/mod.rs` into smaller orchestration modules (init, run loop, reporting, selector/static analysis)
- [x] Keep `src/main.rs` as a thin CLI entrypoint by moving remaining orchestration into `run_*` modules and shared services
- [x] Close remaining clippy debt and prevent regression:
  - [x] convert remaining 8+ argument functions to config/builder structs
  - [x] replace post-`Default::default()` field assignment patterns with struct literal initialization
  - [x] clean redundant variable redefinitions in `src/toolchain_bootstrap.rs`
  - [x] replace manual multiple-of checks with `.is_multiple_of()`
  - [x] add/keep CI clippy gate at warning-free target for all targets/features
- [x] Delete repo-root `new_file.txt` and add a lightweight repo-hygiene check to block accidental placeholder files at root (`scripts/check_repo_hygiene.py`, `tests/test_check_repo_hygiene.py`, `.github/workflows/ci.yml`)
- [x] Audit AI data-egress path before production usage:
  - [x] review `build_ai_circuit_context` and `src/ai/*` for source-data minimization and explicit opt-in controls
  - [x] ensure API keys/secrets and full circuit sources are never logged
  - [x] add regression tests for redaction/no-secret-logging behavior
- [x] Document rationale/tradeoffs for current profiles (`[profile.test] debug=0`, `[profile.dev] incremental=false`) in contributor docs
- [x] Review `lib.rs` public re-export surface and decide whether to keep broad exports or introduce a smaller prelude-oriented API

---

## 📝 Notes

- All implementation tasks for Phases 0-6 are complete; Phase 8 is now the active execution roadmap for backend maturity closure (with Phase 7 tracked as semantic-analysis backlog)
- Panic blockers addressed in current branch (`wait-timeout` abort path removed, run-doc stale-binary path resolved)
- Latest smoke benchmark evidence: `artifacts/benchmark_runs_smoke/benchmark_20260219_153249/summary.json`
- Smoke metrics: `completion_rate=40.0%`, `recall=0.0%`, `safe_fpr=60.0%`
- Latest 20-run fast matrix evidence: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`
- Fast matrix metrics: `completion_rate=100.0%`, `attack_stage_reach_rate=100.0%`, `recall=80.0%`, `recall_high_conf=40.0%`, `precision=100.0%`, `safe_fpr=0.0%`, `safe_high_conf_fpr=0.0%`
- High-confidence metric now uses stricter oracle corroboration in batch scoring (`benchmark_high_confidence_min_oracles=3`)
- Selector hit-rate report: `artifacts/benchmark_runs_fast/benchmark_20260219_182723/selector_hit_rate.json` (`18/20` => `90.0%`)
- Miss reason coverage report: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/miss_reason_coverage.json` (`2/2` misses categorized => `100%`)
- Phase 3A required-check report: `artifacts/phase3a_validation/phase3a_report.json` (required checks `PASS`, backend-heavy checks currently `skip`)
- Phase 3 speedup report: `artifacts/benchmark_runs_speedup_v2/speedup_report.json` (`serial=133.345s`, `parallel=70.790s`, `speedup=1.884x`, collisions `0`)
- Release candidate validation now records two consecutive gate passes (`artifacts/release_candidate_validation/release_candidate_report.json`)
- Nightly CI matrix is operational with fast-smoke and deep-scheduled lanes
