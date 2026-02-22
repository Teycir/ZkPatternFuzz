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
- [x] Automate a daily strict release-validation streak lane with persisted maturity/flake history (`.github/workflows/release_validation.yml` schedule + cache restore/save).

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
- [x] Add hermetic include/path validation in release lanes for deterministic toolchain resolution (`scripts/circom_hermetic_gate.sh`, `scripts/release_candidate_gate.sh`).
- [x] Add large-circuit memory and throughput fitness gates in release validation (`scripts/backend_capacity_fitness_gate.sh`, `scripts/release_candidate_gate.sh`).
- Tracking note: once the two items above land, the same 14-day scorecard gate enforces sustained closure.

### 8.4 Milestones (Informational)
- `M0 (Week 1)`: complete (`>=4.5` gate + scorecard freeze).
- `M1 (Week 3)`: in progress (critical implementation gaps closed; all backends `>=4.5`).
- `M2 (Week 5)`: planned (coverage-fidelity hardening to `>=4.8`).
- `M3 (Week 7)`: planned (all backends sustained at `5.0/5.0` for 14 consecutive daily runs).

### 8.5 Global Exit Criteria (Release Gate)
- [x] Zero unresolved backend-specific release blockers (`scripts/release_candidate_gate.sh` -> `backend_release_blockers.json`).
- [x] Release candidate gate enforces and archives 5/5 evidence bundles (including 14-day consecutive scorecard thresholds) (`scripts/release_candidate_gate.sh` -> evidence bundle manifest/archive).

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
- [x] Add Halo2-specific lookup integration tests to validate Plookup coverage end to end (`tests/test_halo2_lookup_integration.rs`).
- [x] Publish one semantic-analysis operator guide (invariants, witness extension, lookup workflows) with reproducible commands (`docs/SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md`).

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

# Daily strict streak recording lane (scheduled in GitHub Actions)
# cron: 03:20 UTC via .github/workflows/release_validation.yml
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

### External Effectiveness Corrections (2026-02-22)

#### P0: Mutation Correctness + Portability (must fix first)
- [x] Fix field-mutator correctness to keep generated values in-field by default:
  - apply modular reduction in `bit_flip` / `byte_flip` outputs
  - fix `sub_one(0)` to wrap to `p-1` (field semantics), not `2^256-1`
  - replace misleading bitwise-`negate` behavior with true field negation (`p - x`) and keep bitwise inversion as a separately named mutator
- [x] Remove hardcoded developer-local paths from default runtime/config:
  - remove/replace `DEFAULT_ZK0D_BASE` machine-specific path assumptions
  - replace absolute local CVE fixture paths in `known_vulnerabilities.yaml` with repo-relative or env-configurable roots
- [x] Add regression tests that assert mutators always produce valid field elements for BN254 and preserve boundary semantics (`0`, `1`, `p-1`, `p`).

#### P1: Signal Quality + Cross-Backend Depth
- [x] Upgrade proof-soundness mutation from random byte-noise to algebraically-aware transforms:
  - implement structure-aware mutation hooks for supported proof systems (or explicitly gate unsupported systems)
  - keep random-byte mutation only as a negative-control lane, not a primary soundness signal
- [ ] Reduce backend depth imbalance (Circom vs Noir/Halo2/Cairo):
  - extend constraint-inspection style analyses (unused signal / weak-constraint classes where feasible) beyond Circom
  - publish per-backend recall and true-positive contribution slices so aggregate recall is not Circom-dominated without visibility

#### P2: Coverage Breadth + Oracle Completeness
- [ ] Improve spec-inference robustness against sampling blind spots (targeted boundary witness generation and combination coverage for rare input patterns).
- [ ] Expand vulnerability pattern library beyond current Circom-heavy corpus to include non-Circom/ACIR/Halo2 lookup and newer audit-derived classes.
- [ ] Add a differential oracle path for mock backend mode (behavior comparison against at least one real backend/canonical checker) to detect backend-specific divergence.

#### Exit Evidence For This Correction Wave
- [ ] Mutator validity report: invalid out-of-field mutation rate == `0` across stress campaign.
- [ ] Portability report: clean-clone CVE regression lane runs without machine-specific path edits.
- [ ] Per-backend effectiveness report: separate recall/precision for Circom, Noir, Cairo, Halo2 with explicit target counts and contribution share.

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

### AI-Powered Semantic Intent Analysis (2026-02-22)

**Goal:** Bridge the gap between constraint satisfaction and semantic correctness by using AI to understand developer intent from documentation/comments.

**Execution Policy:** This section is deferred and starts only after the current roadmap is complete (Phase 8 sustained-gate exit met). It is not part of active release gating.

**The Problem:**
- Fuzzer generates witnesses that satisfy all constraints
- But some solutions violate intended semantics ("extra" solutions)
- Manual auditors catch these by understanding intent from docs/comments
- Current fuzzing misses semantic bugs that pass constraint checks

#### Future P0 (Post-Roadmap): Intent Extraction & Semantic Oracle
- [ ] Design intent extraction pipeline:
  - [ ] Parse circuit source files for inline comments and docstrings
  - [ ] Extract README/specification documents from project root
  - [ ] Build structured intent representation (expected behaviors, invariants, security properties)
- [ ] Implement AI-powered intent analyzer:
  - [ ] Use LLM (Mistral/Claude/GPT-4) to extract semantic requirements from natural language
  - [ ] Generate formal invariants from informal descriptions
  - [ ] Identify security-critical properties ("must never", "always", "only if")
- [ ] Build semantic violation detector:
  - [ ] Compare fuzzer-generated witnesses against extracted intent
  - [ ] Classify violations: exploitable vs benign
  - [ ] Rank by severity based on security impact
- [ ] Add exploitability classifier:
  - [ ] AI analyzes which "extra solutions" enable attacks
  - [ ] Generate proof-of-concept exploits for confirmed violations
  - [ ] Provide natural language explanations of vulnerability

#### Implementation Structure
```
crates/zk-semantic-analysis/
├── src/
│   ├── intent_extractor.rs    # Parse docs/comments
│   ├── ai_analyzer.rs          # LLM-powered intent understanding
│   ├── semantic_oracle.rs      # Violation detection
│   ├── exploitability.rs       # Classify attack potential
│   └── report_generator.rs     # Human-readable findings
src/attacks/semantic_violation.rs  # Attack integration
```

#### Workflow Example
```yaml
# Circuit comment: "Only merkle tree members can withdraw"
# Fuzzer finds: witness that satisfies constraints but bypasses membership check
# AI detects: intent violation ("only members" → universal quantifier)
# Classifier: EXPLOITABLE (unauthorized withdrawal)
# Output: "Constraint gap allows non-members to withdraw funds"
```

#### Exit Criteria
- [ ] Extract intent from 20+ real-world circuits with docs/comments
- [ ] Detect ≥3 semantic violations missed by constraint-only analysis
- [ ] Achieve ≥80% precision on exploitability classification (manual validation)
- [ ] Generate actionable reports with fix suggestions

#### Integration Points
- Extends existing `underconstrained` attack with semantic awareness
- Feeds into `invariant_checker.rs` with AI-generated invariants
- Complements `witness_extension` attack with intent-guided search
- Enhances reporting with natural language vulnerability explanations

#### Value Proposition
- **Catches semantic bugs:** Detects vulnerabilities that pass all constraint checks
- **Scales audit expertise:** Automates intent understanding that requires human reasoning
- **Reduces false positives:** Distinguishes exploitable violations from benign edge cases
- **Actionable output:** Provides fix suggestions based on intended semantics

**Status:** ⏸ Deferred (post-roadmap backlog; queued after current roadmap completion)

---

### Compiler Fuzzing (2026-02-22)

**Goal:** Extend fuzzing from circuit inputs to circuit structure itself, enabling compiler edge-case detection and semantic correctness validation.

**Execution Policy:** This section is deferred and starts only after the current roadmap is complete (Phase 8 sustained-gate exit met). It is not part of active release gating.

#### Future P1 (Post-Roadmap): Adversarial Circuit Generation & Compiler Testing
- [ ] **Programmatic Circuit Generation:**
  - [ ] Design circuit generation DSL with backend-specific syntax templates (Circom/Noir/Halo2/Cairo)
  - [ ] Implement bulk generator: produce 1000+ random circuits per backend
  - [ ] Add mutation strategies:
    - [ ] Deep nesting (trigger stack/recursion limits)
    - [ ] Wide constraints (trigger memory/compilation limits)
    - [ ] Pathological loops (trigger optimization bugs)
    - [ ] Mixed types (trigger type checker edge cases)
    - [ ] Malformed IR (trigger parser/validator bugs)
  - [ ] Add AI-powered adversarial pattern generator:
    - [ ] LLM analyzes known compiler bugs from GitHub issues
    - [ ] Generate circuit patterns designed to trigger specific edge cases
    - [ ] Evolve patterns based on compiler crash feedback

- [ ] **Semantic Intent Validation:**
  - [ ] Extract semantic intent from circuit comments/docs
  - [ ] Compile generated circuit and extract constraint count/structure
  - [ ] Verify compiled constraints match intended semantics
  - [ ] Detect constraint gaps (satisfiable but violates intent)
  - [ ] Report: "Circuit allows X but docs say 'only Y'"

- [ ] **Differential Compiler Testing:**
  - [ ] Compile same circuit with multiple compilers (Circom v2.0 vs v2.1)
  - [ ] Compile same circuit across backends (Circom vs Noir for compatible logic)
  - [ ] Compare constraint counts (unexpected differences = bug)
  - [ ] Compare constraint structure (same logic → same constraints)
  - [ ] Detect optimization regressions (constraint count increases)
  - [ ] Version matrix testing: test N circuits × M compiler versions

- [ ] **Compiler Crash/Bug Detection:**
  - [ ] Timeout detection (compilation hangs)
  - [ ] Crash detection (segfault, panic, assertion failure)
  - [ ] Error message classification (ICE vs user error)
  - [ ] Automatic bug report generation with minimal repro
  - [ ] Regression suite: known compiler bugs must stay fixed

#### Implementation Structure
```
crates/zk-circuit-gen/
├── src/
│   ├── generator.rs          # Core circuit generator (bulk mode)
│   ├── strategies.rs         # Mutation strategies
│   ├── ai_adversarial.rs     # AI-powered pattern generation
│   ├── templates/            # Backend-specific templates
│   │   ├── circom.rs
│   │   ├── noir.rs
│   │   ├── halo2.rs
│   │   └── cairo.rs
│   ├── semantic_validator.rs # Intent vs constraints checker
│   ├── differential.rs       # Cross-compiler/version comparison
│   └── crash_detector.rs     # Compiler bug detection
src/attacks/compiler_fuzzing.rs  # Attack integration
```

#### Workflow Examples

**Semantic Intent Validation:**
```
// Generated circuit comment: "Only admin can mint"
// Compiled constraints: 42 constraints
// Semantic check: FAIL - no admin verification constraint found
// Report: "Constraint gap: minting is unconstrained"
```

**Differential Testing:**
```
// Circuit: merkle_proof.circom
// Circom v2.0.0: 156 constraints
// Circom v2.1.0: 312 constraints (2x increase!)
// Report: "Optimization regression in v2.1.0"
```

**AI Adversarial Generation:**
```
// AI analyzes: GitHub issue #1234 "Compiler crashes on deeply nested templates"
// Generates: 50 circuits with 10-20 nesting levels
// Result: Circom v2.0.8 crashes on 3/50 circuits
// Report: "Reproduced issue #1234 with minimal circuit"
```

#### Exit Criteria
- [ ] Generate 1000+ syntactically valid circuits per backend
- [ ] Detect ≥5 semantic intent violations (constraints don't match docs)
- [ ] Find ≥1 compiler crash/timeout on adversarial inputs
- [ ] Differential mode: test 100+ circuits × 3 compiler versions
- [ ] Detect ≥1 optimization regression (constraint count increase)
- [ ] AI generates ≥10 adversarial patterns from known bugs
- [ ] Integration tests validate generated circuits compile on ≥1 backend

#### Value Proposition
- **Compiler hardening:** Find bugs before production deployment
- **Semantic correctness:** Verify constraints match intent (not just syntax)
- **Regression detection:** Catch optimization/correctness regressions across versions
- **Proactive testing:** AI generates edge cases humans wouldn't think of
- **Ecosystem health:** Improve reliability of all ZK compilers

**Status:** ⏸ Deferred (post-roadmap backlog; queued after current roadmap completion)

---

### ZK/Non-ZK Boundary Fuzzing (2026-02-22)

**Goal:** Test the interface between ZK circuits and external components (verifiers, serialization, public inputs) where most integration bugs occur.

**Execution Policy:** This section is deferred and starts only after the current roadmap is complete (Phase 8 sustained-gate exit met). It is not part of active release gating.

**The Problem:**
- ZK circuits are tested in isolation
- Bugs often occur at boundaries: proof generation → verification, circuit → Solidity
- Public input manipulation can bypass circuit logic
- Serialization edge cases cause verification failures
- Gas-optimized verifiers may have different behavior than reference

#### Future P0 (Post-Roadmap): Public Input Manipulation Fuzzer
- [ ] **Valid Proof + Manipulated Public Inputs:**
  - [ ] Generate valid proof for witness W with public inputs P
  - [ ] Mutate public inputs: P' = mutate(P)
  - [ ] Test verification: verify(proof, P') should REJECT
  - [ ] Bug if accepts: verifier doesn't check public inputs correctly
- [ ] **Mutation Strategies:**
  - [ ] Bit flips: flip random bits in public input encoding
  - [ ] Field boundary: replace with 0, p-1, p, p+1
  - [ ] Reordering: swap public input positions
  - [ ] Truncation: remove trailing public inputs
  - [ ] Duplication: repeat public inputs
  - [ ] Type confusion: interpret field element as different type
- [ ] **Attack Scenarios:**
  - [ ] Proof for user A, public input changed to user B (identity swap)
  - [ ] Proof for amount 100, public input changed to 1000 (value inflation)
  - [ ] Proof for valid merkle root, public input changed to attacker's root

#### Future P1 (Post-Roadmap): Serialization/Deserialization Fuzzer
- [ ] **Proof Serialization Edge Cases:**
  - [ ] Empty proof: zero-length byte array
  - [ ] Truncated proof: valid proof with bytes removed
  - [ ] Oversized proof: valid proof with extra bytes appended
  - [ ] Invalid encoding: malformed field elements, points not on curve
  - [ ] Endianness: big-endian vs little-endian confusion
  - [ ] Padding: extra zeros, non-canonical representations
- [ ] **Public Input Serialization:**
  - [ ] Array length mismatch: serialize N inputs, deserialize as M
  - [ ] Type confusion: serialize as field, deserialize as bytes
  - [ ] Encoding variants: hex vs base64 vs binary
  - [ ] Delimiter confusion: comma vs space vs newline
- [ ] **Cross-Language Serialization:**
  - [ ] Rust prover → JavaScript verifier (snarkjs)
  - [ ] Circom → Solidity verifier (ABI encoding)
  - [ ] Noir → TypeScript verifier (JSON encoding)
  - [ ] Test: serialize in language A, deserialize in language B

#### Future P1 (Post-Roadmap): Solidity Verifier Fuzzer
- [ ] **Gas-Optimized Verifier Testing:**
  - [ ] Generate reference verifier (unoptimized)
  - [ ] Generate gas-optimized verifier (production)
  - [ ] Differential testing: same inputs → same outputs
  - [ ] Detect optimization bugs: optimized accepts, reference rejects
- [ ] **Verifier Input Fuzzing:**
  - [ ] Fuzz proof bytes: random mutations
  - [ ] Fuzz public inputs: edge-case values
  - [ ] Fuzz calldata: malformed ABI encoding
  - [ ] Test gas limits: does verifier run out of gas?
  - [ ] Test revert conditions: proper error handling
- [ ] **Pairing Check Manipulation:**
  - [ ] Modify pairing equation components
  - [ ] Test with invalid curve points
  - [ ] Test with points not in correct subgroup
  - [ ] Verify rejection of malformed pairing inputs
- [ ] **Solidity-Specific Edge Cases:**
  - [ ] Integer overflow in gas calculations
  - [ ] Array bounds in public input access
  - [ ] Memory allocation edge cases
  - [ ] Calldata vs memory confusion
  - [ ] Reentrancy (if verifier has callbacks)

#### Future P1 (Post-Roadmap): Cross-Component Integration Fuzzer
- [ ] **End-to-End Workflow Testing:**
  - [ ] Circuit → Prover → Verifier (full pipeline)
  - [ ] Test each boundary independently
  - [ ] Inject faults at each stage
  - [ ] Verify fault detection
- [ ] **Component Mismatch Detection:**
  - [ ] Prover version X, Verifier version Y
  - [ ] Circuit compiled with flags A, Verifier expects flags B
  - [ ] Trusted setup ceremony mismatch
  - [ ] Curve parameter mismatch (BN254 vs BLS12-381)

#### Implementation Structure
```
crates/zk-boundary-fuzz/
├── src/
│   ├── public_input_fuzzer.rs    # Public input manipulation
│   ├── serialization_fuzzer.rs   # Encoding/decoding edge cases
│   ├── solidity_verifier_fuzzer.rs # Verifier contract testing
│   ├── cross_component_fuzzer.rs # Integration testing
│   ├── mutators.rs               # Input mutation strategies
│   └── differential_oracle.rs    # Reference vs optimized comparison
src/attacks/boundary_violation.rs  # Attack integration
```

#### Workflow Examples

**Public Input Manipulation:**
```solidity
// Generate valid proof for withdraw(user=Alice, amount=100)
Proof proof = generate_proof(witness);

// Manipulate public inputs
public_inputs[0] = Bob;  // Change user
public_inputs[1] = 1000; // Inflate amount

// Test verification
bool valid = verifier.verify(proof, public_inputs);
assert(!valid, "Verifier accepted manipulated inputs!");
// Bug found: verifier doesn't bind public inputs to proof
```

**Serialization Edge Case:**
```rust
// Serialize proof in Rust
let proof_bytes = proof.serialize();

// Truncate last byte
let truncated = &proof_bytes[..proof_bytes.len()-1];

// Deserialize in JavaScript
let result = snarkjs.deserialize(truncated);
// Bug found: snarkjs doesn't validate proof length
```

**Solidity Verifier Differential:**
```solidity
// Reference verifier (unoptimized)
bool ref_result = ReferenceVerifier.verify(proof, inputs);

// Gas-optimized verifier
bool opt_result = OptimizedVerifier.verify(proof, inputs);

assert(ref_result == opt_result, "Verifier mismatch!");
// Bug found: optimized verifier skips subgroup check
```

#### Exit Criteria
- [ ] Public input fuzzer: test 1000+ valid proofs with manipulated inputs
- [ ] Detect ≥1 public input binding bug (verifier accepts wrong inputs)
- [ ] Serialization fuzzer: test 100+ edge cases per format
- [ ] Detect ≥1 serialization bug (crash, incorrect deserialization)
- [ ] Solidity fuzzer: differential test 500+ proofs (reference vs optimized)
- [ ] Detect ≥1 gas optimization bug (behavior divergence)
- [ ] Cross-component: test 50+ version/configuration combinations
- [ ] Detect ≥1 integration bug (component mismatch)

#### Integration Points
- Extends `verification_fuzzing` attack with boundary-specific tests
- Complements `soundness` attack with public input manipulation
- Feeds into `differential` attack with cross-language testing
- Provides Solidity-specific testing for smart contract verifiers

#### Value Proposition
- **Real-world bugs:** Most vulnerabilities occur at component boundaries
- **Integration testing:** Tests full pipeline, not just isolated circuits
- **Public input security:** Ensures proofs are bound to public inputs
- **Serialization safety:** Catches encoding bugs that cause verification failures
- **Verifier correctness:** Validates gas-optimized Solidity verifiers
- **Cross-language:** Tests interop between Rust/JS/Solidity components

**Status:** ⏸ Deferred (post-roadmap backlog; queued after current roadmap completion)

---

### Cryptographic Primitives Fuzzing (2026-02-22)

**Goal:** Systematically test low-level cryptographic operations (field arithmetic, curve operations, pairings) with edge cases that trigger implementation bugs.

**Execution Policy:** This section is deferred and starts only after the current roadmap is complete (Phase 8 sustained-gate exit met). It is not part of active release gating.

**The Problem:**
- ZK circuits rely on field arithmetic, elliptic curves, and pairings
- Edge cases (0, identity, invalid points) often expose bugs
- Manual testing misses rare combinations
- Implementation bugs can break soundness

#### Future P1 (Post-Roadmap): Field Arithmetic Fuzzer
- [ ] **Edge-Case Value Generator:**
  - [ ] Special values: `0`, `1`, `-1`, `p/2`, `p-1`, `p`, `p+1`
  - [ ] Algebraic properties: squares, non-squares, generators, primitive roots
  - [ ] Random values: uniform distribution across field
  - [ ] Boundary values: near-zero, near-modulus
- [ ] **Operation Coverage:**
  - [ ] Addition: `a + b` (overflow, underflow, identity)
  - [ ] Subtraction: `a - b` (negative results, wraparound)
  - [ ] Multiplication: `a * b` (overflow, zero, one)
  - [ ] Division: `a / b` (division by zero, inverse computation)
  - [ ] Exponentiation: `a^b` (large exponents, zero exponent)
  - [ ] Modular reduction: verify `(a op b) mod p == expected`
- [ ] **Property Testing:**
  - [ ] Commutativity: `a + b == b + a`
  - [ ] Associativity: `(a + b) + c == a + (b + c)`
  - [ ] Distributivity: `a * (b + c) == a*b + a*c`
  - [ ] Identity: `a + 0 == a`, `a * 1 == a`
  - [ ] Inverse: `a * a^(-1) == 1` (for `a != 0`)

#### Future P1 (Post-Roadmap): Curve Operation Fuzzer
- [ ] **Point Generator:**
  - [ ] Identity/infinity point: `O`
  - [ ] Generator point: `G`
  - [ ] Random valid points: `[k]G` for random `k`
  - [ ] Low-order points: points with small order
  - [ ] Invalid points: not on curve `y^2 != x^3 + ax + b`
  - [ ] Points at infinity in different representations
- [ ] **Operation Coverage:**
  - [ ] Point addition: `P + Q`
  - [ ] Point doubling: `2P`
  - [ ] Scalar multiplication: `[k]P`
  - [ ] Multi-scalar multiplication: `[k1]P1 + [k2]P2`
  - [ ] Point negation: `-P`
  - [ ] Point validation: `is_on_curve(P)`
- [ ] **Edge Case Testing:**
  - [ ] Adding identity: `P + O == P`
  - [ ] Adding inverse: `P + (-P) == O`
  - [ ] Doubling identity: `2O == O`
  - [ ] Zero scalar: `[0]P == O`
  - [ ] One scalar: `[1]P == P`
  - [ ] Large scalar: `[p]P` (order wraparound)
  - [ ] Invalid point rejection: operations on invalid points must fail

#### Future P1 (Post-Roadmap): Pairing Fuzzer
- [ ] **Input Combination Matrix:**
  - [ ] G1 inputs: `{O, G1, random, low-order, invalid}` (5 cases)
  - [ ] G2 inputs: `{O, G2, random, low-order, invalid}` (5 cases)
  - [ ] Systematic testing: 5 × 5 = 25 combinations
- [ ] **Pairing Properties:**
  - [ ] Bilinearity: `e([a]P, [b]Q) == e(P, Q)^(ab)`
  - [ ] Non-degeneracy: `e(G1, G2) != 1`
  - [ ] Identity: `e(O, Q) == 1`, `e(P, O) == 1`
  - [ ] Linearity in G1: `e(P1 + P2, Q) == e(P1, Q) * e(P2, Q)`
  - [ ] Linearity in G2: `e(P, Q1 + Q2) == e(P, Q1) * e(P, Q2)`
- [ ] **Degenerate Cases:**
  - [ ] Both inputs identity: `e(O, O)`
  - [ ] One input identity: `e(G1, O)`, `e(O, G2)`
  - [ ] Low-order inputs: detect subgroup attacks
  - [ ] Invalid inputs: must reject or handle safely

#### Implementation Structure
```
crates/zk-crypto-fuzz/
├── src/
│   ├── field_fuzzer.rs       # Field arithmetic testing
│   ├── curve_fuzzer.rs       # Elliptic curve operations
│   ├── pairing_fuzzer.rs     # Pairing operations
│   ├── generators.rs         # Edge-case value generation
│   ├── property_checker.rs   # Algebraic property validation
│   └── oracle.rs             # Reference implementation comparison
src/attacks/crypto_primitives.rs  # Attack integration
```

#### Workflow Example
```rust
// Field arithmetic bug detection
let edge_cases = [0, 1, p-1, p, p+1];
for a in edge_cases {
    for b in edge_cases {
        let result = field_mul(a, b);
        assert!(result < p, "Result not reduced: {}", result);
        // Bug found: field_mul(p, 1) returns p (should be 0)
    }
}

// Curve operation bug detection
let P = random_point();
let result = point_add(P, point_negate(P));
assert!(is_identity(result), "P + (-P) should be identity");
// Bug found: point_add doesn't handle inverse correctly

// Pairing bug detection
let e1 = pairing(identity_g1(), G2);
assert_eq!(e1, GT::one(), "e(O, G2) should be 1");
// Bug found: pairing with identity returns random value
```

#### Exit Criteria
- [ ] Field fuzzer: test 100+ operations × 10 edge-case values = 1000+ tests
- [ ] Curve fuzzer: test 50+ operations × 7 point types = 350+ tests
- [ ] Pairing fuzzer: test 25 input combinations × 5 properties = 125+ tests
- [ ] Detect ≥1 field arithmetic bug (incorrect reduction, overflow)
- [ ] Detect ≥1 curve operation bug (invalid point handling, identity)
- [ ] Detect ≥1 pairing bug (degenerate case, bilinearity violation)
- [ ] Property tests: 100% pass rate on reference implementation
- [ ] Integration with existing attack framework

#### Integration Points
- Extends `arithmetic_overflow` attack with systematic edge-case coverage
- Feeds into `soundness` attack with invalid curve point detection
- Complements `boundary` attack with algebraic property testing
- Provides oracle for differential testing against reference implementations

#### Value Proposition
- **Soundness bugs:** Catch implementation errors that break cryptographic assumptions
- **Systematic coverage:** Test all edge cases, not just random inputs
- **Property-based:** Verify algebraic properties hold (commutativity, bilinearity)
- **Reference comparison:** Detect divergence from canonical implementations
- **Proactive:** Find bugs before they reach production circuits

**Status:** ⏸ Deferred (post-roadmap backlog; queued after current roadmap completion)

---

### Post-Roadmap Execution Workflow (Deferred Additions)

**Applies to:** AI semantic intent analysis, compiler fuzzing, ZK/non-ZK boundary fuzzing, and cryptographic primitive fuzzing.

**Operator Workflow (short form)**
- [ ] Activate only after current roadmap completion (Phase 8 sustained-gate exit met); keep out of active release gates until then.
- [ ] Run a foundation sprint first: shared corpus/evidence store, shared finding schema, shared replay/minimization harness, shared dashboard.
- [ ] Execute in this order for ROI: `boundary -> compiler -> semantic -> crypto`.
- [ ] Use shared data flow: compiler-generated circuits feed boundary tests; boundary/compiler findings feed semantic exploitability ranking; crypto checks validate math-level correctness vs noise; semantic outputs feed generator prioritization for next cycle.
- [ ] Use weekly cadence: `generate -> boundary -> semantic -> crypto -> regress`.
- [ ] Enforce promotion gates: deterministic replay, false-positive budget, explicit coverage counts, and required regression tests for accepted high/critical findings.
- [ ] Operate one integrated pipeline: `generate -> attack -> interpret -> validate -> regress`.

**Modularization Blueprint (design requirement)**
- [ ] Split deferred work into separate crates/modules with strict boundaries:
  - `crates/zk-postroadmap-core`: shared contracts (`TrackInput`, `TrackFinding`, `ReplayArtifact`, scorecard schema, error taxonomy).
  - `crates/zk-track-boundary`: public-input/serialization/verifier boundary testing only.
  - `crates/zk-track-compiler`: circuit generation, compiler differential, crash/timeout classification.
  - `crates/zk-track-semantic`: intent extraction, semantic violation ranking, exploitability classification.
  - `crates/zk-track-crypto`: field/curve/pairing property fuzzing and reference checks.
  - `src/pipeline/post_roadmap_runner.rs`: orchestration only (no track-specific logic).
- [ ] Enforce interface-first integration:
  - each track implements a common runner trait (prepare -> run -> validate -> emit).
  - tracks communicate only through `zk-postroadmap-core` artifact contracts.
  - no direct track-to-track imports (dependency direction: `track -> core`, `runner -> track + core`).
- [ ] Keep adapters modular:
  - AI/LLM providers behind a single adapter interface in semantic track.
  - compiler backend adapters behind per-backend strategy interfaces in compiler track.
  - verifier/serialization adapters behind protocol interfaces in boundary track.
- [ ] Enforce module-level quality gates:
  - per-track tests + replay tests + contract compatibility tests.
  - each track versioned independently in docs/changelog and can be toggled on/off by config.
  - failures in one track should not block execution of other tracks (partial-run resilience).

---

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
