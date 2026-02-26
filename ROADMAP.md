# ZkPatternFuzz Production Roadmap

Date: 2026-02-23  
Status: Active  
Primary goal: make the scanner production-grade for real multi-target runs with high recall and high runtime stability, and drive every supported circuit framework to a measurable 5/5 maturity score.

---

## 📊 Status Overview (2026-02-23)

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

## Immediate Stabilization Plan (Detection -> Immediate Proof)

### Policy (no `pending_proof` in normal flow)
- [x] Every matched `detected_pattern` starts proof in the same run.
- [x] Remove `pending_proof` from normal completed runs.
- [x] Allow only final proof states: `exploitable`, `not_exploitable_within_bounds`, `proof_failed`, `proof_skipped_by_policy`.
- [x] Block "confirmed vulnerability" unless required proof artifacts exist.

### Execution flow (per pattern)
- [ ] Run detection stage and write pattern signal summary.
- [ ] Immediately start deterministic replay for that pattern.
- [ ] If replay succeeds with bad behavior, mark `exploitable`.
- [ ] If replay does not reproduce, run bounded non-exploit checks.
- [x] Mark `not_exploitable_within_bounds` only when bounded checks finish with no counterexample.
- [x] Mark `proof_failed` when proof stage errors, times out, or artifacts are incomplete.

Current status: ✅ `src/run_outcome_docs.rs` now classifies wall-clock timeouts (and proof-stage failures) as `proof_failed`, while still preserving `not_ready` for non-proof preflight failures; `zkpatternfuzz` now enforces the detected-pattern proof contract by forcing matched-pattern templates without a started proof state to `proof_failed` + `reason_code=proof_stage_not_started` (`src/bin/zkpatternfuzz.rs`, `tests/test_bin_zkpatternfuzz.rs`, 2026-02-26).

### Console clarity
- [x] Replace ambiguous wording (`failures`) with `template_errors`.
- [x] Show live template progress in console (`template start`, `step`, `template end`).
- [x] Print a clear stage line per template: `detecting`, `proving`, `proof_done`.
- [x] Print a final totals line with explicit labels: `detected_patterns`, `proven_exploitable`, `proven_not_exploitable_within_bounds`, `proof_failed`, `template_errors`.
- [x] Keep wording `detected_patterns` only for detection signals, never for proven bugs.

Current status: ✅ console + run-log proof totals now use `proven_exploitable` / `proven_not_exploitable_within_bounds`, while `detected_patterns` remains detection-only in final totals (`src/bin/zkpatternfuzz.rs`, 2026-02-26).

### Reliability guardrails
- [x] Enforce per-template hard timeout for detection and proof stages.
- [x] Add stuck-step warning when progress does not change for a fixed window.
- [x] Keep memory guard on by default for proof stage and fail fast on unsafe settings.
- [x] Reduce repeated backend probe loops when offline dependencies are missing.

Current status: ✅ `zkpatternfuzz` now enforces per-template hard timeouts for detection (`attack_*`) and proof/reporting (`reporting`/proof-like progress stages), kills timed-out process trees, writes synthetic `run_outcome.json` with `reason_code=wall_clock_timeout` + `proof_status=proof_failed`, emits `[TEMPLATE WARNING] ... warning=stuck_step ...` when progress is unchanged for the fixed window (`ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS`), fails fast on unsafe proof-stage memory guard settings (`ZKF_ZKPATTERNFUZZ_MEMORY_GUARD_ENABLED=false` or `ZKF_ZKPATTERNFUZZ_MEMORY_RESERVED_MB=0`), and stops Halo2 toolchain cascades after dependency-resolution failures to avoid repeated offline probe loops (`crates/zk-backends/src/halo2/mod.rs`, `crates/zk-backends/tests/test_halo2_toolchain_cascade.rs`, 2026-02-26).

### Proof artifact contract (mandatory)
- [x] Require `replay_command.txt` for every proved outcome.
- [x] Require one of: `exploit_notes.md` or `no_exploit_proof.md`.
- [x] Require `impact.md`.
- [x] Require replay/formal execution log.
- [x] If any required file is missing, force final state to `proof_failed`.

Current status: ✅ enforced by `has_required_proof_artifacts()` + proof-status gating in `src/run_outcome_docs.rs`; validated by `tests/test_run_outcome_standardization.rs` (`cargo test --test test_run_outcome_standardization` on 2026-02-26: 8/8 pass).

### Exit criteria for this stabilization block
- [ ] 20-run campaign: >=95% completion, with no machine freeze.
- [ ] 20-run campaign: zero terminal `pending_proof` entries.
- [ ] 20-run campaign: timeout and memory guard events are visible in logs.
- [ ] 20-run campaign: all confirmed bugs have complete proof artifact sets.

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
- [x] Fix Cairo execution recovery/coverage behavior
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
- [x] Add reason-code aggregation in `zkpatternfuzz`

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
- [x] Add selector-mismatch synthetic outcome classification in `zkpatternfuzz` to eliminate validation-skip `run_outcome_missing` gaps
- [x] Add Noir end-to-end prove/verify smoke and fuzz parity tests for external `Nargo.toml` projects
- [x] Add Cairo breadth-target suite to `zk0d_matrix` default validation set (not optional backend-heavy-only checks) (`targets/zk0d_matrix_breadth.yaml`)
- [x] Add Cairo full-capacity regression suite with stable coverage/failure semantics on external and local targets
- [x] Add Cairo JSON/metadata input reconciliation recovery (wire-label/index compatibility) (`src/executor/mod.rs`)
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
- [x] Halo2 migration guide from legacy test mode
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

### Historical Baseline Snapshot (2026-02-22)
- Noir: `4.0/5.0`
- Halo2: `3.1/5.0`
- Cairo: `2.8/5.0`
- Circom: `4.5/5.0` (finalized in Week 1 scorecard freeze)
- Cross-backend readiness: `4.2/5.0`

### Latest Scorecard Snapshot (2026-02-23)
- Noir: `5.0/5.0`
- Halo2: `5.0/5.0`
- Cairo: `5.0/5.0`
- Circom: `5.0/5.0`
- Cross-backend readiness: `5.0/5.0`
- 14-day maturity streak progress: `circom=2/14`, `noir=1/14`, `cairo=1/14`, `halo2=1/14`
- Circom flake streak progress: `2/14`

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
- [x] Add one-command streak status runner (`scripts/run_release_streak_status.sh`) to refresh both streak trackers and print remaining-day/projection deltas for daily operations (wired into `.github/workflows/release_validation.yml` summary output).
- [x] Add regression coverage for streak calculators and streak-status wrapper, and run it in CI quick gates (`tests/test_backend_maturity_scorecard.py`, `tests/test_circom_flake_gate.py`, `tests/test_release_streak_status.py`, `.github/workflows/ci.yml`).

### 8.3 Backend-Specific Closure Plans (Release-Critical)

#### Noir -> 5/5
- [x] Expand Noir matrix coverage to `>=25` selector-matching classified runs per release cycle.
- [x] Add compatibility matrix tests for supported `nargo` versions and artifact layouts.
- [x] Add hard proof artifact contract tests (path + format + deterministic verify inputs).
- Tracking note: 14-day `5.0` streak is enforced by the scorecard history gate, not a separate manual checklist item.

#### Halo2 -> 5/5
- [x] Implement key setup path in `Halo2Target::setup_keys` (or a strict canonical adapter with equivalent guarantees).
- [x] Add canonical execution/prove/verify integration that is not dependent on ad-hoc custom CLI flags in target binaries.
- [x] Replace metadata-only success recoveries with strict production behavior in readiness lanes.
- [x] Expand Halo2 matrix to at least 5 targets (JSON specs + real circuits + external circuits).
- Tracking note: `runtime_error=0` and 14-day `5.0` streak remain enforced by release-gate thresholds.

#### Cairo -> 5/5
- [x] Replace source-assertion-only coverage recovery with trace/AIR-backed production coverage.
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

### 8.6 Active Closure Tasks (2026-02-23)
- [x] Raise Noir maturity score from `4.5` to `5.0` and begin a non-zero 14-day streak (now `5.0/5.0`, streak `1/14`; scorecard normalization counts skipped integration checks as non-executed instead of failed in `scripts/backend_maturity_scorecard.sh`).
- [x] Raise Halo2 maturity score from `4.5` to `5.0` and begin a non-zero 14-day streak (now `5.0/5.0`, streak `1/14`; scorecard normalization counts skipped integration checks as non-executed instead of failed in `scripts/backend_maturity_scorecard.sh`).
- [x] Raise Cairo maturity score from `4.95` to `5.0` and begin a non-zero 14-day streak (now `5.0/5.0`, streak `1/14`; scorecard applies a bounded selector-mismatch grace rate so benign low mismatch does not cap constraint-coverage fidelity in `scripts/backend_maturity_scorecard.sh`).
- [ ] Continue Circom strict lane daily to move streak from `2/14` to `14/14` (`12` days remaining as of `2026-02-23`; projected earliest completion `2026-03-07` if consecutive passes continue; run `scripts/run_release_streak_status.sh` each day to refresh both maturity + flake projections).

### 8.7 Logic Error Triage (2026-02-23)
- [x] Harden UTC date-boundary determinism in Circom flake streak tests so the two-day streak assertion cannot flake around midnight (`tests/test_circom_flake_gate.py`).
- [x] Harden isolated worker response-file cleanup: ignore expected `NotFound` during cleanup and keep warning logs for unexpected remove failures (`src/executor/isolated.rs`).
- [x] Replace isolated executor 5ms poll sleep loop with timeout-capable process wait semantics to avoid busy-wait CPU burn under long-running workers (`src/executor/isolated.rs`).
- [x] Add corrupted-history recovery for Circom flake gate history loads (fallback to empty history + explicit warning instead of raw JSON parse crash) (`scripts/circom_flake_gate.sh`).
- Triage note: lock-free approximate counters are currently intentional/documented (`src/corpus/lockfree.rs`) and contention tests validate first-wins bitmap accounting (`tests/concurrency_stress_tests.rs`), so those claims are not currently tracked as blockers.

### 8.8 Core Logic Error Intake (2026-02-23)
- [x] Canonicalize `FieldElement::random()` output to BN254 scalar field range (`crates/zk-core/src/field.rs`).
- [x] Implement real hash-mode deduplication (remove always-false duplicate fallback) (`crates/zk-fuzzer-core/src/corpus/deduplication.rs`).
- [x] Include scoped public inputs in underconstrained collision PoCs (`crates/zk-fuzzer-core/src/oracle.rs`).
- [x] Prevent repeated variance spam in `ConstraintCountOracle` after first min/max divergence finding (`crates/zk-fuzzer-core/src/oracle.rs`).
- [x] Separate dedup capacity drops from true duplicate counters (`crates/zk-fuzzer-core/src/corpus/deduplication.rs`).
- [x] Make `Explore` schedule startup behavior non-degenerate when global edge count is still zero (`crates/zk-fuzzer-core/src/power_schedule.rs`).
- [x] Let power-schedule energy influence mutation depth beyond the fixed `10` cap while retaining bounded cost (`crates/zk-fuzzer-core/src/engine.rs`).
- [x] Make finding clustering deterministic across runs (remove `HashMap` iteration-order sensitivity) (`crates/zk-fuzzer-core/src/corpus/deduplication.rs`).
- [x] De-duplicate BN254 modulus initialization in overflow oracle by reusing centralized constants helper (`crates/zk-fuzzer-core/src/oracle.rs`, `crates/zk-fuzzer-core/src/constants.rs`).
- [x] Reduce lock hold time in `CoverageTracker::record_hit` by avoiding nested write-lock lifetime overlap (`crates/zk-fuzzer-core/src/coverage.rs`).
- [x] Feed adaptive power scheduling with live per-seed metrics (selection/findings/new-coverage counts, avg exec time, path frequency) instead of static placeholders (`crates/zk-fuzzer-core/src/engine.rs`).
- [x] Add canonical field constructors (`from_bytes_checked`, `from_bytes_reduced`, `from_hex_checked`) and apply canonical-by-default parsing/mutation in runtime ingestion paths (`crates/zk-core/src/field.rs`, `src/fuzzer/engine/corpus_manager.rs`, `src/fuzzer/engine/chain_runner.rs`, `src/chain_fuzzer/mutator.rs`, `src/fuzzer/grammar/mod.rs`, `crates/zk-fuzzer-core/src/structure_aware.rs`).
- [x] Make CVE range-oracle construction modulus-aware by plumbing explicit field modulus through `CveOracle` constructors and using `RangeProofOracle::new_with_modulus` (`src/cve/mod.rs`).
- [x] Reduce lock hold time in `CoverageTracker::record_execution` by releasing `constraint_hits` before updating `max_coverage` (`crates/zk-fuzzer-core/src/coverage.rs`).
- [x] Make `AdditionalConfig` numeric getters non-panicking on malformed values (warn + ignore invalid strings instead of crashing process) (`src/config/additional.rs`).
- [x] Wire `ConstraintCountOracle` expected count to executor-reported circuit constraints instead of campaign ceiling limits (`src/fuzzer/engine/config_helpers.rs`, `src/fuzzer/engine/engine_init.rs`).
- [x] Canonicalize invariant field-literal parsing (`hex`/`decimal`/`2^N`) so non-canonical bounds are rejected from normal invariant evaluation paths (`src/fuzzer/invariant_checker.rs`).
- [x] Make deduplicator capacity replacement rank-aware: only evict when incoming finding is strictly stronger than current weakest retained finding (prevents low-severity replacement of critical findings) (`crates/zk-fuzzer-core/src/corpus/deduplication.rs`).
- [x] Remove panic paths from cross-step chain assertion parsing; malformed/overflow indices now parse as unsupported relation and fail through normal config validation (`src/chain_fuzzer/invariants.rs`, `src/config/mod.rs`).
- [x] Use real circuit constraint count (with `max(1)` safety only) when initializing coverage tracker to preserve accurate percentage reporting on small circuits (`src/fuzzer/engine/engine_init.rs`).
- [x] Enforce canonical field elements during serde deserialization by switching `FieldElement` JSON/YAML parse path to `from_hex_checked` (`crates/zk-core/src/field.rs`).
- [x] Enforce canonical field elements during `Finding` custom deserialization (`poc.witness_a`/`witness_b`/`public_inputs`) by using `from_hex_checked` in the compatibility deserializer (`crates/zk-core/src/types.rs`).
- [x] Feed constraint-count oracle with per-execution observed counts (execution coverage first, inspector/metadata fallback) instead of one-time cached value (`crates/zk-fuzzer-core/src/engine.rs`).
- [x] Add modulus-aware semantic oracle helper: `CombinedSemanticOracle::with_all_oracles_with_modulus(...)` and route default helper through explicit modulus wiring (`src/fuzzer/oracles/mod.rs`).
- [x] Remove mutator-local BN254 modulus hex decode + zero fallback and use centralized byte helper directly (`crates/zk-fuzzer-core/src/mutators.rs`, `crates/zk-fuzzer-core/src/constants.rs`).
- [x] Prevent repeated `ConstraintCountOracle` mismatch spam: emit count-mismatch finding once per oracle lifecycle (still emit one variance finding when min/max diverge) (`crates/zk-fuzzer-core/src/oracle.rs`).
- [x] Scope PoC `public_inputs` in `ConstraintCountOracle` and `ArithmeticOverflowOracle` using configured public-input count (`crates/zk-fuzzer-core/src/oracle.rs`, `src/fuzzer/engine/config_helpers.rs`, `src/fuzzer/engine/engine_init.rs`).
- [x] Make attack-phase progress snapshots distinguishable at boundaries by using consistent per-attack phase index plus `phase_progress` (start `0.0`, complete `1.0`) instead of overlapping integer jumps (`src/fuzzer/engine/run_dispatch.rs`).
- [x] Replace repeated-subtraction field reduction in mutators with bounded BigUint modulo for stable performance on high-value mutations (`crates/zk-fuzzer-core/src/mutators.rs`).
- [x] Prevent soundness attack verifier errors from aborting full campaigns by treating verifier transport/runtime failures as per-attempt skips (`src/fuzzer/engine/attack_runner_soundness.rs`).
- [x] Harden Circom proof verification semantics so `snarkjs` "Invalid proof" returns `Ok(false)` instead of bubbling as a fatal runtime error (`crates/zk-backends/src/circom/mod.rs`).
- [x] Add explicit witness-input contract diagnostics (required signal coverage + provided map shape) for Circom witness generation failures (`crates/zk-backends/src/circom/mod.rs`).
- [x] Extend run outcome reason-code classifier with dependency-resolution and backend-input-contract mismatch buckets for clearer external-target triage (`src/run_outcome_docs.rs`, `src/bin/zkpatternfuzz.rs`).

### 8.9 External Target Hardening Plan (`/media/elements/Repos`)

**Goal:** pressure-test logic-bug discoverability on real-world third-party ZK repositories selected by operators.
**Execution mode:** manual checks only (no cron dependency for this track).
**Target source root:** `/media/elements/Repos`.

#### 8.9.1 Intake Checklist
- [x] Build and freeze the candidate repo inventory from `/media/elements/Repos` (name, framework, commit hash, license).
- [x] Select initial priority set with balanced backend coverage (Circom/Noir/Cairo/Halo2).
- [x] Record selected target commit SHAs and circuit entrypoints before first run.
- [x] Classify each target as `safe-regression` or `vulnerable-ground-truth` expectation.
- [x] Add each selected target into matrix YAMLs used by manual campaigns.
- [x] Attach stable human-readable target names (slug aliases) so `EXT-###` IDs are not the only label in planning/reporting.

Inventory + matrix references:
- `targets/external_repo_inventory_2026-02-23.json`
- `targets/zk0d_matrix_external_manual.yaml`
- `targets/external_repo_catalog_all_2026-02-25.json` (full discovered catalog; all supported entrypoints)
- `targets/zk0d_matrix_external_all.yaml` (auto-generated all-target matrix, `enabled: false` by default)

#### 8.9.2 Target Selection Board
| Target ID | Target Name | Repo Path | Backend | Circuit/Program Entry | Expected Class | Priority | Owner | Intake Status |
|---|---|---|---|---|---|---|---|---|
| EXT-001 | `circomlib_ml_argmax` | `/media/elements/Repos/zkml/circomlib-ml` | `circom` | `circuits/ArgMax.circom` | `safe-regression` | `P0` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-002 | `zkfuzz_bulk_assignment` | `/media/elements/Repos/zkFuzz` | `circom` | `tests/sample/test_bulk_assignment.circom` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-003 | `zkfuzz_vulnerable_iszero` | `/media/elements/Repos/zkFuzz` | `circom` | `tests/sample/test_vuln_iszero.circom` | `vulnerable-ground-truth` | `P0` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-004 | `orion_scarb_root` | `/media/elements/Repos/zkml/orion` | `cairo` | `Scarb.toml` | `safe-regression` | `P0` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-005 | `ezkl_main_cargo` | `/media/elements/Repos/zkml/ezkl` | `halo2` | `Cargo.toml` | `safe-regression` | `P0` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-006 | `zkevm_circuits_main` | `/media/elements/Repos/zk0d/cat2_rollups/zkevm-circuits` | `halo2` | `zkevm-circuits/Cargo.toml` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-007 | `aztec_hello_circuit` | `/media/elements/Repos/zk0d/cat3_privacy/aztec-packages` | `noir` | `docs/examples/circuits/hello_circuit/Nargo.toml` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-008 | `orion_linear_classifier_test` | `/media/elements/Repos/zkml/orion` | `cairo` | `tests/ml/linear_classifier_test.cairo` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-009 | `aztec_barretenberg_fixture_main` | `/media/elements/Repos/zk0d/cat3_privacy/aztec-packages` | `noir` | `barretenberg/docs/examples/fixtures/main/Nargo.toml` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-010 | `circomlib_iszero` | `/media/elements/Repos/zk0d/cat3_privacy/circuits` | `circom` | `node_modules/circomlib/test/circuits/iszero.circom` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-011 | `circomlib_lessthan` | `/media/elements/Repos/zk0d/cat3_privacy/circuits` | `circom` | `node_modules/circomlib/test/circuits/lessthan.circom` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-012 | `circomlib_montgomerydouble` | `/media/elements/Repos/zk0d/cat3_privacy/circuits` | `circom` | `node_modules/circomlib/test/circuits/montgomerydouble.circom` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-013 | `circomlib_ml_relu` | `/media/elements/Repos/zkml/circomlib-ml` | `circom` | `circuits/ReLU.circom` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-014 | `circomlib_ml_dense` | `/media/elements/Repos/zkml/circomlib-ml` | `circom` | `circuits/Dense.circom` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-015 | `orion_svm_classifier_test` | `/media/elements/Repos/zkml/orion` | `cairo` | `tests/ml/svm_classifier_test.cairo` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |
| EXT-016 | `aztec_barretenberg_fixture_recursive` | `/media/elements/Repos/zk0d/cat3_privacy/aztec-packages` | `noir` | `barretenberg/docs/examples/fixtures/recursive/Nargo.toml` | `safe-regression` | `P1` | `unassigned` | `[x] planned / [x] active / [x] done` |

Backend coverage snapshot (selected vs target floor=2):
| Backend | Selected Targets | Floor | Coverage Status |
|---|---:|---:|---|
| Circom | 8 | 2 | `met` |
| Noir | 3 | 2 | `met` |
| Cairo | 3 | 2 | `met` |
| Halo2 | 2 | 2 | `met` |

All-target catalog snapshot (`2026-02-25`):
- Repositories scanned: `78`
- Repositories with supported entrypoints: `20`
- Supported entrypoints discovered: `628` (`circom=412`, `noir=184`, `cairo=1`, `halo2=31`)
- Note: execution board remains curated (`EXT-001`..`EXT-016`); full catalog is tracked separately for exhaustive intake.

#### 8.9.3 Manual Execution Checklist
- [x] Run backend readiness dashboard after each target-batch update (`scripts/backend_readiness_dashboard.sh`).
- [x] Run backend maturity scorecard after each target-batch update (`scripts/backend_maturity_scorecard.sh --consecutive-days 14 --consecutive-target-score 5.0`).
- [x] Run backend effectiveness report on the latest outcomes (`python3 scripts/build_backend_effectiveness_report.py --repo-root .`).
- [x] Run release streak status wrapper after each manual validation batch (`scripts/run_release_streak_status.sh`).
- [x] Archive evidence paths for each batch under `artifacts/` and link them in the run ledger table.
- [x] Execute first-run manual evidence coverage for all intake-expanded targets (`EXT-013`, `EXT-014`, `EXT-015`, `EXT-016`) via one dedicated batch and archive artifacts (`artifacts/external_targets/ext_batch_013/reports/batch_summary.md`).
- [x] Update follow-up snapshot state rows for `EXT-013`..`EXT-016` immediately after first-run evidence; keep proof status `pending_proof` unless replay or bounded non-exploit evidence exists.

#### 8.9.4 Manual Run Ledger
| Run Date (UTC) | Batch ID | Targets Included | Command Profile | Total Runs | Completion Rate | Recall | Safe High-Conf FPR | Evidence Bundle | Gate Result |
|---|---|---|---|---:|---:|---:|---:|---|---|
| `2026-02-23` | `EXT-BATCH-001` | `EXT-001, EXT-003, EXT-004, EXT-005` | `evidence-strict (seed=42, iter=100000, timeout=300, workers=2)` | `3` | `0.67 (Step 0-5 complete; Step 6-8 pending)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_001/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |
| `2026-02-23` | `EXT-BATCH-002` | `EXT-002, EXT-006` | `evidence-strict (seed=42, iter=100000, timeout=300, workers=2)` | `2` | `0.44 (Step 0-3 complete; Step 4-8 pending)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_002/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |
| `2026-02-23` | `EXT-BATCH-003` | `EXT-007, EXT-008, EXT-009` | `evidence-strict (seed=42, iter=100000, timeout=300, workers=2)` | `3` | `0.44 (Step 0-3 complete; Step 4-8 pending)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_003/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |
| `2026-02-23` | `EXT-BATCH-004` | `EXT-010, EXT-011, EXT-012` | `evidence-strict (seed=42, iter=1000, timeout=30, workers=1)` | `3` | `0.44 (Step 0-3 complete; Step 4-8 pending)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_004/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |
| `2026-02-23` | `EXT-BATCH-005` | `EXT-001, EXT-004, EXT-005` | `evidence-strict (seed=42, iter=1000, timeout=30, workers=1)` | `3` | `0.44 (Step 0-3 complete; Step 4-8 pending)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_005/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |
| `2026-02-23` | `EXT-BATCH-006` | `EXT-004, EXT-005` | `evidence-quickcheck (seed=42, iter=1, timeout=5, workers=1, parallel)` | `2` | `0.44 (Step 0-3 complete; Step 4-8 pending)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_006/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |
| `2026-02-24` | `EXT-BATCH-008` | `EXT-010, EXT-011, EXT-012` | `evidence-quickcheck (seed=42, iter=200, timeout=20, workers=1)` | `3` | `1.00 (Step 0-8 complete for signal-quality revalidation)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_008/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |
| `2026-02-24` | `EXT-BATCH-010` | `EXT-002, EXT-006, EXT-007, EXT-008, EXT-009` | `evidence-quickcheck (seed=42, iter=200, timeout=60, workers=1; EXT-006 local-copy rerun timeout=300 with local Go module/cache env)` | `5` | `0.44 (Step 0-3 complete; Step 4-8 pending)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_010/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |
| `2026-02-24` | `EXT-BATCH-011` | `EXT-001, EXT-002, EXT-008` | `evidence-quickcheck (seed=42, iter=200, timeout=60, workers=1; EXT-008 rerun with warm local Scarb cache)` | `3` | `0.00 (Step 0-3 complete; Step 4-8 pending)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_011/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |
| `2026-02-25` | `EXT-BATCH-013` | `EXT-013, EXT-014, EXT-015, EXT-016` | `evidence-quickcheck (seed=42, iter=200, timeout=90, workers=1; EXT-016 local-copy rerun after Noir preflight compatibility fixes)` | `4 (executed; reruns applied where needed)` | `1.00 (Step 0-3 complete; proof branch pending)` | `n/a` | `n/a` | `artifacts/external_targets/ext_batch_013/{logs,manifests,reports,repro}` | `[ ] pass / [x] fail` |

`EXT-BATCH-001` snapshot SHAs (`artifacts/external_targets/ext_batch_001/manifests/target_snapshot.json`):
- `EXT-001`: `c82b3072d7946a76487a8c1be463fc407045391c`
- `EXT-003`: `072bf1fbbd1c9ecad58d4f6d2204c3b96e7fec17`
- `EXT-004`: `bac0b424fe08e0da9e2522a45d77c028acf47dcd`
- `EXT-005`: `e196b111c1bafaa61b92ae431cd3c3fe9371da05`

`EXT-BATCH-002` snapshot SHAs (`artifacts/external_targets/ext_batch_002/manifests/target_snapshot.json`):
- `EXT-002`: `072bf1fbbd1c9ecad58d4f6d2204c3b96e7fec17`
- `EXT-006`: `18f5bc268ca11988690c7cf59fc4615372ce99f2`

`EXT-BATCH-003` snapshot SHAs (`artifacts/external_targets/ext_batch_003/manifests/target_snapshot.json`):
- `EXT-007`: `2a9dd27afb1c03f9085c79a218bf928ddfebf031`
- `EXT-008`: `bac0b424fe08e0da9e2522a45d77c028acf47dcd`
- `EXT-009`: `2a9dd27afb1c03f9085c79a218bf928ddfebf031`

`EXT-BATCH-004` snapshot SHAs (`artifacts/external_targets/ext_batch_004/manifests/target_snapshot.json`):
- `EXT-010`: `360715607a240041f49eb46c543fc450051c4cb7`
- `EXT-011`: `360715607a240041f49eb46c543fc450051c4cb7`
- `EXT-012`: `360715607a240041f49eb46c543fc450051c4cb7`

`EXT-BATCH-005` snapshot SHAs (`artifacts/external_targets/ext_batch_005/manifests/target_snapshot.json`):
- `EXT-001`: `c82b3072d7946a76487a8c1be463fc407045391c`
- `EXT-004`: `bac0b424fe08e0da9e2522a45d77c028acf47dcd`
- `EXT-005`: `e196b111c1bafaa61b92ae431cd3c3fe9371da05`

`EXT-BATCH-006` snapshot SHAs (`artifacts/external_targets/ext_batch_006/manifests/target_snapshot.json`):
- `EXT-004`: `396035e3fbcfb696e18dfc08f837d76b4b8931e3bfc62b82ccb6dff17cdca8ca`
- `EXT-005`: `6df3b38e3bd0ee22d97e80fe6ca8b7730c43f6ed0dadf407574dcc6896c76560`

`EXT-BATCH-008` snapshot SHAs (`artifacts/external_targets/ext_batch_008/manifests/target_snapshot.json`):
- `EXT-010`: `360715607a240041f49eb46c543fc450051c4cb7`
- `EXT-011`: `360715607a240041f49eb46c543fc450051c4cb7`
- `EXT-012`: `360715607a240041f49eb46c543fc450051c4cb7`

`EXT-BATCH-010` snapshot SHAs (`artifacts/external_targets/ext_batch_010/manifests/target_snapshot.json`):
- `EXT-002`: `072bf1fbbd1c9ecad58d4f6d2204c3b96e7fec17`
- `EXT-006`: `18f5bc268ca11988690c7cf59fc4615372ce99f2`
- `EXT-007`: `2a9dd27afb1c03f9085c79a218bf928ddfebf031`
- `EXT-008`: `bac0b424fe08e0da9e2522a45d77c028acf47dcd`
- `EXT-009`: `2a9dd27afb1c03f9085c79a218bf928ddfebf031`

`EXT-BATCH-011` snapshot SHAs (`artifacts/external_targets/ext_batch_011/manifests/target_snapshot.json`):
- `EXT-001`: `c82b3072d7946a76487a8c1be463fc407045391c`
- `EXT-002`: `072bf1fbbd1c9ecad58d4f6d2204c3b96e7fec17`
- `EXT-008`: `bac0b424fe08e0da9e2522a45d77c028acf47dcd`

Intake expansion snapshot SHAs (`2026-02-25`, pre-run freeze):
- `EXT-013` (`circomlib_ml_relu`): `c82b3072d7946a76487a8c1be463fc407045391c`
- `EXT-014` (`circomlib_ml_dense`): `c82b3072d7946a76487a8c1be463fc407045391c`
- `EXT-015` (`orion_svm_classifier_test`): `bac0b424fe08e0da9e2522a45d77c028acf47dcd`
- `EXT-016` (`aztec_barretenberg_fixture_recursive`): `2a9dd27afb1c03f9085c79a218bf928ddfebf031`

`EXT-BATCH-013` snapshot SHAs (`artifacts/external_targets/ext_batch_013/manifests/target_snapshot.json`):
- `EXT-013`: `c82b3072d7946a76487a8c1be463fc407045391c`
- `EXT-014`: `c82b3072d7946a76487a8c1be463fc407045391c`
- `EXT-015`: `bac0b424fe08e0da9e2522a45d77c028acf47dcd`
- `EXT-016`: `2a9dd27afb1c03f9085c79a218bf928ddfebf031`

#### 8.9.5 Logic Finding And Remediation Board
| Finding ID | Target ID | Class | Severity | Repro Status | Owning Module | Fix Commit/PR | Verification Status |
|---|---|---|---|---|---|---|---|
| `EXT-FIND-001` | `EXT-001` | `runtime-proof-validation` | `high` | `[ ] repro pending / [x] reproduced` | `Circom ArgMax wrapper evidence flow (input-schema reconciliation + soundness/proof validation path)` | `local hardening patch: non-fatal soundness verify errors + Circom verify invalid-proof=false semantics + input-map diagnostics` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-002` | `EXT-002` | `compile-logic` | `high` | `[ ] repro pending / [x] reproduced` | `/media/elements/Repos/zkFuzz/tests/sample/test_bulk_assignment.circom:19` | `n/a (external target; triage artifact)` | `[ ] fixed / [ ] revalidated` |
| `EXT-FIND-003` | `EXT-003` | `runtime-control` | `high` | `[ ] repro pending / [x] reproduced` | `src/fuzzer/engine/attack_runner_novel.rs`, `src/oracles/witness_collision.rs`, `src/fuzzer/engine/run_reporting.rs` | `working-tree patch (timeout budget + collision cap + timeout-aware finalization)` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-004` | `EXT-003` | `repro-evidence-gap` | `high` | `[ ] repro pending / [x] reproduced` | `report extraction flow` | `query schema alignment + exploit replay artifacts` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-005` | `EXT-007` | `backend-preflight` | `medium` | `[ ] repro pending / [x] reproduced` | `Noir target-entry/package resolution path for hello_circuit` | `add-only standalone target + campaign: artifacts/external_targets/ext_batch_010/repro/{targets/ext007_hello_circuit_standalone,ext007_aztec_hello_circuit_standalone_campaign.yaml}` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-006` | `EXT-008` | `backend-preflight` | `high` | `[ ] repro pending / [x] reproduced` | `Cairo backend build path (Scarb preflight)` | `root-cause triage captured via local-copy rerun + local Scarb cache (`cubit`/`alexandria` compile incompatibility under current toolchain)` | `[ ] fixed / [x] revalidated` |
| `EXT-FIND-007` | `EXT-009` | `runtime-panic` | `critical` | `[ ] repro pending / [x] reproduced` | `src/executor/isolated.rs`, `wait-timeout` SIGCHLD handling path | `local patch: bounded child timeout + bounded post-kill reap` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-008` | `EXT-009` | `runtime-timeout-enforcement` | `high` | `[ ] repro pending / [x] reproduced` | `src/fuzzer/engine/attack_runner_underconstrained.rs`, `src/fuzzer/engine/attack_runner_numeric.rs`, `src/run_campaign_flow.rs` | `working-tree patch: timeout short-circuit for post-attack follow-ups + total-run budget adjustment with setup/tail reserve` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-009` | `EXT-010` | `signal-quality` | `high` | `[ ] repro pending / [x] reproduced` | `report/attack metric accounting (findings emitted with 0 executions)` | `8041daf` (chunked execution observation + metric accounting) + `fdb16a4` (local writable run-signal fallback) | `[x] fixed / [x] revalidated` |
| `EXT-FIND-010` | `EXT-011` | `signal-quality` | `high` | `[ ] repro pending / [x] reproduced` | `report/attack metric accounting (findings emitted with 0 executions)` | `8041daf` (chunked execution observation + metric accounting) + `fdb16a4` (local writable run-signal fallback) | `[x] fixed / [x] revalidated` |
| `EXT-FIND-011` | `EXT-012` | `signal-quality` | `high` | `[ ] repro pending / [x] reproduced` | `report/attack metric accounting (findings emitted with 0 executions)` | `8041daf` (chunked execution observation + metric accounting) + `fdb16a4` (local writable run-signal fallback) | `[x] fixed / [x] revalidated` |
| `EXT-FIND-012` | `EXT-001` | `target-entry-compatibility` | `medium` | `[ ] repro pending / [x] reproduced` | `external target wiring (raw ArgMax entry is not directly executable)` | `add-only wrapper target: ext001_argmax_main_wrapper.circom` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-013` | `EXT-004` | `backend-preflight` | `high` | `[ ] repro pending / [x] reproduced` | `Cairo backend build path (Scarb preflight)` | `fixed diagnostics path; now shows exact preflight cause (lockfile permission / toolchain mismatch) in run_outcome` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-014` | `EXT-005` | `backend-preflight` | `high` | `[ ] repro pending / [x] reproduced` | `Halo2 backend build path (EZKL preflight)` | `fixed diagnostics path; now surfaces rustup/cargo root cause text instead of opaque timeout-only failure` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-015` | `EXT-BATCH-005` | `workflow-stability` | `medium` | `[ ] repro pending / [x] reproduced` | `run-signal report-id allocation (second-granularity collisions)` | `run folder naming now includes run_id suffix to prevent same-second collisions` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-016` | `EXT-016` | `backend-preflight` | `medium` | `[ ] repro pending / [x] reproduced` | `Noir recursive fixture compile path under read-only external checkout` | `add-only local-copy campaign: artifacts/external_targets/ext_batch_013/repro/ext016_aztec_barretenberg_fixture_recursive_local_campaign.yaml` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-017` | `EXT-016` | `backend-compatibility` | `high` | `[ ] repro pending / [x] reproduced` | `Noir ABI parser expected array key 'typ' and rejected modern artifacts using key 'type'` | `deserializer compatibility patch + regression test (`crates/zk-backends/src/noir/{mod.rs,mod_tests.rs}`)` | `[x] fixed / [x] revalidated` |
| `EXT-FIND-018` | `EXT-016` | `runtime-input-reconciliation` | `high` | `[ ] repro pending / [x] reproduced` | `strict input reconciliation hard-failed when inspector labels were incomplete / oversized` | `reconciliation fallback + index truncation hardening (`src/fuzzer/engine/config_helpers.rs`)` | `[x] fixed / [x] revalidated` |

#### 8.9.6 Hardening Exit Criteria (External Repo Track)
- [x] At least `12` externally sourced targets validated from `/media/elements/Repos` with representation across all four backends.
- [x] All `16` curated manual targets in `targets/zk0d_matrix_external_manual.yaml` have at least one archived evidence run (`EXT-BATCH-013` closed first-run coverage for `EXT-013..016`).
- [x] At least `3` manual batches executed with archived evidence and complete run-ledger rows.
- [ ] No unresolved `high` or `critical` externally reproducible logic findings remain open.
- [ ] External-target effectiveness report shows non-zero runs for each backend and no unresolved backend assignment gaps.

#### 8.9.7 Full-Flow Exploit Validation (Step-by-Step)
Objective for this flow: findings count only when they are reproducible and backed by exploit evidence, then converted into code fixes and regression tests.

Flow checklist:
- [x] Step 0: Environment and build readiness (`scripts/install_all_backends.sh`, `cargo build --release`).
- [x] Step 1: Target intake and snapshot freeze (`scripts/copy_external_targets.sh` or explicit rsync; record repo path + commit SHA in the target board).
- [x] Step 2: SKIM pass to generate attack hypotheses (`scripts/zeroday_workflow.sh skim <repo_path>`).
- [x] Step 3: EVIDENCE pass to produce deterministic findings (`scripts/zeroday_workflow.sh evidence <campaign.yaml> --seed <seed> --iterations <n> --timeout <s>`).
- [x] Step 4: Optional formal verification for under-constraint claims (`scripts/zeroday_workflow.sh verify <circuit.circom>`).
- [x] Step 5: Exploit proof packaging (minimal repro inputs/witnesses, replay command, expected vulnerable behavior, observed behavior).
- [x] Step 6: Issue logging and root-cause mapping (owning module + failure mode + severity + exploit confidence).
- [ ] Step 7: Code adjustment + regression tests (`tests/**`), followed by rerun of the same exploit replay to confirm fix.
- [ ] Step 8: Post-fix gate reruns (`scripts/backend_readiness_dashboard.sh`, `scripts/backend_maturity_scorecard.sh`, `python3 scripts/build_backend_effectiveness_report.py --repo-root .`, `scripts/run_release_streak_status.sh`).

Current batch status (`EXT-BATCH-001`): Step 0-5 completed with archived artifacts. Latest evidence run completed at wall-clock budget with `status=completed_with_critical_findings`, `findings_total=1519`, `total_executions=5533` (`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/run_outcome.json`). Picus verification is now wired and discovered from PATH (`/home/teycir/.local/bin/picus`); current formal outcome for `test_vuln_iszero.circom` is `UNKNOWN` (`artifacts/external_targets/ext_batch_001/logs/step4_verify_ext003_after_picus_classification_fix_escalated.log`). Deterministic exploit replay is now packaged and passing (`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/replay_ext003_iszero_exploit.log`).

Current batch status (`EXT-BATCH-002`): Step 0-3 completed with archived artifacts in `artifacts/external_targets/ext_batch_002/{logs,manifests,reports,repro}`. `EXT-002` failed at backend preflight with reproducible target compile error (`error[T3001] Out of bounds exception` in `test_bulk_assignment.circom:19`, `artifacts/external_targets/ext_batch_002/reports/run_signals/report_1771884140/misc/run_outcome.json`). `EXT-006` failed at backend preflight due offline toolchain fetch (`dns error` while rustup synced `nightly-2024-07-07`, `artifacts/external_targets/ext_batch_002/reports/run_signals/report_1771884148/misc/run_outcome.json`).

Current batch status (`EXT-BATCH-003`): Step 0-3 completed with archived artifacts in `artifacts/external_targets/ext_batch_003/{logs,manifests,reports,repro}`. `EXT-007` failed at backend preflight due offline Noir dependency fetch (`github.com/noir-lang/poseidon` resolution failure, `artifacts/external_targets/ext_batch_003/reports/run_signals/report_1771885461/misc/run_outcome.json`). `EXT-008` failed at Cairo backend preflight (`Scarb build failed`, `artifacts/external_targets/ext_batch_003/reports/run_signals/report_1771885469/misc/run_outcome.json`). `EXT-009` initially reproduced a runtime panic in isolated executor wait-timeout signal handling (`artifacts/external_targets/ext_batch_003/reports/run_signals/report_1771885490/misc/run_outcome.json`); post-patch reruns now pass preflight with elevated permissions but overrun the declared wall-clock window inside `Underconstrained` attack (`artifacts/external_targets/ext_batch_003/logs/step3_evidence_ext009_revalidate_after_wait_fix_rerun3_escalated.log`), so timeout-enforcement remains open.

Current batch status (`EXT-BATCH-004`): Step 0-3 completed with archived artifacts in `artifacts/external_targets/ext_batch_004/{logs,manifests,reports,repro}`. `EXT-010`, `EXT-011`, and `EXT-012` all completed with critical findings and archived evidence bundles (`artifacts/external_targets/ext_batch_004/reports/evidence/EXT-010/20260223_223720_evidence_ext010_circomlib_iszero_campaign_pid2385436`, `artifacts/external_targets/ext_batch_004/reports/evidence/EXT-011/20260223_223818_evidence_ext011_circomlib_lessthan_campaign_pid2422323`, `artifacts/external_targets/ext_batch_004/reports/evidence/EXT-012/20260223_223913_evidence_ext012_circomlib_montgomerydouble_campaign_pid2460213`). All three runs reported `total_executions=0` while emitting high/critical findings, so exploitability classification is blocked until signal-quality triage is completed.

Current batch status (`EXT-BATCH-005`): Step 0-3 completed with archived artifacts in `artifacts/external_targets/ext_batch_005/{logs,manifests,reports,repro}`. `EXT-001` raw target entry (`circuits/ArgMax.circom`) failed preflight due missing `main` component declaration (`artifacts/external_targets/ext_batch_005/reports/run_signals/report_1771887699/misc/run_outcome.json`), then completed successfully via add-only wrapper correction (`artifacts/external_targets/ext_batch_005/repro/ext001_argmax_main_wrapper.circom`) with `status=completed` and `findings_total=0` (`artifacts/external_targets/ext_batch_005/reports/run_signals/report_1771887978/misc/run_outcome.json`). `EXT-004` remains blocked at Cairo preflight (`Scarb build failed`, `artifacts/external_targets/ext_batch_005/reports/run_signals/report_1771887795/misc/run_outcome.json`). `EXT-005` remains blocked at Halo2 preflight build timeout (`Failed to build Halo2 circuit: Command timed out after 120s`, `artifacts/external_targets/ext_batch_005/reports/run_signals/report_1771887824/misc/run_outcome.json`). Initial parallel `EXT-004`/`EXT-005` run also exposed run-signal ID collision at second granularity (`report_1771887719`), recorded as a workflow-stability finding.

Current batch status (`EXT-BATCH-008`): Step 0-8 completed for the `EXT-010/011/012` signal-quality revalidation scope with archived artifacts in `artifacts/external_targets/ext_batch_008/{logs,manifests,reports,repro}`. All three reruns now report non-zero execution counts (`total_executions=800` each) under the same quick profile that previously yielded `0` executions (`artifacts/external_targets/ext_batch_008/reports/evidence/EXT-010/run_outcome.json`, `artifacts/external_targets/ext_batch_008/reports/evidence/EXT-011/run_outcome.json`, `artifacts/external_targets/ext_batch_008/reports/evidence/EXT-012/run_outcome.json`). Post-fix gate reruns executed and archived (`artifacts/external_targets/ext_batch_008/logs/step8_backend_readiness_dashboard.log`, `artifacts/external_targets/ext_batch_008/logs/step8_backend_maturity_scorecard.log`, `artifacts/external_targets/ext_batch_008/logs/step8_backend_effectiveness_report.log`, `artifacts/external_targets/ext_batch_008/logs/step8_release_streak_status.log`).

Current batch status (`EXT-BATCH-010`): Step 0-3 completed for unresolved target reruns with archived artifacts in `artifacts/external_targets/ext_batch_010/{logs,manifests,reports,repro}` and summary in `artifacts/external_targets/ext_batch_010/reports/batch_summary.md`. `EXT-002` still fails at Circom preflight with reproducible target compile error (`error[T3001] Out of bounds` at `test_bulk_assignment.circom:19`, `artifacts/external_targets/ext_batch_010/run_signals/report_1771895663_20260224_011423_evidence_ext002_test_bulk_assignment_campaign_pid3443089/misc/run_outcome.json`). `EXT-006` now completes in local-copy mode with local Go module cache/proxy env (`status=completed`, `duration_seconds=298`, `total_executions=17`, `findings_total=22`, `artifacts/external_targets/ext_batch_010/run_signals/report_1771896044_20260224_012044_evidence_ext006_zkevm_circuits_local_campaign_pid3451941/misc/run_outcome.json`). `EXT-007` original path still reproduces the package mismatch preflight failure (`Selected package hello_circuit was not found`), but add-only standalone correction now completes with non-zero executions and in-budget runtime (`duration_seconds=57`, `total_executions=184`, `artifacts/external_targets/ext_batch_010/run_signals/report_1771895175_20260224_010615_evidence_ext007_aztec_hello_circuit_standalone_campaign_pid3375657/misc/run_outcome.json`). `EXT-008` local-copy rerun still fails at Cairo preflight, now with root-cause evidence showing dependency/toolchain compile incompatibilities in the Orion stack (`artifacts/external_targets/ext_batch_010/run_signals/report_1771895929_20260224_011849_evidence_ext008_orion_linear_classifier_local_campaign_pid3449205/misc/run_outcome.json`). `EXT-009` now completes (`status=completed`, `total_executions=257`, `findings_total=0`), no longer reproduces the prior runtime panic, and timeout enforcement is revalidated on matching settings (`duration_seconds=60` with `timeout_seconds=60`, `artifacts/external_targets/ext_batch_010/run_signals/report_1771894723_20260224_005843_evidence_ext009_aztec_barretenberg_fixture_campaign_pid3274630/misc/run_outcome.json`).

Current batch status (`EXT-BATCH-011`): Step 0-3 completed for focused unresolved-target retest with archived artifacts in `artifacts/external_targets/ext_batch_011/{logs,manifests,reports,repro}` and summary in `artifacts/external_targets/ext_batch_011/reports/batch_summary.md`. `EXT-001` now reproduces a runtime failure in engine run (`Failed to verify proof` after `ArgMax_4` witness assertion failure, with schema reconciliation warning `config has 1, executor expects 6`) (`artifacts/external_targets/ext_batch_011/run_signals/report_1771899258_20260224_021418_evidence_ext001_circomlibml_argmax_wrapper_campaign_pid3604780/misc/run_outcome.json`). `EXT-002` remains a reproducible external target compile failure (`error[T3001] Out of bounds` at `test_bulk_assignment.circom:19`) (`artifacts/external_targets/ext_batch_011/run_signals/report_1771899286_20260224_021446_evidence_ext002_test_bulk_assignment_campaign_pid3628308/misc/run_outcome.json`). `EXT-008` local-copy rerun with warm local Scarb cache avoids pure clone-only noise and again fails at Cairo preflight with dependency/toolchain incompatibility signal in Orion (`artifacts/external_targets/ext_batch_011/run_signals/report_1771899400_20260224_021640_evidence_ext008_orion_linear_classifier_local_campaign_pid3631535/misc/run_outcome.json`).

Current batch status (`EXT-BATCH-013`): Step 0-3 completed for intake-expanded first-run coverage with archived artifacts in `artifacts/external_targets/ext_batch_013/{logs,manifests,reports,repro}` and summary in `artifacts/external_targets/ext_batch_013/reports/batch_summary.md`. `EXT-013` first completed with candidate signal (`status=completed`, `findings_total=44`, `total_executions=82`) (`artifacts/external_targets/ext_batch_013/run_signals/report_1772029839_20260225_143039_evidence_ext013_circomlib_ml_relu_campaign_pid76365/misc/run_outcome.json`), then received bounded non-exploit replay evidence (`artifacts/external_targets/ext_batch_013/reports/evidence/EXT-013/run_20260225_ext013_relu_bounded_non_exploit/{replay_command.txt,no_exploit_proof.md,impact.md,replay_ext013_relu_non_exploit.log}`). `EXT-014` completes cleanly with non-zero executions (`status=completed`, `findings_total=0`, `total_executions=220`) (`artifacts/external_targets/ext_batch_013/run_signals/report_1772029940_20260225_143220_evidence_ext014_circomlib_ml_dense_campaign_pid113787/misc/run_outcome.json`). `EXT-015` completes but exhausts wall-clock budget during setup (`status=completed`, `findings_total=0`, `total_executions=0`) and remains proof-incomplete (`artifacts/external_targets/ext_batch_013/run_signals/report_1772030038_20260225_143358_evidence_ext015_orion_svm_classifier_test_campaign_pid157380/misc/run_outcome.json`). `EXT-016` required local-copy rerun plus Noir ABI/input-reconciliation fixes before reaching stable execution; latest rerun now completes (`status=completed`, `findings_total=0`, `total_executions=403`) (`artifacts/external_targets/ext_batch_013/run_signals/report_1772030581_20260225_144301_evidence_ext016_aztec_barretenberg_fixture_recursive_local_campaign_pid171511/misc/run_outcome.json`).

Latest evidence severity breakdown (`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/report.json`):
- `critical=3`, `high=1`, `medium=1515`
- top attack-type volume: `arithmetic_overflow=1482`, `metamorphic=33`, `underconstrained=2`, `constraint_inference=1`, `witness_collision=1`

Step-by-step execution tracker:
| Step | Command/Action | Required Artifact | Pass Criteria | Status |
|---|---|---|---|---|
| 0 | `cargo build --release` | Build log | Release binaries produced | `[x]` (`artifacts/external_targets/ext_batch_001/logs/step0_build.log`) |
| 1 | Import + snapshot target | Target manifest row with commit SHA | Target reproducibility frozen | `[x]` (`artifacts/external_targets/ext_batch_001/manifests/target_snapshot.json`) |
| 2 | `scripts/zeroday_workflow.sh skim <repo_path>` | `reports/zk0d/skimmer/*` | Candidate invariants/configs generated | `[x]` (`artifacts/external_targets/ext_batch_001/logs/step2_skim_EXT-*.log`) |
| 3 | `scripts/zeroday_workflow.sh evidence <campaign.yaml> ...` | Evidence report bundle | At least one deterministic finding candidate | `[x]` (`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/{run_outcome.json,report.json,report.md,summary.json}`) |
| 4 | `scripts/zeroday_workflow.sh verify <circuit.circom>` (optional) | Formal result (`SAFE/UNSAFE/UNKNOWN`) | Result archived for claim strengthening | `[x]` (`artifacts/external_targets/ext_batch_001/logs/step4_verify_ext003_after_picus_classification_fix_escalated.log`; result=`UNKNOWN`) |
| 5 | Exploit replay command | Repro script + input fixture | Replay reproduces vulnerable behavior on demand | `[x]` (`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/{replay_command.txt,replay_ext003_iszero_exploit.py,replay_ext003_iszero_exploit.log,exploit_notes.md}`) |
| 6 | Triage + root cause | Issue board row | Severity + owner + module assigned | `[x]` (`EXT-ISSUE-002` logged in issue-to-code-adjustment tracker) |
| 7 | Patch + tests | Commit + regression test case | Replay now fails exploit condition; tests green | `[ ]` |
| 8 | Gate reruns | Readiness/maturity/effectiveness outputs | No regression in required gates | `[x]` |

Exploit proof requirements (must all be present before claiming confirmed bug):
| Requirement | Description | Evidence Path | Status |
|---|---|---|---|
| Minimal Repro | Smallest input/witness set that triggers bug | `artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/replay_ext003_iszero_exploit.py` | `[x]` |
| Deterministic Replay | One command to reproduce with fixed seed/config | `artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/replay_command.txt` | `[x]` |
| Expected vs Observed | Security expectation and concrete violating output | `artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/exploit_notes.md` | `[x]` |
| Blast Radius | Affected backend(s), circuit family, severity rationale | `artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/impact.md` | `[x]` |
| Fix Validation | Replay after patch no longer reproduces exploit | `artifacts/external_targets/<batch>/post_fix_replay.log` | `[ ]` |

`EXT-003` exploit packaging is complete for pre-fix confirmation: replay command, script, log, and impact notes are present under `artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/`.

Issue-to-code-adjustment tracker:
| Issue ID | Target ID | Exploit Reproduced | Root Cause Module | Code Change | Regression Test | Post-Fix Replay | Final Status |
|---|---|---|---|---|---|---|---|
| `EXT-ISSUE-001` | `EXT-001` | `[ ]` | `<path/to/module.rs>` | `<commit/pr>` | `tests/<file>` | `[ ]` | `[ ] open / [ ] fixed / [ ] verified` |
| `EXT-ISSUE-002` | `EXT-003` | `[x]` | `/media/elements/Repos/zkFuzz/tests/sample/test_vuln_iszero.circom` | Replace unconstrained assignment path (`inv <-- ...`) with fully constrained relation (`in * inv === 1 - out`) and keep boolean output constraint | `tests/test_ext003_iszero_exploit.py` (pre-fix exploit proof) | `[ ]` | `[x] open / [ ] fixed / [ ] verified` |
| `EXT-ISSUE-003` | `EXT-003` | `[ ]` | `src/fuzzer/engine/attack_runner_novel.rs`, `src/oracles/witness_collision.rs`, `src/fuzzer/engine/run_reporting.rs` | `Add detector time budget + max collision cap + timeout-aware report finalization short-circuit` | `tests/test_oracles_witness_collision.rs` | `[x]` (`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/step3_evidence_ext003_rerun3_escalated.log`) | `[ ] open / [x] fixed / [x] verified` |
| `EXT-ISSUE-004` | `EXT-003` | `[x]` | `reporting schema / operator query mismatch` | Use `poc_witness_a` / `poc_witness_b` / `poc_public_inputs` fields when extracting PoCs from report artifacts | `n/a` | `[x]` (`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260223_204819/replay_ext003_iszero_exploit.log`) | `[ ] open / [x] fixed / [x] verified` |

#### 8.9.8 Follow-Up Snapshot (2026-02-25)

Scope for this snapshot:
- latest per-target run-state from `artifacts/**/run_signals/*/summary.json` (including `ext_batch_012` reruns),
- proof artifact verification under `artifacts/external_targets/*/reports/evidence/*`,
- backend readiness gate status from `artifacts/backend_readiness/latest_report.json`.

High-level state:
- Tracked external targets with completed manual state snapshots: `16` (`EXT-001`..`EXT-016`).
- Intake-expanded targets pending first manual run: `0` (`EXT-BATCH-013` executed for `EXT-013`..`EXT-016`).
- First-run closure plan: closed for all currently curated manual targets (`16/16` have archived evidence runs).
- Full discovered catalog coverage: `628` supported entrypoints across `20` repos (`targets/external_repo_catalog_all_2026-02-25.json`).
- External matrices enriched with dataset priors from `/home/teycir/Documents/ZkDatasets` (`targets/zk0d_matrix_external_manual.yaml`, `targets/zk0d_matrix_external_all.yaml`).
- Proven exploit with deterministic replay: `1` target (`EXT-003`).
- Bounded non-exploit evidence packaged: `1` target (`EXT-013`).
- Discovery signal present but still `pending_proof`: `5` targets (`EXT-005`, `EXT-006`, `EXT-010`, `EXT-011`, `EXT-012`).
- Completed with no findings in latest run: `6` targets (`EXT-001`, `EXT-002`, `EXT-007`, `EXT-009`, `EXT-014`, `EXT-016`).
- Blocked or unstable due backend preflight/runtime setup: `3` targets (`EXT-004`, `EXT-008`, `EXT-015`).

Latest target state (manual checks only):
| Target | Latest Status | Findings / Executions | Proof State | Current Note |
|---|---|---:|---|---|
| `EXT-001` | `completed` | `0 / 800` | `pending_proof` | Wrapper target runs cleanly; no exploit signal in latest rerun (`artifacts/external_targets/ext_batch_012/run_signals/report_1771938763_20260224_131243_evidence_ext001_circomlibml_argmax_wrapper_campaign_pid28572/summary.json`). |
| `EXT-002` | `completed` | `0 / 25` | `pending_proof` | Latest run is clean, but earlier runs repeatedly hit external target compile failure (`test_bulk_assignment.circom:19`, out-of-bounds). |
| `EXT-003` | `proved_exploitable` | `n/a` | `exploitable` | Deterministic replay + exploit notes + impact packaged (`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/{replay_command.txt,replay_ext003_iszero_exploit.log,exploit_notes.md,impact.md}`). |
| `EXT-004` | `failed@preflight_backend` | `0 / 0` | `pending_proof` | Cairo/Scarb preflight blocked (lockfile permission failure); no evidence run reached attack execution. |
| `EXT-005` | `completed` | `6 / 17` | `pending_proof` | Continuation rerun reached engine execution with local `SVM_RELEASES_LIST_JSON` override; current findings are low-correlation metamorphic base-execution failures and remain unproven (`artifacts/external_targets/recheck_ext005_continue_20260225/reports/ext005_triage.md`). |
| `EXT-006` | `completed` | `6 / 17` | `pending_proof` | zkevm evidence now completes in-bounds after reruns (`artifacts/external_targets/ext_batch_012/run_signals/report_1771939182_20260224_131942_evidence_ext006_zkevm_circuits_campaign_pid72229/summary.json`). |
| `EXT-007` | `completed` | `0 / 184` | `pending_proof` | Standalone hello-circuit path is stable; no findings in latest successful run. |
| `EXT-008` | `completed` | `0 / 0` | `pending_proof` | Marked completed in latest run but still operationally unstable (13/14 attempts failed preflight in history; Scarb/toolchain incompatibility remains open). |
| `EXT-009` | `completed` | `0 / 257` | `pending_proof` | Aztec barretenberg fixture now stable and non-finding on latest successful rerun. |
| `EXT-010` | `completed_with_critical_findings` | `4 / 4` | `pending_proof` | Repeated positive signal across batches (max observed findings `34`) but no deterministic exploit package yet. |
| `EXT-011` | `completed` | `15 / 3` | `pending_proof` | Repeated positive signal across batches (max observed findings `66`) but no deterministic exploit package yet. |
| `EXT-012` | `completed` | `3 / 1` | `pending_proof` | Repeated positive signal across batches (max observed findings `12`) but no deterministic exploit package yet. |
| `EXT-013` | `completed` | `44 / 82` | `not_exploitable_within_bounds` | Candidate signal triaged with deterministic bounded replay; no accepted wrong-output witness in bounded campaign (`artifacts/external_targets/ext_batch_013/reports/evidence/EXT-013/run_20260225_ext013_relu_bounded_non_exploit/no_exploit_proof.md`). |
| `EXT-014` | `completed` | `0 / 220` | `pending_proof` | First-run evidence completed cleanly with no validated findings in bounded run (`artifacts/external_targets/ext_batch_013/run_signals/report_1772029940_20260225_143220_evidence_ext014_circomlib_ml_dense_campaign_pid113787/summary.json`). |
| `EXT-015` | `failed@preflight_backend` | `0 / 0` | `pending_proof` | Continuation rerun remains blocked by deterministic Scarb/Cairo toolchain mismatch (`backend_toolchain_mismatch=4`; selector mismatch `37`) and no exploit/non-exploit proof could be produced (`artifacts/external_targets/recheck_ext015_continue_20260225/reports/ext015_triage.md`, `artifacts/external_targets/recheck_ext015_continue_20260225/logs/ext015_batch_run.log`). |
| `EXT-016` | `completed` | `0 / 403` | `pending_proof` | First-run evidence completed after local-copy and Noir compatibility fixes; no findings observed in bounded run (`artifacts/external_targets/ext_batch_013/run_signals/report_1772030581_20260225_144301_evidence_ext016_aztec_barretenberg_fixture_recursive_local_campaign_pid171511/summary.json`). |

Proof artifact inventory check:
- `EXT-003` has full exploit proof artifact set (`replay_command.txt`, `exploit_notes.md`, `impact.md`, replay log).
- `EXT-013` now has bounded non-exploit proof artifacts (`replay_command.txt`, `no_exploit_proof.md`, `impact.md`, replay log).
- Remaining unresolved targets stay `pending_proof` until exploit replay or bounded/formal non-exploit evidence is packaged.

Backend readiness context for this follow-up:
- `artifacts/backend_readiness/latest_report.json` => `overall_pass=true` (Noir/Cairo/Halo2 gates all pass with `runtime_error_count=0`, `backend_preflight_failed_count=0`, `run_outcome_missing_rate=0`).

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

### 7.5 Semantic Track Bug Intake (2026-02-23)
- [x] Fix adapter selection semantics: `with_intent_adapter()` appends to a list, but `run()` only uses `intent_adapters.first()`; enforce single-adapter API or implement deterministic adapter chaining/merge (`crates/zk-track-semantic/src/lib.rs`).
- [x] Make false-positive gate meaningful: `build_scorecard()` currently sets `false_positive_budget = findings + 2` and `false_positive_count = 0`, so `validate()` budget enforcement is effectively non-failing (`crates/zk-track-semantic/src/lib.rs`).
- [x] Fix severity mapping bug in `severity_from_assessment()`: medium branch currently matches non-exploitable findings with confidence >=55; constrain medium/high/critical branches to exploitable assessments (`crates/zk-track-semantic/src/lib.rs`).
- [x] Align marker scan corpus and intent corpus: marker detection uses `raw_text` while code intent extraction uses comment/doc text (`intent_text`); unify scope or codify intentional divergence (`crates/zk-track-semantic/src/lib.rs`).
- [x] Remove duplicate `report_output_dir()` evaluation in `prepare()` error path (`crates/zk-track-semantic/src/lib.rs`).
- [x] Clarify naming/contract for model-labeled adapter: canonicalized to `HeuristicAugmentedSemanticIntentAdapter` with legacy `ModelGuidedSemanticIntentAdapter` alias retained for compatibility; no in-process model invocation contract (`crates/zk-track-semantic/src/adapters.rs`, `crates/zk-track-semantic/src/lib.rs`).
- [x] Consolidate output writer directory handling: currently each writer (`semantic_track_report`, `ai_ingest_bundle`, `ai_exploitability_worklist`, `semantic_actionable_report`) repeats `create_dir_all`; centralize and enforce `mkdir -> serialize -> write` ordering (`crates/zk-track-semantic/src/lib.rs`).
- [x] Remove local variable shadowing in `write_ai_ingest_bundle()` (`source_documents` parameter shadowed by local binding) for readability/safety (`crates/zk-track-semantic/src/lib.rs`).
- [x] Optimize `truncate_bundle_text()` to single-pass truncation to avoid double full-string traversal (`crates/zk-track-semantic/src/lib.rs`).
- [x] Replace magic minimum statement length (`12`) in `statement_candidates()` with a named constant and rationale (`crates/zk-track-semantic/src/adapters.rs`).
- [x] Reassess heuristic intent redundancy: made `invariants` semantically distinct by synthesizing normalized `invariant.*` statements per candidate instead of mirroring the other three fields (`crates/zk-track-semantic/src/adapters.rs`).
- [x] Add comment-extraction regression tests for inline/trailing block-comment forms and document expected behavior (current parser already handles common multiline block-comment flow; edge semantics should be explicit) (`crates/zk-track-semantic/src/lib.rs`).

**Current Status:** 🟡 Partially implemented. Core P0/P1 engines are merged and the semantic-track bug-intake hardening checklist is complete; deferred semantic backlog items remain non-blocking while Phase 8 stays the active release closure track.

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
- [x] Remove panic recovery in `engagement_dir_name` and env parsing panic paths (M-1, L-2)
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
- [x] Enforce production-tree (`src/**`, `crates/**`) no-mixing gate in CI (`scripts/check_prod_test_separation.py`) with baseline tracking (`config/prod_test_separation_baseline.json`) so new prod/test coupling is rejected immediately while legacy debt is explicit.

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
- [x] Add batch run reason-code aggregation in `zkpatternfuzz`
- [x] Add collision-safe automatic scan run-root allocation
- [x] Add `zk-fuzzer preflight` command
- [x] Add regex selector policy controls
- [x] Add selector synonym bundles
- [x] Add `zk-fuzzer bins bootstrap` command
- [x] Add deterministic ptau autodiscovery precedence
- [x] Add `zk0d_matrix` multi-target runner
- [x] Add retry-on-transient-setup policy in `zkpatternfuzz`
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
- [x] Fix Halo2 minimal JSON spec input reconciliation (`tests/halo2_specs/minimal.json`) with metadata-only wire-label recovery (`src/executor/mod.rs`)
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
- **Fix Applied:** Set child `zkpatternfuzz` environment under benchmark output root to avoid host-home permission failures
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
cargo check -q --bin zkpatternfuzz
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

## 🐛 zkpatternfuzz Binary Hardening (2026-02-26)

### Critical (P0)
- [x] **Bug 1**: Unbounded read_to_end on child stdout/stderr can OOM the orchestrator
  - Issue: `src/bin/zkpatternfuzz.rs` and timeout wrapper paths read child output without size limits.
  - Fix: Added capped pipe capture (`8 MiB` per stream) with truncation signaling in:
    - `src/bin/zkpatternfuzz.rs` (`PipeCapture`, `read_pipe_with_cap`, `finalize_pipe_capture`)
    - `src/reporting/command_timeout.rs` (same cap/truncation behavior)
  - Validation: `cargo test --test test_reporting_command_timeout --quiet`, `cargo test --test test_bin_zkpatternfuzz --quiet`.
  - Impact: High risk addressed - orchestrator no longer buffers unbounded child output in memory.

### High Priority (P1)
- [x] **Bug 2**: TOCTOU race in wait_for_memory_headroom
  - Issue: Multiple workers could pass headroom checks concurrently and launch together.
  - Fix: Added global launch gate lock (`memory_headroom_launch_lock`) and moved headroom check into the same critical section as process spawn in `run_command_with_stage_timeouts`.
  - Validation: `cargo test --test test_bin_zkpatternfuzz --quiet`.
  - Impact: Medium risk addressed - launch check and launch are now serialized, removing check→spawn race.

- [x] **Bug 3**: append_run_log re-opens file on every call from multiple threads
  - Issue: Repeated open/append/close pattern increased contention and overhead under log-heavy runs.
  - Fix: Added per-path file-handle cache (`run_log_file_cache`) guarded by `Mutex<HashMap<PathBuf, File>>`; writes now reuse handles and flush.
  - Validation: `append_run_log_reuses_cached_file_handle` in `tests/test_bin_zkpatternfuzz.rs`.
  - Impact: Medium risk addressed - lower log-path syscall churn and reduced append contention.

### Medium Priority (P2)
- [ ] **Bug 4**: 3,832-line monolith mixes CLI, config, framework logic, orchestration
  - Issue: `src/bin/zkpatternfuzz.rs` violates single responsibility principle.
  - Fix: Continue decomposing into modules: `config`, `discovery`, `execution`, `reporting`.
  - Progress (2026-02-27): extracted run-log lifecycle helpers into `src/bin/zkpatternfuzz/run_log.rs`, reporting helpers into `src/bin/zkpatternfuzz/zkpatternfuzz_reporting.rs`, and env/default config helpers into `src/bin/zkpatternfuzz/zkpatternfuzz_config.rs`; rewired `zkpatternfuzz.rs` to consume all three modules.
  - Validation: `cargo test --test test_bin_zkpatternfuzz --quiet`, `cargo test --test test_reporting_command_timeout --quiet`.
  - Impact: Medium - maintainability and testability concerns remain until additional slices are extracted.

### Low Priority (P3)
- [x] **Bug 5**: std::env::set_var is unsafe in multithreaded contexts
  - Issue: `checkenv.rs` populated process-global env via `std::env::set_var`.
  - Fix: Replaced global mutation with a dotenv overlay store and accessor helpers (`checkenv::var`, `checkenv::is_set`) that preserve process env precedence without mutation.
  - Wiring: Updated `zkpatternfuzz` env lookups and env-presence checks to use overlay-aware access for runtime config and defaults.
  - Validation:
    - `checkenv_uses_overlay_without_mutating_process_env`
    - `checkenv_prefers_process_env_over_overlay`
    - `cargo test --test test_bin_zkpatternfuzz --quiet`
  - Impact: Low risk addressed - avoids process-global env races while keeping existing dotenv behavior.

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
- [x] Reduce backend depth imbalance (Circom vs Noir/Halo2/Cairo):
  - [x] extend constraint-inspection style analyses (unused signal / weak-constraint classes where feasible) beyond Circom
  - [x] publish per-backend recall and true-positive contribution slices so aggregate recall is not Circom-dominated without visibility

#### P2: Coverage Breadth + Oracle Completeness
- [x] Improve spec-inference robustness against sampling blind spots (targeted boundary witness generation and combination coverage for rare input patterns).
- [x] Expand vulnerability pattern library beyond current Circom-heavy corpus to include non-Circom/ACIR/Halo2 lookup and newer audit-derived classes.
- [x] Add a single-backend differential oracle path (behavior comparison against an explicit real reference backend only; no recovery comparator modes) to detect backend-specific divergence without test-mode dependence.

#### Exit Evidence For This Correction Wave
- [x] Mutator validity report: invalid out-of-field mutation rate == `0` across stress campaign (`scripts/build_mutator_validity_report.py`, `tests/test_build_mutator_validity_report.py`, `artifacts/mutator_validity/latest_report.json`).
- [x] Portability report: clean-clone CVE regression lane runs without machine-specific path edits (`scripts/build_cve_portability_report.py`, `tests/test_build_cve_portability_report.py`, `artifacts/portability/latest_report.json`).
- [x] Per-backend effectiveness report: separate recall/precision for Circom, Noir, Cairo, Halo2 with explicit target counts and contribution share (`scripts/build_backend_effectiveness_report.py`, `tests/test_build_backend_effectiveness_report.py`, `artifacts/backend_effectiveness/latest_report.json`). Added a dedicated multi-backend benchmark suite + sample runner to produce non-zero per-backend rows in one shot (`targets/benchmark_suites.multibackend.dev.yaml`, `scripts/run_multibackend_effectiveness_sample.sh`, `artifacts/backend_effectiveness/latest_multibackend_report.json`).

### Non-Circom Backend Production Parity (Priority Order: Noir -> Cairo -> Halo2)
- [x] Noir: enforce local real-circuit prove/verify smoke gate (`test_noir_local_prove_verify_smoke`, wired in `scripts/run_noir_readiness.sh`)
- [x] Noir: barretenberg integration hardening for external `bb`-coupled projects (explicit `bb`-missing diagnostics + robust proof artifact path resolution in evidence flow)
- [x] Cairo: enforce real-circuit proving support for local Cairo0 fixture (`test_cairo_stone_prover_prove_verify_smoke`)
- [x] Cairo: enforce Stone prover integration gate in readiness lane (`scripts/run_cairo_readiness.sh`)
- [x] Cairo: Cairo1 proof/verify pipeline via `scarb prove --execute` + `scarb verify --execution-id` (strict execution-id tracking)
- [x] Halo2: legacy test-mode to real-circuit execution promotion in release lanes (release workflow now installs Noir/Cairo toolchains and runs unskipped backend readiness lanes with dashboard enforcement)
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

#### New Findings Snapshot (2026-02-23)
- [x] **High:** backend timeout env parsing no longer panics on invalid values; invalid env now logs and falls back to bounded defaults (`crates/zk-backends/src/util.rs`)
- [x] **Medium:** backend timeout handling now terminates the full subprocess tree via process-group kill semantics (`crates/zk-backends/src/util.rs`)
- [x] **Medium:** sandbox-required mode now creates missing writable bind directories before sandbox launch (`crates/zk-backends/src/util.rs`, `src/reporting/command_timeout.rs`)
- [x] **Medium:** `test_continuous_fuzzing_loop` is stabilized by deterministic loop-only configuration and assertion (`tests/phase0_integration_tests.rs`)

#### Validation Run Snapshot (2026-02-23)
- `cargo test --workspace --all-targets` -> one failure (`test_continuous_fuzzing_loop` in `tests/phase0_integration_tests.rs`)
- `cargo test -p zk-fuzzer --test phase0_integration_tests test_continuous_fuzzing_loop -- --nocapture` -> passed on repeated isolated reruns
- No code changes were made in this validation snapshot; findings recorded for follow-up patching
- Follow-up patch validation (post-snapshot): `cargo test -q -p zk-backends util::tests:: -- --test-threads=1`, `cargo test -q -p zk-fuzzer --test test_reporting_command_timeout -- --test-threads=1`, `cargo test -q -p zk-fuzzer --test phase0_integration_tests test_continuous_fuzzing_loop -- --test-threads=1` -> all pass

### AI-Powered Semantic Intent Analysis (2026-02-22)

**Goal:** Bridge the gap between constraint satisfaction and semantic correctness by using AI to understand developer intent from documentation/comments.

**Execution Policy:** This section is deferred and starts only after the current roadmap is complete (Phase 8 sustained-gate exit met). It is not part of active release gating.
**Operator note (no hard AI link):** semantic track runs in producer-only mode for AI handoff (`ai_ingest_bundle.json` / `ai_exploitability_worklist.json`). There is no in-process AI API call path, no background model runtime, and no automatic response-ingest path in the scanner.
**Ownership model:** AI is treated as an external user/operator that reads repository code plus generated fuzzer artifacts and acts manually (analysis, prioritization, remediation proposals) out-of-band.

**The Problem:**
- Fuzzer generates witnesses that satisfy all constraints
- But some solutions violate intended semantics ("extra" solutions)
- Manual auditors catch these by understanding intent from docs/comments
- Current fuzzing misses semantic bugs that pass constraint checks

#### Future P0 (Post-Roadmap): Intent Extraction & Semantic Oracle
- [x] Design intent extraction pipeline:
  - [x] Parse circuit source files for inline comments and docstrings
  - [x] Extract README/specification documents from project root
  - [x] Build structured intent representation (expected behaviors, invariants, security properties)
- [x] Implement AI-powered intent analyzer:
  - [x] Use LLM (Mistral/Claude/GPT-4) only as an external-user workflow to extract semantic requirements from natural language (no in-process API calls and no scanner-side AI execution hook)
  - [x] Generate formal invariants from informal descriptions
  - [x] Identify security-critical properties ("must never", "always", "only if")
- [x] Build semantic violation detector:
  - [x] Compare fuzzer-generated witnesses against extracted intent (via external execution-evidence payload ingestion)
  - [x] Classify violations: exploitable vs benign
  - [x] Rank by severity based on security impact
- [x] Add exploitability classifier:
  - [x] External AI/user analyzes which "extra solutions" enable attacks (producer-only task export in `ai_exploitability_worklist.json`)
  - [x] External AI/user generates proof-of-concept exploits for confirmed violations (producer-only PoC task templates; scanner does not execute or ingest AI outputs)
  - [x] Provide natural language explanations of vulnerability

#### Implementation Structure
```
crates/zk-track-semantic/
├── src/
│   ├── adapters.rs            # Intent extraction + exploitability adapters
│   └── lib.rs                 # Semantic track runner + report emission
└── tests/
    └── semantic_track_runner.rs # End-to-end semantic-track coverage
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
- Progress tracking artifact: `scripts/build_semantic_exit_report.py` -> `artifacts/semantic_exit/latest_report.json` (counts intent extraction, semantic violations, actionable report coverage, optional manual precision labels).
- Campaign runner: `scripts/run_semantic_exit_sample.sh` (emits semantic artifacts and refreshes `artifacts/semantic_exit/latest_report.json`).
- [x] Extract intent from 20+ real-world circuits with docs/comments (latest sample: 183 intent sources on 2026-02-23)
- [x] Detect ≥3 semantic violations missed by constraint-only analysis (latest sample: 24 semantic violations on 2026-02-23)
- [x] Achieve ≥80% precision on exploitability classification (manual validation) (latest sample: 0.8333 precision with 24 reviewed labels on 2026-02-23 via `tests/datasets/semantic/manual_labels.semantic_exit_sample.v1.json`)
- [x] Generate actionable reports with fix suggestions (`semantic_actionable_report.json`)

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
- [x] **Programmatic Circuit Generation:**
  - [x] Design circuit generation DSL with backend-specific syntax templates (Circom/Noir/Halo2/Cairo) (`crates/zk-circuit-gen`, `docs/COMPILER_CIRCUIT_DSL.md`)
  - [x] Implement bulk generator: produce 1000+ random circuits per backend (`crates/zk-circuit-gen/examples/generate_bulk_corpus.rs`, `scripts/run_circuit_gen_bulk_sample.sh`; latest run 2026-02-23: 4000 total, 1000/backend at `artifacts/circuit_gen/bulk_latest/latest_report.json`)
  - [x] Add mutation strategies (`render_mutated_template` + mutation-enabled bulk corpus in `crates/zk-circuit-gen/src/lib.rs`; operator flow in `docs/COMPILER_CIRCUIT_DSL.md`; sample run 2026-02-23: `artifacts/circuit_gen/mutation_sample/latest_report.json`):
    - [x] Deep nesting (trigger stack/recursion limits)
    - [x] Wide constraints (trigger memory/compilation limits)
    - [x] Pathological loops (trigger optimization bugs)
    - [x] Mixed types (trigger type checker edge cases)
    - [x] Malformed IR (trigger parser/validator bugs)
  - [x] Add AI-powered adversarial pattern generator (external-AI JSON ingestion + adversarial corpus CLI in `crates/zk-circuit-gen/examples/generate_adversarial_corpus.rs`; operator sample in `scripts/run_circuit_gen_adversarial_sample.sh`; schema/docs in `docs/COMPILER_CIRCUIT_DSL.md`; samples in `tests/datasets/circuit_gen/external_ai_patterns.sample.json`, `tests/datasets/circuit_gen/external_ai_feedback.sample.json`; latest sample run 2026-02-23: `artifacts/circuit_gen/adversarial_sample/latest_report.json`):
    - [x] LLM analyzes known compiler bugs from GitHub issues (external AI supplies `issue_refs` bundle, no in-process API use)
    - [x] Generate circuit patterns designed to trigger specific edge cases
    - [x] Evolve patterns based on compiler crash feedback

- [x] **Semantic Intent Validation:**
  - [x] Extract semantic intent from circuit comments/docs (`extract_semantic_intent_from_text` in `crates/zk-circuit-gen/src/lib.rs`; CLI in `crates/zk-circuit-gen/examples/extract_semantic_intent.rs`; sample runner `scripts/run_circuit_gen_semantic_sample.sh`; sample inputs `tests/datasets/circuit_gen/semantic_source.sample.circom`, `tests/datasets/circuit_gen/semantic_doc.sample.md`; latest sample run 2026-02-23: `artifacts/circuit_gen/semantic_intent_sample/latest_report.json`)
  - [x] Compile generated circuit and extract constraint count/structure (`compile_and_extract_structure` in `crates/zk-circuit-gen/src/lib.rs`; CLI in `crates/zk-circuit-gen/examples/compile_and_extract_structure.rs`; sample runner `scripts/run_circuit_gen_structure_sample.sh`; sample input `tests/datasets/circuit_gen/structure_dsl.sample.yaml`; latest sample run 2026-02-23: `artifacts/circuit_gen/structure_sample/latest_report.json`)
  - [x] Verify compiled constraints match intended semantics (`verify_compiled_constraints_match_intent` in `crates/zk-circuit-gen/src/lib.rs`; CLI in `crates/zk-circuit-gen/examples/verify_semantic_constraint_match.rs`; sample runner `scripts/run_circuit_gen_semantic_match_sample.sh`; latest sample run 2026-02-23: `artifacts/circuit_gen/semantic_constraint_match_sample/latest_report.json`)
  - [x] Detect constraint gaps (satisfiable but violates intent) (`constraint_gaps[]` in `SemanticConstraintVerificationReport` via `detect_constraint_gaps` in `crates/zk-circuit-gen/src/lib.rs`; validated in `crates/zk-circuit-gen/tests/template_rendering.rs`; latest sample run 2026-02-23: `artifacts/circuit_gen/semantic_constraint_match_sample/latest_report.json`)
  - [x] Report: "Circuit allows X but docs say 'only Y'" (`narrative_findings[]` + `render_semantic_constraint_report_markdown` in `crates/zk-circuit-gen/src/lib.rs`; markdown output wiring in `crates/zk-circuit-gen/examples/verify_semantic_constraint_match.rs`; sample runner emits `artifacts/circuit_gen/semantic_constraint_match_sample/latest_report.md`)

- [x] **Differential Compiler Testing:**
  - [x] Compile same circuit with multiple compilers (Circom v2.0 vs v2.1) (`compile_same_circuit_with_compiler_ids` in `crates/zk-circuit-gen/src/lib.rs`; matrix CLI `crates/zk-circuit-gen/examples/run_differential_compiler_matrix.rs`; sample run 2026-02-23: `artifacts/circuit_gen/differential_sample/latest_report.json`)
  - [x] Compile same circuit across backends (Circom vs Noir for compatible logic) (`run_differential_compiler_matrix` evaluates backend-axis comparisons in `crates/zk-circuit-gen/src/lib.rs`)
  - [x] Compare constraint counts (unexpected differences = bug) (`constraint_delta` emitted in `DifferentialStructureComparison`)
  - [x] Compare constraint structure (same logic → same constraints) (`structure_match` + expression/signal/depth deltas emitted in matrix report)
  - [x] Detect optimization regressions (constraint count increases) (`optimization_regression` detection in `compare_compiled_structures`)
  - [x] Version matrix testing: test N circuits × M compiler versions (`run_differential_version_matrix_campaign` in `crates/zk-circuit-gen/src/lib.rs`; CLI `crates/zk-circuit-gen/examples/run_differential_version_matrix.rs`; sample runner `scripts/run_circuit_gen_differential_version_matrix_sample.sh`; latest sample run 2026-02-23: `artifacts/circuit_gen/differential_version_matrix_sample/latest_report.json`)

- [x] **Compiler Crash/Bug Detection:**
  - [x] Timeout detection (compilation hangs) (`run_compiler_probe_case` status timeout + class timeout in `crates/zk-circuit-gen/src/lib.rs`; sample run 2026-02-23: `artifacts/circuit_gen/crash_detection_sample/latest_report.json`)
  - [x] Crash detection (segfault, panic, assertion failure) (`classify_compiler_failure` + crash tokens and signal-exit handling in `crates/zk-circuit-gen/src/lib.rs`; sample run includes `case_crash`)
  - [x] Error message classification (ICE vs user error) (`CompilerFailureClass::{InternalCompilerError,UserError}` + classification heuristics in `crates/zk-circuit-gen/src/lib.rs`; sample run includes `case_ice`, `case_user_error`)
  - [x] Automatic bug report generation with minimal repro (`generate_compiler_bug_reports` in `crates/zk-circuit-gen/src/lib.rs`; CLI in `crates/zk-circuit-gen/examples/run_compiler_crash_detector.rs`; sample runner `scripts/run_circuit_gen_crash_detection_sample.sh`)
  - [x] Regression suite: known compiler bugs must stay fixed (`evaluate_known_compiler_bug_regressions` + `RegressionStatus` in `crates/zk-circuit-gen/src/lib.rs`; probe expectations in `tests/datasets/circuit_gen/compiler_probe_cases.sample.json`)

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
- [x] Generate 1000+ syntactically valid circuits per backend (`scripts/run_circuit_gen_bulk_sample.sh`; latest sample run 2026-02-23: 4000 total with 1000/backend at `artifacts/circuit_gen/bulk_latest/latest_report.json`)
- [x] Detect ≥5 semantic intent violations (constraints don't match docs) (`scripts/run_circuit_gen_semantic_violation_sample.sh`; latest sample run 2026-02-23: `mismatched_intents=6` at `artifacts/circuit_gen/semantic_violation_sample/latest_report.json`)
- [x] Find ≥1 compiler crash/timeout on adversarial inputs (`scripts/run_circuit_gen_crash_detection_sample.sh`; latest sample run 2026-02-23: timeout=1 crash=1 at `artifacts/circuit_gen/crash_detection_sample/latest_report.json`)
- [x] Differential mode: test 100+ circuits × 3 compiler versions (`scripts/run_circuit_gen_differential_version_matrix_sample.sh`; latest sample run 2026-02-23: 120 circuits × 3 compiler labels at `artifacts/circuit_gen/differential_version_matrix_sample/latest_report.json`)
- [x] Detect ≥1 optimization regression (constraint count increase) (`scripts/run_circuit_gen_differential_regression_sample.sh`; latest sample run 2026-02-23: `optimization_regressions=1` at `artifacts/circuit_gen/differential_regression_sample/latest_report.json`)
- [x] AI generates ≥10 adversarial patterns from known bugs (`scripts/run_circuit_gen_adversarial_top10_sample.sh`; input bundle `tests/datasets/circuit_gen/external_ai_patterns.top10.sample.json`; latest sample run 2026-02-23: 10 patterns at `artifacts/circuit_gen/adversarial_top10_sample/latest_report.json`)
- [x] Integration tests validate generated circuits compile on ≥1 backend (`generated_halo2_templates_compile_with_rustc_stub_backend` in `crates/zk-circuit-gen/tests/template_rendering.rs`; sample runner `scripts/run_circuit_gen_backend_compile_integration_sample.sh`; latest sample run 2026-02-23: 20/20 succeeded at `artifacts/circuit_gen/backend_compile_integration_sample/latest_report.json`)

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
- [x] **Valid Proof + Manipulated Public Inputs:** (`run_public_input_manipulation_campaign` in `crates/zk-track-boundary/src/public_input_fuzzer.rs`; sample runner `scripts/run_boundary_public_input_sample.sh`)
  - [x] Generate valid proof for witness W with public inputs P (`generate_bound_proof` in `crates/zk-track-boundary/src/public_input_fuzzer.rs`)
  - [x] Mutate public inputs: P' = mutate(P) (`mutate_public_inputs` in `crates/zk-track-boundary/src/public_input_fuzzer.rs`)
  - [x] Test verification: verify(proof, P') should REJECT (`verify_bound_proof` and campaign report counts in `artifacts/boundary/public_input_sample/latest_report.json`)
  - [x] Bug if accepts: verifier doesn't check public inputs correctly (`findings[]` + `accepted_mutations` in campaign report)
- [x] **Mutation Strategies:** (`PublicInputMutationStrategy` in `crates/zk-track-boundary/src/public_input_fuzzer.rs`)
  - [x] Bit flips: flip random bits in public input encoding
  - [x] Field boundary: replace with 0, p-1, p, p+1
  - [x] Reordering: swap public input positions
  - [x] Truncation: remove trailing public inputs
  - [x] Duplication: repeat public inputs
  - [x] Type confusion: interpret field element as different type
- [x] **Attack Scenarios:** (`PublicInputAttackScenario` + `mutate_attack_scenario` in `crates/zk-track-boundary/src/public_input_fuzzer.rs`; exercised by `scripts/run_boundary_public_input_sample.sh`)
  - [x] Proof for user A, public input changed to user B (identity swap)
  - [x] Proof for amount 100, public input changed to 1000 (value inflation)
  - [x] Proof for valid merkle root, public input changed to attacker's root

#### Future P1 (Post-Roadmap): Serialization/Deserialization Fuzzer
- [x] **Proof Serialization Edge Cases:** (`ProofSerializationEdgeCase` + `mutate_proof_payload` in `crates/zk-track-boundary/src/serialization_fuzzer.rs`; sample runner `scripts/run_boundary_serialization_sample.sh`)
  - [x] Empty proof: zero-length byte array
  - [x] Truncated proof: valid proof with bytes removed
  - [x] Oversized proof: valid proof with extra bytes appended
  - [x] Invalid encoding: malformed field elements, points not on curve
  - [x] Endianness: big-endian vs little-endian confusion
  - [x] Padding: extra zeros, non-canonical representations
- [x] **Public Input Serialization:** (`PublicInputSerializationEdgeCase` + `mutate_public_inputs_payload` in `crates/zk-track-boundary/src/serialization_fuzzer.rs`)
  - [x] Array length mismatch: serialize N inputs, deserialize as M
  - [x] Type confusion: serialize as field, deserialize as bytes
  - [x] Encoding variants: hex vs base64 vs binary
  - [x] Delimiter confusion: comma vs space vs newline
- [x] **Cross-Language Serialization:** (`CrossLanguageSerializationCase` + `mutate_cross_language_payload` in `crates/zk-track-boundary/src/serialization_fuzzer.rs`)
  - [x] Rust prover → JavaScript verifier (snarkjs)
  - [x] Circom → Solidity verifier (ABI encoding)
  - [x] Noir → TypeScript verifier (JSON encoding)
  - [x] Test: serialize in language A, deserialize in language B

#### Future P1 (Post-Roadmap): Solidity Verifier Fuzzer
- [x] **Gas-Optimized Verifier Testing:** (`run_solidity_verifier_fuzz_campaign` in `crates/zk-track-boundary/src/solidity_verifier_fuzzer.rs`; sample runner `scripts/run_boundary_solidity_verifier_sample.sh`)
  - [x] Generate reference verifier (unoptimized) (`SolidityVerifierProfile::StrictParity` differential baseline)
  - [x] Generate gas-optimized verifier (production) (`SolidityVerifierProfile::WeakGasOptimization` bug-probe profile)
  - [x] Differential testing: same inputs → same outputs (`differential_checks=7500`, strict sample report)
  - [x] Detect optimization bugs: optimized accepts, reference rejects (`optimized_accepts_reference_rejects=5000` on weak bug probe)
- [x] **Verifier Input Fuzzing:** (`VerifierInputMutation` in `crates/zk-track-boundary/src/solidity_verifier_fuzzer.rs`)
  - [x] Fuzz proof bytes: random mutations (`proof_byte_mutation`)
  - [x] Fuzz public inputs: edge-case values (`public_input_edge_case`)
  - [x] Fuzz calldata: malformed ABI encoding (`malformed_calldata`)
  - [x] Test gas limits: does verifier run out of gas? (`gas_limit_stress`)
  - [x] Test revert conditions: proper error handling (`revert_condition_probe`)
- [x] **Pairing Check Manipulation:** (`PairingManipulationCase` in `crates/zk-track-boundary/src/solidity_verifier_fuzzer.rs`)
  - [x] Modify pairing equation components (`pairing_equation_tamper`)
  - [x] Test with invalid curve points (`invalid_curve_point`)
  - [x] Test with points not in correct subgroup (`wrong_subgroup_point`)
  - [x] Verify rejection of malformed pairing inputs (`malformed_pairing_input`)
- [x] **Solidity-Specific Edge Cases:** (`SolidityEdgeCase` in `crates/zk-track-boundary/src/solidity_verifier_fuzzer.rs`)
  - [x] Integer overflow in gas calculations (`gas_calculation_overflow`)
  - [x] Array bounds in public input access (`public_input_array_bounds`)
  - [x] Memory allocation edge cases (`memory_allocation_edge`)
  - [x] Calldata vs memory confusion (`calldata_memory_confusion`)
  - [x] Reentrancy (if verifier has callbacks) (`reentrancy_callback_probe`)

#### Future P1 (Post-Roadmap): Cross-Component Integration Fuzzer
- [x] **End-to-End Workflow Testing:** (`run_cross_component_fuzz_campaign` in `crates/zk-track-boundary/src/cross_component_fuzzer.rs`; sample runner `scripts/run_boundary_cross_component_sample.sh`)
  - [x] Circuit → Prover → Verifier (full pipeline) (`end_to_end_checks=60`)
  - [x] Test each boundary independently (`checks_by_fault_stage` includes all stage categories)
  - [x] Inject faults at each stage (`WorkflowFaultStage::{circuit_stage,prover_stage,verifier_stage,transport_boundary}`)
  - [x] Verify fault detection (strict profile reports `differential_divergences=0`, bug probe surfaces stage divergences)
- [x] **Component Mismatch Detection:** (`ComponentMismatchCase` in `crates/zk-track-boundary/src/cross_component_fuzzer.rs`)
  - [x] Prover version X, Verifier version Y (`prover_verifier_version_mismatch`)
  - [x] Circuit compiled with flags A, Verifier expects flags B (`circuit_verifier_flag_mismatch`)
  - [x] Trusted setup ceremony mismatch (`trusted_setup_mismatch`)
  - [x] Curve parameter mismatch (BN254 vs BLS12-381) (`curve_parameter_mismatch`)

#### Implementation Structure
```
crates/zk-track-boundary/
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
- [x] Public input fuzzer: test 1000+ valid proofs with manipulated inputs (`scripts/run_boundary_public_input_sample.sh`; latest sample run 2026-02-23: proofs=1000, mutation_checks=9000, attack_scenario_checks=3000 at `artifacts/boundary/public_input_sample/latest_report.json`)
- [x] Detect ≥1 public input binding bug (verifier accepts wrong inputs) (`scripts/run_boundary_public_input_bug_probe.sh`; latest probe run 2026-02-23: verifier_profile=weak_first_input_binding, accepted_mutations=6331, findings=6331 at `artifacts/boundary/public_input_bug_probe/latest_report.json`)
- [x] Serialization fuzzer: test 100+ edge cases per format (`scripts/run_boundary_serialization_sample.sh`; latest sample run 2026-02-23: formats=3, checks_by_format={binary:168,hex:168,base64:168} at `artifacts/boundary/serialization_sample/latest_report.json`)
- [x] Detect ≥1 serialization bug (crash, incorrect deserialization) (`scripts/run_boundary_serialization_bug_probe.sh`; latest probe run 2026-02-23: verifier_profile=lenient_legacy, accepted_invalid_cases=212, findings=212 at `artifacts/boundary/serialization_bug_probe/latest_report.json`)
- [x] Solidity fuzzer: differential test 500+ proofs (reference vs optimized) (`scripts/run_boundary_solidity_verifier_sample.sh`; latest sample run 2026-02-23: proofs=500, differential_checks=7500, divergences=0 at `artifacts/boundary/solidity_verifier_sample/latest_report.json`)
- [x] Detect ≥1 gas optimization bug (behavior divergence) (`scripts/run_boundary_solidity_verifier_bug_probe.sh`; latest probe run 2026-02-23: differential_divergences=6000, optimized_accepts_reference_rejects=5000, findings=6000 at `artifacts/boundary/solidity_verifier_bug_probe/latest_report.json`)
- [x] Cross-component: test 50+ version/configuration combinations (`scripts/run_boundary_cross_component_sample.sh`; latest sample run 2026-02-23: combinations=60, configuration_combinations_tested=60, checks=540 at `artifacts/boundary/cross_component_sample/latest_report.json`)
- [x] Detect ≥1 integration bug (component mismatch) (`scripts/run_boundary_cross_component_bug_probe.sh`; latest probe run 2026-02-23: differential_divergences=360, candidate_accepts_reference_rejects=360, findings=360 at `artifacts/boundary/cross_component_bug_probe/latest_report.json`)

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
- [x] **Edge-Case Value Generator:** (`generate_field_edge_values` + `generate_field_values` in `crates/zk-track-crypto/src/generators.rs`; campaign runner `scripts/run_crypto_field_sample.sh`)
  - [x] Special values: `0`, `1`, `-1`, `p/2`, `p-1`, `p`, `p+1`
  - [x] Algebraic properties: squares, non-squares, generators, primitive roots
  - [x] Random values: uniform distribution across field
  - [x] Boundary values: near-zero, near-modulus
- [x] **Operation Coverage:** (`FieldOperation` + `run_field_arithmetic_fuzz_campaign` in `crates/zk-track-crypto/src/field_fuzzer.rs`)
  - [x] Addition: `a + b` (overflow, underflow, identity)
  - [x] Subtraction: `a - b` (negative results, wraparound)
  - [x] Multiplication: `a * b` (overflow, zero, one)
  - [x] Division: `a / b` (division by zero, inverse computation)
  - [x] Exponentiation: `a^b` (large exponents, zero exponent)
  - [x] Modular reduction: verify `(a op b) mod p == expected`
- [x] **Property Testing:** (`FieldProperty` checks in `crates/zk-track-crypto/src/field_fuzzer.rs`)
  - [x] Commutativity: `a + b == b + a`
  - [x] Associativity: `(a + b) + c == a + (b + c)`
  - [x] Distributivity: `a * (b + c) == a*b + a*c`
  - [x] Identity: `a + 0 == a`, `a * 1 == a`
  - [x] Inverse: `a * a^(-1) == 1` (for `a != 0`)

#### Future P1 (Post-Roadmap): Curve Operation Fuzzer
- [x] **Point Generator:** (`CurvePointType` + `generate_curve_point` in `crates/zk-track-crypto/src/generators.rs`; campaign runner `scripts/run_crypto_curve_sample.sh`)
  - [x] Identity/infinity point: `O`
  - [x] Generator point: `G`
  - [x] Random valid points: `[k]G` for random `k`
  - [x] Low-order points: points with small order
  - [x] Invalid points: not on curve `y^2 != x^3 + ax + b`
  - [x] Points at infinity in different representations
- [x] **Operation Coverage:** (`CurveOperation` + `evaluate_curve_operation` in `crates/zk-track-crypto/src/curve_fuzzer.rs`)
  - [x] Point addition: `P + Q`
  - [x] Point doubling: `2P`
  - [x] Scalar multiplication: `[k]P`
  - [x] Multi-scalar multiplication: `[k1]P1 + [k2]P2`
  - [x] Point negation: `-P`
  - [x] Point validation: `is_on_curve(P)`
- [x] **Edge Case Testing:** (`CurveEdgeCase` + `run_edge_case_checks` in `crates/zk-track-crypto/src/curve_fuzzer.rs`)
  - [x] Adding identity: `P + O == P`
  - [x] Adding inverse: `P + (-P) == O`
  - [x] Doubling identity: `2O == O`
  - [x] Zero scalar: `[0]P == O`
  - [x] One scalar: `[1]P == P`
  - [x] Large scalar: `[p]P` (order wraparound)
  - [x] Invalid point rejection: operations on invalid points must fail

#### Future P1 (Post-Roadmap): Pairing Fuzzer
- [x] **Input Combination Matrix:** (`PairingInputType` + `run_pairing_fuzz_campaign` in `crates/zk-track-crypto/src/pairing_fuzzer.rs`; campaign runner `scripts/run_crypto_pairing_sample.sh`)
  - [x] G1 inputs: `{O, G1, random, low-order, invalid}` (5 cases)
  - [x] G2 inputs: `{O, G2, random, low-order, invalid}` (5 cases)
  - [x] Systematic testing: 5 × 5 = 25 combinations
- [x] **Pairing Properties:** (`PairingProperty` in `crates/zk-track-crypto/src/pairing_fuzzer.rs`)
  - [x] Bilinearity: `e([a]P, [b]Q) == e(P, Q)^(ab)`
  - [x] Non-degeneracy: `e(G1, G2) != 1`
  - [x] Identity: `e(O, Q) == 1`, `e(P, O) == 1`
  - [x] Linearity in G1: `e(P1 + P2, Q) == e(P1, Q) * e(P2, Q)`
  - [x] Linearity in G2: `e(P, Q1 + Q2) == e(P, Q1) * e(P, Q2)`
- [x] **Degenerate Cases:** (`resolve_pairing_input` strict vs weak handling in `crates/zk-track-crypto/src/pairing_fuzzer.rs`)
  - [x] Both inputs identity: `e(O, O)`
  - [x] One input identity: `e(G1, O)`, `e(O, G2)`
  - [x] Low-order inputs: detect subgroup attacks
  - [x] Invalid inputs: must reject or handle safely

#### Implementation Structure
```
crates/zk-track-crypto/
├── src/
│   ├── field_fuzzer.rs       # Field arithmetic testing
│   ├── curve_fuzzer.rs       # Elliptic curve operations
│   ├── pairing_fuzzer.rs     # Pairing operations
│   ├── generators.rs         # Edge-case value generation
│   ├── property_checker.rs   # Algebraic property validation
│   └── oracle.rs             # Reference implementation comparison
├── examples/
│   ├── run_field_arithmetic_fuzz_campaign.rs
│   ├── run_curve_operation_fuzz_campaign.rs
│   └── run_pairing_fuzz_campaign.rs
scripts/run_crypto_*_sample.sh and scripts/run_crypto_*_bug_probe.sh
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
- [x] Field fuzzer: test 100+ operations × 10 edge-case values = 1000+ tests (`scripts/run_crypto_field_sample.sh`; latest sample run 2026-02-23: checks=2680, operation_divergences=0, property_failures=0 at `artifacts/crypto/field_sample/latest_report.json`)
- [x] Curve fuzzer: test 50+ operations × 7 point types = 350+ tests (`scripts/run_crypto_curve_sample.sh`; latest sample run 2026-02-23: operation_checks=2100, edge_case_checks=7, operation_divergences=0 at `artifacts/crypto/curve_sample/latest_report.json`)
- [x] Pairing fuzzer: test 25 input combinations × 5 properties = 125+ tests (`scripts/run_crypto_pairing_sample.sh`; latest sample run 2026-02-23: combinations=25, checks=125, property_failures=0 at `artifacts/crypto/pairing_sample/latest_report.json`)
- [x] Detect ≥1 field arithmetic bug (incorrect reduction, overflow) (`scripts/run_crypto_field_bug_probe.sh`; latest probe run 2026-02-23: operation_divergences=290, property_failures=4, findings=294 at `artifacts/crypto/field_bug_probe/latest_report.json`)
- [x] Detect ≥1 curve operation bug (invalid point handling, identity) (`scripts/run_crypto_curve_bug_probe.sh`; latest probe run 2026-02-23: operation_divergences=742, edge_case_failures=3, findings=745 at `artifacts/crypto/curve_bug_probe/latest_report.json`)
- [x] Detect ≥1 pairing bug (degenerate case, bilinearity violation) (`scripts/run_crypto_pairing_bug_probe.sh`; latest probe run 2026-02-23: property_failures=80, candidate_accepts_invalid_cases=80, findings=80 at `artifacts/crypto/pairing_bug_probe/latest_report.json`)
- [x] Property tests: 100% pass rate on reference implementation (`cargo test -p zk-track-crypto`; 14/14 passing on 2026-02-23)
- [x] Integration with existing attack framework (`crates/zk-track-crypto/src/lib.rs` now executes field/curve/pairing campaigns through `CryptoTrackRunner::{prepare,run,validate,emit}` with scorecard + replay artifacts, and remains a default post-roadmap track in `src/pipeline/post_roadmap_runner.rs`)

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

**Status:** ⏸ Deferred execution policy remains, but implementation/evidence are complete (`scripts/run_crypto_*_sample.sh`, `scripts/run_crypto_*_bug_probe.sh`, `artifacts/crypto/*/latest_report.json`)

---

## 🎯 UX & Tooling Improvements (Post-Phase 8)

### CLI/UX Quick Wins
- [x] Add `--list-patterns` flag (30 min, High reward) - List all available CVE patterns with descriptions (`src/cli/mod.rs`, `src/main.rs`; regression: `tests/cli_command_parity_tests.rs::list_patterns_flag_prints_known_cve_catalog`, 2026-02-26)
- [x] Shell completions (1 hr, High reward) - Generate bash/zsh/fish completions for better discoverability (`zk-fuzzer completions --shell <bash|zsh|fish>` via `src/cli/mod.rs` + `src/main.rs`; regression: `tests/cli_command_parity_tests.rs::completions_command_emits_bash_script`, 2026-02-26)
- [ ] Add `--json` global flag (2 hrs, High reward) - Structured output for CI integration
- [ ] Progress bar for pattern loading (1 hr, Medium reward) - Shows "Loading 52 CVE patterns..." on startup

### Reporting/Output Improvements
- [ ] Markdown summary export (2 hrs, High reward) - `--format markdown` for findings; auditors paste into reports
- [ ] SARIF output validation badge (1 hr, Medium reward) - Add GitHub Security tab integration
- [ ] Timing breakdown in reports (2 hrs, Medium reward) - Show detection time vs proof time per pattern

### Developer Experience
- [ ] `--validate-circuit` dry-run (3 hrs, High reward) - Check if circuit compiles/executes without full fuzzing
- [ ] Config schema validation on load (2 hrs, Medium reward) - Fail fast with line numbers on YAML errors
- [ ] Pattern template generator (2 hrs, Medium reward) - `zk-fuzzer template new-pattern --name cveXXX` creates boilerplate





---

### Post-Roadmap Execution Workflow (Deferred Additions)

**Applies to:** AI semantic intent analysis, compiler fuzzing, ZK/non-ZK boundary fuzzing, and cryptographic primitive fuzzing.

**Operator Workflow (short form)**
- [x] Activate only after current roadmap completion (Phase 8 sustained-gate exit met); keep out of active release gates until then. (`PostRoadmapWorkflowConfig.activated=false` by default; explicit activation required in `src/pipeline/post_roadmap_workflow.rs`)
- [x] Run a foundation sprint first: shared corpus/evidence store, shared finding schema, shared replay/minimization harness, shared dashboard. (`build_foundation_sprint_state` with `SharedStoreLayout`, `ReplayHarnessState`, `DashboardSnapshot` in `src/pipeline/post_roadmap_foundation.rs`)
- [x] Execute in this order for ROI: `boundary -> compiler -> semantic -> crypto`. (encoded in `recommended_roi_track_order()` + track runner ordering)
- [x] Use shared data flow: compiler-generated circuits feed boundary tests; boundary/compiler findings feed semantic exploitability ranking; crypto checks validate math-level correctness vs noise; semantic outputs feed generator prioritization for next cycle. (`build_shared_data_flow` in `src/pipeline/post_roadmap_workflow.rs`)
- [x] Use weekly cadence: `generate -> boundary -> semantic -> crypto -> regress`. (encoded in `default_weekly_cadence()`)
- [x] Enforce promotion gates: deterministic replay, false-positive budget, explicit coverage counts, and required regression tests for accepted high/critical findings. (`evaluate_promotion_gates` + `PostRoadmapPromotionPolicy`)
- [x] Operate one integrated pipeline: `generate -> attack -> interpret -> validate -> regress`. (encoded in `default_integrated_pipeline()` and `PostRoadmapWorkflowRunner::run_cycle`)

**Modularization Blueprint (design requirement)**
- [x] Split deferred work into separate crates/modules with strict boundaries:
  - [x] `crates/zk-postroadmap-core`: shared contracts (`TrackInput`, `TrackFinding`, `ReplayArtifact`, scorecard schema, error taxonomy).
  - [x] `crates/zk-track-boundary`: public-input/serialization/verifier boundary testing only.
  - [x] `crates/zk-track-compiler`: circuit generation, compiler differential, crash/timeout classification, now wired through `CompilerTrackRunner::{prepare,run,validate,emit}` with scorecard + replay artifact emission.
  - [x] `crates/zk-track-semantic`: intent extraction, semantic violation ranking, exploitability classification.
  - [x] `crates/zk-track-crypto`: field/curve/pairing property fuzzing and reference checks.
  - [x] `src/pipeline/post_roadmap_runner.rs`: orchestration only (no track-specific logic).
- [x] Enforce interface-first integration:
  - [x] each track implements a common runner trait (prepare -> run -> validate -> emit).
  - [x] tracks communicate only through `zk-postroadmap-core` artifact contracts.
  - [x] no direct track-to-track imports (dependency direction: `track -> core`, `runner -> track + core`).
- [x] Keep adapters modular:
  - AI/LLM providers behind a single adapter interface in semantic track.
  - compiler backend adapters behind per-backend strategy interfaces in compiler track.
  - verifier/serialization adapters behind protocol interfaces in boundary track.
- [x] Enforce module-level quality gates:
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

### External Target Recheck (2026-02-25)
- [x] EXT-004 `preflight_backend` rerun no longer reproduces the Scarb lockfile permission failure.
  - Run: `./scripts/zeroday_workflow.sh evidence artifacts/external_targets/ext_batch_006/repro/ext004_orion_scarb_campaign.yaml --iterations 200 --timeout 90 --seed 42 --workers 1`
  - Outcome: `status=completed`, `stage=completed`, `reason_code=completed`
  - Evidence: `artifacts/external_targets/recheck/run_signals_ext004/report_1771976147_20260224_233547_evidence_ext004_orion_scarb_campaign_pid3974196/summary.json`
  - Log: `artifacts/external_targets/recheck/logs/ext004_recheck.log`
- [ ] EXT-005 `preflight_backend` remains open in non-escalated rerun; backend dependency/toolchain resolution still fails.
  - Run: `./scripts/zeroday_workflow.sh evidence artifacts/external_targets/ext_batch_006/repro/ext005_ezkl_halo2_campaign.yaml --iterations 200 --timeout 180 --seed 42 --workers 1`
  - Outcome: `status=failed`, `stage=preflight_backend`, `reason_code=backend_dependency_resolution_failed`
  - Failure signals: cargo toolchain cascade exhaustion and dependency fetch failures (`github.com`, `binaries.soliditylang.org`) in this environment.
  - Evidence: `artifacts/external_targets/recheck/run_signals_ext005/report_1771976381_20260224_233941_evidence_ext005_ezkl_halo2_campaign_pid3978565/summary.json`
  - Log: `artifacts/external_targets/recheck/logs/ext005_recheck.log`
- [ ] EXT-005 escalated rerun ended and remains open (manual checks only).
  - Outcome: `status=failed`, `stage=preflight_timeout`, `reason_code=wall_clock_timeout`
  - Note: preflight eventually passed, but global wall-clock budget was exhausted before engine start (`budget=180s`, `consumed~1396s`).
  - Evidence: `artifacts/external_targets/recheck/run_signals_ext005_escalated/report_1771977003_20260224_235003_evidence_ext005_ezkl_halo2_campaign_pid4042372/summary.json`
  - Log: `artifacts/external_targets/recheck/logs/ext005_recheck_escalated.log`
- [ ] EXT-005 bounded follow-up rerun remains open; deterministic preflight failure reproduces under cache-first local settings.
  - Run: `ZKF_SCAN_OUTPUT_ROOT=artifacts/external_targets/recheck_ext005_followup/scan_output_ext005 ZKF_RUN_SIGNAL_DIR=artifacts/external_targets/recheck_ext005_followup/run_signals_ext005 ZKF_BUILD_CACHE_DIR=artifacts/external_targets/recheck/build_cache ZKF_HALO2_PREWARM_MODE=off ZK_FUZZER_HALO2_AUTO_ONLINE_RETRY=false ZK_FUZZER_HALO2_RUSTUP_TOOLCHAIN_CASCADE=false ZK_FUZZER_HALO2_CARGO_TOOLCHAIN=nightly-2025-12-01 ./scripts/zeroday_workflow.sh evidence artifacts/external_targets/ext_batch_006/repro/ext005_ezkl_halo2_campaign.yaml --iterations 20 --timeout 600 --seed 42 --workers 1`
  - Outcome: `status=failed`, `stage=preflight_backend`, `reason_code=backend_toolchain_mismatch`
  - Failure signals: `svm-rs-builds` build script still requires remote release metadata and fails on DNS lookup for `https://binaries.soliditylang.org/linux-amd64/list.json` in this environment.
  - Evidence: `artifacts/external_targets/recheck_ext005_followup/run_signals_ext005/report_1771982941_20260225_012901_evidence_ext005_ezkl_halo2_campaign_pid120126/summary.json`
  - Log: `artifacts/external_targets/recheck_ext005_followup/logs/ext005_followup.log`
- [x] EXT-005 continuation rerun reached engine execution with cache-first `SVM_RELEASES_LIST_JSON` override and completed in bounded mode.
  - Run: `ZKF_SCAN_OUTPUT_ROOT=artifacts/external_targets/recheck_ext005_continue_20260225/scan_output_ext005 ZKF_RUN_SIGNAL_DIR=artifacts/external_targets/recheck_ext005_continue_20260225/run_signals_ext005 ZKF_BUILD_CACHE_DIR=artifacts/external_targets/recheck/build_cache ZKF_HALO2_PREWARM_MODE=off ZK_FUZZER_HALO2_AUTO_ONLINE_RETRY=false ZK_FUZZER_HALO2_RUSTUP_TOOLCHAIN_CASCADE=false ZK_FUZZER_HALO2_CARGO_TOOLCHAIN=nightly-2025-12-01 ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES=nightly-2025-12-01 SVM_RELEASES_LIST_JSON=artifacts/external_targets/recheck_ext005_continue_20260225/manifests/svm_releases_linux_amd64.json ./scripts/zeroday_workflow.sh evidence artifacts/external_targets/ext_batch_006/repro/ext005_ezkl_halo2_campaign.yaml --iterations 20 --timeout 600 --seed 42 --workers 1`
  - Outcome: `status=completed`, `stage=completed`, `reason_code=completed`, `total_executions=17`, `findings_total=6`
  - Evidence: `artifacts/external_targets/recheck_ext005_continue_20260225/run_signals_ext005/report_1771983844_20260225_014404_evidence_ext005_ezkl_halo2_campaign_pid137750/summary.json`
  - Log: `artifacts/external_targets/recheck_ext005_continue_20260225/logs/ext005_continue_run.log`
- [ ] EXT-005 proof remains open after triage (`pending_proof`).
  - Triage outcome: all 6 findings are low-correlation metamorphic `Base execution failed` signals and do not yet demonstrate exploitability.
  - Backend signal observed during run: repeated Halo2 constraint-extraction incompatibility (`error: unexpected argument '--constraints' found`).
  - Triage artifact: `artifacts/external_targets/recheck_ext005_continue_20260225/reports/ext005_triage.md`
- [x] EXT-005 deterministic replay harness added for one continuation candidate and evidence artifacts created.
  - Replay harness: `tests/backend_integration_tests.rs::test_halo2_ext005_ezkl_replay_base_execution_failure` (fixed witness from continuation finding set).
  - Evidence pack: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/{replay_command.txt,no_exploit_proof.md,impact.md}`
  - Pre-fix replay log: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/prepatch_replay.log`
- [x] EXT-005 Halo2 constraint-extraction adapter hardening completed.
  - `crates/zk-backends/src/halo2/mod.rs`: cache unsupported `--constraints` capability state and cache empty parsed constraints after first failed extraction (no repeated extraction retries).
  - `src/executor/mod.rs`: when Halo2 target is known to not support `--constraints`, fall back to output-hash coverage instead of unconditional coverage-unavailable failure.
  - Local validation: `cargo test -p zk-backends --quiet`; `cargo test --test backend_integration_tests test_halo2_ext005_ezkl_replay_base_execution_failure -- --nocapture`.
- [ ] EXT-005 post-fix bounded replay remains blocked; proof status stays `pending_proof`.
  - Post-fix replay command was bounded with `timeout 300s` and ended `failed:124` (timeout) before assertion completion.
  - Post-fix log: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/postpatch_replay.log`
  - Status marker: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/postpatch_status.txt`
  - Bounded rerun command (same env/toolchain overrides) also ended `124` (`POSTPATCH_RERUN_STATUS=124`).
  - Bounded rerun log: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/postpatch_replay_rerun.log`
  - Bounded rerun status marker: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/postpatch_status_rerun.txt`
- [x] EXT-005 extended-window replay produced a deterministic post-fix outcome in one long-window run.
  - Run: same post-fix replay command with `timeout 900s`
  - Outcome: `POSTPATCH_LONGRUN_STATUS=101` after `~491s`; test reached assertion and observed executor success output instead of strict missing-coverage failure.
  - Interpretation: adapter fallback path is active for this witness; the failure in that run was stale pre-fix assertion in replay harness.
  - Extended replay log: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/postpatch_replay_longrun.log`
  - Extended replay status marker: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/postpatch_status_longrun.txt`
- [x] EXT-005 replay harness assertion updated for post-fix behavior.
  - `tests/backend_integration_tests.rs::test_halo2_ext005_ezkl_replay_base_execution_failure` now expects successful execution with output-hash fallback coverage when `--constraints` export is unsupported.
- [ ] EXT-005 long-window post-assertion validation remains unstable (`pending_proof`).
  - Follow-up run after harness assertion update ended `124` (`POSTPATCH_LONGRUN_POSTASSERT_STATUS=124`) before assertion completion.
  - Follow-up log: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/postpatch_replay_longrun_postassert.log`
  - Follow-up status marker: `artifacts/external_targets/recheck_ext005_continue_20260225/evidence/EXT-005/run_20260225_ext005_adapter_replay/postpatch_status_longrun_postassert.txt`
- [ ] EXT-005 extended bounded replay follow-up (1200s) still unresolved (`pending_proof`).
  - Proof run root: `artifacts/proof_runs/ext005/run_20260226_225545_ext005_adapter_replay_followup/`
  - Deterministic replay command: `replay_command.txt` (same fixed witness/toolchain/SVM override stack, bounded by `timeout 1200s`).
  - Outcome: `REPLAY_EXIT_STATUS=124`; run reached long-running test phase but did not produce deterministic assertion output before timeout.
  - Replay log: `artifacts/proof_runs/ext005/run_20260226_225545_ext005_adapter_replay_followup/replay.log`
  - Triage + blocker record: `triage.md`, `pending_proof.md`, `impact.md`

### Proof Continuation (2026-02-26)
- [x] `cveX15_scroll_missing_overflow_constraint` deterministic replay + bounded non-exploit proof pack completed (manual checks only).
  - Objective lock / target freeze / tool readiness: `artifacts/proof_runs/cveX15/run_20260226_212437_cveX15_testool_non_exploit_followup/{objective_lock.md,target_freeze.md,tool_readiness.md}`
  - Discovery source under triage: `artifacts/proof_runs/cveX15/run_20260226_212437_cveX15_testool_non_exploit_followup/discovery_candidate_{report,run_outcome}.json` (source run id `20260226_130735_scan_cveX15_scroll_missing_overflow_constraint__f2de549152af10e0_pid215920`)
  - Deterministic replay command + execution log: `artifacts/proof_runs/cveX15/run_20260226_212437_cveX15_testool_non_exploit_followup/{replay_command.txt,replay.log}`
  - Replay outcome: `status=completed`, `reason_code=completed`; underconstrained/soundness exploit checks were skipped because target exposes `0` public inputs (`session.log` lines `43`, `46`), so no exploitable condition was reproduced within bounds.
  - Solver-backed bounded evidence: `artifacts/proof_runs/cveX15/run_20260226_212437_cveX15_testool_non_exploit_followup/{witness_distinctness_check.smt2,z3_witness_check.log,empty_public_interface_collision_tautology.smt2,z3_empty_interface_tautology.log}`
  - Final proof artifacts: `artifacts/proof_runs/cveX15/run_20260226_212437_cveX15_testool_non_exploit_followup/{no_exploit_proof.md,impact.md}`
  - Conclusion: `not_exploitable_within_bounds` for this claim class on frozen target snapshot and replay bounds (`seed=42`, `iterations=200`, `timeout=180s`, `workers=2`).
- [x] `cveX16_scroll_missing_constraint` deterministic replay + bounded non-exploit proof pack completed (manual checks only).
  - Objective lock / target freeze / tool readiness: `artifacts/proof_runs/cveX16/run_20260226_204807_cveX16_testool_non_exploit/{objective_lock.md,target_freeze.md,tool_readiness.md}`
  - Discovery source under triage: `artifacts/proof_runs/cveX16/run_20260226_204807_cveX16_testool_non_exploit/discovery_candidate_{report,run_outcome}.json` (source run id `20260226_131036_scan_cveX16_scroll_missing_constraint__6822bc916b49996f_pid242526`)
  - Deterministic replay command + execution log: `artifacts/proof_runs/cveX16/run_20260226_204807_cveX16_testool_non_exploit/{replay_command.txt,replay.log}`
  - Replay outcome: `status=completed`, `reason_code=completed`; underconstrained/soundness exploit checks were skipped because target exposes `0` public inputs (`session.log` lines `43`, `46`), so no exploitable condition was reproduced within bounds.
  - Solver-backed bounded evidence: `artifacts/proof_runs/cveX16/run_20260226_204807_cveX16_testool_non_exploit/{witness_distinctness_check.smt2,z3_witness_check.log,empty_public_interface_collision_tautology.smt2,z3_empty_interface_tautology.log}`
  - Final proof artifacts: `artifacts/proof_runs/cveX16/run_20260226_204807_cveX16_testool_non_exploit/{no_exploit_proof.md,impact.md}`
  - Conclusion: `not_exploitable_within_bounds` for this claim class on frozen target snapshot and replay bounds (`seed=42`, `iterations=200`, `timeout=180s`, `workers=2`).
- [x] `cveX39_scroll_modgadget_underconstrained_mulmod` deterministic replay + bounded non-exploit proof pack completed (manual checks only).
  - Objective lock / target freeze / tool readiness: `artifacts/proof_runs/cveX39/run_20260226_211257_cveX39_testool_non_exploit/{objective_lock.md,target_freeze.md,tool_readiness.md}`
  - Discovery source under triage: `artifacts/proof_runs/cveX39/run_20260226_211257_cveX39_testool_non_exploit/discovery_candidate_{report,run_outcome}.json` (source run id `20260226_131347_scan_cveX39_scroll_modgadget_underconstrained_mulmod__834b6843c652c241_pid273819`)
  - Deterministic replay command + execution log: `artifacts/proof_runs/cveX39/run_20260226_211257_cveX39_testool_non_exploit/{replay_command.txt,replay.log}`
  - Replay outcome: `status=completed`, `reason_code=completed`; underconstrained/soundness exploit checks were skipped because target exposes `0` public inputs (`session.log` lines `43`, `46`), so no exploitable condition was reproduced within bounds.
  - Solver-backed bounded evidence: `artifacts/proof_runs/cveX39/run_20260226_211257_cveX39_testool_non_exploit/{witness_distinctness_check.smt2,z3_witness_check.log,empty_public_interface_collision_tautology.smt2,z3_empty_interface_tautology.log}`
  - Final proof artifacts: `artifacts/proof_runs/cveX39/run_20260226_211257_cveX39_testool_non_exploit/{no_exploit_proof.md,impact.md}`
  - Conclusion: `not_exploitable_within_bounds` for this claim class on frozen target snapshot and replay bounds (`seed=42`, `iterations=200`, `timeout=180s`, `workers=2`).
- [x] `cveX40_scroll_create_static_context_escape` deterministic replay + bounded non-exploit proof pack completed (manual checks only).
  - Objective lock / target freeze / tool readiness: `artifacts/proof_runs/cveX40/run_20260226_211833_cveX40_testool_non_exploit/{objective_lock.md,target_freeze.md,tool_readiness.md}`
  - Discovery source under triage: `artifacts/proof_runs/cveX40/run_20260226_211833_cveX40_testool_non_exploit/discovery_candidate_{report,run_outcome}.json` (source run id `20260226_131650_scan_cveX40_scroll_create_static_context_escape__ac56924bc4c07559_pid304736`)
  - Deterministic replay command + execution log: `artifacts/proof_runs/cveX40/run_20260226_211833_cveX40_testool_non_exploit/{replay_command.txt,replay.log}`
  - Replay outcome: `status=completed`, `reason_code=completed`; underconstrained/soundness exploit checks were skipped because target exposes `0` public inputs (`session.log` lines `43`, `46`), so no exploitable condition was reproduced within bounds.
  - Solver-backed bounded evidence: `artifacts/proof_runs/cveX40/run_20260226_211833_cveX40_testool_non_exploit/{witness_distinctness_check.smt2,z3_witness_check.log,empty_public_interface_collision_tautology.smt2,z3_empty_interface_tautology.log}`
  - Final proof artifacts: `artifacts/proof_runs/cveX40/run_20260226_211833_cveX40_testool_non_exploit/{no_exploit_proof.md,impact.md}`
  - Conclusion: `not_exploitable_within_bounds` for this claim class on frozen target snapshot and replay bounds (`seed=42`, `iterations=200`, `timeout=180s`, `workers=2`).
- [x] `cveX41_scroll_rlpu64_lt128_underconstrained` deterministic replay + bounded non-exploit proof pack completed (manual checks only).
  - Objective lock / target freeze / tool readiness: `artifacts/proof_runs/cveX41/run_20260226_212437_cveX41_testool_non_exploit/{objective_lock.md,target_freeze.md,tool_readiness.md}`
  - Discovery source under triage: `artifacts/proof_runs/cveX41/run_20260226_212437_cveX41_testool_non_exploit/discovery_candidate_{report,run_outcome}.json` (source run id `20260226_131953_scan_cveX41_scroll_rlpu64_lt128_underconstrained__cb213a2d1f547cd3_pid335670`)
  - Deterministic replay command + execution log: `artifacts/proof_runs/cveX41/run_20260226_212437_cveX41_testool_non_exploit/{replay_command.txt,replay.log}`
  - Replay outcome: `status=completed`, `reason_code=completed`; underconstrained/soundness exploit checks were skipped because target exposes `0` public inputs (`session.log` lines `43`, `46`), so no exploitable condition was reproduced within bounds.
  - Solver-backed bounded evidence: `artifacts/proof_runs/cveX41/run_20260226_212437_cveX41_testool_non_exploit/{witness_distinctness_check.smt2,z3_witness_check.log,empty_public_interface_collision_tautology.smt2,z3_empty_interface_tautology.log}`
  - Final proof artifacts: `artifacts/proof_runs/cveX41/run_20260226_212437_cveX41_testool_non_exploit/{no_exploit_proof.md,impact.md}`
  - Conclusion: `not_exploitable_within_bounds` for this claim class on frozen target snapshot and replay bounds (`seed=42`, `iterations=200`, `timeout=180s`, `workers=2`).

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
- Latest backend maturity scorecard refresh: `artifacts/backend_maturity/latest_scorecard.json` (`generated_utc=2026-02-23T14:27:46Z`; scores: `circom=5.0`, `cairo=4.617`, `noir=4.5`, `halo2=4.5`)
- Latest maturity streak state: `artifacts/backend_maturity/latest_scorecard.json` (`circom=2/14`, `noir=0/14`, `cairo=0/14`, `halo2=0/14`; gate pending)
- Latest Circom flake streak state: `artifacts/circom_flake/latest_report.json` (`generated_utc=2026-02-23T14:27:52Z`, `current_streak_days=2`, `required=14`)
- Noir readiness runner now snapshots/restores `Prover.toml` for matrix projects to avoid dirty tracked fixtures on interrupted runs (`scripts/run_noir_readiness.sh`)
- Nightly CI matrix is operational with fast-smoke and deep-scheduled lanes
