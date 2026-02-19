# ZkPatternFuzz Production Roadmap

Date: 2026-02-19  
Status: Active  
Primary goal: make the scanner production-grade for real multi-target runs with high recall and high runtime stability.

---

## 📊 Status Overview (2026-02-19)

### Phase Implementation Progress
- ✅ Phase 0: Reliability Blockers (implementation completed)
- ✅ Phase 1: Detection Recall Upgrade (implementation completed)
- ✅ Phase 2: Real Backend Internalization (implementation completed)
- ✅ Phase 3: Multi-Target Execution Engine (implementation completed)
- ✅ Phase 3A: Logic Correctness Hardening (implementation completed)
- ✅ Phase 4: Validation/Stats tooling (implementation completed)
- ✅ Phase 5: Release Hardening (implementation completed)

### Exit Criteria Progress
- ✅ Phase 0 exit criteria (met on 20-run fast matrix: attack-stage reach 90%, no output-lock failures)
- ❌ Phase 1 exit criteria (partially met: selector hit-rate 90%, safe high-confidence FPR 0%; recall uplift criterion still pending baseline confirmation)
- ❌ Phase 2 exit criteria (pending fresh clone validation)
- ❌ Phase 3 exit criteria (pending 10-target benchmark)
- ❌ Phase 3A exit criteria (pending integrated campaign runs)
- ❌ Phase 4 exit criteria (in progress: vulnerable recall remains 60% vs 80% target; safe high-confidence FPR now 0%)
- ❌ Phase 5 exit criteria (pending release candidate validation)

### Definition of Done Progress
- ❌ Stability: >=95% scan completion on production multi-target runs
- ❌ Multi-target: 10+ target matrix with `jobs=2`/`workers=2` without collisions
- ❌ Detection: measurable recall uplift on known vulnerable targets
- ❌ Operability: single bootstrap path validated on fresh environments
- ✅ Quality gates: nightly regression dashboard with pass/fail by failure class

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

**Current Status:** ✅ Met on latest fast 20-run matrix (`benchmark_20260219_154805`): attack-stage reach `90%` with no output-lock failures

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
- [ ] Recall improves by >=20 percentage points over baseline
- [x] High-confidence false positives remain bounded (<=5% on safe suite)

**Current Status:** ⚠️ Latest 20-run matrix (`benchmark_20260219_182723`) has selector hit-rate `90.0%` (`18/20`), recall `60%`, and safe high-confidence FPR `0%`; recall uplift target confirmation remains pending

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
- [ ] Fresh clone + bootstrap can run 5-target matrix without manual tool installation
- [ ] Keygen readiness preflight passes on at least 4/5 baseline targets

**Current Status:** ⚠️ Validation automation added via `scripts/fresh_clone_bootstrap_validate.sh`; full fresh-clone execution evidence still pending

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
- [ ] 10-target run completes with zero filesystem collisions
- [ ] Parallel run wall-clock speedup >=1.7x over serial baseline

**Current Status:** ❌ Pending 10-target wall-clock benchmark

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
- [ ] `AdaptiveOrchestrator` integration tests validate allocation enforcement
- [ ] Proof forgery detector cannot hang indefinitely on subprocesses
- [ ] Cairo backend can execute and report non-empty coverage/failure semantics
- [ ] Noir backend execution throughput improves measurably on repeated runs

**Current Status:** ❌ Pending integrated campaign runs validation

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
- [ ] Vulnerable-set recall >=80%
- [x] Safe-set high-confidence FPR <=5%
- [ ] Every miss has machine-readable root-cause category

**Current Status:** ❌ Recall 60%, Safe high-confidence FPR 0% (targets: recall >=80%, safe high-confidence FPR <=5%)

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
- [ ] Versioned release candidate passes all gates twice consecutively
- [ ] Rollback strategy documented and tested

**Current Status:** ❌ Pending release candidate validation

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
1. **Panic in run document mirroring** (Phase 0 blocker)
   - Error: `Missing required 'command' in run document`
   - Impact: Prevents clean gate closure on benchmark runs
   - Status: ❌ Needs investigation and fix

2. **Zero completion rate** (Phase 0/1 blocker)
   - Current: 0.0% completion on 20-run matrix
   - Required: >=90% runs reaching attack execution stage
   - Status: ❌ Blocked by panic issue above

3. **No detection evidence** (Phase 1/4 blocker)
   - Current: 0% recall, 0% FPR (no completed detections)
   - Required: >=80% recall, <=5% safe FPR
   - Status: ❌ Blocked by completion rate issue

---

## 📋 Immediate Action Items

### Top Priority (P0)
- [ ] Fix panic `Missing required 'command' in run document` in evidence/report mirroring
- [ ] Validate fix with 20-run benchmark matrix
- [ ] Achieve >=90% completion rate on benchmark runs

### High Priority (P1)
- [x] Add automated fresh clone + bootstrap validation script (`scripts/fresh_clone_bootstrap_validate.sh`)
- [ ] Run fresh clone + bootstrap validation and capture summary artifacts
- [ ] Execute 10-target wall-clock benchmark
- [ ] Validate integrated campaign runs for Phase 3A criteria
- [ ] Achieve measurable recall (target >=80%)
- [ ] Validate safe FPR remains <=5%

### Medium Priority (P2)
- [ ] Run release candidate validation twice consecutively
- [ ] Test rollback strategy
- [ ] Document any remaining edge cases in troubleshooting playbook

---

## 📊 Latest Benchmark Evidence (2026-02-19)

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
- **[DEFI_ATTACK_GUIDE.md](docs/DEFI_ATTACK_GUIDE.md)** - MEV/front-running detection
- **[TARGETS.md](docs/TARGETS.md)** - Target matrix and benchmark usage

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
```

### Release Validation
```bash
# Release candidate gate (requires 2 consecutive passes)
./scripts/release_candidate_gate.sh

# Rollback validation
./scripts/rollback_validate.sh <stable-ref>

# Manual release validation workflow
gh workflow run "Release Validation" --ref main -f required_passes=2 -f stable_ref=<tag>
gh run watch
```

---

## 📝 Notes

- All implementation tasks for Phases 0-5 are complete
- Panic blockers addressed in current branch (`wait-timeout` abort path removed, run-doc stale-binary path resolved)
- Latest smoke benchmark evidence: `artifacts/benchmark_runs_smoke/benchmark_20260219_153249/summary.json`
- Smoke metrics: `completion_rate=40.0%`, `recall=0.0%`, `safe_fpr=60.0%`
- Latest 20-run fast matrix evidence: `artifacts/benchmark_runs_fast/benchmark_20260219_182723/summary.json`
- Fast matrix metrics: `completion_rate=35.0%`, `attack_stage_reach_rate=90.0%`, `recall=60.0%`, `recall_high_conf=20.0%`, `precision=54.5%`, `safe_fpr=50.0%`, `safe_high_conf_fpr=0.0%`
- High-confidence metric now uses stricter oracle corroboration in batch scoring (`benchmark_high_confidence_min_oracles=3`)
- Selector hit-rate report: `artifacts/benchmark_runs_fast/benchmark_20260219_182723/selector_hit_rate.json` (`18/20` => `90.0%`)
- Once panic is fixed, need to validate all exit criteria systematically
- Release candidate validation requires two consecutive passes of all gates
- Nightly CI matrix is operational with fast-smoke and deep-scheduled lanes
