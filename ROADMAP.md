# ZkPatternFuzz Production Roadmap

Date: 2026-02-17  
Status: Active  
Primary goal: make the scanner production-grade for real multi-target runs with high recall and high runtime stability.

## Latest Progress (2026-02-18)
Completed reliability hardening in Circom backend (`crates/zk-backends/src/circom/mod.rs`):
1. Removed panic-based lock handling in compile/setup/prove/verify/witness paths (poisoned lock now returns `Result` error with context).
2. Replaced several unbounded external command executions with timeout-wrapped execution (`run_with_timeout`) in compile/prove/verify and tool availability checks.
3. Removed panic in output basename derivation by returning structured error instead of `expect`.
4. Improved backend failure diagnostics with richer command-failure context in critical paths.
5. Bounded ptau `curl` download with timeout + explicit command-failure diagnostics (min 300s download timeout).
6. Added batch run reason-code aggregation in `zk0d_batch` from per-template `run_outcome.json` (console scorecard summary + per-template non-success reasons).
7. Added collision-safe automatic scan run-root allocation for parallel scans (atomic reservation under `.scan_run_artifacts`, keeping `scan_runYYYYMMDD_HHMMSS` naming).
8. Added backend preflight hardening for Circom key setup (`circom_require_setup_keys`) and wired scan materialization to enforce key-setup/toolchain readiness up front.
9. Added `zk-fuzzer preflight <campaign.yaml> [--setup-keys]` command for explicit backend/keygen readiness checks.
10. Implemented regex selector policy controls (`selector_policy`) with weighted matching, `k_of_n` thresholds, and optional group-level gates while preserving default behavior (`>=1` match).
11. Added selector-policy regression tests in `src/main.rs` for default compatibility, pass/fail gating, and invalid-policy rejection.
12. Implemented selector synonym bundles (`selector_synonyms` / `synonym_bundles`) with placeholder expansion (`{{bundle}}`) and optional normalization controls (`selector_normalization.synonym_flexible_separators`) for style-tolerant matching.
13. Added selector normalization/synonym regression tests in `src/main.rs` (bundle expansion pass, normalization toggle, unknown-bundle validation).
14. Added `zk-fuzzer bins bootstrap` command to internalize local Circom dependencies under `bins/`:
   - Circom release download from GitHub assets with SHA-256 digest verification.
   - Local `snarkjs` install/link under `bins/node_modules` and `bins/bin`.
   - ptau install from verified local fixture or URL+checksum.
15. Added deterministic ptau autodiscovery precedence in Circom executor (`ZKF_PTAU_PATH` override, local `bins/ptau` first) with regression tests.
16. Added full logic audit report (`LOGIC_AUDIT.md`) with severity-ranked findings and prioritized remediation queue.
17. Fixed adaptive orchestrator budget wiring (`src/fuzzer/adaptive_orchestrator.rs`): scheduler allocations are now enforced through per-attack phase execution instead of being computed and ignored.
18. Fixed adaptive scheduler budget semantics (`src/fuzzer/adaptive_attack_scheduler.rs`): clamped fractions are normalized and rounded with largest-remainder allocation so total allocated time equals requested budget exactly.
19. Added timeout-wrapped external command execution in proof forgery detector (`crates/zk-constraints/src/proof_forgery.rs`) for `snarkjs wtns import`, `groth16 prove`, and `groth16 verify` with kill-on-timeout behavior.
20. Fixed Cairo executor always-fail path (`src/executor/mod.rs`) by using deterministic output-hash coverage fallback when constraint-level coverage is unavailable, plus regression test.
21. Added Noir constraint caching (`src/executor/mod.rs`) via `OnceLock<Vec<ConstraintEquation>>` to avoid repeated disk loads/parsing in `get_constraints` and `check_constraints`.
22. Removed panic fallback in `engagement_dir_name` (`src/main.rs`) and replaced with deterministic sanitized fallback directory naming.
23. Removed panic on invalid `CIRCOM_INCLUDE_PATHS` decoding (`src/executor/mod.rs`) and switched to non-panicking warning + fallback path resolution.
24. Removed runtime `set_var` in Circom execution path by switching to command-local PATH injection in backend command builders (`crates/zk-backends/src/circom/mod.rs`) and dropping runtime env mutation in CLI timeout alignment (`src/main.rs`).
25. Hardened Circom external-timeout env parsing to warn-and-fallback defaults instead of panicking on invalid values.
26. Added `zk0d_matrix` multi-target runner (`src/bin/zk0d_matrix.rs`) with `jobs`/`batch-jobs`/`workers` guardrails, parallel target execution, and per-target reason-code aggregation from `zk0d_batch --emit-reason-tsv`.
27. Added default matrix config template (`targets/zk0d_matrix.yaml`) and target-matrix usage docs (`docs/TARGETS.md`).
28. Added retry-on-transient-setup policy in `zk0d_batch` (`src/bin/zk0d_batch.rs`) with one retry and configurable backoff (`--retry-transient-setup`, `--retry-backoff-secs`), keyed by stable reason-code classification.
29. Completed repeated-trial benchmark harness for vulnerable/safe suites (`src/bin/zk0d_benchmark.rs`, `targets/benchmark_suites.yaml`): env-aware path expansion, non-dropped failed trials, recall/precision/safe-FPR metrics with 95% Wilson confidence intervals, and benchmark run docs in `docs/TARGETS.md`.
30. Added CI benchmark regression gates (`.github/workflows/ci.yml`, `scripts/ci_benchmark_gate.sh`) using `zk0d_benchmark` summary metrics with explicit thresholds for completion/recall/precision/safe-FPR and artifact upload of benchmark outputs.
31. Added explicit environment config separation for dev/prod benchmark and batch runs:
   - `zk0d_batch --config-profile <dev|prod>` registry defaults (`targets/fuzzer_registry.dev.yaml`, `targets/fuzzer_registry.prod.yaml`)
   - `zk0d_benchmark --config-profile <dev|prod>` suites/registry defaults (`targets/benchmark_suites.{dev,prod}.yaml`, `targets/benchmark_registry.{dev,prod}.yaml`)
   - Dev profile wired as CI default for fast/stable regression gating.
32. Hardened ptau validation to reject truncated/corrupt files by size + header in Circom backend (`crates/zk-backends/src/circom/mod.rs`), preventing false-valid 263-byte ptau cache entries from causing repeated keygen failures.

Validation:
1. `cargo check -p zk-backends` passed.
2. `cargo test -p zk-backends circom::tests:: -- --test-threads=1` passed.
3. Note: existing unrelated failure remains in `halo2::tests::test_halo2_execute_metadata_only_spec_returns_public_projection`.
4. `cargo check` passed.
5. `cargo test -q adaptive_attack_scheduler::tests::test_budget_allocation -- --test-threads=1` passed.
6. `cargo test -q adaptive_orchestrator::tests:: -- --test-threads=1` passed.
7. `cargo test -q -p zk-constraints proof_forgery::tests:: -- --test-threads=1` passed.
8. `cargo test -q test_coverage_fallback_uses_output_hash_when_constraints_missing -- --test-threads=1` passed.
9. `cargo test -q test_execution_result -- --test-threads=1` passed after executor/main hardening changes.
10. `cargo check -q -p zk-backends -p zk-constraints` passed.
11. `cargo check -q --bin zk0d_matrix` passed.
12. `cargo test -q --bin zk0d_matrix -- --test-threads=1` passed.
13. `cargo run --quiet --bin zk0d_matrix -- --dry-run --jobs 1 --batch-jobs 1 --workers 1` smoke run passed.
14. `cargo check -q --bin zk0d_batch` passed.
15. `cargo test -q --bin zk0d_batch -- --test-threads=1` passed.
16. `cargo check -q --bin zk0d_benchmark` passed.
17. `cargo test -q --bin zk0d_benchmark -- --test-threads=1` passed.
18. `cargo run --quiet --bin zk0d_benchmark -- --dry-run --trials 1 --jobs 1 --batch-jobs 1 --workers 1` smoke run passed.
19. Real non-dry benchmark run executed (`jobs=2`, `batch_jobs=1`, `workers=2`, `iterations=10000`, `timeout=900`) with `CIRCOM_INCLUDE_PATHS=third_party:node_modules`; outcome saved at `artifacts/benchmark_runs/benchmark_20260218_130428/summary.json`.
20. Local gate check run (`./scripts/ci_benchmark_gate.sh`) failed as expected on current baseline: completion=0.0%, recall=0.0%, precision=0.0% (safe FPR=0.0%).
21. Profile validation commands passed:
    - `cargo run --quiet --bin zk0d_batch -- --config-profile dev --list-catalog`
    - `cargo run --quiet --bin zk0d_batch -- --config-profile prod --list-catalog`
    - `cargo run --quiet --bin zk0d_benchmark -- --config-profile dev --dry-run --trials 1 --jobs 1 --batch-jobs 1 --workers 1`
    - `cargo run --quiet --bin zk0d_benchmark -- --config-profile prod --dry-run --trials 1 --jobs 1 --batch-jobs 1 --workers 1`

## Audit Intake (2026-02-18)
Source: `LOGIC_AUDIT.md` (13 findings total: High=3, Medium=5, Low=3, Info=2).

P0 (must-fix before broader tuning) — Completed:
1. Wire adaptive scheduler allocations into engine execution (`H-2`).
2. Add timeout-wrapped external command execution in proof forgery detector (`H-3`).

P1 (next correctness/stability wave) — Completed:
1. Normalize adaptive budget allocations to exact total budget (`H-1`).
2. Fix Cairo executor always-fail coverage path (`M-3`).
3. Cache Noir constraints to avoid per-exec disk reloads (`M-4`).
4. Remove runtime `std::env::set_var` hazards in multi-threaded paths (`M-2`).

P2/P3 (defensive + maintainability):
1. Remove panic fallback in `engagement_dir_name` and env parsing panic paths (`M-1`, `L-2`).
2. Improve zero-day confirmation matching from category-only to content-aware (`L-3`).
3. Document/contain dynamic log file routing edge window (`M-5`).
4. CLI modularization and run lifecycle deduplication (`I-1`, `I-2`).

## Product Principles
1. YAML-first scanning remains the primary interface.
2. Pattern matching is target-agnostic and regex-driven, not tied to exact CVE strings.
3. Real backend execution is required for evidence (`circom` and other supported frameworks).
4. Report/output schemas and output roots remain stable unless explicitly approved.
5. Recall-first tuning is allowed in scan mode (slightly higher low-confidence false positives to reduce misses).

## Baseline Snapshot (from recent real runs)
Source: `artifacts/real_runs_20260217_231138_elev/`
1. Selector matching works on most targets (4/5 had non-zero regex hits).
2. Findings are still 0/5 in this matrix.
3. 3/5 runs failed early due output lock contention on shared `/home/teycir/ZkFuzz`.
4. Remaining runs hit key setup failure and then timed out before first attack execution.

## Definition Of Done (Production Grade)
1. Stability: >=95% scan completion rate on multi-target batch runs.
2. Multi-target: 10+ target matrix with `jobs=2` and `--workers 2` runs without lock collisions.
3. Detection: measurable recall uplift on known vulnerable targets, with controlled low-confidence FPR.
4. Operability: single bootstrap path for required binaries and ptau assets.
5. Quality gates: nightly regression dashboard with pass/fail by failure class.

## Phase 0: Reliability Blockers (P0, 1 week)
Goal: stop easy breakage before tuning detection quality.

Implementation:
1. Add per-run output root isolation for parallel scans by default in batch mode.
2. Classify run outcomes explicitly (`completed`, `locked_output`, `keygen_failed`, `timeout_pre_attack`, `pattern_miss`).
3. Add preflight for toolchain/keygen readiness and fail fast with actionable reason.
4. Preserve output schema while adding stable reason codes in summary metadata.

Exit Criteria:
1. 20-run matrix on 5 local targets has 0 output-lock failures.
2. >=90% runs reach attack execution stage (not blocked in setup).

## Phase 1: Detection Recall Upgrade (P0/P1, 1-2 weeks)
Goal: reduce missed true positives while keeping YAML workflow.

Implementation:
1. Extend YAML selector semantics with weighted regex groups and `k-of-n` matching.
2. Add lexical normalization before regex matching (case/style/token normalization).
3. Support optional synonym bundles per pattern family.
4. Keep current recall bias defaults, but make them profile-controlled and auditable in logs.
5. Keep summary output focused on matched pattern IDs and frequency counts.

Exit Criteria:
1. Selector hit-rate >=90% on intended target set.
2. Recall improves by >=20 percentage points over current baseline on known vulnerable matrix.
3. High-confidence false positives remain bounded (target <=5% on safe suite).

## Phase 2: Real Backend Internalization (P0/P1, 1-2 weeks)
Goal: avoid environment fragility across circuits.

Implementation:
1. Add `bins bootstrap` command for circom/snarkjs/ptau acquisition with checksum verification.
2. Standardize include-path and binary-path resolution to local `bins/` first.
3. Add ptau discovery policy with deterministic precedence and clear warnings.
4. Ensure local binary assets remain untracked by git (already enforced via `.gitignore`).

Exit Criteria:
1. Fresh clone + bootstrap can run 5-target matrix without manual tool installation.
2. Keygen readiness preflight passes on at least 4/5 baseline targets.

## Phase 3: Multi-Target Execution Engine (P1, 2 weeks)
Goal: make large real-world test campaigns predictable and parallel-safe.

Implementation:
1. Build matrix runner for target lists (`/media/elements/Repos/zk0d`) with bounded parallelism.
2. Separate process parallelism (`jobs`) from scan worker parallelism (`--workers`) with guardrails.
3. Emit per-target outcome table and aggregate campaign scorecard.

Exit Criteria:
1. 10-target run completes with zero filesystem collisions.
2. Parallel run wall-clock speedup >=1.7x over serial baseline.

## Phase 3A: Logic Correctness Hardening (P0/P1, 1 week)
Goal: close audit-confirmed semantic bugs before scaling campaign volume.

Implementation:
1. Make adaptive orchestrator actually enforce scheduler allocations per attack phase.
2. Add hard timeout wrappers to proof forgery `snarkjs` subprocesses.
3. Normalize allocation fractions post-clamp so sums match total budget exactly.
4. Fix Cairo execution fallback/coverage behavior so non-empty execution paths are possible.
5. Cache Noir constraints (OnceLock) to remove repeated disk parse overhead.
6. Replace runtime global env mutation paths (`set_var`) with startup-time/static configuration.

Exit Criteria:
1. `AdaptiveOrchestrator` integration tests validate allocation enforcement.
2. Proof forgery detector cannot hang indefinitely on subprocesses.
3. Cairo backend can execute and report non-empty coverage/failure semantics deterministically.
4. Noir backend execution throughput improves measurably on repeated runs.

## Phase 4: Validation And Statistical Confidence (P1, 2 weeks)
Goal: prove detection quality with statistically meaningful results.

Implementation:
1. Curate vulnerable matrix (minimum 5 known vulnerable targets) and safe matrix (minimum 5 clean targets).
2. Run repeated trials with fixed seeds and report confidence intervals for recall/precision.
3. Add regression gates that fail on recall regression or stability regression.
4. Publish detection reasons for misses (`pattern_miss`, `keygen_failed`, `timeout_pre_attack`, `no_violation_found`).

Exit Criteria:
1. Vulnerable-set recall >=80%.
2. Safe-set high-confidence FPR <=5%.
3. Every miss has machine-readable root-cause category.

## Phase 5: Release Hardening (P2, 1 week)
Goal: production operations and predictable upgrades.

Implementation:
1. Add release checklist (toolchain, regression matrix, docs, migration notes).
2. Freeze public scan/report contract and add compatibility tests.
3. Add troubleshooting playbook for keygen, includes, lock contention, and timeout tuning.
4. Add nightly CI matrix (fast smoke + deep scheduled).

Exit Criteria:
1. Versioned release candidate passes all gates twice consecutively.
2. Rollback strategy documented and tested.

## Execution Backlog (Immediate Top 12)
1. Add CI gates for stability/recall regression using `zk0d_benchmark` summary metrics.
2. Add nightly benchmark trend artifacts (completion, recall, precision, safe FPR) and regression alerts.
