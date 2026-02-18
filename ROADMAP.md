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

Validation:
1. `cargo check -p zk-backends` passed.
2. `cargo test -p zk-backends circom::tests:: -- --test-threads=1` passed.
3. Note: existing unrelated failure remains in `halo2::tests::test_halo2_execute_metadata_only_spec_returns_public_projection`.

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
3. Add retry policy for transient setup failures (single retry with backoff).
4. Emit per-target outcome table and aggregate campaign scorecard.

Exit Criteria:
1. 10-target run completes with zero filesystem collisions.
2. Parallel run wall-clock speedup >=1.7x over serial baseline.

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

## Execution Backlog (Immediate Top 10)
1. Extend batch reason-code aggregation into external real-run TSV harness (without changing report schema).
2. Add matrix runner for zk0d target lists with `jobs` + `workers` guardrails.
3. Add retry-on-transient-setup policy.
4. Add vulnerable/safe benchmark suites with repeated-trial harness.
5. Add CI gates for stability and recall regression.
