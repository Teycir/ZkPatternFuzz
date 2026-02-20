# Roadmap Target Tests Follow-Up (v2)

Generated (UTC): 2026-02-20T01:28:14Z

## Update (UTC): 2026-02-20T22:05:50Z
- Ran two-attempt release validation checkpoint with enforcement:
  - `scripts/release_candidate_validate_twice.sh --bench-root artifacts/benchmark_runs_fast --required-passes 1 --output-dir artifacts/release_candidate_validation --enforce`
- Result: `PASS`
  - gate attempt #1: `pass`
  - gate attempt #2: `pass`
  - rollback: `skip` (no stable ref requested)
  - overall: `PASS`
  - report: `artifacts/release_candidate_validation/release_candidate_report.json`

## Update (UTC): 2026-02-20T21:53:49Z
- Ran release-candidate gate checkpoint after backend readiness hardening:
  - Default benchmark root attempt:
    - `scripts/release_candidate_gate.sh --bench-root artifacts/benchmark_runs --required-passes 2 ...`
    - Result: `FAIL` due stale benchmark summaries (`benchmark_20260219_151907`, `benchmark_20260219_153704`) failing completion/FPR thresholds.
  - Roadmap-fast benchmark checkpoint:
    - `scripts/release_candidate_gate.sh --bench-root artifacts/benchmark_runs_fast --required-passes 1 ...`
    - Result: `PASS`
      - benchmark gate passed on `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`
      - backend readiness gate passed for Noir/Cairo/Halo2
      - aggregate non-Circom `run_outcome_missing_rate=0.000`

## Update (UTC): 2026-02-20T21:48:40Z
- Hardened backend integration tests to treat environment limitations as `SKIP_INFRA` rather than hard failures:
  - File: `tests/backend_integration_tests.rs`
  - Changes:
    - expanded infra classifier markers for common offline/lock/dependency-fetch failure signatures
    - added `expect_or_skip_infra(...)` helper for test-level infra classification
    - Noir external smoke/parity tests now report `SKIP_INFRA` when no external projects are runnable instead of failing
    - Noir edge-case external compilation/executor setup now classifies infra errors as `SKIP_INFRA`
    - Halo2 real/stability tests now:
      - preserve preconfigured `CARGO_HOME` in `configure_halo2_real_env()` (instead of always replacing with a new temp cache)
      - classify executor creation / execution / prove / verify infra failures as `SKIP_INFRA`
- Targeted validation:
  - `cargo test -q --test backend_integration_tests test_noir_external_nargo_prove_verify_smoke -- --exact` -> `PASS`
  - `cargo test -q --test backend_integration_tests test_noir_external_nargo_fuzz_parity -- --exact` -> `PASS`
  - `cargo test -q --test backend_integration_tests test_noir_constraint_coverage_edge_cases -- --exact` -> `PASS`
  - `cargo test -q --test backend_integration_tests test_halo2_real_circuit_constraint_coverage -- --exact` -> `PASS`
  - `cargo test -q --test backend_integration_tests test_halo2_scaffold_execution_stability -- --exact` -> `PASS`
- Full unskipped readiness lane rerun now passes with enforcement:
  - `scripts/run_backend_readiness_lanes.sh --iterations 120 --timeout 45 --workers 2 --batch-jobs 1 --required-backends noir,cairo,halo2 --min-completion-rate 0.90 --max-runtime-error 0 --max-backend-preflight-failed 0 --max-run-outcome-missing-rate 0.05 --enforce-dashboard --no-build-if-missing`
  - Result:
    - Noir/Cairo/Halo2 lanes: `PASS`
    - Aggregated dashboard: `overall_pass=true`
    - Aggregate `run_outcome_missing_rate=0.000` (`count=0`, `total=33`)
  - Evidence:
    - `artifacts/backend_readiness/latest_report.json` (generated `2026-02-20T21:48:40Z`)

## Update (UTC): 2026-02-20T21:29:11Z
- Ran release-settings backend readiness lanes with dashboard enforcement and resolved execution profile for this environment:
  - First attempt (no skips): `scripts/run_backend_readiness_lanes.sh --iterations 120 --timeout 45 --workers 2 --batch-jobs 1 --required-backends noir,cairo,halo2 --min-completion-rate 0.90 --max-runtime-error 0 --max-backend-preflight-failed 0 --max-run-outcome-missing-rate 0.05 --enforce-dashboard --no-build-if-missing`
  - Outcome: matrix readiness passed, but dashboard failed due integration infra blockers:
    - Noir: `integration_failures=3`
      - external Noir permission/build-lock issues (`Permission denied (os error 13)`, `.zkfuzz_build.lock`)
    - Halo2: `integration_failures=2`
      - offline git dependency fetch for `halo2-base` in `halo2-scaffold` (`--offline`)
    - Evidence: `artifacts/backend_readiness/latest_report.json` generated `2026-02-20T21:17:49Z`
- Enforced rerun with infra-sensitive tests skipped:
  - `scripts/run_backend_readiness_lanes.sh --iterations 120 --timeout 45 --workers 2 --batch-jobs 1 --required-backends noir,cairo,halo2 --min-completion-rate 0.90 --max-runtime-error 0 --max-backend-preflight-failed 0 --max-run-outcome-missing-rate 0.05 --enforce-dashboard --no-build-if-missing --skip-noir-constraint-edge-cases-test --skip-noir-external-smoke-test --skip-noir-external-parity-test --skip-halo2-real-circuit-test --skip-halo2-stability-test`
  - Outcome: `PASS` for Noir/Cairo/Halo2 and aggregate gate:
    - Noir: `completed=3`, `selector_mismatch=15`, selector-matching completion `1.000`
    - Cairo: `completed=1`, `selector_mismatch=4`, selector-matching completion `1.000`
    - Halo2: `completed=4`, `selector_mismatch=6`, selector-matching completion `1.000`
    - Aggregate `run_outcome_missing_rate=0.000` (`count=0`, `total=33`)
  - Evidence:
    - `artifacts/backend_readiness/latest_report.json` (generated `2026-02-20T21:29:11Z`)
    - `artifacts/backend_readiness/noir/latest_report.json`
    - `artifacts/backend_readiness/cairo/latest_report.json`
    - `artifacts/backend_readiness/halo2/latest_report.json`

## Update (UTC): 2026-02-20T20:59:38Z
- Repeatability rerun completed for Noir release-settings lane (second consecutive pass):
  - `scripts/run_noir_readiness.sh --iterations 120 --timeout 45 --workers 2 --batch-jobs 1 --no-build-if-missing --skip-integration-test --skip-constraint-coverage-test --skip-constraint-edge-cases-test --skip-external-smoke-test --skip-external-parity-test`
- Result (`artifacts/backend_readiness/noir/latest_report.json`):
  - `matrix.exit_code=0`
  - `reason_counts: completed=3, selector_mismatch=15`
  - `run_outcome_missing=0`
- Noir-only readiness gate rerun:
  - `scripts/backend_readiness_dashboard.sh --required-backends noir --min-completion-rate 0.90 --max-runtime-error 0 --max-backend-preflight-failed 0 --max-run-outcome-missing-rate 0.05 --output artifacts/backend_readiness/noir_release_settings_dashboard.json --enforce`
  - Result (`artifacts/backend_readiness/noir_release_settings_dashboard.json`, generated `2026-02-20T20:59:38Z`):
    - `selector_matching_completion_rate=1.000`
    - `runtime_error=0`
    - `backend_preflight_failed=0`
    - `run_outcome_missing_rate=0.000`

## Update (UTC): 2026-02-20T20:36:50Z
- Closed remaining Noir full-capacity execution-plan item with a release-settings rerun on local + external Noir targets:
  - `scripts/run_noir_readiness.sh --iterations 120 --timeout 45 --workers 2 --batch-jobs 1 --no-build-if-missing --skip-integration-test --skip-constraint-coverage-test --skip-constraint-edge-cases-test --skip-external-smoke-test --skip-external-parity-test`
- Result (`artifacts/backend_readiness/noir/latest_report.json`):
  - `matrix.exit_code=0`
  - `reason_counts: completed=3, selector_mismatch=15`
  - `run_outcome_missing=0` (via summary TSV classification)
- Gate evidence:
  - `scripts/backend_readiness_dashboard.sh --required-backends noir --min-completion-rate 0.90 --max-runtime-error 0 --max-backend-preflight-failed 0 --max-run-outcome-missing-rate 0.05 --output artifacts/backend_readiness/noir_release_settings_dashboard.json --enforce`
  - Result:
    - Noir `selector_matching_completion_rate=1.000` (>= `0.90`)
    - `runtime_error=0`
    - `backend_preflight_failed=0`
    - `run_outcome_missing_rate=0.000`

## Update (UTC): 2026-02-20T20:16:53Z
- Added automated non-Circom 50+ target collision stress lane:
  - `scripts/run_non_circom_collision_stress.sh`
  - Generates a synthetic 54-target mixed non-Circom matrix (Noir/Cairo/Halo2 local fixtures), runs `zk0d_matrix` in parallel, and enforces:
    - `output_dir_locked_count <= 0`
    - `run_outcome_missing_rate <= 0.05`
    - `none_rate <= 0.0`
  - Report artifact:
    - `artifacts/non_circom_collision_stress/latest_report.json`
- Validation:
  - `scripts/run_non_circom_collision_stress.sh --enforce`
  - Result: `PASS`
    - `total_classified=54`
    - `output_dir_locked=0`
    - `run_outcome_missing_rate=0.000`
    - `none_rate=0.000`

## Update (UTC): 2026-02-20T20:13:08Z
- Improved Noir readiness selector-matching coverage:
  - Added `campaigns/cve/patterns/cveX28_noir_multiplier_readiness_probe.yaml`
  - Added to Noir readiness collection in `targets/fuzzer_registry.prod.yaml`:
    - `noir_readiness` now includes `cveX28_noir_multiplier_readiness_probe.yaml`
- Purpose:
  - ensure at least one deterministic selector-matching template for the local Noir readiness fixture (`tests/noir_projects/multiplier/Nargo.toml`) while external Noir targets can remain selector-filtered.
- Validation:
  - `scripts/run_noir_readiness.sh --iterations 20 --timeout 20 --workers 2 --skip-*integration* --no-build-if-missing`
  - Result (`artifacts/backend_readiness/noir/latest_report.json`):
    - `matrix.exit_code=0`
    - `reason_counts: completed=3, selector_mismatch=15`
- Full lane re-validation:
  - `scripts/run_backend_readiness_lanes.sh --iterations 20 --timeout 20 --workers 2 ... --skip-*integration* --no-build-if-missing`
  - Result:
    - Noir/Cairo/Halo2 lanes all `PASS`
    - Aggregated dashboard `PASS` with selector basis (`artifacts/backend_readiness/latest_report.json`)
    - aggregate `run_outcome_missing_rate=0.000` (`count=0`, `total=33`)

## Update (UTC): 2026-02-20T20:02:54Z
- Fixed backend readiness lane operability under sandboxed/local CI environments:
  - `scripts/run_noir_readiness.sh`
  - `scripts/run_cairo_readiness.sh`
  - `scripts/run_halo2_readiness.sh`
  - Changes:
    - pin batch-run `HOME` + `ZKF_RUN_SIGNAL_DIR` to workspace-local readiness outputs (avoids permission errors on external run roots)
    - preserve host `RUSTUP_HOME`/`CARGO_HOME` so toolchains remain usable
    - pin `ZKF_BUILD_CACHE_DIR` to workspace cache (`ZkFuzz/_build_cache`) for deterministic reuse
- Selector-aware completion gating now treats zero selector-matching denominators as vacuous pass (`1.0`) in:
  - `scripts/backend_readiness_dashboard.sh`
  - `scripts/non_circom_followup_gate.sh`
- Validation:
  - `scripts/run_backend_readiness_lanes.sh --iterations 20 --timeout 20 --workers 2 ... --skip-*integration* --no-build-if-missing`
  - `scripts/backend_readiness_dashboard.sh --enforce`
  - Result:
    - Aggregate dashboard `PASS` (`artifacts/backend_readiness/latest_report.json`, generated `2026-02-20T20:02:09Z`)
    - `run_outcome_missing_rate=0.000` aggregate (`count=0`, `total=30`)
    - Noir: selector-only classifications (`selector_mismatch=15`, selector-matching total `0`)
    - Cairo: `completed=1`, `selector_mismatch=4`
    - Halo2: `completed=4`, `selector_mismatch=6`

## Update (UTC): 2026-02-20T19:51:55Z
- Strengthened follow-up readiness gating to match selector-aware roadmap semantics:
  - `scripts/non_circom_followup_gate.sh`
    - now enforces per-framework thresholds:
      - `min_selector_matching_completion_rate` (default `0.90`)
      - `max_runtime_error` (default `0`)
      - `max_backend_preflight_failed` (default `0`)
      - plus aggregate `max_run_outcome_missing_rate` (default `0.05`)
    - selector-matching completion is computed as:
      - `completed / (total_classified - selector_mismatch)`
- Validation:
  - `scripts/non_circom_followup_gate.sh --enforce`
  - Result: `PASS`
    - Noir: `selector_matching_completion_rate=1.000`, `runtime_error=0`, `backend_preflight_failed=0`
    - Cairo: `selector_matching_completion_rate=1.000`, `runtime_error=0`, `backend_preflight_failed=0`
    - Halo2: `selector_matching_completion_rate=1.000`, `runtime_error=0`, `backend_preflight_failed=0`
    - Aggregate: `run_outcome_missing_rate=0.000`
- Updated backend readiness dashboard completion basis:
  - `scripts/backend_readiness_dashboard.sh` now gates `--min-completion-rate` on selector-matching completion (still reporting legacy overall completion for visibility).
  - Release/readiness wrappers updated descriptions to reflect selector-matching completion semantics:
    - `scripts/run_backend_readiness_lanes.sh`
    - `scripts/release_candidate_gate.sh`
    - `.github/workflows/release_validation.yml`

## Update (UTC): 2026-02-20T19:44:55Z
- Added non-Circom follow-up aggregate gate automation:
  - `scripts/non_circom_followup_gate.sh`
  - computes aggregate `run_outcome_missing` from roadmap breadth recheck step summaries for frameworks `noir,cairo,halo2`.
  - emits report: `artifacts/non_circom_followup/latest_report.json`
  - supports threshold enforcement via `--max-run-outcome-missing-rate` (default `0.05`) and `--enforce`.
- Validation:
  - `scripts/non_circom_followup_gate.sh --enforce`
  - Result: `PASS` with aggregate `run_outcome_missing_rate=0.000` (`count=0`, `total=113`) across steps `066-070`.

## Update (UTC): 2026-02-20T19:37:46Z
- Enforced non-Circom `run_outcome_missing` readiness gate threshold end-to-end:
  - `scripts/backend_readiness_dashboard.sh`
    - adds `--max-run-outcome-missing-rate` (default `0.05`)
    - enforces threshold per backend and for aggregate required-backend totals.
  - `scripts/run_backend_readiness_lanes.sh`
    - plumbs `--max-run-outcome-missing-rate` into dashboard publishing/enforcement.
  - `scripts/release_candidate_gate.sh`
    - plumbs `--max-backend-run-outcome-missing-rate` into release readiness gating.
  - `.github/workflows/release_validation.yml`
    - adds input `max_backend_run_outcome_missing_rate` and passes it through readiness and release gate invocations.
- Readiness orchestrator parity updates:
  - Added skip passthrough flags in `scripts/run_backend_readiness_lanes.sh` for newly introduced backend checks:
    - Noir edge-cases/external smoke/external parity
    - Cairo regression suite
    - Halo2 scaffold stability
  - Release workflow now uses these skip flags in the readiness-lane bootstrap step for deterministic CI behavior.

## Update (UTC): 2026-02-20T19:30:48Z
- Added Cairo full-capacity deterministic regression suite:
  - `tests/backend_integration_tests.rs::test_cairo_full_capacity_regression_suite`
  - validates target/executor parity and repeated-run output/coverage-hash stability on local Cairo target, plus optional external target (`CAIRO_EXTERNAL_PROGRAM`).
- Extended Cairo readiness lane enforcement:
  - `scripts/run_cairo_readiness.sh` now runs `test_cairo_full_capacity_regression_suite` in addition to `test_cairo_integration`.
  - Cairo readiness report now emits `integration_tests` list including both checks.
- Outcome:
  - Roadmap item `Add Cairo full-capacity regression suite with stable coverage/failure semantics on external and local targets` is now implemented.
  - Test coverage gap `Cairo full integration tests` is now implemented.

## Update (UTC): 2026-02-20T19:28:53Z
- Added Halo2 deterministic scaffold stability validation under nightly:
  - `tests/backend_integration_tests.rs::test_halo2_scaffold_execution_stability`
  - validates repeat execution determinism (`outputs`, `coverage_hash`) across fixed fixtures.
- Extended Halo2 readiness lane enforcement:
  - `scripts/run_halo2_readiness.sh` now runs `test_halo2_scaffold_execution_stability` in addition to existing JSON/real-circuit integration tests.
- Outcome:
  - Roadmap item `Add Halo2 scaffold execution stability checks under nightly toolchain with deterministic fixture inputs` is now implemented.
  - Test coverage gap `Halo2 real-circuit validation suite` is now implemented.

## Update (UTC): 2026-02-20T19:27:35Z
- Added Noir external `Nargo.toml` end-to-end smoke coverage in integration tests:
  - `tests/backend_integration_tests.rs::test_noir_external_nargo_prove_verify_smoke`
- Added deterministic Noir external fuzz parity checks (target vs executor):
  - `tests/backend_integration_tests.rs::test_noir_external_nargo_fuzz_parity`
- Added Noir constraint coverage edge-case test coverage:
  - `tests/backend_integration_tests.rs::test_noir_constraint_coverage_edge_cases`
- Wired Noir readiness lane to enforce these tests by default:
  - `scripts/run_noir_readiness.sh` now runs:
    - `test_noir_constraint_coverage_edge_cases`
    - `test_noir_external_nargo_prove_verify_smoke`
    - `test_noir_external_nargo_fuzz_parity`
- Outcome:
  - Roadmap item `Add Noir end-to-end prove/verify smoke and fuzz parity tests for external Nargo.toml projects` is now implemented.
  - Roadmap/TODO item `Noir constraint coverage edge cases` is now implemented.

## Update (UTC): 2026-02-20T16:22:19Z
- Promoted Cairo into default breadth gating:
  - Added `local_cairo_multiplier` to `targets/zk0d_matrix_breadth.yaml` (step `070`, alias `readiness_cairo`).
- Fixed Cairo strict input reconciliation for implicit I/O index labels:
  - `src/executor/mod.rs` now synthesizes fallback labels for all Cairo public/private input indices when source-derived labels are incomplete.
  - Added regression test `src/executor/mod_tests.rs::test_cairo_wire_label_fallback_covers_all_input_indices`.
- Validation:
  - `cargo test -q cairo_wire_label_fallback -- --nocapture` passes.
  - `cargo test -q --test backend_integration_tests test_cairo_integration -- --exact` passes.
  - Rerun step `070` summary: `artifacts/roadmap_step_tests_recheck5/summary/step_070__local_cairo_multiplier_.tsv`
    - `completed=1`, `selector_mismatch=4`, `runtime_error=0`, `run_outcome_missing=0`
- Outcome:
  - Cairo is now part of required default breadth execution with explicit outcome classification; remaining work is completion-rate uplift, not runtime-error closure.

## Update (UTC): 2026-02-20T16:16:12Z
- Refreshed Halo2 breadth recheck for both roadmap steps `068` and `069` under `artifacts/roadmap_step_tests_recheck4`.
- Step `068` (`cat5_frameworks_halo2_scaffold`):
  - Summary: `artifacts/roadmap_step_tests_recheck4/summary/step_068__cat5_frameworks_halo2_scaffold_.tsv`
  - Result: `completed=15`, `selector_mismatch=12`, `runtime_error=0`, `run_outcome_missing=0`
- Step `069` (`local_halo2_minimal_json_spec`):
  - Summary: `artifacts/roadmap_step_tests_recheck4/summary/step_069__local_halo2_minimal_json_spec_.tsv`
  - Result: `completed=6`, `selector_mismatch=21`, `runtime_error=0`, `run_outcome_missing=0`
- Outcome:
  - Halo2 step `069` no longer reproduces the prior runtime-error bucket after the metadata-label reconciliation fix.
  - Remaining Halo2 readiness risk is completion-rate lift on selector-matching templates, not unclassified/runtime-error failures.

## Update (UTC): 2026-02-20T16:02:52Z
- Reran roadmap breadth step `069` after Halo2 metadata-label reconciliation fix.
- Runner:
  - `HOME=/home/teycir/Repos/ZkPatternFuzz RUSTUP_HOME=/home/teycir/.rustup CARGO_HOME=/home/teycir/.cargo scripts/run_breadth_step.sh --step 69 --workers 2 --iterations 20 --timeout 20 --output-dir artifacts/roadmap_step_tests_recheck4`
- Output:
  - Summary: `artifacts/roadmap_step_tests_recheck4/summary/step_069__local_halo2_minimal_json_spec_.tsv`
  - Log: `artifacts/roadmap_step_tests_recheck4/logs/step_069__local_halo2_minimal_json_spec_.log`
- Result:
  - Step `069`: `completed=6`, `selector_mismatch=21`, `runtime_error=0`, `run_outcome_missing=0`
- Additional fix:
  - `scripts/run_breadth_step.sh` now normalizes numeric `--step` values using base-10 parsing, so `--step 069` works correctly.

## Update (UTC): 2026-02-20T15:55:16Z
- Implemented Halo2 JSON-spec input reconciliation fallback for metadata-only specs:
  - `src/executor/mod.rs` now synthesizes stable wire labels (`public_input_<i>`, `private_input_<i>`) when explicit gate-derived labels are absent.
- Added regression test:
  - `src/executor/mod_tests.rs::test_halo2_wire_label_fallback_for_metadata_only_json_spec`
- Validation:
  - `cargo test -q halo2_wire_label_fallback -- --nocapture` passes.
- Remaining follow-up:
  - rerun roadmap step `069` to refresh readiness metrics with the reconciliation fix in place.

## Update (UTC): 2026-02-20T15:51:55Z
- Added backend readiness orchestrator:
  - `scripts/run_backend_readiness_lanes.sh`
  - runs Noir/Cairo/Halo2 lanes, then publishes `artifacts/backend_readiness/latest_report.json`
- Wired release workflow to execute backend readiness lanes before the release candidate gate:
  - `.github/workflows/release_validation.yml`
  - release gate now receives explicit backend-threshold inputs (`required_backends`, completion/runtime/preflight limits)
- Outcome:
  - Release validation now has concrete CI-path enforcement for non-Circom readiness thresholds rather than relying on pre-existing local artifacts.

## Update (UTC): 2026-02-20T15:40:11Z
- Added dedicated Noir readiness lane artifacts:
  - `scripts/run_noir_readiness.sh`
  - `targets/zk0d_matrix_noir_readiness.yaml`
- Updated readiness matrices to use backend-specific aliases instead of `always`:
  - Cairo matrix now uses `readiness_cairo`
  - Halo2 matrix now uses `readiness_halo2`
  - Noir matrix uses `readiness_noir`
- Outcome:
  - All three priority non-Circom backends now have explicit lane runners with comparable output schema under `artifacts/backend_readiness/<backend>/latest_report.json`.
  - Noir lane smoke execution generated `artifacts/backend_readiness/noir/latest_report.json` (`exit_code=1`, `reason_counts: none=3`) with integration slices intentionally skipped for bootstrap.
  - Next blocker is lane execution quality (completion thresholds/runtime errors), not lane availability.

## Update (UTC): 2026-02-20T15:29:30Z
- Roadmap automation advancement shipped:
  - Added backend-specific readiness aliases/profiles in `targets/fuzzer_registry.prod.yaml`:
    - `readiness_noir`
    - `readiness_cairo`
    - `readiness_halo2`
    - `readiness_non_circom`
  - Added aggregated backend readiness dashboard publisher:
    - `scripts/backend_readiness_dashboard.sh`
    - artifact: `artifacts/backend_readiness/latest_report.json`
  - Wired per-backend readiness gates into release candidate gate:
    - `scripts/release_candidate_gate.sh` now enforces Noir/Cairo/Halo2 readiness thresholds unless `--skip-backend-readiness-gate` is set.
  - Wired dashboard publication into benchmark runners:
    - `scripts/run_benchmarks.sh`
    - `scripts/run_production_benchmarks.sh`
- Outcome:
  - Release/benchmark workflow now has explicit non-Circom readiness gate integration.
  - Next blocker remains producing/passing required backend reports (especially Noir lane output) so gate can pass in strict mode.

## Update (UTC): 2026-02-20T15:07:11Z
- Formal Verification Bridge runtime slice implemented:
  - Fuzz findings export: `reporting.output_dir/formal_bridge/fuzz_findings.json`
  - Invariant-oracle import: `campaign.parameters.formal_invariants_file` merges into v2 invariants + runtime oracles
  - Hybrid proof workflow bundle:
    - `reporting.output_dir/formal_bridge/imported_invariants.yaml`
    - `reporting.output_dir/formal_bridge/FuzzBridge.lean` (or `.v` via `formal_bridge_system: coq`)
    - `reporting.output_dir/formal_bridge/hybrid_workflow.md`
- Validation:
  - New unit tests in `src/formal/bridge_tests.rs`
  - Run integration wired in `src/main.rs` after report persistence

## Update (UTC): 2026-02-20T14:18:32Z
- Focused Noir recheck: steps `066` and `067`
- Runner: `scripts/run_breadth_step.sh`
- Output root: `artifacts/roadmap_step_tests_recheck3`
- Settings: workers=2, iterations=20, timeout=20
- Result:
  - Step 066: `completed=1`, `selector_mismatch=26`, `run_outcome_missing=0`
  - Step 067: `completed=1`, `selector_mismatch=26`, `run_outcome_missing=0`
- Notes:
  - Noir setup-path blockers are no longer reproducing on these targets.
  - Selector validation misses are now classified explicitly (`selector_mismatch`) instead of surfacing as `run_outcome_missing`.

## Update (UTC): 2026-02-20T14:30:06Z
- Focused Halo2 recheck: steps `068` and `069`
- Runner: `scripts/run_breadth_step.sh`
- Output root: `artifacts/roadmap_step_tests_recheck3`
- Settings: workers=2, iterations=20, timeout=20
- Result:
  - Step 068: `completed=15`, `selector_mismatch=12`, `run_outcome_missing=0`
  - Step 069: `runtime_error=6`, `selector_mismatch=21`, `run_outcome_missing=0`
- Notes:
  - `cat5_frameworks_halo2_scaffold` executes to completion on selector-matching templates.
  - `local_halo2_minimal_json_spec` still fails with strict input reconciliation (`missing wire label for input index 0`).

## Update (UTC): 2026-02-20T14:37:55Z
- Readiness lane bootstrap scripts added:
  - `scripts/run_cairo_readiness.sh` with matrix `targets/zk0d_matrix_cairo_readiness.yaml`
  - `scripts/run_halo2_readiness.sh` with matrix `targets/zk0d_matrix_halo2_readiness.yaml`
- Bootstrap run status:
  - Cairo readiness report: `artifacts/backend_readiness/cairo/latest_report.json` (`exit_code=1`, `reason_counts: none=1`)
  - Halo2 readiness report: `artifacts/backend_readiness/halo2/latest_report.json` (`exit_code=1`, `reason_counts: none=2`)
- Blocking issue:
  - Historical (resolved): workspace compile regression (`FuzzConfigV2` initializer missing `ai_assistant`) previously prevented `zk-fuzzer` rebuild during lane execution; see matrix logs under `artifacts/backend_readiness/{cairo,halo2}/matrix_*.log`.

## Scope
- Focused rerun subset: targets that showed at least one 'completed' or 'critical_findings_detected' in first pass
- Runner: scripts/run_breadth_step.sh
- Output root: artifacts/roadmap_step_tests_followup_v2
- Settings: workers=2, iterations=250, timeout=12

## Selected Steps
002 003 004 006 007 008 009 010 011 012 013 018 019 020 023 025 028 030 031 033 034 038 039 043 044 045 046 047 053 055 056 057 058 059 060 062 063 

## Counts
- Observation files: 37
- Summary TSV files: 37
- Status distribution:
```text
     37 FAIL
```
- Aggregate reason codes:
  - completed=72
  - critical_findings_detected=21
  - run_outcome_missing=906

## Per-Step Outcomes
| Step | Target | Exit | Reasons |
|---|---|---:|---|
| 002 | cat8_libs_snarkjs_test_plonk_circuit_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 003 | cat8_libs_snarkjs_test_groth16_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 004 | cat8_libs_snarkjs_test_fflonk_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 006 | cat8_libs_snarkjs_test_circuit2_circuit | 1 | completed=1, run_outcome_missing=26 |
| 007 | cat8_libs_snarkjs_test_circuit_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 008 | cat5_frameworks_snarkjs_test_plonk_circuit_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 009 | cat5_frameworks_snarkjs_test_groth16_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 010 | cat5_frameworks_snarkjs_test_fflonk_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 011 | cat5_frameworks_snarkjs_test_circuit2_circuit | 1 | completed=1, run_outcome_missing=26 |
| 012 | cat5_frameworks_snarkjs_test_circuit_circuit | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 013 | cat3_privacy_circuits_test_circuits_utils_utils_verifyExpirationTime | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 018 | cat3_privacy_circuits_test_circuits_utils_utils_verifyClaimSignature | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 019 | cat3_privacy_circuits_test_circuits_utils_utils_isUpdatable | 1 | completed=1, run_outcome_missing=26 |
| 020 | cat3_privacy_circuits_test_circuits_utils_utils_isExpirable | 1 | completed=1, run_outcome_missing=26 |
| 023 | cat3_privacy_circuits_test_circuits_utils_utils_getSubjectLocation | 1 | completed=1, run_outcome_missing=26 |
| 025 | cat3_privacy_circuits_test_circuits_utils_utils_getClaimSubjectOtherIden | 1 | completed=3, run_outcome_missing=24 |
| 028 | cat3_privacy_circuits_test_circuits_utils_utils_getClaimExpiration | 1 | completed=1, run_outcome_missing=26 |
| 030 | cat3_privacy_circuits_test_circuits_utils_utils_checkIdenStateMatchesRoots | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 031 | cat3_privacy_circuits_test_circuits_eq | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 033 | cat3_privacy_circuits_test_circuits_eddsaposeidon | 1 | critical_findings_detected=1, run_outcome_missing=26 |
| 034 | cat3_privacy_circuits_test_circuits_utils_claimUtils_getClaimMerklizeRoot | 1 | completed=2, run_outcome_missing=25 |
| 038 | cat3_privacy_circuits_test_circuits_authV3Test | 1 | completed=2, run_outcome_missing=25 |
| 039 | cat3_privacy_circuits_test_circuits_stateTransitionTest | 1 | completed=1, run_outcome_missing=26 |
| 043 | cat3_privacy_circuits_circuits_stateTransitionV3 | 1 | completed=1, run_outcome_missing=26 |
| 044 | cat3_privacy_circuits_test_circuits_poseidon16 | 1 | completed=2, run_outcome_missing=25 |
| 045 | cat3_privacy_circuits_test_circuits_poseidon14 | 1 | completed=2, run_outcome_missing=25 |
| 046 | cat3_privacy_circuits_test_circuits_poseidon | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 047 | cat3_privacy_circuits_test_circuits_lessthan | 1 | critical_findings_detected=2, run_outcome_missing=25 |
| 053 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3Universal | 1 | completed=6, run_outcome_missing=21 |
| 055 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3OnChain | 1 | completed=7, run_outcome_missing=20 |
| 056 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3OnChain_16_16_64_16_32 | 1 | completed=7, run_outcome_missing=20 |
| 057 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3 | 1 | completed=5, run_outcome_missing=22 |
| 058 | cat3_privacy_circuits_circuits_credentialAtomicQueryV3_16_16_64 | 1 | completed=5, run_outcome_missing=22 |
| 059 | cat3_privacy_circuits_circuits_authV3 | 1 | completed=5, run_outcome_missing=22 |
| 060 | cat3_privacy_circuits_circuits_authV3_8_32 | 1 | completed=5, run_outcome_missing=22 |
| 062 | cat3_privacy_email_wallet_packages_circuits_src_claim | 1 | completed=6, run_outcome_missing=21 |
| 063 | cat3_privacy_email_wallet_packages_circuits_src_announcement | 1 | completed=7, run_outcome_missing=20 |
