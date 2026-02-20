# Roadmap Target Tests Follow-Up (v2)

Generated (UTC): 2026-02-20T01:28:14Z

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
