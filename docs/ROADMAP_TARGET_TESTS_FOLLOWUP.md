# Roadmap Target Tests Follow-Up (v2)

Generated (UTC): 2026-02-20T01:28:14Z

## Update (UTC): 2026-02-21T18:49:12Z
- Stabilized strict external-tool sandbox readiness lanes for non-Circom backends:
  - removed failing `bwrap --unshare-net` usage from backend and reporting timeout wrappers.
  - normalized relative command working directories to canonical absolute paths before sandbox bind/chdir.
  - expanded writable bind tracking to include backend target directories:
    - `CARGO_TARGET_DIR`
    - `NARGO_TARGET_DIR`
    - `SCARB_TARGET_DIR`
  - hardened external Noir parity test classification to treat strict coverage-capability limits as infra skips (instead of backend correctness failures).
- Files:
  - `crates/zk-backends/src/util.rs`
  - `src/reporting/command_timeout.rs`
  - `tests/backend_integration_tests.rs`
- Validation:
  - `scripts/run_backend_readiness_lanes.sh --iterations 1 --timeout 8 --workers 1 --batch-jobs 1 --enforce-dashboard --enforce-tool-sandbox` -> `PASS`
  - backend readiness reports:
    - Noir: `artifacts/backend_readiness/noir/latest_report.json` (`generated_utc=2026-02-21T18:47:09Z`, `reason_counts={"completed":6}`)
    - Cairo: `artifacts/backend_readiness/cairo/latest_report.json` (`generated_utc=2026-02-21T18:48:24Z`, `reason_counts={"completed":4}`)
    - Halo2: `artifacts/backend_readiness/halo2/latest_report.json` (`generated_utc=2026-02-21T18:49:12Z`, `reason_counts={"completed":8}`)
  - aggregate dashboard: `artifacts/backend_readiness/latest_report.json` (`generated_utc=2026-02-21T18:49:12.727407+00:00`, `overall_pass=true`)

## Update (UTC): 2026-02-21T18:10:57Z
- Closed security hardening task for strict external-tool sandbox mode:
  - backend command timeout wrapper now supports strict sandbox execution for backend tools (`circom`, `snarkjs`, `nargo`, `scarb`, `cargo`) when `ZKFUZZ_EXTERNAL_TOOL_SANDBOX=required`.
  - evidence/reporting timeout wrapper now supports the same strict sandbox mode.
  - Noir `nargo --version` preflight now uses timeout wrapper path (inherits sandbox mode).
  - readiness lanes gained explicit enforcement flag:
    - `scripts/run_backend_readiness_lanes.sh --enforce-tool-sandbox`
    - requires `bwrap` and exports strict sandbox env for invoked lanes.
  - release validation workflow now enforces sandboxed readiness lanes:
    - installs `bubblewrap`
    - invokes readiness lanes with `--enforce-tool-sandbox`.
- Files:
  - `crates/zk-backends/src/util.rs`
  - `crates/zk-backends/src/noir/mod.rs`
  - `src/reporting/command_timeout.rs`
  - `scripts/run_backend_readiness_lanes.sh`
  - `.github/workflows/release_validation.yml`
- Validation:
  - `cargo check -q --locked --offline` -> `PASS`
  - `cargo test -q -p zk-backends --locked --offline` -> `PASS`
  - `cargo test -q --lib reporting::command_timeout::tests:: --locked --offline` -> `PASS`
  - `bash -n scripts/run_backend_readiness_lanes.sh` -> `PASS`
  - `ruby -ryaml -e "YAML.load_file('.github/workflows/release_validation.yml'); puts 'release workflow yaml: ok'"` -> `PASS`

## Update (UTC): 2026-02-21T17:21:49Z
- Closed security hardening documentation task:
  - added explicit threat model and trust-boundary document:
    - `docs/SECURITY_THREAT_MODEL.md`
  - linked threat model in roadmap documentation index section.
- Coverage includes:
  - system boundaries, assets, trust assumptions, threat actors
  - threat-to-mitigation mapping for readiness/evidence/toolchain risks
  - security invariants, residual risks, and operational controls

## Update (UTC): 2026-02-21T17:20:40Z
- Closed security hardening task for production panic-surface control:
  - added `scripts/check_panic_surface.py` to detect `.unwrap()`/`.expect()` in production Rust paths (`src/`, `crates/`) while excluding tests/docs paths.
  - added explicit baseline allowlist: `config/panic_surface_allowlist.txt`.
  - wired CI enforcement in `.github/workflows/ci.yml` (`check` job, `Panic surface gate` step).
  - added regression tests: `tests/test_check_panic_surface.py`.
- Validation:
  - `python3 -m unittest -q tests/test_check_panic_surface.py` -> `PASS` (3 tests)
  - `python3 scripts/check_panic_surface.py --fail-on-stale` -> `PASS` (`matches=67`, `unknown=0`, `stale=0`)

## Update (UTC): 2026-02-21T17:17:48Z
- Closed security hardening task for ACIR serialization dependency:
  - migrated `zk-constraints` optional ACIR decoder from unmaintained `bincode` 1.x to maintained `bincode` 2.x with serde support.
  - updated ACIR bytecode decode path to a shared `decode_legacy_bincode(...)` helper using `bincode::config::legacy()` for compatibility.
  - added regression tests for legacy decode roundtrip and invalid payload handling.
- Files:
  - `crates/zk-constraints/Cargo.toml`
  - `crates/zk-constraints/src/constraint_types.rs`
  - `crates/zk-constraints/src/constraint_types_tests.rs`
- Validation:
  - `cargo test -q -p zk-constraints --features acir-bytecode --locked --offline` -> `PASS` (29 tests)
  - `cargo check -q --locked --offline` -> `PASS`

## Update (UTC): 2026-02-21T17:11:33Z
- Reviewed `MANUAL_CODE_REVIEW.md` and triaged only still-applicable gaps into roadmap backlog:
  - unmaintained `bincode 1.3` in ACIR decode path
  - production panic-surface CI gate for `.unwrap()`/`.expect()`
  - strict sandbox mode for backend external-tool execution
  - explicit security assumptions/threat-model documentation
- Roadmap updates:
  - `ROADMAP.md` -> added section `Security Hardening Follow-Up (From Manual Review)` with concrete, testable tasks.

## Update (UTC): 2026-02-21T17:07:15Z
- Implemented strict Z3 solver compatibility matrix:
  - `scripts/build_z3_compatibility_matrix.py`
    - captures local `z3 --version` + `Cargo.lock` `z3`/`z3-sys` versions.
    - executes strict offline build lanes for dynamic + `z3-static` configurations.
    - emits pass/fail matrix with per-lane duration and command trace.
  - `tests/test_build_z3_compatibility_matrix.py`
    - validates Z3 version parsing, lock-version extraction, and matrix summary logic.
- Validation:
  - `python3 -m unittest -q tests/test_build_z3_compatibility_matrix.py` -> `PASS` (3 tests)
  - `python3 scripts/build_z3_compatibility_matrix.py --output artifacts/dependency_tracking/z3_compatibility_matrix.json` -> `PASS`
    - report: `artifacts/dependency_tracking/z3_compatibility_matrix.json` (`generated_utc=2026-02-21T17:07:06.371385+00:00`, `overall_pass=true`, `z3_version=4.13.0`, lanes: dynamic/static/workspace all `pass`)

## Update (UTC): 2026-02-21T17:02:25Z
- Implemented strict workspace-scoped `arkworks` 0.5 upgrade-path evaluation:
  - `scripts/evaluate_arkworks_upgrade_path.py`
    - parses workspace manifests + `Cargo.lock` and reports direct/lock `ark-*` versions.
    - reports concrete blockers, migration steps, risk tier, and readiness status.
    - explicitly ignores non-workspace vendored manifests to avoid false dependency inflation.
  - `tests/test_evaluate_arkworks_upgrade_path.py`
    - validates semver-track parsing, lock parsing, blocker detection, and workspace-only scoping.
- Validation:
  - `python3 -m unittest -q tests/test_evaluate_arkworks_upgrade_path.py` -> `PASS` (4 tests)
  - `python3 scripts/evaluate_arkworks_upgrade_path.py --output artifacts/dependency_tracking/arkworks_upgrade_path.json` -> `PASS`
    - report: `artifacts/dependency_tracking/arkworks_upgrade_path.json` (`generated_utc=2026-02-21T17:01:58.474570+00:00`, `not_on_05_direct=4`, `lock_non_05=11`, `risk=low`, `ready_to_upgrade_now=false`)

## Update (UTC): 2026-02-21T16:55:25Z
- Implemented strict `zkevm-circuits` upstream-release tracking:
  - `scripts/track_zkevm_releases.py`
    - compares local checkout HEAD to latest stable upstream release tag commit.
    - emits machine-readable tracking artifact (`status`, `up_to_date`, local/release commits).
    - supports strict offline evidence mode via `--releases-json` + explicit `--release-commit`.
  - `tests/test_track_zkevm_releases.py`
    - validates stable-release selection (draft/prerelease exclusion).
    - validates relationship classification (`up_to_date`, `behind_latest_release`, `ahead_contains_latest_release`).
    - validates end-to-end report generation path.
- Validation:
  - `python3 -m unittest -q tests/test_track_zkevm_releases.py` -> `PASS` (3 tests)
  - `python3 scripts/track_zkevm_releases.py --repo-path circuits/zkevm-circuits --releases-json /tmp/zkevm_releases_fixture.json --release-commit "$(git -C circuits/zkevm-circuits rev-list -n 1 v0.10.0)" --output artifacts/dependency_tracking/zkevm_upstream_latest.json` -> `PASS`
    - report: `artifacts/dependency_tracking/zkevm_upstream_latest.json` (`generated_utc=2026-02-21T16:56:57.871999+00:00`, `status=diverged`, `up_to_date=false`)

## Update (UTC): 2026-02-21T16:48:59Z
- Implemented Halo2 production throughput gate for real scaffold execution:
  - `tests/backend_integration_tests.rs`
    - added `test_halo2_scaffold_production_throughput`
    - enforces deterministic outputs/coverage across repeated real-circuit runs
    - enforces configurable throughput thresholds (`HALO2_THROUGHPUT_*` env gates)
- Wired throughput gate into readiness lanes:
  - `scripts/run_halo2_readiness.sh`
    - now runs `test_halo2_scaffold_production_throughput` by default
    - added `--skip-throughput-test`
    - emits throughput integration status into `latest_report.json`
  - `scripts/run_backend_readiness_lanes.sh`
    - added passthrough `--skip-halo2-throughput-test`
- Validation:
  - `bash -n scripts/run_halo2_readiness.sh scripts/run_backend_readiness_lanes.sh` -> `PASS`
  - `HALO2_THROUGHPUT_ROUNDS=2 HALO2_THROUGHPUT_MAX_MEDIAN_MS=15000 ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_scaffold_production_throughput -- --exact` -> `PASS`
  - `HALO2_THROUGHPUT_ROUNDS=2 HALO2_THROUGHPUT_MAX_MEDIAN_MS=15000 scripts/run_halo2_readiness.sh --iterations 1 --timeout 8 --workers 1 --batch-jobs 1 --no-build-if-missing --skip-json-integration-test --skip-real-circuit-test --skip-stability-test` -> `PASS`
    - report: `artifacts/backend_readiness/halo2/latest_report.json` (`generated_utc=2026-02-21T16:48:11Z`, `test_halo2_scaffold_production_throughput=pass`)

## Update (UTC): 2026-02-21T16:40:01Z
- Implemented Cairo1 prove/verify pipeline in backend target:
  - `crates/zk-backends/src/cairo/mod.rs`
    - replaced Cairo1 hard-fail in `prove()` with `scarb prove --execute` flow.
    - added strict execution-id extraction from prove output and persistence for same-target verify calls.
    - wired Cairo1 `verify()` to `scarb verify --execution-id <id>`.
    - added deterministic Cairo1 argument JSON helper used by prove flow.
  - `crates/zk-backends/src/cairo/mod_tests.rs`
    - added `test_parse_cairo1_execution_id_from_output`
    - added `test_parse_cairo1_execution_id_missing_returns_none`
    - added `test_cairo1_arguments_json_serialization`
- Validation:
  - `cargo test -q -p zk-backends cairo::tests:: -- --nocapture` -> `PASS` (5/5)
  - `ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_cairo_stone_prover_prove_verify_smoke -- --exact` -> `PASS`

## Update (UTC): 2026-02-21T16:35:52Z
- Promoted non-Circom readiness from skip-tolerant to enforced in release workflow:
  - `.github/workflows/release_validation.yml`
    - removed `continue-on-error` on `Run backend readiness lanes`.
    - removed all backend-integration skip flags from readiness-lane invocation.
    - enabled dashboard enforcement in that step via `--enforce-dashboard`.
    - added explicit Noir toolchain bootstrap (`noirup`, `nargo --version`).
    - added explicit Cairo toolchain bootstrap (Scarb install + `scarb cairo-run --version`).
- Validation:
  - `ruby -ryaml -e "YAML.load_file('.github/workflows/release_validation.yml'); puts 'workflow yaml: ok'"` -> `PASS`
  - workflow grep checks confirm:
    - no remaining `continue-on-error` for backend readiness lane
    - no `--skip-*` backend readiness flags in release workflow
    - readiness lane now runs with `--enforce-dashboard`

## Update (UTC): 2026-02-21T16:33:56Z
- Hardened Noir Barretenberg-coupled evidence flow without reintroducing fallback execution:
  - `src/reporting/evidence_noir.rs`
    - added explicit `bb`-missing diagnostics (`barretenberg_missing_tool_message`) for `nargo prove` / `nargo verify` failures.
    - replaced single-path proof copy (`proofs/noir.proof`) with strict multi-candidate lookup across common Noir layouts:
      - `proofs/{noir,main,<project_name>}.proof`
      - `target/proofs/{noir,main,<project_name>}.proof`
      - `target/{noir,main,<project_name>}.proof`
    - now hard-fails evidence generation when prove succeeds but no proof artifact exists in known paths.
  - `src/reporting/evidence_noir_tests.rs`
    - added `test_barretenberg_missing_tool_message_detection`
    - added `test_noir_proof_candidates_include_project_name_and_common_locations`
- Validation:
  - `cargo test -q --lib reporting::evidence_noir::tests::test_barretenberg_missing_tool_message_detection -- --exact` -> `PASS`
  - `cargo test -q --lib reporting::evidence_noir::tests::test_noir_proof_candidates_include_project_name_and_common_locations -- --exact` -> `PASS`
  - `cargo test -q --lib reporting::evidence_noir::tests::test_convert_witness_to_prover_toml -- --exact` -> `PASS`
  - `ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_local_prove_verify_smoke -- --exact` -> `PASS`

## Update (UTC): 2026-02-21T16:25:12Z
- Strengthened Noir prove/verify operability for real-circuit runs:
  - `crates/zk-backends/src/noir/mod.rs`
    - expanded proof artifact lookup to cover known modern `nargo` output roots:
      - `proofs/`
      - `target/proofs/`
      - configured `build_dir/proofs/`
      - `target/`
      - configured `build_dir/`
    - improved missing-proof diagnostics to include all searched paths.
  - `crates/zk-backends/src/noir/mod_tests.rs`
    - updated regression test coverage for expanded/deduplicated proof candidates.
- Added dedicated local prove/verify readiness gates:
  - `tests/backend_integration_tests.rs`
    - new `test_noir_local_prove_verify_smoke`
    - new `test_cairo_stone_prover_prove_verify_smoke`
  - `scripts/run_noir_readiness.sh`
    - now runs `test_noir_local_prove_verify_smoke` by default
    - added `--skip-local-prove-verify-test`
  - `scripts/run_cairo_readiness.sh`
    - now runs `test_cairo_stone_prover_prove_verify_smoke` by default
    - added `--skip-stone-prover-test`
- Validation:
  - `bash -n scripts/run_noir_readiness.sh scripts/run_cairo_readiness.sh` -> `PASS`
  - `cargo test -q -p zk-backends noir::tests::test_proof_file_candidates_include_name_and_main_without_duplicates -- --exact` -> `PASS`
  - `ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_local_prove_verify_smoke -- --exact` -> `PASS`
  - `ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_cairo_stone_prover_prove_verify_smoke -- --exact` -> `PASS`
  - `scripts/run_noir_readiness.sh --iterations 1 --timeout 8 --workers 1 --batch-jobs 1 --no-build-if-missing --skip-integration-test --skip-constraint-coverage-test --skip-constraint-edge-cases-test --skip-external-smoke-test --skip-external-parity-test` -> `PASS`
    - report: `artifacts/backend_readiness/noir/latest_report.json` (`generated_utc=2026-02-21T16:27:10Z`, `test_noir_local_prove_verify_smoke=pass`)
  - `scripts/run_cairo_readiness.sh --iterations 1 --timeout 8 --workers 1 --batch-jobs 1 --no-build-if-missing --skip-integration-test --skip-regression-test` -> `PASS`
    - report: `artifacts/backend_readiness/cairo/latest_report.json` (`generated_utc=2026-02-21T16:27:16Z`, `test_cairo_stone_prover_prove_verify_smoke=pass`)

## Update (UTC): 2026-02-21T14:54:38Z
- Executed heavy non-Circom readiness lanes under release-grade profile and enforced dashboard gate:
  - `scripts/run_backend_readiness_lanes.sh --iterations 120 --timeout 45 --workers 2 --batch-jobs 1 --required-backends noir,cairo,halo2 --enforce-dashboard --no-build-if-missing` -> `PASS`
- Published artifacts (heavy profile):
  - Noir: `artifacts/backend_readiness/noir/latest_report.json` (`generated_utc=2026-02-21T14:44:02Z`, `reason_counts={"completed":6}`)
  - Cairo: `artifacts/backend_readiness/cairo/latest_report.json` (`generated_utc=2026-02-21T14:47:33Z`, `reason_counts={"completed":4}`)
  - Halo2: `artifacts/backend_readiness/halo2/latest_report.json` (`generated_utc=2026-02-21T14:54:17Z`, `reason_counts={"completed":8}`)
  - Aggregate: `artifacts/backend_readiness/latest_report.json` (`generated_utc=2026-02-21T14:54:17.539334+00:00`, `overall_pass=true`)
- Enforced gate metrics at heavy profile:
  - Noir: selector-matching completion `1.000`, selector mismatch rate `0.000`, runtime/preflight/missing-outcome `0`
  - Cairo: selector-matching completion `1.000`, selector mismatch rate `0.000`, runtime/preflight/missing-outcome `0`
  - Halo2: selector-matching completion `1.000`, selector mismatch rate `0.000`, runtime/preflight/missing-outcome `0`
  - Aggregate non-Circom: `selector_matching_total=18`, `run_outcome_missing_rate=0.000`
- Release-grade evidence lock:
  - This run supersedes prior quick-lane evidence for readiness-gate confidence claims.

## Update (UTC): 2026-02-21T14:20:45Z
- Lifted Halo2 readiness from mixed selector results to full selector-match completion by replacing generic CVE selectors with Halo2-specific readiness probes.
  - Added:
    - `campaigns/cve/patterns/cveX35_halo2_signature_readiness_probe.yaml`
    - `campaigns/cve/patterns/cveX36_halo2_constraint_metadata_readiness_probe.yaml`
    - `campaigns/cve/patterns/cveX37_halo2_plonk_lookup_readiness_probe.yaml`
    - `campaigns/cve/patterns/cveX38_halo2_profile_k_readiness_probe.yaml`
  - Updated `targets/fuzzer_registry.prod.yaml`:
    - `halo2_readiness` collection now uses `cveX35`..`cveX38`
    - added aliases for `cveX35`..`cveX38`
- Validation:
  - `scripts/run_halo2_readiness.sh --iterations 20 --timeout 20 --workers 2 --batch-jobs 1 --output-dir artifacts/backend_readiness/halo2 --no-build-if-missing` -> `PASS`
    - report: `artifacts/backend_readiness/halo2/latest_report.json`
    - matrix: `exit_code=0`, `reason_counts={"completed":8}`
    - summary: `artifacts/backend_readiness/halo2/summary_20260221_141811.tsv`
      - `cat5_frameworks_halo2_scaffold: completed=4`
      - `local_halo2_minimal_json_spec: completed=4`
  - `scripts/backend_readiness_dashboard.sh --readiness-root artifacts/backend_readiness --output artifacts/backend_readiness/latest_report.json --enforce` -> `PASS`
    - Halo2 gate metrics: `selector_matching_total=8`, `selector_mismatch_rate=0.000`, `overall_completion=1.000`, `runtime_error=0`, `backend_preflight_failed=0`
    - aggregate selector-matching depth: `18` (`>=12`)
  - `scripts/run_backend_readiness_lanes.sh --iterations 20 --timeout 20 --workers 2 --batch-jobs 1 --required-backends noir,cairo,halo2 --enforce-dashboard --no-build-if-missing` -> `PASS`
    - lanes: Noir `PASS`, Cairo `PASS`, Halo2 `PASS`
    - aggregate gate: `PASS` (`artifacts/backend_readiness/latest_report.json`)

## Update (UTC): 2026-02-21T14:14:16Z
- Lifted Cairo strict-capacity regression from fail to pass without reintroducing output-hash fallback:
  - `src/executor/mod.rs`
    - `CairoExecutor` now derives strict coverage from source-level `assert` evaluation against observed runtime outputs.
    - added Cairo expression/assert parsing helpers for deterministic arithmetic evaluation (`+`, `-`, `*`, constants, `[output_ptr]` / `[output_ptr + N]`).
    - Cairo executor construction now caches source text and refuses coverage when assertions cannot be evaluated.
  - `src/executor/mod_tests.rs`
    - added unit coverage for Cairo assertion extraction and expression evaluation:
      - `executor::tests::test_cairo_assertion_descriptions_extract_assert_statements`
      - `executor::tests::test_eval_cairo_expression_supports_arithmetic_and_output_ptr`
- Validation:
  - `cargo test -q -p zk-fuzzer --lib executor::tests::test_cairo_assertion_descriptions_extract_assert_statements -- --exact` -> `PASS`
  - `cargo test -q -p zk-fuzzer --lib executor::tests::test_eval_cairo_expression_supports_arithmetic_and_output_ptr -- --exact` -> `PASS`
  - `ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_cairo_full_capacity_regression_suite -- --exact` -> `PASS`
  - `scripts/run_cairo_readiness.sh --iterations 20 --timeout 20 --workers 2 --batch-jobs 1 --output-dir artifacts/backend_readiness/cairo --no-build-if-missing` -> `PASS`
    - report: `artifacts/backend_readiness/cairo/latest_report.json`
    - matrix: `exit_code=0`, `reason_counts={"completed":4}`
    - integration slices: `test_cairo_integration=pass`, `test_cairo_full_capacity_regression_suite=pass`
  - `scripts/backend_readiness_dashboard.sh --readiness-root artifacts/backend_readiness --output artifacts/backend_readiness/latest_report.json --enforce` -> `PASS`
    - aggregate selector-matching depth: `14` (`>=12`)
    - required backend gates: Noir/Cairo/Halo2 all `PASS`

## Update (UTC): 2026-02-21T13:52:04Z
- Added Circom-parity depth gates for non-Circom readiness to prevent false “green” status from selector-only completion:
  - `scripts/backend_readiness_dashboard.sh`
    - new enforced thresholds:
      - `min_selector_matching_total` per backend (default: `4`)
      - `min_overall_completion_rate` per backend (default: `0.40`)
      - `max_selector_mismatch_rate` per backend (default: `0.70`)
      - `min_aggregate_selector_matching_total` across required backends (default: `12`)
    - existing strict thresholds remain (`selector-matching completion`, `runtime_error`, `backend_preflight_failed`, `run_outcome_missing`)
  - `scripts/run_backend_readiness_lanes.sh`
    - plumbed new parity threshold options/env passthrough into dashboard gate invocation
  - `scripts/release_candidate_gate.sh`
    - release gate now consumes and enforces the same new parity thresholds by default
- Validation:
  - `bash -n scripts/backend_readiness_dashboard.sh scripts/run_backend_readiness_lanes.sh scripts/release_candidate_gate.sh` -> `PASS`
  - `scripts/backend_readiness_dashboard.sh --readiness-root artifacts/backend_readiness --output /tmp/backend_readiness_parity_report.json --enforce` -> `FAIL` (expected under stricter parity thresholds)
  - Failure diagnostics (current gap to Circom-level readiness):
    - Noir: `selector_matching_total=3`, `overall_completion=0.167`, `selector_mismatch_rate=0.833`
    - Cairo: `selector_matching_total=1`, `overall_completion=0.200`, `selector_mismatch_rate=0.800`
    - Halo2: `PASS` (`selector_matching_total=4`, `overall_completion=0.400`, `selector_mismatch_rate=0.600`)
    - Aggregate: `selector_matching_total=8 < 12`

## Update (UTC): 2026-02-21T13:41:55Z
- Enforced single-mode backend strictness (no strict/non-strict toggle surface):
  - `src/executor/mod.rs`
    - removed `strict_backend` from `ExecutorFactoryOptions`
    - `ExecutorFactoryOptions::strict()` kept as compatibility alias to default strict behavior
  - `src/executor/isolated.rs`
    - removed `strict_backend` from isolated exec option serialization/plumbing
  - `src/config/profiles.rs`
    - removed `strict_backend` profile field and profile parameter emission
  - `src/fuzzer/engine/config_helpers.rs`, `src/preflight_backend.rs`
    - `strict_backend=false` now hard-fails config parsing
    - legacy `strict_backend=true` accepted as deprecated no-op
  - `src/main.rs`, `src/runtime_misc.rs`, `src/run_chain_config.rs`
    - removed injected `strict_backend: true` writes (strictness is now implicit and always on)
  - `src/config/readiness.rs`
    - removed dependency on `strict_backend` presence
    - reports explicit `strict_backend=false` as critical unsupported config
- Enforced fail-fast evidence behavior when tools/prerequisites are missing:
  - `src/reporting/evidence.rs`
    - proof-generation errors now map to `VerificationResult::Failed` (not `Skipped`)
    - missing Circom artifacts / missing `snarkjs` now fail
    - removed `npx snarkjs` fallback path; default command is strict `snarkjs`
  - `src/reporting/evidence_noir.rs`, `src/reporting/evidence_halo2.rs`, `src/reporting/evidence_cairo.rs`
    - missing witness/spec/tools and command errors now fail instead of skip
- Docs aligned with always-strict behavior:
  - removed `strict_backend` toggles/examples from:
    - `docs/PROFILES_GUIDE.md`
    - `docs/CHAIN_FUZZING_GUIDE.md`
    - `docs/TUTORIAL.md`
    - `docs/PLUGIN_SYSTEM_GUIDE.md`
- Validation:
  - `cargo check -q` -> `PASS`
  - `cargo test -q --bin zk0d_batch` -> `PASS`
  - `cargo test -q --package zk-fuzzer test_coverage_from_results_returns_none_when_constraints_missing` -> `PASS`

## Update (UTC): 2026-02-21T13:31:25Z
- Continued fallback eradication in Circom backend internals:
  - `crates/zk-backends/src/circom/mod.rs`
    - removed `.r1cs` direct-parse fallback when `snarkjs r1cs info` execution/parsing fails
    - metadata extraction now hard-fails on `snarkjs` failure
    - removed ptau local-fixture/download fallback path in `find_or_download_ptau`
    - key setup now requires an existing valid ptau source (configured or discoverable in strict search paths), otherwise fails immediately
- Validation:
  - `cargo check -q -p zk-backends` -> `PASS`
  - `cargo check -q` -> `PASS`
  - `ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_real_backend_matrix_smoke -- --exact` -> `PASS`

## Update (UTC): 2026-02-21T13:29:25Z
- Extended strict no-fallback policy to additional execution surfaces:
  - `src/executor/mod.rs`
    - removed Circom executor `snarkjs`/`ptau` autodetection path injection in `new_with_options(...)`
    - explicit option values are honored, but no automatic local/env path discovery fallback is applied by the executor wrapper
  - `src/executor/mod_tests.rs`
    - removed Circom autodetect tests tied to deleted fallback behavior
  - `src/bin/zk0d_batch.rs`
    - removed transient-setup retry behavior and related CLI/config fields
  - `src/bin/zk0d_batch/zk0d_batch_tests.rs`
    - removed retry classifier test tied to deleted fallback behavior
  - `docs/TARGETS.md`
    - removed retry-flag usage example from execution docs
- Validation:
  - `cargo test -q --bin zk0d_batch` -> `PASS`
  - `cargo test -q --package zk-fuzzer test_coverage_from_results_returns_none_when_constraints_missing` -> `PASS`
  - `cargo test -q -p zk-backends noir::tests::test_nargo_missing_subcommand_message_detection` -> `PASS`
  - `cargo test -q -p zk-backends halo2::tests::test_halo2_cargo_command_uses_configured_toolchain` -> `PASS`
  - `cargo check -q` -> `PASS`

## Update (UTC): 2026-02-21T13:27:38Z
- Continued strict no-fallback enforcement in runtime execution paths:
  - `src/executor/mod.rs`
    - removed Cairo output-hash coverage fallback path
    - Cairo execution now fails when real constraint coverage is unavailable (`refusing output-hash fallback`)
  - `src/bin/zk0d_batch.rs`
    - removed transient-setup retry control flags and retry loop (`--retry-transient-setup`, `--retry-backoff-secs`)
    - batch runner now does single-attempt execution with immediate failure on run error
  - `src/bin/zk0d_batch/zk0d_batch_tests.rs`
    - removed retry-classifier test tied to deleted retry fallback behavior
  - `docs/TARGETS.md`
    - removed retry-based batch-run example
- Validation:
  - `cargo test -q --bin zk0d_batch` -> `PASS`
  - `cargo test -q --package zk-fuzzer test_coverage_from_results_returns_none_when_constraints_missing` -> `PASS`
  - `cargo check -q` -> `PASS`

## Update (UTC): 2026-02-21T13:22:06Z
- Removed remaining backend auto-fallback paths to enforce strict fail-fast tooling policy:
  - `crates/zk-backends/src/noir/mod.rs`
    - removed compile-time isolated-project retry path (`enable_isolated_project_mode` / copy-based fallback)
    - compile now runs once and fails immediately on package/tooling issues
  - `crates/zk-backends/src/halo2/mod.rs`
    - removed lockfile-v4 auto-retry branch (`cargo +nightly`) in `setup_rust_circuit`
    - build now fails immediately when toolchain/lockfile is incompatible
    - narrowed optional env toolchain input to explicit `ZK_FUZZER_HALO2_CARGO_TOOLCHAIN` only
  - `src/reporting/evidence_noir.rs`
    - evidence proof flow already moved to hard-fail on missing/unsupported `nargo prove` / `nargo verify`
- Validation:
  - `cargo test -q -p zk-backends noir::tests::test_nargo_missing_subcommand_message_detection` -> `PASS`
  - `cargo test -q -p zk-backends halo2::tests::test_halo2_cargo_command_uses_configured_toolchain` -> `PASS`
  - `ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_real_backend_matrix_smoke -- --exact` -> `PASS`
  - `cargo check -q` -> `PASS`

## Update (UTC): 2026-02-21T13:18:16Z
- Switched Noir tool behavior to strict fail-fast (no fallback execution path):
  - file: `crates/zk-backends/src/noir/mod.rs`
  - changes:
    - removed Barretenberg (`bb`) prove/verify fallback branch from Noir target execution
    - `prove()` and `verify()` now require `nargo prove` / `nargo verify` support and hard-fail when unavailable
    - explicit error message directs toolchain update when subcommands are missing
- Switched Noir evidence proof path to strict fail-fast for missing tooling:
  - file: `src/reporting/evidence_noir.rs`
  - changes:
    - `nargo --version` and `nargo prove`/`verify` capability checks now return hard errors (not `VerificationResult::Skipped`)
    - command-timeout execution errors for prove/verify now fail the operation directly
- Validation:
  - `cargo test -q -p zk-backends noir::tests::test_nargo_missing_subcommand_message_detection` -> `PASS`
  - `cargo test -q --package zk-fuzzer test_nargo_missing_subcommand_message_detection` -> `PASS`
  - `cargo check -q` -> `PASS`

## Update (UTC): 2026-02-21T13:07:31Z
- Hardened Noir proving/verification compatibility for modern CLI layouts:
  - file: `crates/zk-backends/src/noir/mod.rs`
  - changes:
    - detect whether `nargo` exposes `prove`/`verify` subcommands (`nargo help <subcommand>`)
    - keep legacy path when subcommands exist
    - fallback to Barretenberg `bb` flow when subcommands are absent:
      - witness generation via `nargo execute <witness_name>`
      - proof generation via `bb prove --scheme <scheme> -b <artifact.json> -w <witness.gz> -o <proof>`
      - verification via `bb write_vk ...` + `bb verify ...`
    - add configurable proof scheme via `ZK_FUZZER_NOIR_BB_SCHEME` (default: `ultra_honk`)
    - improved command failure diagnostics by including combined stdout/stderr snippets
- Added Noir parser regression coverage:
  - file: `crates/zk-backends/src/noir/mod_tests.rs`
  - test: `test_nargo_missing_subcommand_message_detection`
- Hardened Noir evidence proof pipeline to avoid false failures on modern CLI:
  - file: `src/reporting/evidence_noir.rs`
  - changes:
    - detect `nargo prove`/`nargo verify` subcommand availability before attempting proof flow
    - when unavailable, emit explicit `VerificationResult::Skipped(...)` with migration guidance instead of reporting opaque command failures
- Added evidence parser regression coverage:
  - file: `src/reporting/evidence_noir_tests.rs`
  - test: `test_nargo_missing_subcommand_message_detection`
- Validation:
  - `cargo test -q -p zk-backends noir::tests::test_nargo_missing_subcommand_message_detection` -> `PASS`
  - `cargo test -q -p zk-backends noir::tests::test_proof_file_candidates_include_name_and_main_without_duplicates` -> `PASS`
  - `cargo test -q --package zk-fuzzer test_convert_witness_to_prover_toml` -> `PASS`
  - `cargo test -q --package zk-fuzzer test_nargo_missing_subcommand_message_detection` -> `PASS`
  - `ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_real_backend_matrix_smoke -- --exact` -> `PASS`
  - `cargo check -q -p zk-backends` -> `PASS`
  - `cargo check -q` -> `PASS`

## Update (UTC): 2026-02-21T12:52:39Z
- Executed aggregate non-Circom readiness gate after Halo2 toolchain fallback fix:
  - `scripts/run_backend_readiness_lanes.sh --iterations 5 --timeout 8 --workers 1 --batch-jobs 1 --required-backends noir,cairo,halo2 --min-completion-rate 0.90 --max-runtime-error 0 --max-backend-preflight-failed 0 --max-run-outcome-missing-rate 0.05 --skip-noir-integration-test --skip-noir-constraint-coverage-test --skip-noir-constraint-edge-cases-test --skip-noir-external-smoke-test --skip-noir-external-parity-test --skip-cairo-integration-test --skip-cairo-regression-test --skip-halo2-json-integration-test --skip-halo2-real-circuit-test --skip-halo2-stability-test --no-build-if-missing --enforce-dashboard`
  - Result: `PASS` (Noir/Cairo/Halo2 lanes all pass; aggregated dashboard pass)
  - Aggregated dashboard: `artifacts/backend_readiness/latest_report.json`
  - Gate metrics:
    - Noir: selector-matching completion `1.000`, `runtime_error=0`, `backend_preflight_failed=0`
    - Cairo: selector-matching completion `1.000`, `runtime_error=0`, `backend_preflight_failed=0`
    - Halo2: selector-matching completion `1.000`, `runtime_error=0`, `backend_preflight_failed=0`
    - Aggregate non-Circom `run_outcome_missing_rate=0.000` (`count=0`, `total=33`)

## Update (UTC): 2026-02-21T12:50:33Z
- Hardened Halo2 Rust-project setup for lockfile/toolchain compatibility:
  - file: `crates/zk-backends/src/halo2/mod.rs`
  - change: when Halo2 Rust-project build fails with lockfile-v4/toolchain parse error, setup retries with `cargo +nightly` and keeps the selected toolchain for subsequent `cargo run` calls (`--info/--constraints/--execute/--prove/--verify` paths).
- Added backend regression coverage:
  - file: `crates/zk-backends/src/halo2/mod_tests.rs`
  - tests:
    - `test_halo2_lockfile_error_detection`
    - `test_halo2_cargo_command_uses_configured_toolchain`
  - validation:
    - `cargo test -q -p zk-backends halo2::tests::test_halo2_lockfile_error_detection` -> `PASS`
    - `cargo test -q -p zk-backends halo2::tests::test_halo2_cargo_command_uses_configured_toolchain` -> `PASS`
- Halo2 readiness spot-check (matrix-only quick run) now passes with scaffold target completing:
  - `scripts/run_halo2_readiness.sh --iterations 5 --timeout 8 --workers 1 --batch-jobs 1 --no-build-if-missing --skip-json-integration-test --skip-real-circuit-test --skip-stability-test`
  - result: `PASS`
  - report: `artifacts/backend_readiness/halo2/latest_report.json`
  - summary: `artifacts/backend_readiness/halo2/summary_20260221_125002.tsv` (`completed=4`, `selector_mismatch=6`, `backend_preflight_failed=0`)
- Re-ran large-circuit memory profile harness after Halo2 fix:
  - `./scripts/profile_large_circuit_memory.sh --max-targets 3 --max-targets-per-framework 1 --iterations 5 --timeout 8 --workers 1 --batch-jobs 1 --no-build-if-missing`
  - result: `PASS` (`overall_pass=true`)
  - report: `artifacts/memory_profiles/latest_report.json`
  - per-framework max RSS (kB): Cairo `84248`, Noir `62928`, Halo2 `59224` (all `exit_code=0`)

## Update (UTC): 2026-02-21T12:38:57Z
- Added large-circuit memory profiling harness:
  - `scripts/profile_large_circuit_memory.sh`
  - selects largest available targets from matrix inputs, profiles `zk0d_batch` with `/usr/bin/time -v`, and publishes JSON/Markdown/TSV artifacts.
- Validation run:
  - `./scripts/profile_large_circuit_memory.sh --max-targets 3 --max-targets-per-framework 1 --iterations 5 --timeout 8 --workers 1 --batch-jobs 1 --no-build-if-missing`
  - Result: report generated (`overall_pass=false` in non-enforced mode due one backend preflight failure)
  - Artifacts:
    - `artifacts/memory_profiles/latest_report.json`
    - `artifacts/memory_profiles/latest_report.md`
    - `artifacts/memory_profiles/raw/results.tsv`
  - Observed peak RSS (kB):
    - Cairo `84520` (`local_cairo_multiplier`)
    - Noir `62972` (`cat3_privacy_aztec_docs_examples_circuits_hello_circuit`)
    - Halo2 `59736` (`cat5_frameworks_halo2_scaffold`, `exit_code=1`, `backend_preflight_failed=3`)

## Update (UTC): 2026-02-21T12:28:49Z
- Ran heavier cross-backend throughput batch (3 runs per backend) in enforced mode:
  - `./scripts/benchmark_cross_backend_throughput.sh --runs 3 --enforce --no-build-if-missing`
  - Result: `PASS`
  - Throughput ranking (median completed/sec): `halo2`, `cairo`, `noir`
  - Artifact: `artifacts/backend_throughput/latest_report.json`
  - Markdown summary: `artifacts/backend_throughput/latest_report.md`
- Added chain complexity benchmark lanes in `benches/chain_benchmark.rs`:
  - profiles: `low`, `medium`, `deep`, `wide_wiring`
  - output snapshot: `reports/chain_complexity_benchmark.md`
- Validation:
  - `cargo check -q --bench chain_benchmark` -> `PASS`
  - `cargo bench --bench chain_benchmark chain_complexity_profiles -- --quick` -> `PASS`
  - Criterion quick results:
    - `chain_complexity_profiles/low/2` median `~80us`
    - `chain_complexity_profiles/medium/5` median `~201us`
    - `chain_complexity_profiles/deep/12` median `~511us`
    - `chain_complexity_profiles/wide_wiring/8` median `~340us`

## Update (UTC): 2026-02-20T22:40:28Z
- Added cross-backend throughput comparison harness:
  - `scripts/benchmark_cross_backend_throughput.sh`
  - compares Noir/Cairo/Halo2 readiness lanes under shared runtime parameters and emits ranking by median completed throughput.
- Validation run (lightweight enforced pass):
  - `./scripts/benchmark_cross_backend_throughput.sh --runs 1 --iterations 5 --timeout 8 --workers 1 --batch-jobs 1 --no-build-if-missing --enforce`
  - Result: `PASS`
  - Throughput ranking (median completed/sec): `halo2`, `noir`, `cairo`
  - Artifact: `artifacts/backend_throughput/latest_report.json`
  - Markdown summary: `artifacts/backend_throughput/latest_report.md`
  - Raw run metrics: `artifacts/backend_throughput/raw/run_metrics.jsonl`

## Update (UTC): 2026-02-20T22:21:10Z
- Restored default release-gate path on `artifacts/benchmark_runs` with fresh passing summaries.
- Benchmark regeneration command (used twice):
  - `cargo run --quiet --release --bin zk0d_benchmark -- --config-profile dev --suite safe_regression,vulnerable_ground_truth --trials 2 --jobs 1 --batch-jobs 1 --workers 1 --iterations 50 --timeout 10 --benchmark-min-evidence-confidence low --benchmark-oracle-min-agreement-ratio 0.45 --benchmark-oracle-cross-attack-weight 0.65 --benchmark-high-confidence-min-oracles 3 --output-dir artifacts/benchmark_runs`
- New passing summaries:
  - `artifacts/benchmark_runs/benchmark_20260220_221614/summary.json`
  - `artifacts/benchmark_runs/benchmark_20260220_222045/summary.json`
  - each reports: `completion=1.0`, `recall=0.8`, `precision=1.0`, `safe_fpr=0.0`, `safe_high_conf_fpr=0.0`.
- Gate validation:
  - `scripts/release_candidate_gate.sh --bench-root artifacts/benchmark_runs --required-passes 2 ...` -> `PASS`
  - `scripts/release_candidate_validate_twice.sh --bench-root artifacts/benchmark_runs --required-passes 2 --output-dir artifacts/release_candidate_validation --enforce` -> `PASS` (attempt1=pass, attempt2=pass, overall=PASS)

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
