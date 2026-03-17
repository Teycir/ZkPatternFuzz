# Target Intake Plan

## Objective

Assess how to fuzz targets from `/home/teycir/ZkRepos` with ZkPatternFuzz without relying on stale hardcoded target bindings, including dependency readiness and the broadest practical template coverage.

## Frozen Context

- Repo path: `/home/teycir/Repos/ZkPatternFuzz`
- Repo commit: `da4658af5eb525a4670b37e6920c3a522593d31b`
- External target root under review: `/home/teycir/ZkRepos`

## Plan

- [x] Inspect repository layout, operator docs, registries, wrappers, and mode-2 patterns.
- [x] Inspect host tool inventory and confirm the expected ZK toolchain is documented as installed.
- [x] Inspect `/home/teycir/ZkRepos` and compare live target paths to the checked-in external target matrix.
- [x] Add a dynamic discovery helper for current targets under `/home/teycir/ZkRepos`.
- [x] Make the helper emit runnable target metadata for standardized wrappers and direct batch runs.
- [x] Decide whether to use standardized wrappers or direct batch mode for the requested "maximum templates" behavior.
- [x] Add or adapt a dynamic intake path so current `/home/teycir/ZkRepos` targets are runnable without stale hardcoded bindings.
- [x] Rename the runtime config file away from `.env` and update the loading path, examples, and operator docs.
- [x] Validate the helper against representative live repos under `/home/teycir/ZkRepos`.
- [x] Run a low-cost dry-run to confirm dispatch works before any heavy fuzzing.
- [ ] Run the chosen broader campaign and capture evidence artifacts.
- [x] Re-inventory `/home/teycir/ZkRepos` after the failed broad run and identify why the raw discovery output is too noisy for operator use.
- [x] Build a clean target-curation pass that filters out non-fit targets and reports per-target prerequisites/blockers.
- [x] Verify the curated list against representative live repos and update operator docs with the clean intake flow.

## Findings

- The standardized wrapper path is already implemented through `scripts/run_std_{smoke,standard,deep}.sh` and `scripts/run_fixed_target_deep_fuzz.sh`.
- Standardized deep runs do not maximize templates for every framework:
  - Circom uses alias `readiness_circom` with 2 templates.
  - Noir uses alias `readiness_noir` with 3 templates.
  - Cairo uses alias `readiness_cairo` with 4 templates.
  - Halo2 uses alias `readiness_halo2` with 4 templates.
  - Special-case zkEVM Halo2 uses a fixed 9-template CSV.
- The broadest catalog currently exposed in `targets/fuzzer_registry.prod.yaml` is alias `always`, which resolves to 43 CVE-style templates.
- The checked-in external target matrix at `targets/zk0d_matrix_external_manual.yaml` points to `/media/elements/Repos/...`, not the live `/home/teycir/ZkRepos/...` clone root.
- The user explicitly does not want hardcoded old targets; the live target root must become the source of truth for intake.
- Host tool inventory indicates the main backend prerequisites are installed: `circom`, `snarkjs`, `nargo`, `scarb`, `cairo-*`, `z3`, and Rust/Node toolchains.
- `/home/teycir/ZkRepos` currently contains a strong Circom-heavy intake set plus Noir, Cairo, and Halo2 repos.
- The new helper `scripts/discover_zkrepos_targets.py` discovers live Circom, Noir, Cairo, and Halo2 targets under `/home/teycir/ZkRepos`, emits TSV/JSON inventories, and can render `ZKF_STD_TARGET_*` binding triplets for `config.env`.
- Chosen target for the first broad campaign: `/home/teycir/ZkRepos/tornado-core/circuits/withdraw.circom`.
- Direct batch mode with `--config-profile prod --alias always` is the correct path for full coverage; the standardized wrappers remain useful for smaller readiness passes.
- Staged `tests/circuits/build/pot12_final.ptau` to `bins/ptau/pot12_final.ptau` and wired `config.env` via `ZKF_PTAU_PATH`.
- The new helper `scripts/curate_zkrepos_targets.py` produces a clean shortlist from the live root, separating fit targets from skipped framework/test/monorepo noise and attaching per-target prerequisites, dependency notes, and optional lightweight verification results.

## Review

- Runtime config renamed to `config.env`, with loaders, examples, and operator docs updated.
- Standardized wrappers now accept direct target paths plus optional `*_FRAMEWORK` and `*_MAIN_COMPONENT` hints in `config.env`.
- Added focused discovery coverage in `tests/test_discover_zkrepos_targets.py`; those tests pass.
- Live discovery on `/home/teycir/ZkRepos` now only reports Circom files with a direct `component main`, which prevents library-style template sources such as Semaphore's `src/semaphore.circom` from being surfaced as runnable targets.
- Added `config.env` (gitignored) with `tornado-core/circuits/withdraw.circom` as the default standardized target binding and a new `scripts/run_full_coverage_target.sh` helper for `prod/always` campaigns.
- `scripts/run_full_coverage_target.sh semaphore` failed because `semaphore/packages/circuits/src/semaphore.circom` is a reusable template source with no direct `component main`, and its bare includes such as `babyjub.circom` depend on extra package-path handling outside the simple direct-file runner.
- `DRY_RUN=1 scripts/run_full_coverage_target.sh` against the default Tornado `withdraw.circom` target passed local readiness, built `zk-fuzzer`, and exercised all 43 templates in the `always` alias with `0` template errors.

# Clean Target Curation Plan

## Objective

Build a clean, repeatable shortlist of `/home/teycir/ZkRepos` targets that are structurally fit for fuzzing, filter out noisy/non-fit repos and manifests, and report the concrete prerequisites and dependency blockers for each candidate.

## Plan

- [x] Review the current discovery helper against live `/home/teycir/ZkRepos` inventory and capture repo-level noise patterns.
- [x] Implement a curated target inventory script that classifies fit versus skipped targets and reports prerequisites/dependency state.
- [x] Add focused tests for the curation heuristics and readiness annotations.
- [x] Verify the curated inventory on the live `/home/teycir/ZkRepos` tree and record the resulting shortlist and blockers.

## Findings

- Raw live discovery is too noisy to use directly as a first intake list:
  - `aztec-packages` contributes 198 runnable-looking manifests, but they are dominated by monorepo internals, contracts, and test-oriented content.
  - `circomlib`, `halo2`, and `cairo` are framework/library repos, not operator-grade first-pass fuzz targets.
  - `semaphore`, `maci`, and `circom-ecdsa` currently expose no direct runnable targets under the present discovery rules.
- Added `scripts/curate_zkrepos_targets.py` as the operator-grade intake entrypoint. It filters non-fit targets and reports:
  - fit targets versus skipped targets
  - per-target prerequisites
  - dependency notes
  - optional live verification status
  - repo-level summaries
- Clean verified shortlist on the current live tree:
  - Ready Circom: `/home/teycir/ZkRepos/tornado-core/circuits/withdraw.circom`
  - Ready Noir: 9 manifests under `/home/teycir/ZkRepos/noir-examples/...`
  - Blocked but structurally fit Halo2: `zkevm-circuits/bin/mpt-test/Cargo.toml`, `zkevm-circuits/testool/Cargo.toml`, and `zkevm-circuits/zkevm-circuits/Cargo.toml`
- Verified blockers on the current machine:
  - `zkevm-circuits` is blocked by missing Rust git dependencies such as `ecc` / `halo2wrong` and other remote Halo2 ecosystem crates.
  - Circom local prerequisites are satisfied for the shortlisted Tornado target, including `circom`, `snarkjs`, and a local `.ptau`.
  - The verified Noir shortlist passes `nargo check` locally.

## Review

- Added `tests/test_curate_zkrepos_targets.py`; focused curation tests pass (`3 passed`).
- `python3 scripts/curate_zkrepos_targets.py --root /home/teycir/ZkRepos --verify --format json` now produces a clean verified shortlist instead of the raw 272-target discovery set.
- The current ready first-pass targets are:
  - `tornado-core/circuits/withdraw.circom`
  - `noir-examples/bignum_example/circuits/Nargo.toml`
  - `noir-examples/lib_examples/base64_example/Nargo.toml`
  - `noir-examples/noir_by_example/generic_traits/noir/Nargo.toml`
  - `noir-examples/noir_by_example/loops/noir/Nargo.toml`
  - `noir-examples/noir_by_example/simple_macros/noir/Nargo.toml`
  - `noir-examples/recursion/circuits/inner/Nargo.toml`
  - `noir-examples/recursion/circuits/recursive/Nargo.toml`
  - `noir-examples/solidity-example/circuits/Nargo.toml`
  - `noir-examples/web-starter/circuits/Nargo.toml`
- The current structurally fit but blocked advanced targets are the three `zkevm-circuits` Cargo manifests noted above.

# Fuzz Validation Run

## Objective

Validate the current end-to-end fuzzing path on a live external target using the supported full-coverage runner, and capture enough evidence to judge whether the tool is operational beyond dry-run readiness.

## Plan

- [x] Confirm the configured default target and local prerequisites are still ready.
- [x] Re-run a low-cost execution pass to verify the full-coverage runner still works on the live target.
- [x] Execute follow-up validation runs to distinguish wrapper health from backend/target integration blockers.
- [x] Summarize what the run proves, what remains unproven, and any next corrective work.

## Findings

- Default runtime target remains `/home/teycir/ZkRepos/tornado-core/circuits/withdraw.circom` with framework `circom` and main component `main`.
- `config.env` points `ZKF_PTAU_PATH` at `bins/ptau/pot12_final.ptau`, and the curated live-target verifier still marks Tornado `withdraw.circom` as `ready`.
- `ITERATIONS=50 TIMEOUT_SECS=600 JOBS=1 WORKERS=2 scripts/run_full_coverage_target.sh` against Tornado `withdraw.circom` exercised all 43 templates and produced a timestamped bundle at `artifacts/manual_runs/ResultJsonTimestamped/20260317_223219_471`, but 12 selector-matched templates failed in backend preflight with `circom_compilation_failed`.
- The concrete Tornado blocker is a Circom compilation failure in the target's legacy `pedersen.circom` include stack. The run outcome for `cveX06_aztec_missing_bit_length_nondeterministic_nullifier` captured the failure under `artifacts/manual_runs/.scan_run_artifacts/scan_run20260317_223219_599_p2_n3/auto__cveX06_aztec_missing_bit_length_nondeterministic_nullifier/run_outcome.json`.
- A second low-cost full-coverage run against `/home/teycir/ZkRepos/circom-ecdsa/scripts/pubkeygen/pubkeygen.circom` also exercised all 43 templates and wrote `artifacts/manual_runs/ResultJsonTimestamped/20260317_223931_975`, but 2 matched templates failed in backend preflight because Circom includes such as `../node_modules/circomlib/circuits/comparators.circom` were not present under that external repo layout.
- A Noir readiness run against `/home/teycir/ZkRepos/noir-examples/noir_by_example/loops/noir/Nargo.toml` first failed in the sandbox with `ReadOnlyFilesystem`, then, after elevated filesystem access, compiled successfully but still failed backend preflight because the tool could not locate the expected Noir ABI artifacts. The escalated evidence bundle is `artifacts/manual_runs/ResultJsonTimestamped/20260317_224111_052`.
- A control run on the in-repo Circom fixture succeeded end to end:
  - Command: `set -a && source config.env && set +a && target/release/zk-fuzzer scan tests/patterns/scan_smoke_mono.yaml --target-circuit tests/circuits/multiplier.circom --main-component Multiplier --framework circom --workers 2 --iterations 50 --timeout 60`
  - Result: `completed`, `scan findings: 33`
  - Evidence: `artifacts/manual_runs/report.json`, `artifacts/manual_runs/report.md`, `artifacts/manual_runs/evidence/EVIDENCE_SUMMARY.md`
  - Proof bundles: `39 confirmed, 0 failed, 0 skipped`

## Review

- The batch wrapper, runtime environment loading, report generation, proof bundling, and in-repo Circom execution path are operational.
- The current external-target validation lane is not yet operator-clean:
  - Tornado `withdraw.circom` is blocked by legacy Circom include compatibility in `pedersen.circom`.
  - `circom-ecdsa` discovery may overstate readiness when repo-local `node_modules` includes are absent.
  - Noir target intake can require elevated filesystem access and still fails later on ABI artifact discovery.
- The most reliable current validation command is the in-repo multiplier control scan above; it proves the fuzzer can execute real attacks and generate reproducible evidence on a self-contained target.

# External Cleanup

## Objective

Remove the concrete backend setup failures discovered during external validation so live targets fail only on real target/tooling limits, not on avoidable path or artifact assumptions.

## Plan

- [x] Patch Circom external-target handling so missing repo-local `circomlib` includes can fall back to the vendored copy.
- [x] Keep Circom compatibility rewriting enabled for legacy include stacks even when the entry file uses a modern pragma.
- [x] Patch Noir ABI loading so projects without the expected JSON artifact can still derive ABI information from source.
- [x] Add focused regression tests for the Circom include fallback and Noir ABI fallback.
- [x] Re-run representative external targets and capture what failures remain after cleanup.

## Findings

- Circom external include resolution now recognizes `circomlib/circuits/...` imports and falls back to the vendored `vendor/circomlib/circuits` copy when the external repo does not ship the expected local dependency tree.
- Circom compatibility rewriting now stays active for modern top-level sources when their transitive include graph still pulls in legacy Circom-1 style files, which clears the original Tornado `pedersen.circom` parse failure.
- Noir ABI loading now falls back to parsing `src/main.nr` when compiled artifact JSON is absent, which clears the original `Failed to locate ABI in Noir artifacts` backend preflight failure.
- Added regression coverage in `tests/test_external_backend_cleanup.rs`:
  - Circom temp-project compile succeeds even when the external fixture references a missing `../node_modules/circomlib/...` include.
  - Noir temp-project compile succeeds and reports both private inputs from source-derived ABI data.
- `cargo test --test test_external_backend_cleanup -- --nocapture` passes with `2 passed`.
- Re-running `/home/teycir/ZkRepos/circom-ecdsa/scripts/pubkeygen/pubkeygen.circom` no longer fails on missing `circomlib` includes; it now compiles and advances to key generation, where it fails because the configured ceremony is too small: `snarkJS: circuit too big for this power of tau ceremony. 164934*2 > 2**12`.
- Re-running `/home/teycir/ZkRepos/tornado-core/circuits/withdraw.circom` no longer fails on the legacy `pedersen.circom` parse issue; it now compiles and advances to key generation, where it fails because the configured ceremony is too small: `snarkJS: circuit too big for this power of tau ceremony. 36451*2 > 2**12`.
- Re-running the Noir readiness target `/home/teycir/ZkRepos/noir-examples/noir_by_example/loops/noir/Nargo.toml` with elevated filesystem access now gets through target setup and attack execution; the first readiness template completed `ok`, which is enough to prove the old ABI-discovery blocker is resolved in practice.

## Review

- External cleanup succeeded for the three concrete integration bugs found during validation:
  - Tornado legacy Circom include handling
  - `circom-ecdsa` missing repo-local `circomlib`
  - Noir ABI artifact discovery
- The remaining Circom external failures are now about proof setup capacity, not source ingestion:
  - the checked-in `bins/ptau/pot12_final.ptau` is too small for larger real-world circuits
- The next operator-grade cleanup should focus on proof setup strategy for large Circom targets, for example by documenting or auto-selecting a larger `.ptau` artifact.

# Larger PTAU Cleanup

## Objective

Raise the Circom proof-capacity ceiling for larger external targets and clean up local tooling so `.ptau` selection is predictable, fast, and operator-friendly.

## Plan

- [x] Inspect the current Circom `.ptau` lookup path and identify where size assumptions leak into external runs.
- [x] Teach the Circom backend to reason about required ceremony power from compiled circuit size.
- [x] Avoid slow `.ptau` inspection paths for common local files by using filename power hints first.
- [x] Make local readiness/curation prefer the strongest staged `.ptau` instead of always gravitating to `pot12`.
- [x] Stage a larger local `.ptau`, switch the runtime config to it, and validate on a representative large external Circom target.

## Findings

- The Circom backend now computes a minimum required Powers of Tau exponent from the compiled constraint count and rejects undersized configured ceremonies with an explicit requirement message instead of failing later inside `snarkjs groth16 setup`.
- Local `.ptau` selection now inspects candidate power and chooses a sufficient staged file when multiple valid `.ptau` files are present.
- To keep large-ptau selection fast, the backend now prefers filename-based power hints for common names such as `pot19_final.ptau` and `powersOfTau28_hez_final_12.ptau`, only falling back to deeper inspection when the filename is ambiguous.
- The local readiness checker and `scripts/curate_zkrepos_targets.py` now prefer the strongest staged `.ptau` under `bins/ptau` instead of hard-preferencing `pot12_final.ptau`.
- Staged a larger local ceremony at `bins/ptau/pot19_final.ptau` and updated the local runtime config to point `ZKF_PTAU_PATH` at it.
- Focused validation now passes on the previously blocked large external Circom target:
  - Command: `target/release/zk-fuzzer scan campaigns/cve/patterns/cveX08_stealthdrop_nondeterministic_nullifier.yaml --target-circuit /home/teycir/ZkRepos/circom-ecdsa/scripts/pubkeygen/pubkeygen.circom --main-component ECDSAPrivToPub --framework circom --workers 2 --iterations 50 --timeout 600`
  - Result: `Using ptau file from ZKF_PTAU_PATH: ".../bins/ptau/pot19_final.ptau"`, followed by `Key setup complete` and `Backend preflight passed`
- This confirms the old `circuit too big for this power of tau ceremony` blocker is cleared for the validated `circom-ecdsa` lane.

## Review

- Large-circuit Circom handling is materially cleaner now:
  - the backend understands required ceremony size
  - local tooling prefers a stronger staged `.ptau`
  - common `.ptau` names do not pay a slow inspection timeout penalty
- The repo bootstrap path still stages only the small `pot12` fixture by default, so operators running bigger external circuits still need to generate or stage a larger ceremony such as `pot19_final.ptau`.

# Backend Test Separation

## Objective

Remove backend-local test modules from `src/` and keep backend coverage under `tests/` to preserve production/test separation.

## Plan

- [x] Inventory source-local test modules under the backend crates touched in this pass.
- [x] Remove backend `mod_tests.rs` attachments from `circom`, `noir`, `cairo`, and `halo2`.
- [x] Recreate the useful public-behavior coverage under `tests/`.
- [x] Re-run focused backend integration tests and verify the source modules no longer embed local test modules.

## Findings

- Removed source-level backend test module attachments from:
  - `crates/zk-backends/src/circom/mod.rs`
  - `crates/zk-backends/src/noir/mod.rs`
  - `crates/zk-backends/src/cairo/mod.rs`
  - `crates/zk-backends/src/halo2/mod.rs`
- Deleted the corresponding backend-local files:
  - `crates/zk-backends/src/circom/mod_tests.rs`
  - `crates/zk-backends/src/noir/mod_tests.rs`
  - `crates/zk-backends/src/cairo/mod_tests.rs`
  - `crates/zk-backends/src/halo2/mod_tests.rs`
- Recreated public-behavior coverage under `tests/`:
  - `tests/test_circom_public_api.rs`
  - `tests/test_noir_public_api.rs`
  - `tests/test_cairo_public_api.rs`
  - `tests/test_halo2_public_api.rs`
- Focused verification passed:
  - `cargo test --test test_circom_public_api -- --nocapture`
  - `cargo test --test test_noir_public_api -- --nocapture`
  - `cargo test --test test_cairo_public_api -- --nocapture`
  - `cargo test --test test_halo2_public_api -- --nocapture`
  - `cargo test --test test_external_backend_cleanup -- --nocapture`
- A direct grep over the four backend module files no longer finds `#[cfg(test)]`, `mod tests;`, or `mod_tests`.

## Review

- Backend production files are cleaner now and no longer carry local test modules for the four moved backends.
- Private-helper-only assertions were not preserved by widening production visibility; the moved coverage stays on public behavior and public analysis APIs.
