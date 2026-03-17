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
