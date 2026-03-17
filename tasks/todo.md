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
- [ ] Discover current targets dynamically from `/home/teycir/ZkRepos` instead of assuming the checked-in external matrix is current.
- [ ] Select the first target family to onboard based on framework fit and template coverage.
- [ ] Decide whether to use standardized wrappers or direct batch mode for the requested "maximum templates" behavior.
- [ ] Add or adapt a dynamic intake path so current `/home/teycir/ZkRepos` targets are runnable without stale hardcoded bindings.
- [x] Rename the runtime config file away from `.env` and update the loading path, examples, and operator docs.
- [ ] Validate dependency readiness for the chosen target repo.
- [ ] Run a low-cost dry-run to confirm dispatch works before any heavy fuzzing.
- [ ] Run the chosen broader campaign and capture evidence artifacts.

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

## Review

- Runtime config renamed to `config.env`, with loaders, examples, and operator docs updated.
- Standardized wrappers now accept direct target paths plus optional `*_FRAMEWORK` and `*_MAIN_COMPONENT` hints in `config.env`.
- Dynamic discovery for the full `/home/teycir/ZkRepos` target set is still pending.
