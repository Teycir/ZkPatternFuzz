# Dead Code Analysis (2026-02-25)

## Scope
Goal: reduce repository surface to one operational flow:
- input: JSON run config
- input: YAML vulnerability patterns
- execution: fuzz target circuit
- output: JSON findings report

Canonical binary after cleanup: `zkpatternfuzz` (`src/bin/zkpatternfuzz.rs`).

## Method
- Static reference scan across `src/`, `tests/`, `scripts/`, `docs/`.
- Compile validation with `cargo check --all-targets`.
- Test compile validation with `cargo test --tests --no-run`.
- Focus on entrypoints and wrappers that do not participate in the canonical flow.

## Removed As Dead/Legacy Entry Points
### Binaries removed
- `src/bin/zk0d_matrix.rs`
- `src/bin/zk0d_benchmark.rs`
- `src/bin/zk0d_skimmer.rs`
- `src/bin/zk0d_noir_throughput.rs`
- `src/bin/zk0d_config_migrate.rs`
- `src/bin/gen_tornado_seed.rs`

### Legacy wrapper scripts removed
- `scripts/run_backend_readiness_lanes.sh`
- `scripts/run_skimmer.sh`
- `scripts/prefetch_external_toolchains.sh`
- `scripts/zeroday_workflow.sh`
- `scripts/run_halo2_readiness.sh`
- `scripts/profile_large_circuit_memory.sh`
- `scripts/benchmark_parallel_speedup.sh`
- `scripts/run_non_circom_collision_stress.sh`
- `scripts/run_cairo_readiness.sh`
- `scripts/non_circom_followup_gate.sh`
- `scripts/fresh_clone_bootstrap_validate.sh`
- `scripts/phase3a_timeout_noir_validate.sh`
- `scripts/run_noir_readiness.sh`
- `scripts/run_multibackend_effectiveness_sample.sh`
- `scripts/run_breadth_step.sh`

### Obsolete tests removed
- `tests/test_bin_zk0d_matrix.rs`
- `tests/test_bin_zk0d_benchmark.rs`
- `tests/test_readiness_matrix_targets.py`
- `tests/test_external_roadmap_targets.rs`

## Replacement / Surviving Path
- Binary: `zkpatternfuzz`
- Inputs:
  - `--config-json` (JSON/YAML config; supports `run_overrides` wrapper)
  - `--pattern-yaml` (comma-separated YAML pattern paths)
  - target fields (`--target-circuit`, `--framework`, `--main-component`)
- Output:
  - `--report-json <path>` with verdict + per-pattern findings

## Validation Status
- `cargo check --all-targets`: PASS
- `cargo test --tests --no-run`: PASS
- `cargo test --test test_bin_zkpatternfuzz`: PASS (19 tests)

## Residual Cleanup Backlog
These are documentation-only leftovers (not executable code paths) and should be normalized to avoid operator confusion:
- `docs/RELEASE_CHECKLIST.md` (still contains broader release-gate script assumptions outside the direct runner)
- `docs/TARGETS.md` (contains profile/registry guidance that should be split into a separate legacy note if strict minimal mode is enforced)
