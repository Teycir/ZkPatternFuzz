# Target Execution Model

This document covers the current ways to run pattern YAML against concrete targets.

## Core Separation

- Pattern YAML contains reusable attack logic.
- Runtime target details are passed at execution time.
- Registry files group patterns into collections and aliases.
- Output roots are environment-managed; direct batch runs do not accept `--output-root` or `--report-json`.

## Recommended Paths

Use the standardized wrappers for routine smoke, standard, and deep work:

```bash
scripts/run_std_smoke.sh
scripts/run_std_standard.sh
scripts/run_std_deep.sh
```

Use `zk-fuzzer scan` for single-pattern work and `zkpatternfuzz` for catalog-driven batches.

## Direct Batch Environment

For direct `zkpatternfuzz` use, export writable paths and stage timeouts first:

```bash
export ZKF_SCAN_OUTPUT_ROOT="$PWD/artifacts/manual_batch"
export ZKF_RUN_SIGNAL_DIR="$PWD/artifacts/manual_batch/run_signals"
export ZKF_BUILD_CACHE_DIR="$PWD/artifacts/manual_batch/build_cache"
export ZKF_SHARED_BUILD_CACHE_DIR="$PWD/artifacts/manual_batch/build_cache"
export ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS=1800
export ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS=3600
export ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS=120
mkdir -p "$ZKF_SCAN_OUTPUT_ROOT" "$ZKF_RUN_SIGNAL_DIR" "$ZKF_BUILD_CACHE_DIR"
```

## List The Catalog

The current `--list-catalog` path expects registry mode, so pair it with a selector flag such as `--alias always`:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias always \
  --jobs 1 \
  --workers 2 \
  --list-catalog
```

## Run A Catalog Alias

Verified dry-run example against the local Cairo readiness fixture:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias readiness_cairo \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --main-component main \
  --framework cairo \
  --jobs 1 \
  --workers 2 \
  --iterations 50 \
  --timeout 30 \
  --dry-run \
  --emit-reason-tsv
```

This produces:

- `Gate 1/3` expected-template counting,
- per-template dispatch to `zk-fuzzer scan`,
- timestamped bundles under `ZKF_SCAN_OUTPUT_ROOT/ResultJsonTimestamped/`,
- `.scan_run_artifacts/` entries for non-dry runs.

## Run An Explicit Pattern File

Use `zk-fuzzer scan` when you already know the exact pattern YAML you want:

```bash
target/release/zk-fuzzer scan \
  campaigns/cve/patterns/cveX34_cairo_multiplier_assert_readiness_probe.yaml \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --main-component main \
  --framework cairo \
  --workers 2 \
  --iterations 50 \
  --timeout 30 \
  --dry-run
```

Use `zkpatternfuzz --pattern-yaml ...` only when you specifically need batch-style orchestration around explicit files.

## `--config-json` Notes

`zkpatternfuzz --config-json` is still supported for target and environment overrides, but output paths remain env-only. If your config file contains `output_root`, the runner now rejects it.

## Benchmarks

Use the benchmark runner for repeated-trial suites:

```bash
target/release/zk0d_benchmark --help
scripts/run_benchmarks.sh --help
```

The canonical benchmark root for the release gate is `artifacts/benchmark_runs`.

## Outputs

Important locations:

- `ZKF_SCAN_OUTPUT_ROOT/ResultJsonTimestamped/`: timestamped result bundles
- `ZKF_SCAN_OUTPUT_ROOT/.scan_run_artifacts/`: per-template artifacts
- `ZKF_RUN_SIGNAL_DIR`: live run status and signal files
- target-specific readiness or benchmark directories under `artifacts/`
