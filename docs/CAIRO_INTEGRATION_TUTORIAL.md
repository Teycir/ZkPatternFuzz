# Cairo Integration Tutorial

Current path for moving a Cairo target into the readiness pipeline.

## 1. Prerequisites

```bash
scarb --version
scarb cairo-run --version
cairo-compile --version
cairo-run --version
cargo build --release --bins
```

If Cairo tooling is missing, install it from the upstream Scarb and Cairo projects. This repository no longer ships a working `install_cairo.sh` helper.

## 2. Start With The Existing Local Cairo Target

Reference fixture:

- `tests/cairo_programs/multiplier.cairo`

Quick integration check:

```bash
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_cairo_integration -- --exact
```

## 3. Run Cairo Readiness

Primary operational entrypoint:

```bash
scripts/run_cairo_readiness.sh --workers 2 --iterations 250 --timeout 30
```

Key artifacts:

- `artifacts/backend_readiness/cairo/latest_report.json`
- `artifacts/backend_readiness/latest_report.json`

## 4. Reproduce A Single Cairo Target

Export writable batch paths first:

```bash
export ZKF_SCAN_OUTPUT_ROOT="$PWD/artifacts/cairo_manual"
export ZKF_RUN_SIGNAL_DIR="$PWD/artifacts/cairo_manual/run_signals"
export ZKF_BUILD_CACHE_DIR="$PWD/artifacts/cairo_manual/build_cache"
export ZKF_SHARED_BUILD_CACHE_DIR="$PWD/artifacts/cairo_manual/build_cache"
export ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS=1800
export ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS=3600
export ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS=120
mkdir -p "$ZKF_SCAN_OUTPUT_ROOT" "$ZKF_RUN_SIGNAL_DIR" "$ZKF_BUILD_CACHE_DIR"
```

Then run:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias readiness_cairo \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --main-component main \
  --framework cairo \
  --jobs 1 \
  --workers 2 \
  --iterations 100 \
  --timeout 30 \
  --dry-run \
  --emit-reason-tsv
```

## 5. Troubleshooting Notes

- `backend_preflight_failed`: Cairo runtime or toolchain not resolvable.
- `selector_mismatch`: template mismatch, not an executor crash.
- `runtime_error`: inspect the readiness logs for target-specific stderr.
- `run_outcome_missing`: interrupted execution or artifact write; rerun a single target.

## 6. Done Criteria

1. `test_cairo_integration` passes.
2. `test_cairo_stone_prover_prove_verify_smoke` and `test_cairo1_scarb_prove_verify_smoke` pass when applicable.
3. `scripts/run_cairo_readiness.sh` produces `artifacts/backend_readiness/cairo/latest_report.json`.
4. Cairo remains passing in the aggregate backend readiness dashboard.
