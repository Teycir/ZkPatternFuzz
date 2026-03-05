# Noir Backend Troubleshooting Guide

Operational guide for diagnosing Noir readiness and full-capacity execution issues.

## 1. Fast Health Check

```bash
nargo --version
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_integration -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_local_prove_verify_smoke -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_constraint_coverage -- --exact
scripts/run_noir_readiness.sh --workers 2 --iterations 250 --timeout 30
```

Then inspect:

```bash
cat artifacts/backend_readiness/noir/latest_report.json
```

## 2. Common Failure Modes

| Signal | Likely cause | Fix |
|---|---|---|
| `backend_preflight_failed` | Missing or incompatible Noir toolchain | Verify `nargo --version` and project layout |
| `selector_mismatch` | Template does not fit target semantics | Choose a better alias or explicit pattern |
| `run_outcome_missing` | Early abort or interrupted artifact write | Rerun with `--emit-reason-tsv` and inspect logs |
| `runtime_error` | Executor path failure | Reproduce on one target and inspect stderr |
| missing `bb` | External Barretenberg binary not installed | Install matching `bb` and ensure it is on `PATH` |

## 3. Target Path Rule

For Noir, `target_circuit` should be the project `Nargo.toml`, not the `.nr` source file.

## 4. Direct Single-Target Repro

Export writable batch paths first:

```bash
export ZKF_SCAN_OUTPUT_ROOT="$PWD/artifacts/noir_manual"
export ZKF_RUN_SIGNAL_DIR="$PWD/artifacts/noir_manual/run_signals"
export ZKF_BUILD_CACHE_DIR="$PWD/artifacts/noir_manual/build_cache"
export ZKF_SHARED_BUILD_CACHE_DIR="$PWD/artifacts/noir_manual/build_cache"
export ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS=1800
export ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS=3600
export ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS=120
mkdir -p "$ZKF_SCAN_OUTPUT_ROOT" "$ZKF_RUN_SIGNAL_DIR" "$ZKF_BUILD_CACHE_DIR"
```

Then run:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias readiness_noir \
  --target-circuit /path/to/project/Nargo.toml \
  --main-component main \
  --framework noir \
  --jobs 1 \
  --workers 2 \
  --iterations 100 \
  --timeout 20 \
  --dry-run \
  --emit-reason-tsv
```

## 5. Readiness And Release Gate View

- Noir lane report: `artifacts/backend_readiness/noir/latest_report.json`
- Aggregate dashboard: `artifacts/backend_readiness/latest_report.json`

Refresh the aggregate dashboard with:

```bash
scripts/backend_readiness_dashboard.sh
```

## 6. Practical Checklist

1. `test_noir_integration` passes.
2. `test_noir_local_prove_verify_smoke` passes.
3. `test_noir_constraint_coverage` passes.
4. Noir readiness report has no unexpected `backend_preflight_failed`.
5. Any remaining `run_outcome_missing` cases are explicitly classified or reproduced.
