# Halo2 Migration Guide From Legacy Test Mode

Guide to move campaigns from legacy test execution into real Halo2-backed execution.

## 1. Why Migrate

Testing mode is useful for fast logic checks, but readiness requires real backend execution to validate:

- input and output wiring behavior,
- JSON-spec and Cargo-target integration,
- runtime stability under real proof paths.

## 2. Minimal Target Shapes

JSON-spec target:

```yaml
campaign:
  target:
    framework: halo2
    circuit_path: tests/halo2_specs/minimal.json
    main_component: minimal
```

Cargo-project target:

```yaml
campaign:
  target:
    framework: halo2
    circuit_path: /path/to/halo2-project/Cargo.toml
    main_component: zk0d_mul
```

## 3. Integration Tests

```bash
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_json_integration -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_real_circuit_constraint_coverage -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_scaffold_execution_stability -- --exact
HALO2_THROUGHPUT_ROUNDS=2 ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_scaffold_production_throughput -- --exact
```

## 4. Use The Readiness Wrapper

Primary operational entrypoint:

```bash
scripts/run_halo2_readiness.sh --workers 2 --iterations 100 --timeout 20
```

## 5. Reproduce A Single Target

Export writable batch paths first:

```bash
export ZKF_SCAN_OUTPUT_ROOT="$PWD/artifacts/halo2_manual"
export ZKF_RUN_SIGNAL_DIR="$PWD/artifacts/halo2_manual/run_signals"
export ZKF_BUILD_CACHE_DIR="$PWD/artifacts/halo2_manual/build_cache"
export ZKF_SHARED_BUILD_CACHE_DIR="$PWD/artifacts/halo2_manual/build_cache"
export ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS=1800
export ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS=3600
export ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS=120
mkdir -p "$ZKF_SCAN_OUTPUT_ROOT" "$ZKF_RUN_SIGNAL_DIR" "$ZKF_BUILD_CACHE_DIR"
```

Then run:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias readiness_halo2 \
  --target-circuit tests/halo2_specs/minimal.json \
  --main-component minimal \
  --framework halo2 \
  --jobs 1 \
  --workers 2 \
  --iterations 100 \
  --timeout 20 \
  --dry-run \
  --emit-reason-tsv
```

## 6. Common Migration Pitfalls

| Symptom | Root cause | Action |
|---|---|---|
| `runtime_error` on JSON spec | malformed spec or input metadata mismatch | validate spec fields and rerun single target |
| `backend_preflight_failed` | nightly or dependency issue | set `RUSTUP_TOOLCHAIN=nightly`, rebuild, rerun |
| high `selector_mismatch` | alias or templates do not match target semantics | tune selection |
| wrong `main_component` behavior | target entrypoint mismatch | fix `main_component` |

## 7. Exit Criteria

1. Halo2 integration coverage, stability, and throughput tests pass.
2. `scripts/run_halo2_readiness.sh` consistently produces a lane report.
3. Canonical Halo2 targets run without unexpected `runtime_error`.
4. Halo2 contributes passing metrics in the aggregate readiness dashboard.
