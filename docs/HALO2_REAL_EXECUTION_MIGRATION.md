# Halo2 Migration Guide From Legacy Test Mode

Guide to move campaigns from legacy test execution into real Halo2-backed execution.

## 1. Why Migrate

Testing mode is useful for fast logic checks, but readiness requires real backend execution to validate:
- input/output wiring behavior
- integration with Halo2 specs/projects
- runtime stability under real proof paths

## 2. Baseline: Keep A Test Campaign For Quick Regression

Keep your existing test config for short feedback cycles, then add a Halo2 variant.

## 3. Move Target Definition To Halo2

Minimal JSON-spec target example:

```yaml
campaign:
  target:
    framework: halo2
    circuit_path: tests/halo2_specs/minimal.json
    main_component: minimal
```

Cargo project target example:

```yaml
campaign:
  target:
    framework: halo2
    circuit_path: /path/to/halo2-project/Cargo.toml
    main_component: zk0d_mul
```

## 4. Validate Halo2 Integration Tests

```bash
export RUSTUP_TOOLCHAIN=nightly
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_json_integration -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_real_circuit_constraint_coverage -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_scaffold_execution_stability -- --exact
HALO2_THROUGHPUT_ROUNDS=2 ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_scaffold_production_throughput -- --exact
```

## 5. Run Halo2 Readiness Lane

```bash
scripts/run_halo2_readiness.sh --workers 2 --iterations 100 --timeout 20
cat artifacts/backend_readiness/halo2/latest_report.json
```

Primary lane targets come from `targets/zk0d_matrix_halo2_readiness.yaml`.

## 6. Common Migration Pitfalls

| Symptom | Root cause | Action |
|---|---|---|
| `runtime_error` on JSON spec | Input metadata mismatch or malformed spec | Validate spec fields and rerun single target |
| `backend_preflight_failed` | Nightly/toolchain or build dependency issues | `export RUSTUP_TOOLCHAIN=nightly`, rebuild target |
| High `selector_mismatch` | Alias/templates not aligned with target semantics | Tune alias/template set (`readiness_halo2`) |
| Wrong `main_component` behavior | Component name does not match target | Update `main_component` in matrix/campaign |

## 7. Run Full Non-Circom Gate

```bash
scripts/run_backend_readiness_lanes.sh --enforce-dashboard
cat artifacts/backend_readiness/latest_report.json
```

## 8. Exit Criteria For Halo2 Migration

1. Halo2 integration coverage + stability + throughput tests pass.
2. Halo2 lane report is consistently produced.
3. Canonical Halo2 targets run without `runtime_error`.
4. Halo2 contributes passing metrics in aggregated readiness dashboard.
