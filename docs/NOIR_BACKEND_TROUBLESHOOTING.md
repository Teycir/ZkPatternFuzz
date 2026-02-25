# Noir Backend Troubleshooting Guide

Operational guide for diagnosing Noir readiness and full-capacity execution issues.

## 1. Fast Health Check

Run these in order:

```bash
nargo --version
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_integration -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_local_prove_verify_smoke -- --exact
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_constraint_coverage -- --exact
scripts/run_noir_readiness.sh --workers 2 --iterations 100 --timeout 20
```

Then inspect:

```bash
cat artifacts/backend_readiness/noir/latest_report.json
```

## 2. Common Failure Modes

| Signal | Likely cause | Fix |
|---|---|---|
| `backend_preflight_failed` | Missing/invalid Noir toolchain, bad `Nargo.toml` path | Verify `nargo --version`, ensure `target_circuit` points to a real `Nargo.toml` |
| High `selector_mismatch` | Template attack does not match target circuit selectors | Not a runtime crash; tune alias/templates for Noir target shape |
| `run_outcome_missing` | Early process abort or artifact write interruption | Re-run with `--emit-reason-tsv`, inspect matrix log |
| `runtime_error` | Executor path failure, often dependency/layout mismatch | Check lane logs and reproduce with a single target run |
| Integration test fails but matrix runs | Real-backend env/test setup mismatch | Re-run with `ZKFUZZ_REAL_BACKENDS=1` and inspect per-test log from lane output |
| `proof generation failed: missing Barretenberg 'bb' tool` | Project/toolchain expects external `bb` binary but it is unavailable | Install matching Barretenberg and ensure `bb` is on `PATH` |

## 3. Target Path Rules (Noir)

For Noir, `target_circuit` should be the project `Nargo.toml`, not the `.nr` source file:

```yaml
targets:
  - name: my_noir_target
    target_circuit: /path/to/project/Nargo.toml
    main_component: main
    framework: noir
    alias: readiness_noir
    enabled: true
```

## 4. Reproduce A Single Failing Target

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
  --emit-reason-tsv
```

## 5. Readiness And Release Gate View

- Noir lane report: `artifacts/backend_readiness/noir/latest_report.json`
- Aggregated report: `artifacts/backend_readiness/latest_report.json`

Run all backend lanes plus aggregate dashboard:

```bash
scripts/run_backend_readiness_lanes.sh --enforce-dashboard
```

Default gate intent is non-Circom readiness with:
- minimum completion ratio per backend (`>= 0.90`)
- `runtime_error` at `0`
- `backend_preflight_failed` at `0`

## 6. Practical Checklist Before Marking Noir Ready

1. `test_noir_integration` passes.
2. `test_noir_constraint_coverage` passes.
3. Noir lane report has no `backend_preflight_failed`.
4. `run_outcome_missing` is eliminated or explicitly classified.
5. Aggregated backend dashboard keeps Noir in passing state.
