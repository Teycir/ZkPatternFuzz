# Cairo Integration Tutorial

Step-by-step path to move a Cairo target into the readiness pipeline.

## 1. Prerequisites

```bash
scarb --version
scarb cairo-run --version
cargo build --release --bin zkpatternfuzz
```

If Scarb/Cairo is missing, install with `scripts/install_cairo.sh`.

## 2. Start With The Existing Local Cairo Target

Reference target used by readiness/breadth:
- `tests/cairo_programs/multiplier.cairo`

Quick integration check:

```bash
ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_cairo_integration -- --exact
```

## 3. Run A Single Cairo Batch

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
  --timeout 20 \
  --emit-reason-tsv
```

## 4. Run Cairo Readiness Directly

```bash
cargo run --release --bin zkpatternfuzz -- \
  --pattern-yaml campaigns/cve/patterns/cveX34_cairo_multiplier_assert_readiness_probe.yaml \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --framework cairo \
  --main-component main \
  --workers 2 \
  --iterations 250 \
  --timeout 30 \
  --output-root artifacts/backend_readiness/cairo \
  --report-json artifacts/backend_readiness/cairo/latest_findings.json
```

Artifacts to check:
- findings report: `artifacts/backend_readiness/cairo/latest_findings.json`
- run outcomes under `artifacts/backend_readiness/cairo/.scan_run_artifacts/`

```bash
scripts/backend_readiness_dashboard.sh
cat artifacts/backend_readiness/latest_report.json
```

## 7. Troubleshooting Quick Notes

- `backend_preflight_failed`: Cairo runtime/toolchain not resolvable.
- `selector_mismatch`: template mismatch, not an executor crash.
- `runtime_error`: inspect lane matrix log for target-specific details.
- `run_outcome_missing`: interrupted execution/artifact write path; rerun single target with `--emit-reason-tsv`.

## 8. Done Criteria For Cairo Capacity

1. `test_cairo_integration` passes consistently.
2. Cairo lane report is generated each run.
3. Cairo reason codes are classified (no unbounded missing outcomes).
4. Aggregate backend dashboard keeps Cairo above gate thresholds.
