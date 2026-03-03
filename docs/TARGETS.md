# Target Execution Model

This document describes how to run reusable attack-pattern YAML against concrete targets.

## Key Separation

- Pattern YAML: attack logic only (reusable)
- Runtime target: passed at execution (`--target-circuit`, `--main-component`, `--framework`)
- Catalog: pattern grouping via `targets/fuzzer_registry.yaml`

## Catalog-Driven Batch Runs

Default behavior (no `--pattern-yaml`, `--collection`, `--alias`, `--template`):
- auto-discover and run all pattern-compatible YAML files in the repository.

List collections, aliases, and templates:

```bash
cargo run --release --bin zkpatternfuzz -- --list-catalog
```

Run always-on patterns:

```bash
cargo run --release --bin zkpatternfuzz -- \
  --alias always \
  --target-circuit /media/elements/Repos/zk0d/path/to/target.circom \
  --main-component Main \
  --framework circom
```

Run with direct JSON config + explicit YAML pattern paths:

```bash
cargo run --release --bin zkpatternfuzz -- \
  --config-json targets/external/target_run_overrides/ext015_orion_svm_classifier_test.json \
  --pattern-yaml campaigns/cve/patterns/cveX34_cairo_multiplier_assert_readiness_probe.yaml \
  --target-circuit /media/elements/Repos/zkml/orion/tests/ml/svm_classifier_test.cairo \
  --framework cairo \
  --main-component main \
  --output-root artifacts/simple_flow \
  --report-json artifacts/simple_flow/findings.json
```

### Strict 3-Check Gate (Enforced by `zkpatternfuzz`)

Every batch run enforces:

1. Expected template count before run.
2. Completion check after run (`executed == expected` and `failures == 0`).
3. Artifact reconciliation for this batch window (all expected output suffixes observed under new `scan_run*` artifact roots).

You will see:

```text
Gate 1/3 (expected templates): <N>
[BATCH PROGRESS] 1/<N> (...) ok=1 fail=0 ... last=<template>.yaml result=ok
[BATCH PROGRESS] ...
Batch complete. Templates executed: <N>, failures: 0, duration: <sec>s, avg_rate: <r>/s
Gate 2/3 (completion line): PASS ...
Gate 3/3 (artifact reconciliation): PASS ...
```

If any gate fails, `zkpatternfuzz` exits non-zero.

To suppress live progress lines (for quieter CI logs), pass:

```bash
--no-batch-progress
```

Run additional patterns:

```bash
cargo run --release --bin zkpatternfuzz -- \
  --alias deep \
  --target-circuit /media/elements/Repos/zk0d/path/to/target.circom \
  --main-component Main \
  --framework circom
```

Then build a per-backend report:

```bash
python3 scripts/build_backend_effectiveness_report.py --repo-root .
```

Outputs are written under:

- `artifacts/benchmark_runs/benchmark_<timestamp>/summary.json`
- `artifacts/benchmark_runs/benchmark_<timestamp>/outcomes.json`
- `artifacts/benchmark_runs/benchmark_<timestamp>/summary.md`
- `artifacts/benchmark_trends/latest_trend.json` (nightly trend snapshot)
- `artifacts/benchmark_trends/latest_failure_dashboard.json` (nightly failure-class dashboard)
- `artifacts/benchmark_trends/latest_failure_dashboard.md` (human-readable failure-class pass/fail table)

## Cross-Backend Throughput Harness

Use the throughput harness to compare Noir/Cairo/Halo2 readiness lane throughput
under the same runtime parameters.

```bash
./scripts/benchmark_cross_backend_throughput.sh \
  --runs 2 \
  --iterations 20 \
  --timeout 20 \
  --workers 2 \
  --batch-jobs 1 \
  --enforce
```

Artifacts:

- `artifacts/backend_throughput/latest_report.json`
- `artifacts/backend_throughput/latest_report.md`
- `artifacts/backend_throughput/raw/run_metrics.jsonl`

## Large-Circuit Memory Profiling

Use the memory profiling harness to run selected large targets under
`/usr/bin/time -v` and capture peak RSS by backend/framework.

```bash
# Memory profiling is now integrated into the release candidate gate.
# Use the --backend-capacity-fitness-* flags of release_candidate_gate.sh
# or run benchmark_cross_backend_throughput.sh for throughput measurements.
```

Artifacts:

- `artifacts/memory_profiles/latest_report.json`
- `artifacts/memory_profiles/latest_report.md`
- `artifacts/memory_profiles/raw/results.tsv`

Failure dashboard class thresholds are configurable without changing output paths:

- Environment overrides:
  - `ZKF_FAILURE_MAX_RATE_LOCK_CONTENTION`
  - `ZKF_FAILURE_MAX_RATE_SETUP_TOOLING`
  - `ZKF_FAILURE_MAX_RATE_TIMEOUTS`
  - `ZKF_FAILURE_MAX_RATE_STABILITY_RUNTIME`
  - `ZKF_FAILURE_MAX_RATE_CONTRACT_OR_CONFIG`
  - `ZKF_FAILURE_MAX_RATE_OTHER_FAILURE`
- Optional CLI overrides:
  - `cargo run --bin zkf_checks -- benchmark-failure-dashboard --threshold setup_tooling=0.20 --threshold timeouts=0.12`

The default suites file includes:

- `vulnerable_ground_truth` (positive suite, 5 known vulnerable circuits)
- `safe_regression` (negative suite, 5 known safe circuits)
- `real_world_examples` (disabled by default, `/media/elements/Repos/zk0d` examples)

Config profiles:

- `dev`:
  - `targets/benchmark_suites.dev.yaml`
  - `targets/benchmark_registry.dev.yaml`
  - Fast, stable local validation defaults.
- `prod`:
  - `targets/benchmark_suites.prod.yaml`
  - `targets/benchmark_registry.prod.yaml`
  - Heavier production-depth pattern budgets.
- No profile:
  - Backward-compatible defaults (`targets/benchmark_suites.yaml`, `targets/benchmark_registry.yaml`).

`zkpatternfuzz` also supports profile-based registry selection:

```bash
# Fast development catalog
cargo run --release --bin zkpatternfuzz -- --config-profile dev --list-catalog

# Production CVE catalog
cargo run --release --bin zkpatternfuzz -- --config-profile prod --list-catalog
```

To run a tighter set, pass explicit pattern files:

```bash
cargo run --release --bin zkpatternfuzz -- \
  --pattern-yaml campaigns/cve/patterns/cveX01_dark_forest_missing_bit_length.yaml,campaigns/cve/patterns/cveX04_semaphore_missing_range_check.yaml \
  --target-circuit /path/to/target.circom \
  --framework circom \
  --main-component main \
  --output-root artifacts/simple_flow \
  --report-json artifacts/simple_flow/findings.json
```

## Release Validation Workflow (Scheduled + Manual)

Use the dedicated GitHub Actions workflow to validate release criteria.
- Scheduled lane: runs daily at 03:20 UTC for strict 14-day maturity/flake streak tracking.
- Manual lane: `workflow_dispatch` for release cutover validation with rollback checks.

Trigger from CLI:

```bash
gh workflow run "Release Validation" \
  -f stable_ref=<previous_stable_tag_or_commit> \
  -f config_profile=prod \
  -f iterations=400 \
  -f timeout=180 \
  -f required_passes=2
```

Watch the run:

```bash
gh run list --workflow "Release Validation" --limit 1
gh run watch <run_id> --exit-status
```

Notes:
- `stable_ref` is required and should point to the previous production-stable
  tag/commit used for rollback validation (manual lane).
- `required_passes=2` matches the release checklist requirement for consecutive
  release-candidate gate passes.
- If `gh` is unavailable, run the same workflow via GitHub Actions UI using
  `workflow_dispatch` inputs.

## Naming Rule

Template filenames must follow:

- `<attacktype>_<attack>.yaml`

The runner always executes in parallel and supports regex-focused dispatch.
