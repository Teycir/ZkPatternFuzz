# Ground Truth Validation

Published from: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`
Generated at source: `2026-02-19T21:26:57.645761822+00:00`

## Scope

- Benchmark suites: `safe_regression`, `vulnerable_ground_truth`
- Suite config: `targets/benchmark_suites.dev.yaml`
- Trials per target: `2`
- Base seed: `42`
- Iterations per run: `50`
- Timeout per run: `10`
- Confidence threshold: `low`

## Current Published Metrics

| Metric | Value |
| --- | --- |
| Total runs | `20` |
| Overall completion rate | `100.0%` |
| Attack-stage reach rate | `100.0%` |
| Vulnerable recall | `80.0%` |
| Vulnerable recall (high-confidence) | `40.0%` |
| Precision | `100.0%` |
| Safe actionable false-positive rate | `0.0%` |
| Safe high-confidence false-positive rate | `0.0%` |

## Confidence Intervals

| Metric | 95% CI |
| --- | --- |
| Vulnerable recall | `49.0% - 94.3%` |
| Vulnerable high-confidence recall | `16.8% - 68.7%` |
| Precision | `67.6% - 100.0%` |
| Safe actionable false-positive rate | `0.0% - 27.8%` |
| Safe high-confidence false-positive rate | `0.0% - 27.8%` |

## Suite Breakdown

| Suite | Runs | Result |
| --- | ---: | --- |
| `safe_regression` | `10` | `0.0%` actionable false positives, `100.0%` completion |
| `vulnerable_ground_truth` | `10` | `80.0%` recall, `40.0%` high-confidence recall, `100.0%` completion |

## Notable Outcome

The target documented in [tests/ground_truth_circuits/README.md](../tests/ground_truth_circuits/README.md) is `90%+` detection on the ground-truth suite. The latest published benchmark in this repository does **not** meet that target yet:

- published vulnerable recall: `80.0%`
- published high-confidence vulnerable recall: `40.0%`

This report intentionally records the measured result rather than the desired target.

The high-confidence figure should also be read in the context of the benchmark profile used for this publication:

- only `50` iterations per run
- only `10` seconds timeout per run
- lightweight benchmark template `campaigns/benchmark/patterns/underconstrained_strict_probe.yaml`
- strict high-confidence thresholding enabled in the benchmark summary

These settings are useful for fast comparative regression, but they are intentionally shallow and are not representative of a production-depth campaign.

## Detected And Missed Targets

Detected in both seeded trials:

- `nullifier_collision`
- `range_overflow`
- `bit_decomposition`
- `division_by_zero`

Missed in both seeded trials:

- `merkle_unconstrained`

## Merkle Miss Diagnosis

Current diagnosis for `merkle_unconstrained`:

- the target did not fail due to infrastructure or setup issues
- both benchmark trials completed successfully
- both trials reached the attack stage
- both trials produced `0` findings

This points away from backend readiness problems and toward signal-generation gaps under the shallow benchmark profile.

Most likely contributing factors:

- the published benchmark used the generic strict probe template, which only carries a baseline invariant (`field_input_domain`) and does not encode a Merkle-specific binary-path invariant
- the dedicated regression test for this same target in [ground_truth_regression.rs](../tests/ground_truth_regression.rs) expects detection with `10_000` iterations, which is materially deeper than the published benchmark's `50`
- the current `MerkleOracle` models extracted path indices as booleans, which is useful for some Merkle soundness checks but is not a direct detector for arbitrary non-binary selector values

Working conclusion:

- primary suspicion: benchmark-pattern gap plus insufficient search depth
- secondary suspicion: Merkle oracle coverage is too indirect for this bug class in generic benchmark mode

Follow-up status:

- benchmark suite routing now assigns `merkle_unconstrained` to `campaigns/benchmark/patterns/merkle_path_binarity_probe.yaml` in default/dev runs and `merkle_path_binarity_probe_prod.yaml` in prod-depth runs
- the published metrics at the top of this report predate that routing change and should be treated as a pre-fix baseline for this target
- the next required measurement is a rerun at production-depth settings so this diagnosis can move from configuration hypothesis to measured outcome

## Source Artifacts

- Markdown summary: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.md`
- JSON summary: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`
- Trial outcomes: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/outcomes.json`
- Related roadmap snapshot: [docs/ROADMAP.md](ROADMAP.md)
