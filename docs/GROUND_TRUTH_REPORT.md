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

## Detected And Missed Targets

Detected in both seeded trials:

- `nullifier_collision`
- `range_overflow`
- `bit_decomposition`
- `division_by_zero`

Missed in both seeded trials:

- `merkle_unconstrained`

## Source Artifacts

- Markdown summary: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.md`
- JSON summary: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`
- Trial outcomes: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/outcomes.json`
- Related roadmap snapshot: [docs/ROADMAP.md](ROADMAP.md)
