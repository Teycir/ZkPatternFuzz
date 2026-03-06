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

## Merkle Target Status

Published baseline status for `merkle_unconstrained`:

- the benchmark published at the top of this report still missed the target in both seeded trials
- those published metrics remain the official fast-regression baseline for this document

Current focused rerun status on the current tree:

- a dedicated diagnostic rerun now detects `merkle_unconstrained`:
  - suite artifact: `artifacts/benchmark_runs_merkle_diagnostic_no_rlimit_as/benchmark_20260306_015923/summary.json`
  - scan artifact: `artifacts/benchmark_runs_merkle_diagnostic_no_rlimit_as/scan_outputs/merkle_diagnostic/merkle_unconstrained/trial_1_seed_42/.scan_run_artifacts/scan_run20260306_015826/auto__merkle_path_binarity_probe/report.json`
- the suite completed successfully, reached the attack stage, and recorded `1/1` detections
- high-confidence detection is still `0/1`, so this focused rerun improves recall but does not yet improve the published high-confidence number
- the critical signal is a real `underconstrained` finding, not just a generic crash or hint-only artifact
- underconstrained execution summary from the diagnostic rerun:
  - `attempted=128`
  - `successful=28`
  - `failed=100`
  - `collision_groups=1`
  - `non_binary_generated=40/128`
  - `non_binary_successful=6/28`

What changed between the miss and the detection:

- benchmark suite routing now assigns `merkle_unconstrained` to `campaigns/benchmark/patterns/merkle_path_binarity_probe.yaml` in default/dev runs and `merkle_path_binarity_probe_prod.yaml` in prod-depth runs
- quantified `forall` array invariants now evaluate correctly in both the core semantic oracle engine and the fuzzer invariant checker
- reconciled indexed inputs such as `path_indices[0]` are now aliased back to their base array names for invariant evaluation and scalarized when the executor-derived schema flattens arrays into individual field slots
- underconstrained attack seeding now loads direct witness seeds from `campaigns/benchmark/seed_inputs/merkle_unconstrained_seed_inputs.json` instead of relying only on corpus-derived recovery
- Circom per-exec isolation no longer applies a default `RLIMIT_AS` cap when the operator has not explicitly set `isolation_memory_limit_mb` or `isolation_memory_limit_bytes`; this removes the prior `WebAssembly.instantiate(): Out of memory` worker failure seen under isolated witness generation

Remaining limitations:

- the published metrics at the top of this report still predate these changes and should be treated as a pre-fix baseline
- the focused rerun is diagnostic, not yet a replacement for the full `vulnerable_ground_truth` benchmark publication
- `100/128` underconstrained candidate executions still failed, mostly due to circuit-level assertion failures on invalid witness candidates
- boundary-path execution for this target is still noisy under the reconciled `8`-signal input shape
- high-confidence detection remains `0%` in the focused rerun, so the credibility gap is narrowed but not closed

Next required work:

- rerun the full vulnerable benchmark suite on the current tree so the published top-line recall numbers reflect the Merkle detection fix
- reduce invalid witness-candidate generation for this target so more non-binary Merkle paths survive execution and improve confidence/precision under deeper settings

## Source Artifacts

- Markdown summary: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.md`
- JSON summary: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`
- Trial outcomes: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/outcomes.json`
- Related roadmap snapshot: [docs/ROADMAP.md](ROADMAP.md)
