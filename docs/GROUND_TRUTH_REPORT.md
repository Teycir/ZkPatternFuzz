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
- a focused production-depth rerun with the dedicated Merkle template (`5000` iterations, `300s` timeout) also completed, reached the attack stage, and produced `0` findings on the current tree
- subsequent focused reruns after quantified-invariant and reconciled-input fixes still produced `0` findings on the current tree

This points away from backend readiness problems and toward signal-generation gaps that persist even after the benchmark-template correction.

Most likely contributing factors:

- the published benchmark used the generic strict probe template, which only carried a baseline invariant (`field_input_domain`) and did not encode a Merkle-specific binary-path invariant
- the dedicated regression test for this same target in [ground_truth_regression.rs](../tests/ground_truth_regression.rs) expects detection with `10_000` iterations, which is materially deeper than the published benchmark's `50`
- focused rerun logs still show input-schema reconciliation (`config has 4, executor expects 8`) before attack execution, so public/private slot mapping remains a plausible source of degraded signal quality
- focused rerun logs also show underconstrained post-processing terminating at the wall-clock budget, which suggests the remaining miss is now more likely in candidate generation, seed quality, or post-processing coverage than in pure pattern selection
- the current `MerkleOracle` models extracted path indices as booleans, which is useful for some Merkle soundness checks but is not a direct detector for arbitrary non-binary selector values

Working conclusion:

- primary suspicion: underconstrained attack generation is not producing or preserving the non-binary Merkle-path witnesses needed for this target under the reconciled input shape
- secondary suspicion: public/private witness ordering or reconciliation is still diluting the effective search space for this circuit
- tertiary suspicion: Merkle oracle coverage remains too indirect for this bug class without a stronger exploit-oriented post-check

Follow-up status:

- benchmark suite routing now assigns `merkle_unconstrained` to `campaigns/benchmark/patterns/merkle_path_binarity_probe.yaml` in default/dev runs and `merkle_path_binarity_probe_prod.yaml` in prod-depth runs
- quantified `forall` array invariants now evaluate correctly in both the core semantic oracle engine and the fuzzer invariant checker
- reconciled indexed inputs such as `path_indices[0]` are now aliased back to their base array names for invariant evaluation and scalarized when the executor-derived schema flattens arrays into individual field slots
- the published metrics at the top of this report still predate these changes and should be treated as a pre-fix baseline for this target
- focused production-depth validation artifacts now exist under:
  - `artifacts/benchmark_runs_merkle_validation/benchmark_20260306_004139/`
  - `artifacts/benchmark_runs_merkle_validation_after_quantifier_fix/benchmark_20260306_005312/`
  - `artifacts/benchmark_runs_merkle_validation_after_reconcile_fix/benchmark_20260306_010018/`
- the next required work is not another template tweak; it is targeted instrumentation of underconstrained candidate generation and reconciliation behavior for `merkle_unconstrained`, followed by another production-depth rerun

## Source Artifacts

- Markdown summary: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.md`
- JSON summary: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`
- Trial outcomes: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/outcomes.json`
- Related roadmap snapshot: [docs/ROADMAP.md](ROADMAP.md)
