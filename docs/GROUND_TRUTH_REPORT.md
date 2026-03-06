# Ground Truth Validation

Published from: `artifacts/benchmark_runs_prod_current_tree_p8/benchmark_20260306_025706/summary.json`
Generated at source: `2026-03-06T02:57:06.999583266+00:00`
Repo commit: `034b9300f9537a8e9a6b4bfaf0650b4f101fc6e6`
Previous current-tree fast snapshot: `artifacts/benchmark_runs_fast_current_tree/benchmark_20260306_021602/summary.json`
Previous archived baseline: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`

## Scope

- Selected suites in config: `safe_regression`, `vulnerable_ground_truth`
- Suite config: `targets/benchmark_suites.prod.yaml`
- Registry config: `targets/benchmark_registry.prod.yaml`
- Trials per target: `2`
- Base seed: `42`
- Parallel target jobs: `8`
- Workers per scan: `1`
- Iterations per run: `5000`
- Timeout per run: `300`
- Confidence threshold: `low`

## Current Published Metrics

| Metric | Value |
| --- | --- |
| Total runs | `30` |
| Overall completion rate | `80.0%` |
| Attack-stage reach rate | `80.0%` |
| Vulnerable recall | `20.0%` |
| Vulnerable recall (high-confidence) | `0.0%` |
| Precision (actionable only) | `100.0%` |
| Safe actionable false-positive rate | `0.0%` |
| Safe high-confidence false-positive rate | `0.0%` |
| Safe raw detection rate (suite-level) | `20.0%` |

## Confidence Intervals

| Metric | 95% CI |
| --- | --- |
| Vulnerable recall | `8.1% - 41.6%` |
| Vulnerable high-confidence recall | `0.0% - 16.1%` |
| Precision (actionable only) | `51.0% - 100.0%` |
| Safe actionable false-positive rate | `0.0% - 27.8%` |
| Safe high-confidence false-positive rate | `0.0% - 27.8%` |
| Safe raw detection rate (suite-level) | `5.7% - 51.0%` |

## Suite Breakdown

| Suite | Runs | Result |
| --- | ---: | --- |
| `safe_regression` | `10` | `20.0%` raw detections, `0.0%` actionable/high-confidence false positives, `100.0%` completion |
| `vulnerable_ground_truth` | `20` | `20.0%` recall, `0.0%` high-confidence recall, `70.0%` completion |

## Notable Outcome

The target documented in [tests/ground_truth_circuits/README.md](../tests/ground_truth_circuits/README.md) is `90%+` detection on the ground-truth suite. The latest published benchmark in this repository does **not** meet that target yet:

- published vulnerable recall: `20.0%`
- published high-confidence vulnerable recall: `0.0%`

This report intentionally records the measured result rather than the desired target.

These figures should be read in the context of the benchmark profile used for this publication:

- `5000` iterations per run
- `300` seconds timeout per run
- production-depth benchmark templates from `targets/benchmark_registry.prod.yaml`
- strict high-confidence thresholding enabled in the benchmark summary

This profile is materially more representative than the earlier `50`-iteration / `10s` fast snapshot, but it still does not yield stable high-confidence recall on the current tree.

The production-depth run improves raw vulnerable recall over the fast current-tree snapshot (`20.0%` vs `10.0%`), but it also exposes two additional operational realities that the fast run masked:

- three vulnerable targets fail Circom preflight compilation in both trials: `eddsa_malleability`, `hash_length_extension`, and `multiexp_soundness`
- `range_proof_secure` produces low-confidence `soundness` findings in both safe-suite trials, so the raw safe detection rate is `20.0%` even though the actionable/high-confidence safe false-positive rates remain `0.0%`

Under the benchmark's current accounting, "actionable" safe false positives only count `high_confidence_detected` safe runs. That is why the top-line safe actionable false-positive rate remains `0.0%` while the suite-level safe raw detection rate is `20.0%`.

## Fast Snapshot Comparison

Current-tree fast regression snapshot from `artifacts/benchmark_runs_fast_current_tree/benchmark_20260306_021602/summary.json`:

- `20` total runs
- `100.0%` completion
- `100.0%` attack-stage reach
- `10.0%` vulnerable recall
- `0.0%` high-confidence vulnerable recall

Compared with that fast snapshot, the production-depth publication doubles raw vulnerable recall (`20.0%` vs `10.0%`) but still fails to produce any high-confidence vulnerable detections and still leaves the repository far below the stated `90%+` target.

## Detected And Missed Targets

Detected in both seeded trials:

- `bit_decomposition`
- `division_by_zero`

Missed in both completed seeded trials:

- `merkle_unconstrained`
- `nullifier_collision`
- `range_overflow`
- `commitment_binding`
- `public_input_leak`

Failed to compile in both seeded trials:

- `eddsa_malleability`
- `hash_length_extension`
- `multiexp_soundness`

Safe raw detections in both seeded trials:

- `range_proof_secure` via low-confidence `soundness` findings only; these did not count toward actionable/high-confidence safe false-positive rate

## Merkle Target Status

Full-suite production-depth status for `merkle_unconstrained`:

- the current published production-depth benchmark still missed the target in both seeded trials, even though both trials ran the dedicated production Merkle template `merkle_path_binarity_probe_prod.yaml`
- both trials reached the `Underconstrained` attack and used the full `5000` witness-pair budget:
  - trial 1 log: `artifacts/benchmark_runs_prod_current_tree_p8/scan_outputs/vulnerable_ground_truth/merkle_unconstrained/trial_1_seed_52/run_signals/report_1772765229_20260306_024709_scan_merkle_path_binarity_probe_prod__532a02ea0a95b1c1_pid2352143/session.log`
  - trial 2 log: `artifacts/benchmark_runs_prod_current_tree_p8/scan_outputs/vulnerable_ground_truth/merkle_unconstrained/trial_2_seed_1053/run_signals/report_1772764930_20260306_024210_scan_merkle_path_binarity_probe_prod__532a02ea0a95b1c1_pid1713489/session.log`
- underconstrained execution summaries from those trials:
  - trial 1: `attempted=5000 successful=418 failed=1855 collision_groups=1 timed_out=true`
  - trial 2: `attempted=5000 successful=392 failed=1801 collision_groups=1 timed_out=true`
- both trials then logged:
  - `MILESTONE attack_complete ... type=Underconstrained new_findings=0 total_findings=0`
  - `Global wall-clock timeout reached after attack Underconstrained; ending run early`

Current fast current-tree snapshot status for `merkle_unconstrained`:

- the earlier `50`-iteration / `10s` current-tree snapshot still missed the target in both trials because the wall-clock budget expired before `Underconstrained` could run
- fast-snapshot log paths remain archived at:
  - `artifacts/benchmark_runs_fast_current_tree/scan_outputs/vulnerable_ground_truth/merkle_unconstrained/trial_1_seed_52/run_signals/report_1772763280_20260306_021440_scan_merkle_path_binarity_probe__4da52ea06c9d97a8_pid1443624/session.log`
  - `artifacts/benchmark_runs_fast_current_tree/scan_outputs/vulnerable_ground_truth/merkle_unconstrained/trial_2_seed_1053/run_signals/report_1772763289_20260306_021449_scan_merkle_path_binarity_probe__4da52ea06c9d97a8_pid1445129/session.log`

Current focused rerun status on the current tree:

- a dedicated diagnostic rerun now detects `merkle_unconstrained`:
  - suite artifact: `artifacts/benchmark_runs_merkle_diagnostic_no_rlimit_as/benchmark_20260306_015923/summary.json`
  - scan artifact: `artifacts/benchmark_runs_merkle_diagnostic_no_rlimit_as/scan_outputs/merkle_diagnostic/merkle_unconstrained/trial_1_seed_42/.scan_run_artifacts/scan_run20260306_015826/auto__merkle_path_binarity_probe/report.json`
- the suite completed successfully, reached the attack stage, and recorded `1/1` detections
- the critical signal is a real `underconstrained` finding, not just a generic crash or hint-only artifact
- underconstrained execution summary from the diagnostic rerun:
  - `attempted=128`
  - `successful=28`
  - `failed=100`
  - `collision_groups=1`
  - `non_binary_generated=40/128`
  - `non_binary_successful=6/28`

Current stable high-confidence diagnostic status:

- after adding behavioral corroboration for accepted non-binary path selectors, the focused Merkle diagnostic now reaches high-confidence detection:
  - single-trial confirmation artifact: `artifacts/benchmark_runs_merkle_diagnostic_high_conf/benchmark_20260306_020809/summary.json`
  - two-trial stability artifact: `artifacts/benchmark_runs_merkle_diagnostic_high_conf_stability/benchmark_20260306_021012/summary.json`
- the two-trial stability rerun recorded:
  - `2/2` detections
  - `2/2` high-confidence detections
  - `100%` completion
  - `100%` attack-stage reach
- the new high-confidence path comes from cross-group corroboration:
  - structural evidence: `underconstrained` identical-output witness collision
  - behavioral evidence: accepted non-binary `path_indices` under the same fixed public root
- this means the target now has a stable high-confidence focused diagnostic on the current tree, but that focused diagnostic still does not carry through to either the fast full-suite snapshot or the current production-depth full-suite publication

What changed between the miss and the detection:

- benchmark suite routing now assigns `merkle_unconstrained` to `campaigns/benchmark/patterns/merkle_path_binarity_probe.yaml` in default/dev runs and `merkle_path_binarity_probe_prod.yaml` in prod-depth runs
- quantified `forall` array invariants now evaluate correctly in both the core semantic oracle engine and the fuzzer invariant checker
- reconciled indexed inputs such as `path_indices[0]` are now aliased back to their base array names for invariant evaluation and scalarized when the executor-derived schema flattens arrays into individual field slots
- underconstrained attack seeding now loads direct witness seeds from `campaigns/benchmark/seed_inputs/merkle_unconstrained_seed_inputs.json` instead of relying only on corpus-derived recovery
- Circom per-exec isolation no longer applies a default `RLIMIT_AS` cap when the operator has not explicitly set `isolation_memory_limit_mb` or `isolation_memory_limit_bytes`; this removes the prior `WebAssembly.instantiate(): Out of memory` worker failure seen under isolated witness generation
- underconstrained collision reporting now emits a paired behavioral-domain finding when the same accepted witness uses non-binary Merkle path selectors, allowing cross-group correlation to promote the issue to `HIGH` confidence instead of leaving it as a structural-only `LOW`

Remaining limitations:

- the production-depth publication still only reaches `20.0%` vulnerable recall and `0.0%` high-confidence vulnerable recall
- six vulnerable trials fail at Circom preflight on `eddsa_malleability`, `hash_length_extension`, and `multiexp_soundness`, so the vulnerable suite only reaches `70.0%` completion/attack-stage coverage
- the safe suite now shows a `20.0%` raw detection rate because `range_proof_secure` produces low-confidence `soundness` findings in both trials
- top-line actionable false-positive and precision metrics exclude low-confidence safe detections by design, so they should be read alongside the suite-level raw detection rate rather than in isolation
- `merkle_unconstrained` still misses in the full production-depth suite even after `5000` witness pairs and hundreds of successful executions per trial
- the focused Merkle diagnostic remains high-confidence evidence for one target, not a substitute for representative suite-wide effectiveness

Next required work:

- diagnose and fix the `circom_compilation_failed` preflight failures for `eddsa_malleability`, `hash_length_extension`, and `multiexp_soundness`
- investigate `range_proof_secure` low-confidence `soundness` findings and either eliminate the false-positive path or tighten the detector so the safe raw detection rate drops back to zero
- reconcile the full-suite `merkle_unconstrained` miss with the focused `2/2` high-confidence Merkle diagnostic, now that the production-depth suite clearly reaches the attack path but still emits `0` findings
- rerun the production-depth benchmark after those fixes, then decide whether the fast `50`-iteration / `10s` profile should remain a published comparison metric or be relabeled as smoke-only

## Source Artifacts

- Markdown summary: `artifacts/benchmark_runs_prod_current_tree_p8/benchmark_20260306_025706/summary.md`
- JSON summary: `artifacts/benchmark_runs_prod_current_tree_p8/benchmark_20260306_025706/summary.json`
- Trial outcomes: `artifacts/benchmark_runs_prod_current_tree_p8/benchmark_20260306_025706/outcomes.json`
- Current-tree fast snapshot: `artifacts/benchmark_runs_fast_current_tree/benchmark_20260306_021602/summary.json`
- Previous archived baseline: `artifacts/benchmark_runs_fast/benchmark_20260219_212657/summary.json`
- Related roadmap snapshot: [docs/ROADMAP.md](ROADMAP.md)
