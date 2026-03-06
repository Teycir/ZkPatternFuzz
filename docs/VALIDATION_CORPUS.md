# ZkPatternFuzz Validation Corpus

This document is generated from the checked-in validation corpus manifest and points at the current public evidence lanes.

- Generated: `2026-03-06T04:03:18.734393+00:00`
- Repo commit: `420551985a505aa3750f741f278c5f893e778f86`
- Registered lanes: `4`

## Summary

- Published benchmark coverage: `30` runs (`20` vulnerable controls, `10` safe controls)
- Deterministic replay cases: `1`
- Semantic validation runs: `1` across `1` passing semantic lanes
- CVE regression catalog: `35` entries, `35` enabled regression definitions, `8` bundled fixture files
- Evidence files present for all lanes: `true`

## Registered Lanes

| Lane | Kind | Status | Scope | Primary Evidence |
| --- | --- | --- | --- | --- |
| `production_depth_benchmark` | `benchmark_publication` | `published_result` | 20 vulnerable / 10 safe runs | [`artifacts/benchmark_runs_prod_current_tree_p8/benchmark_20260306_025706/summary.json`](../artifacts/benchmark_runs_prod_current_tree_p8/benchmark_20260306_025706/summary.json) |
| `ext003_clean_checkout_replay` | `deterministic_replay` | `replay_bundle_present` | exploitable | [`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_ext003_iszero_exploit.log`](../artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_ext003_iszero_exploit.log) |
| `semantic_exit_sample` | `semantic_validation` | `pass` | 1 run, 13 violations | [`artifacts/semantic_exit/latest_report.json`](../artifacts/semantic_exit/latest_report.json) |
| `cve_regression_lane` | `cve_regression_lane` | `checked_in_regression_lane` | 35 catalog entries / 8 fixtures | [`templates/known_vulnerabilities.yaml`](../templates/known_vulnerabilities.yaml) |

## Production-depth benchmark publication

Published benchmark over vulnerable and safe suites on the current tree.

- Lane ID: `production_depth_benchmark`
- Kind: `benchmark_publication`
- Status: `published_result`
- Missing evidence paths: none
- Rerun command: `cargo run --quiet --bin zk0d_benchmark -- --config-profile prod --suite safe_regression,vulnerable_ground_truth --trials 2 --jobs 8 --batch-jobs 1 --workers 1 --iterations 5000 --timeout 300 --output-dir artifacts/benchmark_runs_prod_current_tree_p8`
- Current published recall: `20.0%`
- Current published high-confidence recall: `0.0%`
- Current published safe actionable false-positive rate: `0.0%`
- Current published safe high-confidence false-positive rate: `0.0%`
- Evidence paths:
  - `summary_json`: [`artifacts/benchmark_runs_prod_current_tree_p8/benchmark_20260306_025706/summary.json`](../artifacts/benchmark_runs_prod_current_tree_p8/benchmark_20260306_025706/summary.json)
  - `report_md`: [`docs/GROUND_TRUTH_REPORT.md`](GROUND_TRUTH_REPORT.md)

## EXT-003 clean-checkout exploit replay

Deterministic replay bundle proving exploitability of the IsZero-style target on a frozen external checkout.

- Lane ID: `ext003_clean_checkout_replay`
- Kind: `deterministic_replay`
- Status: `replay_bundle_present`
- Missing evidence paths: none
- Rerun command: `python3 artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_ext003_iszero_exploit.py --repo /tmp/ext003_clean_20260224_231039 --entrypoint tests/sample/test_vuln_iszero.circom --component VulnerableIsZero --input 5 --expected-sha 072bf1fbbd1c9ecad58d4f6d2204c3b96e7fec17`
- Replay conclusion: `exploitable`
- Evidence paths:
  - `replay_command`: [`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_command.txt`](../artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_command.txt)
  - `exploit_notes`: [`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/exploit_notes.md`](../artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/exploit_notes.md)
  - `replay_log`: [`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_ext003_iszero_exploit.log`](../artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/replay_ext003_iszero_exploit.log)
  - `impact_md`: [`artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/impact.md`](../artifacts/external_targets/ext_batch_001/reports/evidence/EXT-003/run_20260224_231300_clean_checkout/impact.md)
  - `report_md`: [`docs/VALIDATION_EVIDENCE.md`](VALIDATION_EVIDENCE.md)

## Semantic exit sample

Checked-in semantic analysis lane with execution evidence, generated reports, and manual-label workflow.

- Lane ID: `semantic_exit_sample`
- Kind: `semantic_validation`
- Status: `pass`
- Missing evidence paths: none
- Rerun command: `scripts/run_semantic_exit_sample.sh`
- Intent sources extracted: `195`
- Semantic violations: `13`
- Fix suggestions emitted: `13`
- Overall pass: `true`
- Evidence paths:
  - `summary_json`: [`artifacts/semantic_exit/latest_report.json`](../artifacts/semantic_exit/latest_report.json)
  - `campaign_readme`: [`campaigns/semantic/README.md`](../campaigns/semantic/README.md)
  - `guide_md`: [`docs/SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md`](SEMANTIC_ANALYSIS_OPERATOR_GUIDE.md)

## Bundled CVE regression lane

Deterministic in-repo CVE-style regression fixtures with a checked-in runner and catalog.

- Lane ID: `cve_regression_lane`
- Kind: `cve_regression_lane`
- Status: `checked_in_regression_lane`
- Missing evidence paths: none
- Rerun command: `cargo test --test cve_regression_runner -- --nocapture`
- Catalog entries: `35`
- Enabled regression definitions: `35`
- Bundled fixture references: `35`
- Bundled fixture files: `8`
- Evidence paths:
  - `catalog_yaml`: [`templates/known_vulnerabilities.yaml`](../templates/known_vulnerabilities.yaml)
  - `runner_rs`: [`tests/cve_regression_runner.rs`](../tests/cve_regression_runner.rs)
  - `fixtures_dir`: [`tests/cve_fixtures`](../tests/cve_fixtures)
  - `catalog_readme`: [`CVErefs/README.md`](../CVErefs/README.md)

## Source Of Truth

- Manifest: [`docs/validation_corpus_manifest.yaml`](validation_corpus_manifest.yaml)
- Generator: [`scripts/build_validation_corpus_report.py`](../scripts/build_validation_corpus_report.py)
