# Release Checklist

Production release checklist for ZkPatternFuzz.

Use this for `rc` and final tags. Each item is a hard gate unless explicitly waived in the release notes.

## 1. Release Metadata

- [ ] Version chosen and documented (`vX.Y.Z`).
- [ ] Release branch/tag candidate identified.
- [ ] Scope frozen (features, bugfixes, known limitations).
- [ ] Owner assigned for go/no-go decision.

## 2. Contract Guards (Do Not Break)

- [ ] Output path + report contract unchanged unless explicitly approved in this release cycle.
- [ ] If contract changes were approved, migration notes are included and compatibility tests updated.
- [ ] `run_outcome.json` and engagement summary compatibility checks pass.

## 3. Toolchain + Environment Validation

- [ ] Rust toolchain healthy:
  - `rustc --version`
  - `cargo --version`
- [ ] Core dependencies available where required:
  - `circom --version`
  - `snarkjs --help`
  - `z3 --version`
- [ ] Local Circom assets validated (if using internalized bins):
  - `cargo run --release --bin zk-fuzzer -- bins bootstrap --dry-run`

## 4. Build + Test Gates

- [ ] Formatting and lint:
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Core test suite:
  - `cargo test --all-features --verbose`
  - `cargo test --doc --all-features`
- [ ] Contract regression tests:
  - `cargo test -q --test mode123_nonregression scan_engagement_contract_fixture_passes -- --test-threads=1`
  - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`

## 5. Multi-Target + Benchmark Gates

- [ ] Batch catalog checks (dev + prod):
  - `cargo run --quiet --bin zk0d_batch -- --config-profile dev --list-catalog`
  - `cargo run --quiet --bin zk0d_batch -- --config-profile prod --list-catalog`
- [ ] Benchmark dry-runs:
  - `cargo run --quiet --bin zk0d_benchmark -- --config-profile dev --dry-run --trials 1 --jobs 1 --batch-jobs 1 --workers 1`
  - `cargo run --quiet --bin zk0d_benchmark -- --config-profile prod --dry-run --trials 1 --jobs 1 --batch-jobs 1 --workers 1`
- [ ] Benchmark regeneration for release gate evidence (recommended profile):
  - `cargo run --quiet --release --bin zk0d_benchmark -- --config-profile dev --suite safe_regression,vulnerable_ground_truth --trials 2 --jobs 1 --batch-jobs 1 --workers 1 --iterations 50 --timeout 10 --benchmark-min-evidence-confidence low --benchmark-oracle-min-agreement-ratio 0.45 --benchmark-oracle-cross-attack-weight 0.65 --benchmark-high-confidence-min-oracles 3 --output-dir artifacts/benchmark_runs`
  - Run the command twice to produce two fresh summaries for `--required-passes 2`.
- [ ] Regression gate check:
  - `./scripts/ci_benchmark_gate.sh`
- [ ] Consecutive release-candidate benchmark gate:
  - `./scripts/release_candidate_gate.sh --bench-root artifacts/benchmark_runs --required-passes 2`
- [ ] Backend readiness lanes executed and dashboard published:
  - `./scripts/run_backend_readiness_lanes.sh --required-backends noir,cairo,halo2 --min-completion-rate 0.90 --min-enabled-targets 5 --max-runtime-error 0 --max-backend-preflight-failed 0 --max-run-outcome-missing-rate 0.05 --enforce-tool-sandbox`
- [ ] Backend readiness gate enforced as part of release candidate validation:
  - `./scripts/release_candidate_gate.sh --bench-root artifacts/benchmark_runs --required-passes 2 --required-backends noir,cairo,halo2 --min-backend-completion-rate 0.90 --min-backend-enabled-targets 5 --max-backend-runtime-error 0 --max-backend-preflight-failed 0 --max-backend-run-outcome-missing-rate 0.05`
  - Note: `min-backend-completion-rate` is evaluated on selector-matching templates (`completed / (total - selector_mismatch)`).
- [ ] Backend maturity scorecard published and gate enforced:
  - `./scripts/backend_maturity_scorecard.sh --readiness-dashboard artifacts/backend_readiness/latest_report.json --benchmark-root artifacts/benchmark_runs --keygen-preflight artifacts/keygen_preflight/latest_report.json --output artifacts/backend_maturity/latest_scorecard.json --required-backends circom,noir,cairo,halo2 --min-score 4.5 --enforce`
  - `./scripts/release_candidate_gate.sh --bench-root artifacts/benchmark_runs --required-passes 2 --required-backends noir,cairo,halo2 --required-maturity-backends circom,noir,cairo,halo2 --min-backend-completion-rate 0.90 --min-backend-enabled-targets 5 --min-backend-maturity-score 4.5 --max-backend-runtime-error 0 --max-backend-preflight-failed 0 --max-backend-run-outcome-missing-rate 0.05`
- [x] Heavy backend readiness lanes (release-grade evidence snapshot) captured:
  - Command:
    - `./scripts/run_backend_readiness_lanes.sh --iterations 120 --timeout 45 --workers 2 --batch-jobs 1 --required-backends noir,cairo,halo2 --enforce-dashboard --no-build-if-missing`
  - Evidence:
    - `artifacts/backend_readiness/noir/latest_report.json` (`generated_utc=2026-02-21T14:44:02Z`, `reason_counts={"completed":6}`)
    - `artifacts/backend_readiness/cairo/latest_report.json` (`generated_utc=2026-02-21T14:47:33Z`, `reason_counts={"completed":4}`)
    - `artifacts/backend_readiness/halo2/latest_report.json` (`generated_utc=2026-02-21T14:54:17Z`, `reason_counts={"completed":8}`)
    - `artifacts/backend_readiness/latest_report.json` (`generated_utc=2026-02-21T14:54:17.539334+00:00`, `overall_pass=true`, `selector_matching_total=18`, `run_outcome_missing_rate=0.000`)
- [ ] Non-Circom collision stress lane (50+ targets) passes:
  - `./scripts/run_non_circom_collision_stress.sh --enforce`
- [ ] If shipping production-depth changes, run at least one non-dry benchmark suite and archive `summary.json`.
- [ ] Release validation workflow run recorded:
  - GitHub Actions `Release Validation` (`workflow_dispatch`) with:
    - `stable_ref=<previous_stable_tag_or_commit>`
    - `required_passes=2`
    - readiness + maturity gate inputs set for backend thresholds (`required_backends`, `required_maturity_backends`, `min_backend_completion_rate`, `min_backend_enabled_targets`, `min_backend_maturity_score`, `max_backend_runtime_error`, `max_backend_preflight_failed`, `max_backend_run_outcome_missing_rate`)

## 6. Documentation + Migration

- [ ] `CHANGELOG.md` updated with user-facing changes and fixes.
- [ ] `README.md` and docs updated for new flags/workflows.
- [ ] Migration notes added for any behavior change (config keys, defaults, thresholds, gates).
- [ ] Dynamic session-log routing behavior documented (including transition-window caveat + containment).
- [ ] Known risks and deferred items listed clearly.

## 7. Release Artifact Validation

- [ ] Release build succeeds:
  - `cargo build --release --all-features`
- [ ] Binary smoke check succeeds on release artifact:
  - `./target/release/zk-fuzzer --help`
- [ ] Packaging (if used) includes required files and no unintended large artifacts.

## 8. Rollback Readiness

- [ ] Previous stable version/tag is documented.
- [ ] Rollback command/process validated in staging environment:
  - `./scripts/rollback_validate.sh --stable-ref <previous_stable_tag_or_commit>`
- [ ] Rollback validation workflow job succeeded:
  - GitHub Actions `Release Validation` -> `Rollback Validation`
- [ ] Rollback owner and communication channel assigned.
- [ ] "Abort release" criteria explicitly documented for this cycle.

## 9. Sign-Off

- [ ] Engineering sign-off
- [ ] Security sign-off
- [ ] Operations sign-off
- [ ] Final go/no-go recorded with date and commit/tag
