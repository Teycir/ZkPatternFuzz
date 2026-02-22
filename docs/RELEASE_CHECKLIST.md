# Release Checklist

Production release checklist for ZkPatternFuzz (`rc` and final tags).

Scope update (2026-02-22): this checklist keeps release-blocking gates only. Exploratory and duplicate validation lanes are tracked outside this file.

## 1. Release Metadata

- [ ] Version chosen and documented (`vX.Y.Z`).
- [ ] Release branch/tag candidate identified.
- [ ] Scope frozen (features, bugfixes, known limitations).
- [ ] Go/no-go owner assigned.

## 2. Contract Compatibility

- [ ] Output/report contract decision recorded: unchanged, or explicitly approved change with migration notes and updated compatibility tests.
- [ ] Contract compatibility checks pass:
  - `cargo test -q --test mode123_nonregression scan_engagement_contract_fixture_passes -- --test-threads=1`
  - `cargo test -q run_doc_command_extraction_ -- --test-threads=1`

## 3. Environment Prerequisites

- [ ] Toolchain and core dependencies are available:
  - `rustc --version`
  - `cargo --version`
  - `circom --version`
  - `snarkjs --help`
  - `z3 --version`
- [ ] Local Circom assets validate cleanly (if using internalized bins):
  - `cargo run --release --bin zk-fuzzer -- bins bootstrap --dry-run`

## 4. Build And Test Baseline

- [ ] Formatting and lint pass:
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Test suites pass:
  - `cargo test --all-features --verbose`
  - `cargo test --doc --all-features`

## 5. Release Validation Gates (Canonical Path)

- [ ] Fresh benchmark evidence generated (run twice so the gate has two consecutive summaries):
  - `cargo run --quiet --release --bin zk0d_benchmark -- --config-profile dev --suite safe_regression,vulnerable_ground_truth --trials 2 --jobs 1 --batch-jobs 1 --workers 1 --iterations 50 --timeout 10 --benchmark-min-evidence-confidence low --benchmark-oracle-min-agreement-ratio 0.45 --benchmark-oracle-cross-attack-weight 0.65 --benchmark-high-confidence-min-oracles 3 --output-dir artifacts/benchmark_runs`
- [ ] Release candidate gate passes with readiness, maturity, streak, hermetic include/toolchain enforcement, and backend capacity fitness (large-circuit memory + throughput):
  - `./scripts/release_candidate_gate.sh --bench-root artifacts/benchmark_runs --required-passes 2 --required-backends noir,cairo,halo2 --required-maturity-backends circom,noir,cairo,halo2 --min-backend-completion-rate 0.90 --min-backend-selector-matching-total-per-backend noir=25,cairo=4,halo2=4 --min-backend-enabled-targets 5 --min-backend-maturity-score 4.5 --backend-maturity-consecutive-days 14 --backend-maturity-consecutive-target-score 5.0 --backend-maturity-consecutive-backends circom,noir,cairo,halo2 --circom-flake-consecutive-days 14 --backend-capacity-fitness-min-median-completed-per-sec 0.005 --backend-capacity-fitness-max-rss-kb 262144 --max-backend-runtime-error 0 --max-backend-preflight-failed 0 --max-backend-run-outcome-missing-rate 0.05`
- [ ] Non-Circom collision stress gate passes:
  - `./scripts/run_non_circom_collision_stress.sh --enforce`
- [ ] GitHub Actions `Release Validation` run recorded with matching thresholds/inputs and archived artifacts.

## 6. Documentation And Risk Notes

- [ ] `CHANGELOG.md` updated with user-facing changes and fixes.
- [ ] `README.md` and relevant docs updated for new flags/workflows.
- [ ] Known risks and deferred items explicitly documented.
- [ ] If behavior or defaults changed, migration notes are included.

## 7. Artifact And Rollback Validation

- [ ] Release build and smoke checks pass:
  - `cargo build --release --all-features`
  - `./target/release/zk-fuzzer --help`
- [ ] Previous stable reference documented.
- [ ] Rollback validation passes:
  - `./scripts/rollback_validate.sh --stable-ref <previous_stable_tag_or_commit>`
- [ ] Rollback owner, communication channel, and explicit abort criteria are documented.

## 8. Sign-Off

- [ ] Engineering sign-off.
- [ ] Security sign-off.
- [ ] Operations sign-off.
- [ ] Final go/no-go recorded with date and commit/tag.

## Notes (Informational, Non-Blocking)

- Heavy backend readiness evidence snapshot is already captured under `artifacts/backend_readiness/latest_report.json` plus backend-specific reports dated 2026-02-21.
- Use `./scripts/run_backend_readiness_lanes.sh --enforce-dashboard` when you need to refresh readiness artifacts outside the canonical release gate flow.
