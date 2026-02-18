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
- [ ] Regression gate check:
  - `./scripts/ci_benchmark_gate.sh`
- [ ] Consecutive release-candidate benchmark gate:
  - `./scripts/release_candidate_gate.sh --bench-root artifacts/benchmark_runs --required-passes 2`
- [ ] If shipping production-depth changes, run at least one non-dry benchmark suite and archive `summary.json`.
- [ ] Release validation workflow run recorded:
  - GitHub Actions `Release Validation` (`workflow_dispatch`) with:
    - `stable_ref=<previous_stable_tag_or_commit>`
    - `required_passes=2`

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
