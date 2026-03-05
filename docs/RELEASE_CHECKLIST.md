# Release Checklist

Production release checklist for ZkPatternFuzz (`rc` and final tags).

## 1. Release Metadata

- [ ] Version chosen and documented.
- [ ] Release branch or tag candidate identified.
- [ ] Scope frozen.
- [ ] Go/no-go owner assigned.

## 2. Environment Prerequisites

- [ ] Core tools are available:
  - `rustc --version`
  - `cargo --version`
  - `circom --version`
  - `snarkjs --version`
  - `z3 --version`
- [ ] Local Circom assets validate:
  - `target/release/zk-fuzzer bins bootstrap --dry-run`

## 3. Build And Test Baseline

- [ ] Formatting and lint pass:
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Main test suites pass:
  - `cargo test --all-features --verbose`
  - `cargo test --doc --all-features`

## 4. Benchmark Evidence

- [ ] Fresh benchmark summaries are generated under `artifacts/benchmark_runs`:

```bash
target/release/zk0d_benchmark \
  --config-profile dev \
  --trials 2 \
  --jobs 1 \
  --batch-jobs 1 \
  --workers 1 \
  --iterations 50 \
  --timeout 10 \
  --output-dir artifacts/benchmark_runs
```

- [ ] If you need a lighter operator wrapper for spot checks, `scripts/run_benchmarks.sh --quick` still works, but the canonical release gate consumes `artifacts/benchmark_runs`.

## 5. Release Candidate Gate

- [ ] Release gate passes:

```bash
./scripts/release_candidate_gate.sh \
  --bench-root artifacts/benchmark_runs \
  --required-passes 2 \
  --required-backends noir,cairo,halo2 \
  --required-maturity-backends circom,noir,cairo,halo2 \
  --min-backend-completion-rate 0.90 \
  --min-backend-selector-matching-total-per-backend noir=25,cairo=4,halo2=4 \
  --min-backend-enabled-targets 5 \
  --min-backend-maturity-score 4.5 \
  --backend-maturity-consecutive-days 14 \
  --backend-maturity-consecutive-target-score 5.0 \
  --backend-maturity-consecutive-backends circom,noir,cairo,halo2 \
  --circom-flake-consecutive-days 14 \
  --backend-capacity-fitness-min-median-completed-per-sec 0.005 \
  --backend-capacity-fitness-max-rss-kb 262144 \
  --max-backend-runtime-error 0 \
  --max-backend-preflight-failed 0 \
  --max-backend-run-outcome-missing-rate 0.05
```

- [ ] Verify the release artifacts exist:
  - `artifacts/release_candidate_validation/evidence_bundle_manifest.json`
  - `artifacts/release_candidate_validation/backend_release_blockers.json`

## 6. Documentation And Risk Notes

- [ ] `CHANGELOG.md` updated.
- [ ] `README.md` and relevant docs updated for workflow or flag changes.
- [ ] Deferred risks and known limitations documented.

## 7. Rollback Validation

- [ ] Previous stable reference documented.
- [ ] Rollback check passes:

```bash
./scripts/rollback_validate.sh --stable-ref <previous_stable_tag_or_commit>
```

- [ ] Rollback owner and abort criteria recorded.

## 8. Sign-Off

- [ ] Engineering sign-off.
- [ ] Security sign-off.
- [ ] Operations sign-off.
- [ ] Final go/no-go recorded with date and commit/tag.
