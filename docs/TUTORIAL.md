# ZkPatternFuzz Tutorial

This tutorial uses the current CLI surface in the repository as of 2026-03-05.

## 1. Build The Binaries

```bash
git clone https://github.com/Teycir/ZkPatternFuzz.git
cd ZkPatternFuzz
cargo build --release --bins
```

Quick sanity check:

```bash
target/release/zk-fuzzer --help
```

## 2. Create Writable Local Output Paths

Direct runs need writable output, signal, and build-cache paths. This keeps the examples self-contained inside the repo:

```bash
export ZKF_SCAN_OUTPUT_ROOT="$PWD/artifacts/tutorial_runs"
export ZKF_RUN_SIGNAL_DIR="$PWD/artifacts/tutorial_runs/run_signals"
export ZKF_BUILD_CACHE_DIR="$PWD/artifacts/tutorial_runs/build_cache"
export ZKF_SHARED_BUILD_CACHE_DIR="$PWD/artifacts/tutorial_runs/build_cache"
mkdir -p "$ZKF_SCAN_OUTPUT_ROOT" "$ZKF_RUN_SIGNAL_DIR" "$ZKF_BUILD_CACHE_DIR"
```

For direct `zkpatternfuzz` runs, add the batch-stage timeouts:

```bash
export ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS=1800
export ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS=3600
export ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS=120
target/release/zkpatternfuzz --help
```

## 3. Generate A Sample Pattern File

```bash
target/release/zk-fuzzer init --output /tmp/zkf_sample.yaml --framework circom
sed -n '1,120p' /tmp/zkf_sample.yaml
```

Important:

- `init` generates a pattern-only YAML file.
- It is not a fully bound campaign.
- You will usually need to edit the selector regexes so they match your target source.

## 4. Run A Verified Dry-Run Scan

This example was exercised against a local fixture target and matching pattern:

```bash
target/release/zk-fuzzer scan \
  campaigns/cve/patterns/cveX34_cairo_multiplier_assert_readiness_probe.yaml \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --main-component main \
  --framework cairo \
  --workers 2 \
  --iterations 50 \
  --timeout 30 \
  --dry-run
```

What this does:

- validates selector matching,
- materializes the runtime campaign,
- checks readiness,
- shows where artifacts would be written,
- stops before executing the expensive scan stages.

To run the scan for real, remove `--dry-run`.

## 5. Run A Campaign Preflight

Legacy campaign files still work through `zk-fuzzer run`, `evidence`, `chains`, and `preflight`.

```bash
target/release/zk-fuzzer preflight campaigns/examples/defi_audit.yaml --setup-keys
```

Use this when you want backend/key-setup validation before committing to a full run.

## 6. Explore The Catalog

`zkpatternfuzz` is the batch runner. The current `--list-catalog` path expects registry mode, so pair it with a selector flag such as `--alias always`:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias always \
  --jobs 1 \
  --workers 2 \
  --list-catalog
```

## 7. Run A Verified Dry-Run Batch

This example was exercised locally and writes to the tutorial output paths configured above:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias readiness_cairo \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --main-component main \
  --framework cairo \
  --jobs 1 \
  --workers 2 \
  --iterations 50 \
  --timeout 30 \
  --dry-run \
  --emit-reason-tsv
```

What to expect:

- a 5-step batch preflight,
- `Gate 1/3` template counting,
- per-template dry-run invocations of `zk-fuzzer scan`,
- timestamped result bundles under `ZKF_SCAN_OUTPUT_ROOT/ResultJsonTimestamped/`.

Remove `--dry-run` to execute the batch.

## 8. Use The Standardized Wrappers

For routine smoke, standard, and deep runs, prefer the maintained wrappers:

```bash
scripts/run_std_smoke.sh
scripts/run_std_standard.sh
scripts/run_std_deep.sh
scripts/monitor_std_run.sh
```

The target bindings for those wrappers live in `.env`. Start from `cp .env.example .env`, then edit:

- `ZKF_STD_TARGET_SMOKE`
- `ZKF_STD_TARGET_STANDARD`
- `ZKF_STD_TARGET_DEEP`

## 9. Inspect Artifacts

Useful locations after a run:

- `ZKF_RUN_SIGNAL_DIR`: live run status and per-run signal files
- `ZKF_SCAN_OUTPUT_ROOT/ResultJsonTimestamped/`: batch result bundles
- `ZKF_SCAN_OUTPUT_ROOT/.scan_run_artifacts/`: per-template run artifacts
- repo-local logs under the specific wrapper or readiness output directory you used

## 10. Next Docs

- [TARGETS.md](TARGETS.md) for the target execution model
- [STANDARDIZED_RUN_PROFILES.md](STANDARDIZED_RUN_PROFILES.md) for wrapper policy
- [TROUBLESHOOTING_PLAYBOOK.md](TROUBLESHOOTING_PLAYBOOK.md) for failure triage
- [BACKEND_SETUP.md](BACKEND_SETUP.md) for backend verification
