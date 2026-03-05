# Troubleshooting Playbook

Production troubleshooting guide for common ZkPatternFuzz failures.

## 1. Fast Triage

Direct runs need writable output roots. For local repros, start with:

```bash
export ZKF_SCAN_OUTPUT_ROOT="$PWD/artifacts/troubleshooting"
export ZKF_RUN_SIGNAL_DIR="$PWD/artifacts/troubleshooting/run_signals"
export ZKF_BUILD_CACHE_DIR="$PWD/artifacts/troubleshooting/build_cache"
export ZKF_SHARED_BUILD_CACHE_DIR="$PWD/artifacts/troubleshooting/build_cache"
export ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS=1800
export ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS=3600
export ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS=120
mkdir -p "$ZKF_SCAN_OUTPUT_ROOT" "$ZKF_RUN_SIGNAL_DIR" "$ZKF_BUILD_CACHE_DIR"
```

Then run:

```bash
target/release/zk-fuzzer preflight campaigns/examples/defi_audit.yaml --setup-keys
target/release/zkpatternfuzz --registry targets/fuzzer_registry.prod.yaml --alias always --jobs 1 --workers 2 --list-catalog
```

If a run fails, inspect `run_outcome.json` first.

## 2. Missing Env Vars Or Unwritable Output Roots

### Typical Signals

- `ZKF_RUN_SIGNAL_DIR is required and must point to a writable path`
- `Missing required env keys in '.env'`
- `Unable to create result directory`
- `Permission denied (os error 13)` under the configured output root

### Actions

1. Override output paths to a writable directory under the repo or `/tmp`.
2. For direct `zkpatternfuzz` runs, export the three `ZKF_ZKPATTERNFUZZ_*` stage-timeout vars.
3. Create the directories before rerunning.

## 3. Key Generation Failed

### Typical Signals

- `reason_code=key_generation_failed`
- failure near `preflight_backend`
- proving key or trusted-setup errors

### Actions

1. Stage local tooling:

```bash
target/release/zk-fuzzer bins bootstrap
```

2. Verify binaries:

```bash
circom --version
snarkjs --version
```

3. Check staged ptau:

```bash
ls -lh bins/ptau
```

4. Rerun preflight:

```bash
target/release/zk-fuzzer preflight campaigns/examples/defi_audit.yaml --setup-keys
```

## 4. Circom Include Or Compilation Failures

### Typical Signals

- `reason_code=circom_compilation_failed`
- missing imports or include files

### Actions

1. Export deterministic include roots:

```bash
export CIRCOM_INCLUDE_PATHS="third_party:node_modules"
```

2. Verify the referenced files exist under those roots.
3. Rerun the failing command.

## 5. Selector Mismatch

### Typical Signals

- `reason_code=selector_mismatch`
- `selectors did not match target circuit`

### Actions

1. Confirm you chose a pattern that actually matches the target source.
2. Use `--dry-run` first on single-pattern work.
3. When listing the catalog, remember the current path needs registry mode:

```bash
target/release/zkpatternfuzz \
  --registry targets/fuzzer_registry.prod.yaml \
  --alias always \
  --jobs 1 \
  --workers 2 \
  --list-catalog
```

## 6. Output Lock Contention

### Typical Signals

- `reason_code=output_dir_locked`
- lock file `.zkfuzz.lock`

### Actions

1. Prefer wrapper scripts or isolated output roots for concurrent runs.
2. Do not force multiple runs into the same report directory.
3. Check active processes:

```bash
pgrep -af 'zk-fuzzer|zkpatternfuzz|zk0d_batch'
```

## 7. Timeout Failures

### Typical Signals

- `reason_code=wall_clock_timeout`
- stalled external backend commands

### Actions

1. Increase the run timeout first (`--timeout`).
2. Increase backend-specific external timeouts next.
3. Only then raise per-execution budgets inside YAML.

Example:

```bash
export ZK_FUZZER_CIRCOM_EXTERNAL_TIMEOUT_SECS=300
export ZK_FUZZER_HALO2_MIN_EXTERNAL_TIMEOUT_SECS=180
```

## 8. Release-Gate Failures

Use the current release gate, not the removed `release_candidate_validate_twice.sh` flow:

```bash
scripts/release_candidate_gate.sh --help
```

Useful supporting commands:

```bash
target/release/zk0d_benchmark --help
scripts/run_benchmarks.sh --help
scripts/backend_readiness_dashboard.sh --help
```

## 9. Reason Code Quick Reference

| Reason code | Meaning | First action |
|---|---|---|
| `completed` | Run finished successfully | None |
| `critical_findings_detected` | Run completed with critical findings | Triage proof artifacts immediately |
| `output_dir_locked` | Output lock contention | Use isolated output roots |
| `backend_tooling_missing` | Required tools not found | Verify tool versions and `bins bootstrap` |
| `backend_preflight_failed` | Backend preflight failed | Rerun `preflight --setup-keys` or backend readiness script |
| `circom_compilation_failed` | Circom compile/import failure | Fix include roots |
| `key_generation_failed` | Trusted setup/proving key setup failed | Validate ptau and rerun preflight |
| `wall_clock_timeout` | Run exceeded wall-clock budget | Raise timeout and inspect external tool timing |
| `readiness_failed` | Strict readiness gate failed | Read the readiness report and fix the listed blockers |
| `missing_invariants` | Evidence-mode invariants missing | Add invariants to the YAML |
| `filesystem_permission_denied` | Output/build path issue | Move paths to a writable root |
| `run_outcome_missing` | Per-template outcome file absent | Check for crash, abort, or interrupted artifact write |
| `runtime_error` | Generic execution failure | Inspect stage plus stderr/log output |
