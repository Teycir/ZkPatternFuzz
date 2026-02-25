# Troubleshooting Playbook

Production troubleshooting guide for common ZkPatternFuzz failures.

Focus areas:
- key generation failures
- Circom include path resolution
- output lock contention
- timeout tuning

## 1. Fast Triage

Run these first:

```bash
# Validate backend + key setup readiness for a campaign
cargo run --release --bin zk-fuzzer -- preflight <campaign.yaml> --setup-keys

# Inspect available batch templates and aliases
cargo run --release --bin zkpatternfuzz -- --list-catalog

# Run batch and print per-template reason codes
cargo run --release --bin zkpatternfuzz -- \
  --alias always \
  --target-circuit <target.circom> \
  --main-component <Main> \
  --framework circom \
  --emit-reason-tsv
```

If a run fails, inspect `run_outcome.json` first.

## 2. Key Generation Failed

### Typical signals
- `reason_code=key_generation_failed`
- stage often near `preflight_backend` or setup/prove init
- error text includes "Key generation failed", "key setup failed", or proving key errors

### Actions
1. Bootstrap local tools/assets:
```bash
cargo run --release --bin zk-fuzzer -- bins bootstrap
```
2. Verify binaries:
```bash
circom --version
snarkjs --help
```
3. Ensure ptau is valid and discoverable:
```bash
ls -lh bins/ptau
```
Optional explicit override:
```bash
export ZKF_PTAU_PATH="$PWD/bins/ptau/pot12_final.ptau"
```
4. Re-run preflight with setup:
```bash
cargo run --release --bin zk-fuzzer -- preflight <campaign.yaml> --setup-keys
```

## 3. Circom Include Path / Compilation Failures

### Typical signals
- `reason_code=circom_compilation_failed`
- Circom errors about missing imports / include files

### Actions
1. Export include roots:
```bash
export CIRCOM_INCLUDE_PATHS="third_party:node_modules"
```
2. Re-run the failing command.
3. Verify referenced dependency files exist under included roots.
4. Keep include roots deterministic in CI and local scripts.

## 4. Output Lock Contention

### Typical signals
- `reason_code=output_dir_locked`
- stage `acquire_output_lock`
- lock file `.zkfuzz.lock` in shared output dir

### Actions
1. Prefer batch/matrix runners for parallel runs (they isolate scan suffixes automatically).
2. Do not force multiple processes to the same `reporting.output_dir`.
3. Increase lock wait if needed:
```bash
export ZKF_OUTPUT_LOCK_WAIT_SECS=10
```
4. Check for active processes:
```bash
pgrep -af zk-fuzzer
```

## 5. Timeout Failures

### Typical signals
- `reason_code=wall_clock_timeout`
- process stalls during external Circom/snarkjs commands

### Tunables
1. Whole run timeout (`--timeout` for scan/batch/benchmark wrappers).
2. Circom external command timeout:
```bash
export ZK_FUZZER_CIRCOM_EXTERNAL_TIMEOUT_SECS=300
```
3. Per-execution timeout in campaign YAML:
- `campaign.parameters.additional.execution_timeout_ms`

### Recommended tuning order
1. Increase external command timeout first for large circuits.
2. Increase run wall-clock timeout second.
3. Increase per-exec timeout only if witness/prove operations are legitimately slow.

## 5A. Session Log Routing Edge Window

### Typical signal
- A small number of lines from a new run appear in the previous `session.log` (or vice versa) during rapid run transitions.

### Why this can happen
- Log path selection is dynamic and tied to run context.
- Context changes and subscriber writes are concurrent; a narrow transition window can still exist.

### Current containment
1. Context updates now force an immediate best-effort log-file rebind.
2. Per-write path checks keep the file target aligned even if context changes after startup.

### Operator guidance
1. Treat run artifacts (`run_outcome.json`, summary/report files) as source-of-truth for run status.
2. For strict per-run log separation, avoid overlapping runs that share the same process.
3. If needed, split logs by run id post-hoc using `started_utc`/run metadata from artifacts.

## 5B. Clean-Clone And Release-Gate Edge Cases

### Typical signals
- Fresh-clone validation reaches benchmark stage but report shows high `circom_compilation_failed`.
- Release gate unexpectedly evaluates `benchmark_home/.../report_*` summaries instead of timestamped benchmark runs.
- Rollback evidence is missing because release gates fail before rollback is attempted.

### Actions
1. Ensure fresh-clone failures are triaged from `artifacts/fresh_clone_validation/latest_report.json` using aggregated reason counts (`completed`, `circom_compilation_failed`, etc.).
2. Use benchmark summary paths under `benchmark_YYYYMMDD_HHMMSS/summary.json` for gating checks.
3. Run two-attempt release validation and emit report:
```bash
scripts/release_candidate_validate_twice.sh \
  --bench-root artifacts/benchmark_runs_fast \
  --required-passes 1 \
  --output-dir artifacts/release_candidate_validation
```
4. If rollback evidence is required even when gates fail, force rollback execution:
```bash
scripts/release_candidate_validate_twice.sh \
  --bench-root artifacts/benchmark_runs_fast \
  --required-passes 1 \
  --stable-ref <git-ref> \
  --rollback-even-if-gate-fails \
  --output-dir artifacts/release_candidate_validation
```

## 6. Readiness / Invariant Failures

### Typical signals
- `reason_code=readiness_failed`
- `reason_code=missing_invariants`
- strict evidence gate blocks run before attacks start

### Actions
1. Read the printed 0-day readiness report.
2. Add missing required attacks/invariants in YAML.
3. Raise low iteration budgets for non-trivial targets.
4. Re-run with `preflight` before full campaign execution.

## 7. Reason Code Quick Reference

| Reason code | Meaning | First action |
|---|---|---|
| `completed` | Run finished successfully | None |
| `critical_findings_detected` | Run completed with critical findings | Triage findings + PoCs immediately |
| `output_dir_locked` | Output lock contention | Isolate output dirs / increase lock wait |
| `backend_tooling_missing` | Required tools not found | Bootstrap/check `circom`, `snarkjs` |
| `backend_preflight_failed` | Backend preflight failed | Run `preflight --setup-keys` and inspect stderr |
| `circom_compilation_failed` | Circom compile/import failure | Fix includes (`CIRCOM_INCLUDE_PATHS`) |
| `key_generation_failed` | Trusted setup/proving key setup failed | Validate ptau + re-run key setup preflight |
| `wall_clock_timeout` | Run exceeded wall-clock budget | Increase `--timeout`; tune external timeout |
| `readiness_failed` | Strict readiness gate failed | Resolve reported critical readiness issues |
| `missing_invariants` | Evidence-mode invariants missing | Add invariants to campaign YAML |
| `filesystem_permission_denied` | Permission issue in output/build paths | Fix path permissions or move output root |
| `run_outcome_missing` | Per-template outcome file absent | Inspect crash/abort conditions in logs |
| `run_outcome_invalid_json` | Corrupt outcome artifact | Check process interruption/crash during write |
| `runtime_error` | Generic failure recovery | Inspect `error` + `stage` in run outcome |

## 8. Useful Environment Variables

- `CIRCOM_INCLUDE_PATHS`: import/include roots for Circom.
- `ZKF_PTAU_PATH`: explicit ptau path override.
- `ZKF_OUTPUT_LOCK_WAIT_SECS`: output lock wait budget.
- `ZKF_BUILD_CACHE_DIR`: build artifact cache root.
- `ZKF_RUN_SIGNAL_DIR`: engagement signal root.
- `ZKF_ENGAGEMENT_DIR`: explicit engagement report folder.
- `ZK_FUZZER_CIRCOM_EXTERNAL_TIMEOUT_SECS`: timeout for external Circom/snarkjs subprocesses.
