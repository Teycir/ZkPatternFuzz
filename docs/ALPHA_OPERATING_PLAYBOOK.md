# Alpha Operating Playbook

This playbook turns scan output into proof-bearing security results.

## Goal

Most discovery runs stop at triage artifacts. For this repository, a useful alpha loop means each serious candidate gets pushed toward one of two evidence states:

- `exploitable`
- `not exploitable within bounds`

Anything else remains `pending_proof`.

## 1. Freeze The Environment

Record the exact toolchain you are using before you run discovery:

```bash
rustc --version
cargo --version
circom --version
snarkjs --version
nargo --version
scarb --version
z3 --version
```

Cross-check against [TOOLS_AVAILABLE_ON_HOST.md](TOOLS_AVAILABLE_ON_HOST.md).

## 2. Run Narrow Discovery

For direct batch discovery, export writable paths and stage timeouts:

```bash
export ZKF_SCAN_OUTPUT_ROOT="$PWD/artifacts/alpha_manual"
export ZKF_RUN_SIGNAL_DIR="$PWD/artifacts/alpha_manual/run_signals"
export ZKF_BUILD_CACHE_DIR="$PWD/artifacts/alpha_manual/build_cache"
export ZKF_SHARED_BUILD_CACHE_DIR="$PWD/artifacts/alpha_manual/build_cache"
export ZKF_ZKPATTERNFUZZ_DETECTION_STAGE_TIMEOUT_SECS=1800
export ZKF_ZKPATTERNFUZZ_PROOF_STAGE_TIMEOUT_SECS=3600
export ZKF_ZKPATTERNFUZZ_STUCK_STEP_WARN_SECS=120
mkdir -p "$ZKF_SCAN_OUTPUT_ROOT" "$ZKF_RUN_SIGNAL_DIR" "$ZKF_BUILD_CACHE_DIR"
```

Example narrow discovery run:

```bash
target/release/zkpatternfuzz \
  --pattern-yaml campaigns/cve/patterns/cveX34_cairo_multiplier_assert_readiness_probe.yaml \
  --target-circuit tests/cairo_programs/multiplier.cairo \
  --framework cairo \
  --main-component main \
  --jobs 1 \
  --workers 2 \
  --iterations 100 \
  --timeout 30 \
  --dry-run \
  --emit-reason-tsv
```

Remove `--dry-run` when you are ready to execute.

## 3. Create Proof Artifacts Manually

When a target moves beyond triage, create a dedicated evidence directory, for example:

```bash
mkdir -p artifacts/proof_runs/<case_id>
```

Required files:

- `replay_command.txt`
- `exploit_notes.md` or `no_exploit_proof.md`
- `impact.md`
- replay or formal log (`*_replay.log`, solver log, or equivalent)

Minimum contents:

- exact target identity,
- exact command line,
- exact input or witness material,
- expected behavior,
- observed behavior,
- final conclusion.

## 4. Minimal KPIs

- `proof_closure_rate = closed_targets / completed_targets`
- `pending_proof_backlog = targets still lacking exploit or non-exploit evidence`
- `tooling_blocker_rate = backend/toolchain blockers / total targets`

If those numbers are not improving, discovery output is still mostly triage-only.
