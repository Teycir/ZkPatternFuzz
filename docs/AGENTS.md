# ZkPatternFuzz Agent Session Contract

This file defines mandatory behavior for every new agent session in this repository.

## 1) Mission (Non-Negotiable)
- Primary objective: discover real vulnerabilities.
- Required outcome per confirmed finding:
  - prove exploitability with deterministic replay, or
  - prove non-exploitability with formal/bounded evidence.
- Do not claim success from hints-only output.

## 2) Definition Of Done
A task is complete only when one of these is produced:

1. Exploit proven:
  - minimal repro input/witness/tx sequence,
  - one-command deterministic replay,
  - expected vs observed mismatch,
  - artifact log showing replay success.

2. Non-exploitability proven:
  - formal result with evidence (`SAFE` where applicable),
  - bounded search/fuzz campaign with no counterexample in stated bounds,
  - explicit assumptions and limits documented.

If neither is available, status must remain `pending_proof`.

## 3) Required Session Flow
Execute this flow in order unless the user explicitly overrides:

1. Objective lock:
  - restate target and proof goal.
2. Target freeze:
  - record repo path + commit SHA + entrypoint.
3. Tool readiness:
  - verify required binaries and versions for this target.
4. Discovery:
  - run skimming/fuzzing/formal prechecks to generate candidates.
5. Triage:
  - select high-signal candidates and reject noise.
6. Proof branch:
  - branch A: build exploit replay artifacts, or
  - branch B: build non-exploitability evidence pack.
7. Evidence logging:
  - write artifacts and update roadmap/issue board rows.

## 4) Tooling Expectations
Use tools as complements, not substitutes.

- Discovery:
  - `zk-fuzzer`, `echidna`, `medusa`, `halmos`
- Formal/non-exploitability:
  - `picus`, `z3` (and solver-backed checks)
- Backend support:
  - `circom`, `snarkjs`, `nargo`, `scarb`, `cairo-*`
- Static/depth assist:
  - `slither`, Foundry tools (`forge`, `cast`, `anvil`)

Authoritative local inventory:
- `docs/TOOLS_AVAILABLE_ON_HOST.md`

## 5) Mandatory Artifacts Per Proven Finding
Store under batch evidence directory (or target-specific equivalent):

- `replay_command.txt`
- `exploit_notes.md` (or `no_exploit_proof.md`)
- `impact.md`
- execution log (`*_replay.log` / formal log)

Minimum content:
- target identity (path + SHA + component),
- exact command(s),
- exact witness/input/tx payloads,
- expected behavior,
- observed behavior,
- conclusion (`exploitable` or `not exploitable within bounds`).

## 6) Reporting Rules
- Use `manual checks only` mode; no cron assumptions.
- Mark unresolved findings as open; do not auto-close by confidence.
- If proof is blocked, record concrete blocker and next required step.

## 7) Patch Policy
- Default mode for this track is discovery + proof.
- Only patch code when user explicitly asks to fix after proof.
- If patching is requested, keep pre-fix replay artifact and add post-fix replay artifact.

## 8) Standardized Run Profiles (Mandatory Default)
To avoid ad-hoc command drift, agents must use the standardized wrappers for routine runs.

### Binding Source Of Truth
- `.env` keys:
  - `ZKF_STD_TARGET_SMOKE`
  - `ZKF_STD_TARGET_STANDARD`
  - `ZKF_STD_TARGET_DEEP`
- Keep these as the only routine target bindings for the 3 common profiles.

### Mandatory Wrapper Entry Points
- `scripts/run_std_smoke.sh`
- `scripts/run_std_standard.sh`
- `scripts/run_std_deep.sh`
- `scripts/monitor_std_run.sh` (for all run monitoring requests)

### Agent Rule
- For "smoke", "standard", or "deep" requests, do **not** rebuild CLI command-lines manually.
- Run the matching wrapper script directly.
- Do not pass runtime flags or env overrides to wrappers.
- Change only the `.env` profile bindings (`ZKF_STD_TARGET_*`) when target changes are requested.
- Keep output method/path stable via env (`ZKF_SCAN_OUTPUT_ROOT`) unless operator explicitly asks to change it.
- Rely on automatic console monitoring emitted by the run scripts in all cases.

### Escalation Rule
- If a run fails due to sandbox/write constraints, retry with required execution permissions.
- Do not change output schema, folder layout, or telemetry file names as a workaround.
