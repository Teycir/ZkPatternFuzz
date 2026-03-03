# Standardized Run Profiles

This repository defines 3 fixed run profiles to prevent command drift.

## Source Of Truth

Target bindings are defined in `.env`:

- `ZKF_STD_TARGET_SMOKE`
- `ZKF_STD_TARGET_STANDARD`
- `ZKF_STD_TARGET_DEEP`

Set these once, then use the wrapper scripts below.

## Wrapper Scripts

- `scripts/run_std_smoke.sh`
- `scripts/run_std_standard.sh`
- `scripts/run_std_deep.sh`

Each wrapper delegates to `scripts/run_fixed_target_deep_fuzz.sh` and keeps:

- stable artifact method (`run_signals`, `.scan_run_artifacts`, timestamped logs),
- stable environment wiring,
- stable profile-specific defaults (workers/iterations/timeouts).

Selector policy is fixed and automatic in the shared runner:

- zkevm targets: fixed deep template CSV (`cveX15/16/35/36/37/38/39/40/41`),
- non-zkevm Halo2: `readiness_halo2`,
- Circom: `readiness_circom`,
- Noir: `readiness_noir`,
- Cairo: `readiness_cairo`.

For zkevm targets, dependency preflight is strict:

- checks `integration-tests/contracts/vendor/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol`,
- auto-runs `git submodule update --init --recursive integration-tests/contracts/vendor/openzeppelin-contracts` if missing,
- fails fast if still missing (to prevent `0 constraints` deep runs).

## Usage

```bash
scripts/run_std_smoke.sh
scripts/run_std_standard.sh
scripts/run_std_deep.sh
```

Monitoring is strict and always-on in the run scripts (console step lines + monitor lines).
If you want a second console attached to the same signals:

```bash
scripts/monitor_std_run.sh
```

## Operator Rule

- For routine runs, do not handcraft long `zkpatternfuzz` commands.
- Use one of the 3 wrappers.
- Do not pass flags/overrides to wrappers.
- Change only the 3 target bindings in `.env`.
- Do not override selector profile manually; it is framework-bound by the fixed runner.
