# Standardized Run Profiles

This repository defines 3 fixed run profiles to prevent command drift.

## Source Of Truth

Target bindings are defined in `config.env`. Start from the tracked template:

```bash
cp config.env.example config.env
```

The default template uses repo-relative output paths, and the wrapper scripts resolve them against the repository root.

Routine target bindings are:

- `ZKF_STD_TARGET_SMOKE`
- `ZKF_STD_TARGET_STANDARD`
- `ZKF_STD_TARGET_DEEP`

Set these once, then use the wrapper scripts below.

Each binding may be either:

- a named entry from the checked-in target matrix, or
- a direct target path such as `/home/teycir/ZkRepos/semaphore/packages/circuits/src/semaphore.circom`

When you use a direct path and the framework is not obvious, set the matching `ZKF_STD_TARGET_*_FRAMEWORK` and `ZKF_STD_TARGET_*_MAIN_COMPONENT` values in `config.env`.

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
- Change only the standardized target bindings in `config.env`.
- Do not override selector profile manually; it is framework-bound by the fixed runner.
- Do not commit `config.env`; keep local operator settings in your untracked copy.
