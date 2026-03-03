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

## Usage

```bash
scripts/run_std_smoke.sh
scripts/run_std_standard.sh
scripts/run_std_deep.sh
```

Optional explicit target override:

```bash
TARGET_NAME=ext017_email_wallet_account_creation scripts/run_std_standard.sh
```

## Operator Rule

- For routine runs, do not handcraft long `zkpatternfuzz` commands.
- Use one of the 3 wrappers.
- Change only the `.env` target bindings or `TARGET_NAME` when needed.
