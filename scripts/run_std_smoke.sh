#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

TARGET_NAME="${TARGET_NAME:-${ZKF_STD_TARGET_SMOKE:-}}"
if [[ -z "$TARGET_NAME" ]]; then
  echo "Missing target binding. Set ZKF_STD_TARGET_SMOKE in .env or export TARGET_NAME." >&2
  exit 1
fi

export TARGET_NAME
export JOBS="${JOBS:-1}"
export WORKERS="${WORKERS:-2}"
export ITERATIONS="${ITERATIONS:-800}"
export TIMEOUT_SECS="${TIMEOUT_SECS:-900}"
export STAGE_DETECTION_TIMEOUT_SECS="${STAGE_DETECTION_TIMEOUT_SECS:-1800}"
export STAGE_PROOF_TIMEOUT_SECS="${STAGE_PROOF_TIMEOUT_SECS:-3600}"
export STUCK_STEP_WARN_SECS="${STUCK_STEP_WARN_SECS:-120}"

exec "$ROOT_DIR/scripts/run_fixed_target_deep_fuzz.sh" "$@"
