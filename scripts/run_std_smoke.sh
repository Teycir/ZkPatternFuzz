#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

if [[ -z "${ZKF_STD_TARGET_SMOKE:-}" ]]; then
  echo "Missing target binding: ZKF_STD_TARGET_SMOKE (.env)." >&2
  exit 1
fi

export TARGET_NAME="$ZKF_STD_TARGET_SMOKE"
export JOBS=1
export WORKERS=2
export ITERATIONS=800
export TIMEOUT_SECS=900
export STAGE_DETECTION_TIMEOUT_SECS=1800
export STAGE_PROOF_TIMEOUT_SECS=3600
export STUCK_STEP_WARN_SECS=120

exec "$ROOT_DIR/scripts/run_fixed_target_deep_fuzz.sh"
