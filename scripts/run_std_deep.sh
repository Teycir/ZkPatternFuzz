#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

if [[ -z "${ZKF_STD_TARGET_DEEP:-}" ]]; then
  echo "Missing target binding: ZKF_STD_TARGET_DEEP (.env)." >&2
  exit 1
fi

export TARGET_NAME="$ZKF_STD_TARGET_DEEP"
export JOBS=1
export WORKERS=4
export ITERATIONS=20000
export TIMEOUT_SECS=3600
export STAGE_DETECTION_TIMEOUT_SECS=5400
export STAGE_PROOF_TIMEOUT_SECS=10800
export STUCK_STEP_WARN_SECS=180

exec "$ROOT_DIR/scripts/run_fixed_target_deep_fuzz.sh"
