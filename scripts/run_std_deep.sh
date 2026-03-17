#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_ENV_PATH="$ROOT_DIR/config.env"

if [[ ! -f "$CONFIG_ENV_PATH" ]]; then
  echo "Missing runtime config: $CONFIG_ENV_PATH" >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a
source "$CONFIG_ENV_PATH"
set +a

if [[ -z "${ZKF_STD_TARGET_DEEP:-}" ]]; then
  echo "Missing target binding: ZKF_STD_TARGET_DEEP (config.env)." >&2
  exit 1
fi

export TARGET_NAME="$ZKF_STD_TARGET_DEEP"
export TARGET_FRAMEWORK="${ZKF_STD_TARGET_DEEP_FRAMEWORK:-}"
export TARGET_MAIN_COMPONENT="${ZKF_STD_TARGET_DEEP_MAIN_COMPONENT:-main}"
export JOBS=1
export WORKERS=4
export ITERATIONS=20000
export TIMEOUT_SECS=3600
export STAGE_DETECTION_TIMEOUT_SECS=5400
export STAGE_PROOF_TIMEOUT_SECS=10800
export STUCK_STEP_WARN_SECS=180

exec "$ROOT_DIR/scripts/run_fixed_target_deep_fuzz.sh"
