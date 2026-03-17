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

if [[ -z "${ZKF_STD_TARGET_STANDARD:-}" ]]; then
  echo "Missing target binding: ZKF_STD_TARGET_STANDARD (config.env)." >&2
  exit 1
fi

export TARGET_NAME="$ZKF_STD_TARGET_STANDARD"
export TARGET_FRAMEWORK="${ZKF_STD_TARGET_STANDARD_FRAMEWORK:-}"
export TARGET_MAIN_COMPONENT="${ZKF_STD_TARGET_STANDARD_MAIN_COMPONENT:-main}"
export JOBS=1
export WORKERS=3
export ITERATIONS=6000
export TIMEOUT_SECS=1800
export STAGE_DETECTION_TIMEOUT_SECS=3600
export STAGE_PROOF_TIMEOUT_SECS=7200
export STUCK_STEP_WARN_SECS=150

exec "$ROOT_DIR/scripts/run_fixed_target_deep_fuzz.sh"
