#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_ENV_PATH="$ROOT_DIR/config.env"
DISCOVERY_SCRIPT="$ROOT_DIR/scripts/discover_zkrepos_targets.py"
DEFAULT_TARGET_ROOT="/home/teycir/ZkRepos"

if [[ ! -f "$CONFIG_ENV_PATH" ]]; then
  echo "Missing runtime config: $CONFIG_ENV_PATH" >&2
  exit 1
fi

if [[ ! -f "$DISCOVERY_SCRIPT" ]]; then
  echo "Missing discovery helper: $DISCOVERY_SCRIPT" >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a
source "$CONFIG_ENV_PATH"
set +a

resolve_repo_path() {
  local raw_path="$1"
  if [[ "$raw_path" = /* ]]; then
    printf '%s\n' "$raw_path"
  else
    printf '%s\n' "$ROOT_DIR/$raw_path"
  fi
}

detect_framework_from_target() {
  local target_path="$1"
  local base_name
  base_name="$(basename "$target_path")"
  case "$base_name" in
    *.circom)
      printf '%s\n' "circom"
      ;;
    Nargo.toml)
      printf '%s\n' "noir"
      ;;
    Scarb.toml|*.cairo)
      printf '%s\n' "cairo"
      ;;
    Cargo.toml)
      if grep -Eiq 'halo2' "$target_path"; then
        printf '%s\n' "halo2"
        return 0
      fi
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

TARGET_INPUT="${1:-${TARGET_NAME:-/home/teycir/ZkRepos/tornado-core/circuits/withdraw.circom}}"
TARGET_ROOT="${ZKF_TARGET_ROOT:-$DEFAULT_TARGET_ROOT}"

TARGET_CIRCUIT=""
FRAMEWORK="${TARGET_FRAMEWORK:-}"
MAIN_COMPONENT="${TARGET_MAIN_COMPONENT:-}"

TARGET_PATH_CANDIDATE="$(resolve_repo_path "$TARGET_INPUT")"
if [[ -f "$TARGET_PATH_CANDIDATE" ]]; then
  TARGET_CIRCUIT="$TARGET_PATH_CANDIDATE"
else
  mapfile -t DISCOVERED_ENV < <(
    python3 "$DISCOVERY_SCRIPT" \
      --root "$TARGET_ROOT" \
      --match "$TARGET_INPUT" \
      --format env \
      --profile deep
  )
  for line in "${DISCOVERED_ENV[@]}"; do
    case "$line" in
      ZKF_STD_TARGET_DEEP=*)
        TARGET_CIRCUIT="${line#*=}"
        ;;
      ZKF_STD_TARGET_DEEP_FRAMEWORK=*)
        if [[ -z "$FRAMEWORK" ]]; then
          FRAMEWORK="${line#*=}"
        fi
        ;;
      ZKF_STD_TARGET_DEEP_MAIN_COMPONENT=*)
        if [[ -z "$MAIN_COMPONENT" ]]; then
          MAIN_COMPONENT="${line#*=}"
        fi
        ;;
    esac
  done
fi

if [[ -z "$TARGET_CIRCUIT" ]]; then
  echo "Unable to resolve target from input '$TARGET_INPUT'." >&2
  exit 1
fi

if [[ -z "$FRAMEWORK" ]]; then
  FRAMEWORK="$(detect_framework_from_target "$TARGET_CIRCUIT" || true)"
fi
if [[ -z "$FRAMEWORK" ]]; then
  echo "Unable to detect framework for target '$TARGET_CIRCUIT'." >&2
  echo "Set TARGET_FRAMEWORK in the environment before running this script." >&2
  exit 1
fi

if [[ -z "$MAIN_COMPONENT" ]]; then
  MAIN_COMPONENT="main"
fi

JOBS="${JOBS:-1}"
WORKERS="${WORKERS:-2}"
ITERATIONS="${ITERATIONS:-50000}"
TIMEOUT_SECS="${TIMEOUT_SECS:-3600}"
EXTRA_ARGS=()
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  EXTRA_ARGS+=(--dry-run)
fi

if [[ -x "$ROOT_DIR/target/release/zkpatternfuzz" ]]; then
  RUNNER=("$ROOT_DIR/target/release/zkpatternfuzz")
else
  RUNNER=(cargo run --quiet --bin zkpatternfuzz --)
fi

echo "full_coverage target=$TARGET_CIRCUIT framework=$FRAMEWORK main_component=$MAIN_COMPONENT iterations=$ITERATIONS jobs=$JOBS workers=$WORKERS timeout=$TIMEOUT_SECS"

exec "${RUNNER[@]}" \
  --config-profile prod \
  --alias always \
  --target-circuit "$TARGET_CIRCUIT" \
  --main-component "$MAIN_COMPONENT" \
  --framework "$FRAMEWORK" \
  --jobs "$JOBS" \
  --workers "$WORKERS" \
  --iterations "$ITERATIONS" \
  --timeout "$TIMEOUT_SECS" \
  "${EXTRA_ARGS[@]}"
