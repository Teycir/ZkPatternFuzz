#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DAYS="${BACKEND_MATURITY_CONSECUTIVE_DAYS:-14}"
BACKEND_TARGET_SCORE="${BACKEND_MATURITY_CONSECUTIVE_TARGET_SCORE:-5.0}"
BACKEND_REQUIRED_BACKENDS="${BACKEND_MATURITY_CONSECUTIVE_BACKENDS:-circom,noir,cairo,halo2}"
CIRCOM_DAYS="${CIRCOM_FLAKE_CONSECUTIVE_DAYS:-14}"
ENFORCE=0
VERBOSE=0

usage() {
  cat <<'USAGE'
Usage: scripts/run_release_streak_status.sh [options]

Run both streak trackers (backend maturity + Circom flake) and print a compact
daily delta summary: current streak, remaining days, and projected completion day.

Options:
  --backend-days <int>            Consecutive days target for backend maturity gate
                                  (default: 14)
  --backend-target-score <float>  Target backend maturity score for streak gate
                                  (default: 5.0)
  --backend-backends <csv>        Backends tracked by maturity streak gate
                                  (default: circom,noir,cairo,halo2)
  --circom-days <int>             Consecutive days target for Circom flake gate
                                  (default: 14)
  --verbose                       Print raw child-script output in addition to compact summary
  --enforce                       Exit non-zero when either streak gate is failing
  -h, --help                      Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-days)
      BACKEND_DAYS="$2"
      shift 2
      ;;
    --backend-target-score)
      BACKEND_TARGET_SCORE="$2"
      shift 2
      ;;
    --backend-backends)
      BACKEND_REQUIRED_BACKENDS="$2"
      shift 2
      ;;
    --circom-days)
      CIRCOM_DAYS="$2"
      shift 2
      ;;
    --verbose)
      VERBOSE=1
      shift
      ;;
    --enforce)
      ENFORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! [[ "$BACKEND_DAYS" =~ ^[0-9]+$ ]]; then
  echo "backend-days must be a non-negative integer (got '$BACKEND_DAYS')" >&2
  exit 2
fi
if ! [[ "$CIRCOM_DAYS" =~ ^[0-9]+$ ]]; then
  echo "circom-days must be a non-negative integer (got '$CIRCOM_DAYS')" >&2
  exit 2
fi

BACKEND_SCORECARD_PATH="$ROOT_DIR/artifacts/backend_maturity/latest_scorecard.json"
CIRCOM_FLAKE_PATH="$ROOT_DIR/artifacts/circom_flake/latest_report.json"

backend_cmd=(
  "$ROOT_DIR/scripts/backend_maturity_scorecard.sh"
  --consecutive-days "$BACKEND_DAYS"
  --consecutive-target-score "$BACKEND_TARGET_SCORE"
  --consecutive-required-backends "$BACKEND_REQUIRED_BACKENDS"
)
circom_cmd=(
  "$ROOT_DIR/scripts/circom_flake_gate.sh"
  --required-consecutive-days "$CIRCOM_DAYS"
)

TMP_BACKEND_LOG=""
TMP_CIRCOM_LOG=""
cleanup() {
  if [[ -n "$TMP_BACKEND_LOG" ]]; then
    rm -f "$TMP_BACKEND_LOG"
  fi
  if [[ -n "$TMP_CIRCOM_LOG" ]]; then
    rm -f "$TMP_CIRCOM_LOG"
  fi
}
trap cleanup EXIT

set +e
if [[ "$VERBOSE" -eq 1 ]]; then
  "${backend_cmd[@]}"
  backend_exit=$?
  "${circom_cmd[@]}"
  circom_exit=$?
else
  TMP_BACKEND_LOG="$(mktemp)"
  TMP_CIRCOM_LOG="$(mktemp)"
  "${backend_cmd[@]}" >"$TMP_BACKEND_LOG" 2>&1
  backend_exit=$?
  "${circom_cmd[@]}" >"$TMP_CIRCOM_LOG" 2>&1
  circom_exit=$?
fi
set -e

if [[ "$VERBOSE" -ne 1 ]]; then
  if [[ "$backend_exit" -ne 0 ]]; then
    echo "[run_release_streak_status] backend_maturity_scorecard.sh failed (exit=$backend_exit)" >&2
    cat "$TMP_BACKEND_LOG" >&2
  fi
  if [[ "$circom_exit" -ne 0 ]]; then
    echo "[run_release_streak_status] circom_flake_gate.sh failed (exit=$circom_exit)" >&2
    cat "$TMP_CIRCOM_LOG" >&2
  fi
fi

python3 - "$BACKEND_SCORECARD_PATH" "$CIRCOM_FLAKE_PATH" "$backend_exit" "$circom_exit" "$ENFORCE" <<'PY'
import json
import sys
from pathlib import Path


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_json(path: Path):
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


scorecard_path = Path(sys.argv[1])
flake_path = Path(sys.argv[2])
backend_exit = as_int(sys.argv[3], 1)
circom_exit = as_int(sys.argv[4], 1)
enforce = as_int(sys.argv[5], 0) == 1

scorecard = load_json(scorecard_path)
flake = load_json(flake_path)

backend_gate_pass = False
backend_required = []
backend_rows = []
generated_utc = None
if isinstance(scorecard, dict):
    generated_utc = scorecard.get("generated_utc")
    consecutive_gate = scorecard.get("consecutive_gate")
    if isinstance(consecutive_gate, dict):
        backend_gate_pass = bool(consecutive_gate.get("overall_pass", False))
        backend_required = [
            str(item).strip()
            for item in consecutive_gate.get("required_backends", [])
            if str(item).strip()
        ]
        per_backend = consecutive_gate.get("per_backend", {})
        if isinstance(per_backend, dict):
            for backend in backend_required:
                row = per_backend.get(backend, {})
                current = as_int(row.get("current_streak_days"), 0)
                required = as_int(row.get("required_streak_days"), 0)
                remaining = as_int(
                    row.get("remaining_streak_days"), max(required - current, 0)
                )
                projected = row.get("projected_completion_day_utc")
                backend_rows.append((backend, current, required, remaining, projected))

circom_gate_pass = False
circom_current = 0
circom_required = 0
circom_remaining = 0
circom_projected = None
if isinstance(flake, dict):
    circom_gate_pass = bool(flake.get("overall_pass", False))
    circom_current = as_int(flake.get("current_streak_days"), 0)
    circom_required = as_int(flake.get("required_consecutive_days"), 0)
    circom_remaining = as_int(
        flake.get("remaining_streak_days"), max(circom_required - circom_current, 0)
    )
    circom_projected = flake.get("projected_completion_day_utc")

overall_pass = (
    backend_exit == 0
    and circom_exit == 0
    and backend_gate_pass
    and circom_gate_pass
)

print("release_streak_status")
if isinstance(generated_utc, str) and generated_utc:
    print(f"generated_utc={generated_utc}")
print(
    f"backend_maturity_consecutive_gate={'PASS' if backend_gate_pass else 'FAIL'} "
    f"(script_exit={backend_exit})"
)
for backend, current, required, remaining, projected in backend_rows:
    projected_text = projected if isinstance(projected, str) and projected else "n/a"
    print(
        f"backend={backend} streak={current}/{required} remaining={remaining} "
        f"projected_completion_day_utc={projected_text}"
    )
print(
    f"circom_flake_gate={'PASS' if circom_gate_pass else 'FAIL'} "
    f"(script_exit={circom_exit})"
)
projected_text = circom_projected if isinstance(circom_projected, str) and circom_projected else "n/a"
print(
    f"circom_flake streak={circom_current}/{circom_required} remaining={circom_remaining} "
    f"projected_completion_day_utc={projected_text}"
)
print(f"overall_streak_status={'PASS' if overall_pass else 'FAIL'}")

if enforce and not overall_pass:
    sys.exit(1)
PY
