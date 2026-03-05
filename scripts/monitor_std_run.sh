#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

resolve_repo_path() {
  local raw_path="$1"
  if [[ "$raw_path" = /* ]]; then
    printf '%s\n' "$raw_path"
  else
    printf '%s\n' "$ROOT_DIR/$raw_path"
  fi
}

if [[ -f "$ROOT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

INTERVAL_SECS=5
TAIL_LINES=25

: "${ZKF_SCAN_OUTPUT_ROOT:?ZKF_SCAN_OUTPUT_ROOT must be set in .env}"
: "${ZKF_RUN_SIGNAL_DIR:?ZKF_RUN_SIGNAL_DIR must be set in .env}"

RUN_ROOT="$(resolve_repo_path "$ZKF_SCAN_OUTPUT_ROOT")"
RUN_SIGNAL_DIR="$(resolve_repo_path "$ZKF_RUN_SIGNAL_DIR")"
SESSION_LOG="$RUN_SIGNAL_DIR/session.log"
LATEST_JSON="$RUN_SIGNAL_DIR/latest.json"

print_snapshot() {
  printf '\n=== monitor snapshot @ %s ===\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "run_root:      $RUN_ROOT"
  echo "run_signal_dir:$RUN_SIGNAL_DIR"

  if [[ -f "$LATEST_JSON" ]]; then
    jq '{run_id,status,stage,reason_code,terminal,started_at,updated_at}' "$LATEST_JSON"
  else
    echo "latest.json: missing ($LATEST_JSON)"
  fi

  if [[ -f "$SESSION_LOG" ]]; then
    echo "--- session.log (last $TAIL_LINES lines) ---"
    tail -n "$TAIL_LINES" "$SESSION_LOG"
  else
    echo "session.log: missing ($SESSION_LOG)"
  fi

  REPORT_DIRS="$(find "$RUN_SIGNAL_DIR" -maxdepth 1 -type d -name 'report_*' 2>/dev/null | sort | tail -n 3 || true)"
  if [[ -n "$REPORT_DIRS" ]]; then
    echo "--- recent reports ---"
    echo "$REPORT_DIRS"
  fi
}

while true; do
  print_snapshot
  sleep "$INTERVAL_SECS"
done
