#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_ROOT="$ROOT_DIR/artifacts/benchmark_runs_fast"
REQUIRED_PASSES=1
OUTPUT_DIR="$ROOT_DIR/artifacts/release_candidate_validation"
STABLE_REF=""
ROLLBACK_EVEN_IF_GATE_FAILS=0
ENFORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/release_candidate_validate_twice.sh [options]

Run release candidate gate checks twice consecutively and optionally run
rollback validation, then emit a machine-readable JSON report.

Options:
  --bench-root <path>        Benchmark root directory (default: artifacts/benchmark_runs_fast)
  --required-passes <n>      Summaries required per gate attempt (default: 1)
  --stable-ref <git-ref>     Optional rollback target ref
  --rollback-even-if-gate-fails
                             Run rollback validation when --stable-ref is set,
                             even if gate attempts fail
  --output-dir <path>        Output directory for logs/report
  --enforce                  Exit non-zero when overall validation fails
  -h, --help                 Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bench-root)
      BENCH_ROOT="$2"
      shift 2
      ;;
    --required-passes)
      REQUIRED_PASSES="$2"
      shift 2
      ;;
    --stable-ref)
      STABLE_REF="$2"
      shift 2
      ;;
    --rollback-even-if-gate-fails)
      ROLLBACK_EVEN_IF_GATE_FAILS=1
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
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

if ! [[ "$REQUIRED_PASSES" =~ ^[0-9]+$ ]] || [ "$REQUIRED_PASSES" -lt 1 ]; then
  echo "required-passes must be a positive integer (got '$REQUIRED_PASSES')" >&2
  exit 2
fi

mkdir -p "$OUTPUT_DIR"

attempt_statuses=()
attempt_logs=()

for attempt in 1 2; do
  log_path="$OUTPUT_DIR/release_gate_attempt_${attempt}.log"
  attempt_logs+=("$log_path")

  echo "Running release gate attempt ${attempt}..."
  if "$ROOT_DIR/scripts/release_candidate_gate.sh" \
      --bench-root "$BENCH_ROOT" \
      --required-passes "$REQUIRED_PASSES" >"$log_path" 2>&1; then
    status="pass"
  else
    status="fail"
  fi

  attempt_statuses+=("$status")
  echo "  attempt ${attempt}: ${status} (log: $log_path)"
done

rollback_status="skip"
rollback_log_path=""
rollback_trigger="not_requested"
if [[ -n "$STABLE_REF" ]]; then
  rollback_trigger="gates_passed_twice"
fi
if [[ "$ROLLBACK_EVEN_IF_GATE_FAILS" -eq 1 && -n "$STABLE_REF" ]]; then
  rollback_trigger="forced"
fi
if [[ -n "$STABLE_REF" && ( ("${attempt_statuses[0]}" == "pass" && "${attempt_statuses[1]}" == "pass") || "$ROLLBACK_EVEN_IF_GATE_FAILS" -eq 1 ) ]]; then
  rollback_log_path="$OUTPUT_DIR/rollback_validation.log"
  echo "Running rollback validation against stable ref: $STABLE_REF"
  if "$ROOT_DIR/scripts/rollback_validate.sh" --stable-ref "$STABLE_REF" >"$rollback_log_path" 2>&1; then
    rollback_status="pass"
  else
    rollback_status="fail"
  fi
fi

REPORT_PATH="$OUTPUT_DIR/release_candidate_report.json"
python3 - "$REPORT_PATH" "$BENCH_ROOT" "$REQUIRED_PASSES" "$STABLE_REF" "$rollback_trigger" \
  "${attempt_statuses[0]}" "${attempt_statuses[1]}" \
  "${attempt_logs[0]}" "${attempt_logs[1]}" \
  "$rollback_status" "$rollback_log_path" <<'PY'
import json
import sys
from datetime import datetime, timezone

(
    report_path,
    bench_root,
    required_passes,
    stable_ref,
    rollback_trigger,
    attempt1_status,
    attempt2_status,
    attempt1_log,
    attempt2_log,
    rollback_status,
    rollback_log,
) = sys.argv[1:]

gates_passed_twice = attempt1_status == "pass" and attempt2_status == "pass"
overall_pass = gates_passed_twice and rollback_status in {"skip", "pass"}

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "bench_root": bench_root,
    "required_passes_per_gate": int(required_passes),
    "gate_attempts": [
        {"attempt": 1, "status": attempt1_status, "log_path": attempt1_log},
        {"attempt": 2, "status": attempt2_status, "log_path": attempt2_log},
    ],
    "gates_passed_twice": gates_passed_twice,
    "stable_ref": stable_ref or None,
    "rollback_trigger": rollback_trigger,
    "rollback_status": rollback_status,
    "rollback_log_path": rollback_log or None,
    "overall_pass": overall_pass,
}

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)

print(f"Release gate attempt #1: {attempt1_status}")
print(f"Release gate attempt #2: {attempt2_status}")
print(f"Rollback status: {rollback_status}")
print(f"Overall status: {'PASS' if overall_pass else 'FAIL'}")
print(f"Report: {report_path}")
PY

if [[ "$ENFORCE" -eq 1 ]]; then
  python3 - "$REPORT_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    report = json.load(f)
if not report.get("overall_pass", False):
    sys.exit(1)
PY
fi
