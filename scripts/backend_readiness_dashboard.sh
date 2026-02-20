#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
READINESS_ROOT="${READINESS_ROOT:-$ROOT_DIR/artifacts/backend_readiness}"
OUTPUT_PATH="${OUTPUT_PATH:-$READINESS_ROOT/latest_report.json}"
REQUIRED_BACKENDS="${REQUIRED_BACKENDS:-noir,cairo,halo2}"
MIN_COMPLETION_RATE="${MIN_BACKEND_COMPLETION_RATE:-0.90}"
MAX_RUNTIME_ERROR="${MAX_BACKEND_RUNTIME_ERROR:-0}"
MAX_BACKEND_PREFLIGHT_FAILED="${MAX_BACKEND_PREFLIGHT_FAILED:-0}"
ENFORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/backend_readiness_dashboard.sh [options]

Aggregate per-backend readiness reports into a single dashboard artifact.

Options:
  --readiness-root <path>               Backend readiness root (default: artifacts/backend_readiness)
  --output <path>                       Output dashboard JSON path (default: artifacts/backend_readiness/latest_report.json)
  --required-backends <csv>             Backends to gate (default: noir,cairo,halo2)
  --min-completion-rate <float>         Minimum completion rate per backend (default: 0.90)
  --max-runtime-error <int>             Maximum runtime_error count per backend (default: 0)
  --max-backend-preflight-failed <int>  Maximum backend_preflight_failed count per backend (default: 0)
  --enforce                             Exit non-zero when any backend fails
  -h, --help                            Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --readiness-root)
      READINESS_ROOT="$2"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --required-backends)
      REQUIRED_BACKENDS="$2"
      shift 2
      ;;
    --min-completion-rate)
      MIN_COMPLETION_RATE="$2"
      shift 2
      ;;
    --max-runtime-error)
      MAX_RUNTIME_ERROR="$2"
      shift 2
      ;;
    --max-backend-preflight-failed)
      MAX_BACKEND_PREFLIGHT_FAILED="$2"
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

mkdir -p "$(dirname "$OUTPUT_PATH")"

python3 - \
  "$READINESS_ROOT" \
  "$OUTPUT_PATH" \
  "$REQUIRED_BACKENDS" \
  "$MIN_COMPLETION_RATE" \
  "$MAX_RUNTIME_ERROR" \
  "$MAX_BACKEND_PREFLIGHT_FAILED" \
  "$ENFORCE" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


readiness_root = sys.argv[1]
output_path = sys.argv[2]
required_backends = [part.strip() for part in sys.argv[3].split(",") if part.strip()]
min_completion_rate = as_float(sys.argv[4], 0.90)
max_runtime_error = as_int(sys.argv[5], 0)
max_backend_preflight_failed = as_int(sys.argv[6], 0)
enforce = as_int(sys.argv[7], 0) == 1

backend_entries = []
overall_pass = True

for backend in required_backends:
    report_path = os.path.join(readiness_root, backend, "latest_report.json")
    entry = {
        "backend": backend,
        "report_path": report_path,
        "present": os.path.isfile(report_path),
        "matrix_exit_code": None,
        "reason_counts": {},
        "total_classified": 0,
        "completed": 0,
        "completion_rate": 0.0,
        "runtime_error_count": 0,
        "backend_preflight_failed_count": 0,
        "integration_statuses": [],
        "gate_pass": False,
        "gate_failures": [],
    }

    if not entry["present"]:
        entry["gate_failures"].append("missing latest_report.json")
        backend_entries.append(entry)
        overall_pass = False
        continue

    with open(report_path, "r", encoding="utf-8") as handle:
        report = json.load(handle)

    matrix = report.get("matrix", {})
    reason_counts = matrix.get("reason_counts", {})
    if not isinstance(reason_counts, dict):
        reason_counts = {}

    numeric_reason_counts = {key: as_int(value, 0) for key, value in reason_counts.items()}
    total_classified = sum(max(value, 0) for value in numeric_reason_counts.values())
    completed = max(as_int(numeric_reason_counts.get("completed", 0), 0), 0)
    completion_rate = (completed / total_classified) if total_classified > 0 else 0.0
    runtime_error_count = max(as_int(numeric_reason_counts.get("runtime_error", 0), 0), 0)
    backend_preflight_failed_count = max(
        as_int(numeric_reason_counts.get("backend_preflight_failed", 0), 0), 0
    )

    integration_statuses = []
    if isinstance(report.get("integration_tests"), list):
        for test in report["integration_tests"]:
            if isinstance(test, dict):
                integration_statuses.append(str(test.get("status", "unknown")))
    elif isinstance(report.get("integration_test"), dict):
        integration_statuses.append(str(report["integration_test"].get("status", "unknown")))

    integration_failures = sum(1 for status in integration_statuses if status.lower() == "fail")
    matrix_exit_code = as_int(matrix.get("exit_code", 1), 1)

    gate_failures = []
    if matrix_exit_code != 0:
        gate_failures.append(f"matrix exit_code={matrix_exit_code}")
    if completion_rate < min_completion_rate:
        gate_failures.append(
            f"completion_rate {completion_rate:.3f} < {min_completion_rate:.3f}"
        )
    if runtime_error_count > max_runtime_error:
        gate_failures.append(
            f"runtime_error_count {runtime_error_count} > {max_runtime_error}"
        )
    if backend_preflight_failed_count > max_backend_preflight_failed:
        gate_failures.append(
            f"backend_preflight_failed_count {backend_preflight_failed_count} > {max_backend_preflight_failed}"
        )
    if integration_failures > 0:
        gate_failures.append(f"integration_failures={integration_failures}")

    gate_pass = len(gate_failures) == 0
    if not gate_pass:
        overall_pass = False

    entry.update(
        {
            "matrix_exit_code": matrix_exit_code,
            "reason_counts": numeric_reason_counts,
            "total_classified": total_classified,
            "completed": completed,
            "completion_rate": completion_rate,
            "runtime_error_count": runtime_error_count,
            "backend_preflight_failed_count": backend_preflight_failed_count,
            "integration_statuses": integration_statuses,
            "gate_pass": gate_pass,
            "gate_failures": gate_failures,
        }
    )
    backend_entries.append(entry)

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "readiness_root": readiness_root,
    "thresholds": {
        "required_backends": required_backends,
        "min_completion_rate": min_completion_rate,
        "max_runtime_error": max_runtime_error,
        "max_backend_preflight_failed": max_backend_preflight_failed,
    },
    "backends": backend_entries,
    "overall_pass": overall_pass,
}

with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")

for entry in backend_entries:
    status = "PASS" if entry["gate_pass"] else "FAIL"
    print(
        f"[{status}] {entry['backend']}: "
        f"completion={entry['completion_rate']:.3f} "
        f"runtime_error={entry['runtime_error_count']} "
        f"backend_preflight_failed={entry['backend_preflight_failed_count']}"
    )
    if entry["gate_failures"]:
        for failure in entry["gate_failures"]:
            print(f"  - {failure}")

print(f"Backend readiness dashboard: {output_path}")
print(f"Overall backend readiness: {'PASS' if overall_pass else 'FAIL'}")

if enforce and not overall_pass:
    sys.exit(1)
PY
