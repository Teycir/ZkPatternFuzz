#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
READINESS_ROOT="${READINESS_ROOT:-$ROOT_DIR/artifacts/backend_readiness}"
OUTPUT_PATH="${OUTPUT_PATH:-$READINESS_ROOT/latest_report.json}"
REQUIRED_BACKENDS="${REQUIRED_BACKENDS:-noir,cairo,halo2}"
MIN_COMPLETION_RATE="${MIN_BACKEND_COMPLETION_RATE:-0.90}"
MIN_SELECTOR_MATCHING_TOTAL="${MIN_BACKEND_SELECTOR_MATCHING_TOTAL:-4}"
PER_BACKEND_MIN_SELECTOR_MATCHING_TOTAL="${MIN_BACKEND_SELECTOR_MATCHING_TOTALS:-}"
MIN_OVERALL_COMPLETION_RATE="${MIN_BACKEND_OVERALL_COMPLETION_RATE:-0.40}"
MAX_SELECTOR_MISMATCH_RATE="${MAX_BACKEND_SELECTOR_MISMATCH_RATE:-0.70}"
MAX_RUNTIME_ERROR="${MAX_BACKEND_RUNTIME_ERROR:-0}"
MAX_BACKEND_PREFLIGHT_FAILED="${MAX_BACKEND_PREFLIGHT_FAILED:-0}"
MAX_RUN_OUTCOME_MISSING_RATE="${MAX_RUN_OUTCOME_MISSING_RATE:-0.05}"
MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL="${MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL:-12}"
MIN_ENABLED_TARGETS="${MIN_BACKEND_ENABLED_TARGETS:-5}"
ENFORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/backend_readiness_dashboard.sh [options]

Aggregate per-backend readiness reports into a single dashboard artifact.

Options:
  --readiness-root <path>               Backend readiness root (default: artifacts/backend_readiness)
  --output <path>                       Output dashboard JSON path (default: artifacts/backend_readiness/latest_report.json)
  --required-backends <csv>             Backends to gate (default: noir,cairo,halo2)
  --min-completion-rate <float>         Minimum selector-matching completion rate per backend (default: 0.90)
  --min-selector-matching-total <int>   Minimum selector-matching classified runs per backend (default: 4)
  --per-backend-min-selector-matching-total <csv>
                                      Optional per-backend selector-matching thresholds (e.g. noir=25,cairo=4,halo2=4)
  --min-overall-completion-rate <float> Minimum overall completion rate per backend (default: 0.40)
  --max-selector-mismatch-rate <float>  Maximum selector_mismatch ratio per backend (default: 0.70)
  --max-runtime-error <int>             Maximum runtime_error count per backend (default: 0)
  --max-backend-preflight-failed <int>  Maximum backend_preflight_failed count per backend (default: 0)
  --max-run-outcome-missing-rate <float>
                                      Maximum run_outcome_missing ratio (per backend and aggregate) (default: 0.05)
  --min-aggregate-selector-matching-total <int>
                                      Minimum aggregate selector-matching classified runs across required backends (default: 12)
  --min-enabled-targets <int>          Minimum enabled matrix targets per backend (default: 5)
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
    --min-selector-matching-total)
      MIN_SELECTOR_MATCHING_TOTAL="$2"
      shift 2
      ;;
    --per-backend-min-selector-matching-total)
      PER_BACKEND_MIN_SELECTOR_MATCHING_TOTAL="$2"
      shift 2
      ;;
    --min-overall-completion-rate)
      MIN_OVERALL_COMPLETION_RATE="$2"
      shift 2
      ;;
    --max-selector-mismatch-rate)
      MAX_SELECTOR_MISMATCH_RATE="$2"
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
    --max-run-outcome-missing-rate)
      MAX_RUN_OUTCOME_MISSING_RATE="$2"
      shift 2
      ;;
    --min-aggregate-selector-matching-total)
      MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL="$2"
      shift 2
      ;;
    --min-enabled-targets)
      MIN_ENABLED_TARGETS="$2"
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
  "$MIN_SELECTOR_MATCHING_TOTAL" \
  "$PER_BACKEND_MIN_SELECTOR_MATCHING_TOTAL" \
  "$MIN_OVERALL_COMPLETION_RATE" \
  "$MAX_SELECTOR_MISMATCH_RATE" \
  "$MAX_RUNTIME_ERROR" \
  "$MAX_BACKEND_PREFLIGHT_FAILED" \
  "$MAX_RUN_OUTCOME_MISSING_RATE" \
  "$MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL" \
  "$MIN_ENABLED_TARGETS" \
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


def parse_backend_thresholds(raw_value):
    thresholds = {}
    raw = str(raw_value or "").strip()
    if not raw:
        return thresholds

    for item in raw.split(","):
        pair = item.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError(
                f"invalid backend threshold '{pair}' (expected backend=value)"
            )
        backend, value = pair.split("=", 1)
        backend = backend.strip()
        if not backend:
            raise ValueError(f"invalid backend threshold '{pair}' (empty backend)")
        try:
            threshold = int(value.strip())
        except ValueError as exc:
            raise ValueError(
                f"invalid threshold value '{value.strip()}' for backend '{backend}'"
            ) from exc
        if threshold < 0:
            raise ValueError(
                f"invalid negative threshold {threshold} for backend '{backend}'"
            )
        thresholds[backend] = threshold

    return thresholds


def count_enabled_targets(matrix_path):
    if not matrix_path or not os.path.isfile(matrix_path):
        return None

    count = 0
    in_target = False
    enabled = True

    with open(matrix_path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if line.startswith("- name:"):
                if in_target and enabled:
                    count += 1
                in_target = True
                enabled = True
                continue

            if in_target and line.startswith("enabled:"):
                enabled_value = line.split(":", 1)[1].strip().strip("'\"").lower()
                enabled = enabled_value not in {"false", "0", "no"}

    if in_target and enabled:
        count += 1

    return count


readiness_root = sys.argv[1]
output_path = sys.argv[2]
required_backends = [part.strip() for part in sys.argv[3].split(",") if part.strip()]
min_completion_rate = as_float(sys.argv[4], 0.90)
min_selector_matching_total = as_int(sys.argv[5], 4)
try:
    per_backend_min_selector_matching_total = parse_backend_thresholds(sys.argv[6])
except ValueError as err:
    print(f"Invalid --per-backend-min-selector-matching-total: {err}", file=sys.stderr)
    sys.exit(2)
min_overall_completion_rate = as_float(sys.argv[7], 0.40)
max_selector_mismatch_rate = as_float(sys.argv[8], 0.70)
max_runtime_error = as_int(sys.argv[9], 0)
max_backend_preflight_failed = as_int(sys.argv[10], 0)
max_run_outcome_missing_rate = as_float(sys.argv[11], 0.05)
min_aggregate_selector_matching_total = as_int(sys.argv[12], 12)
min_enabled_targets = as_int(sys.argv[13], 5)
enforce = as_int(sys.argv[14], 0) == 1

backend_entries = []
overall_pass = True
aggregate_total_classified = 0
aggregate_run_outcome_missing = 0
aggregate_selector_matching_total = 0

for backend in required_backends:
    selector_matching_total_threshold = per_backend_min_selector_matching_total.get(
        backend, min_selector_matching_total
    )
    report_path = os.path.join(readiness_root, backend, "latest_report.json")
    entry = {
        "backend": backend,
        "report_path": report_path,
        "present": os.path.isfile(report_path),
        "matrix_exit_code": None,
        "matrix_path": "",
        "enabled_targets_count": None,
        "reason_counts": {},
        "total_classified": 0,
        "completed": 0,
        "completion_rate": 0.0,
        "selector_mismatch_count": 0,
        "selector_mismatch_rate": 0.0,
        "selector_matching_total": 0,
        "selector_matching_total_threshold": selector_matching_total_threshold,
        "selector_matching_completion_rate": 0.0,
        "runtime_error_count": 0,
        "backend_preflight_failed_count": 0,
        "run_outcome_missing_count": 0,
        "run_outcome_missing_rate": 0.0,
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
    matrix_path = str(matrix.get("path", ""))
    enabled_targets_count = count_enabled_targets(matrix_path)
    reason_counts = matrix.get("reason_counts", {})
    if not isinstance(reason_counts, dict):
        reason_counts = {}

    numeric_reason_counts = {key: as_int(value, 0) for key, value in reason_counts.items()}
    total_classified = sum(max(value, 0) for value in numeric_reason_counts.values())
    completed = max(as_int(numeric_reason_counts.get("completed", 0), 0), 0)
    completion_rate = (completed / total_classified) if total_classified > 0 else 0.0
    selector_mismatch_count = max(as_int(numeric_reason_counts.get("selector_mismatch", 0), 0), 0)
    selector_mismatch_rate = (
        selector_mismatch_count / total_classified if total_classified > 0 else 0.0
    )
    selector_matching_total = max(total_classified - selector_mismatch_count, 0)
    selector_matching_completion_rate = (
        completed / selector_matching_total if selector_matching_total > 0 else 1.0
    )
    runtime_error_count = max(as_int(numeric_reason_counts.get("runtime_error", 0), 0), 0)
    backend_preflight_failed_count = max(
        as_int(numeric_reason_counts.get("backend_preflight_failed", 0), 0), 0
    )
    run_outcome_missing_count = max(
        as_int(numeric_reason_counts.get("run_outcome_missing", 0), 0), 0
    )
    run_outcome_missing_rate = (
        run_outcome_missing_count / total_classified if total_classified > 0 else 0.0
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
    if selector_matching_completion_rate < min_completion_rate:
        gate_failures.append(
            "selector_matching_completion_rate "
            f"{selector_matching_completion_rate:.3f} < {min_completion_rate:.3f}"
        )
    if selector_matching_total < selector_matching_total_threshold:
        gate_failures.append(
            "selector_matching_total "
            f"{selector_matching_total} < {selector_matching_total_threshold}"
        )
    if enabled_targets_count is None:
        gate_failures.append("enabled_targets_count unavailable (matrix path missing/unreadable)")
    elif enabled_targets_count < min_enabled_targets:
        gate_failures.append(
            f"enabled_targets_count {enabled_targets_count} < {min_enabled_targets}"
        )
    if completion_rate < min_overall_completion_rate:
        gate_failures.append(
            f"overall_completion_rate {completion_rate:.3f} < {min_overall_completion_rate:.3f}"
        )
    if selector_mismatch_rate > max_selector_mismatch_rate:
        gate_failures.append(
            f"selector_mismatch_rate {selector_mismatch_rate:.3f} > {max_selector_mismatch_rate:.3f}"
        )
    if runtime_error_count > max_runtime_error:
        gate_failures.append(
            f"runtime_error_count {runtime_error_count} > {max_runtime_error}"
        )
    if backend_preflight_failed_count > max_backend_preflight_failed:
        gate_failures.append(
            f"backend_preflight_failed_count {backend_preflight_failed_count} > {max_backend_preflight_failed}"
        )
    if run_outcome_missing_rate > max_run_outcome_missing_rate:
        gate_failures.append(
            f"run_outcome_missing_rate {run_outcome_missing_rate:.3f} > {max_run_outcome_missing_rate:.3f}"
        )
    if integration_failures > 0:
        gate_failures.append(f"integration_failures={integration_failures}")

    gate_pass = len(gate_failures) == 0
    if not gate_pass:
        overall_pass = False

    entry.update(
        {
            "matrix_exit_code": matrix_exit_code,
            "matrix_path": matrix_path,
            "enabled_targets_count": enabled_targets_count,
            "reason_counts": numeric_reason_counts,
            "total_classified": total_classified,
            "completed": completed,
            "completion_rate": completion_rate,
            "selector_mismatch_count": selector_mismatch_count,
            "selector_mismatch_rate": selector_mismatch_rate,
            "selector_matching_total": selector_matching_total,
            "selector_matching_completion_rate": selector_matching_completion_rate,
            "runtime_error_count": runtime_error_count,
            "backend_preflight_failed_count": backend_preflight_failed_count,
            "run_outcome_missing_count": run_outcome_missing_count,
            "run_outcome_missing_rate": run_outcome_missing_rate,
            "integration_statuses": integration_statuses,
            "gate_pass": gate_pass,
            "gate_failures": gate_failures,
        }
    )
    backend_entries.append(entry)
    aggregate_total_classified += total_classified
    aggregate_run_outcome_missing += run_outcome_missing_count
    aggregate_selector_matching_total += selector_matching_total

aggregate_run_outcome_missing_rate = (
    aggregate_run_outcome_missing / aggregate_total_classified
    if aggregate_total_classified > 0
    else 0.0
)
aggregate_gate_failures = []
if aggregate_run_outcome_missing_rate > max_run_outcome_missing_rate:
    aggregate_gate_failures.append(
        f"aggregate_run_outcome_missing_rate {aggregate_run_outcome_missing_rate:.3f} > {max_run_outcome_missing_rate:.3f}"
    )
if aggregate_selector_matching_total < min_aggregate_selector_matching_total:
    aggregate_gate_failures.append(
        "aggregate_selector_matching_total "
        f"{aggregate_selector_matching_total} < {min_aggregate_selector_matching_total}"
    )
if aggregate_gate_failures:
    overall_pass = False

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "readiness_root": readiness_root,
    "thresholds": {
        "required_backends": required_backends,
        "min_completion_rate": min_completion_rate,
        "completion_rate_basis": "selector_matching",
        "min_selector_matching_total": min_selector_matching_total,
        "per_backend_min_selector_matching_total": per_backend_min_selector_matching_total,
        "min_overall_completion_rate": min_overall_completion_rate,
        "max_selector_mismatch_rate": max_selector_mismatch_rate,
        "max_runtime_error": max_runtime_error,
        "max_backend_preflight_failed": max_backend_preflight_failed,
        "max_run_outcome_missing_rate": max_run_outcome_missing_rate,
        "min_aggregate_selector_matching_total": min_aggregate_selector_matching_total,
        "min_enabled_targets": min_enabled_targets,
    },
    "backends": backend_entries,
    "aggregate": {
        "total_classified": aggregate_total_classified,
        "selector_matching_total": aggregate_selector_matching_total,
        "run_outcome_missing_count": aggregate_run_outcome_missing,
        "run_outcome_missing_rate": aggregate_run_outcome_missing_rate,
        "gate_failures": aggregate_gate_failures,
    },
    "overall_pass": overall_pass,
}

with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")

for entry in backend_entries:
    status = "PASS" if entry["gate_pass"] else "FAIL"
    print(
        f"[{status}] {entry['backend']}: "
        f"enabled_targets={entry['enabled_targets_count']} "
        f"selector_completion={entry['selector_matching_completion_rate']:.3f} "
        f"selector_matching_total={entry['selector_matching_total']} "
        f"selector_mismatch_rate={entry['selector_mismatch_rate']:.3f} "
        f"overall_completion={entry['completion_rate']:.3f} "
        f"runtime_error={entry['runtime_error_count']} "
        f"backend_preflight_failed={entry['backend_preflight_failed_count']} "
        f"run_outcome_missing_rate={entry['run_outcome_missing_rate']:.3f}"
    )
    if entry["gate_failures"]:
        for failure in entry["gate_failures"]:
            print(f"  - {failure}")

print(
    "Aggregate non-Circom selector_matching_total="
    f"{aggregate_selector_matching_total} "
    f"(minimum={min_aggregate_selector_matching_total})"
)
print(
    "Aggregate non-Circom run_outcome_missing_rate="
    f"{aggregate_run_outcome_missing_rate:.3f} "
    f"(count={aggregate_run_outcome_missing}, total={aggregate_total_classified})"
)
if aggregate_gate_failures:
    for failure in aggregate_gate_failures:
        print(f"  - {failure}")

print(f"Backend readiness dashboard: {output_path}")
print(f"Overall backend readiness: {'PASS' if overall_pass else 'FAIL'}")

if enforce and not overall_pass:
    sys.exit(1)
PY
