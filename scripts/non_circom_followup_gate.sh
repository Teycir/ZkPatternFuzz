#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX_PATH="$ROOT_DIR/targets/zk0d_matrix_breadth.yaml"
SUMMARY_ROOTS="${SUMMARY_ROOTS:-$ROOT_DIR/artifacts/roadmap_step_tests_recheck3,$ROOT_DIR/artifacts/roadmap_step_tests_recheck4,$ROOT_DIR/artifacts/roadmap_step_tests_recheck5}"
FRAMEWORKS="${FRAMEWORKS:-noir,cairo,halo2}"
MIN_SELECTOR_MATCHING_COMPLETION_RATE="${MIN_SELECTOR_MATCHING_COMPLETION_RATE:-0.90}"
MAX_RUNTIME_ERROR="${MAX_RUNTIME_ERROR:-0}"
MAX_BACKEND_PREFLIGHT_FAILED="${MAX_BACKEND_PREFLIGHT_FAILED:-0}"
MAX_RUN_OUTCOME_MISSING_RATE="${MAX_RUN_OUTCOME_MISSING_RATE:-0.05}"
OUTPUT_PATH="${OUTPUT_PATH:-$ROOT_DIR/artifacts/non_circom_followup/latest_report.json}"
ENFORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/non_circom_followup_gate.sh [options]

Aggregate non-Circom follow-up breadth summaries and enforce run_outcome_missing threshold.

Options:
  --matrix <path>                         Breadth matrix YAML (default: targets/zk0d_matrix_breadth.yaml)
  --summary-roots <csv>                   Comma-separated artifact roots containing summary/step_*.tsv
                                          (default: artifacts/roadmap_step_tests_recheck3,artifacts/roadmap_step_tests_recheck4,artifacts/roadmap_step_tests_recheck5)
  --frameworks <csv>                      Frameworks to aggregate (default: noir,cairo,halo2)
  --min-selector-matching-completion-rate <float>
                                          Minimum per-framework selector-matching completion ratio (default: 0.90)
  --max-runtime-error <int>               Maximum per-framework runtime_error count (default: 0)
  --max-backend-preflight-failed <int>    Maximum per-framework backend_preflight_failed count (default: 0)
  --max-run-outcome-missing-rate <float>  Maximum aggregate run_outcome_missing ratio (default: 0.05)
  --output <path>                         Output JSON report path (default: artifacts/non_circom_followup/latest_report.json)
  --enforce                               Exit non-zero if threshold fails
  -h, --help                              Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix) MATRIX_PATH="$2"; shift 2 ;;
    --summary-roots) SUMMARY_ROOTS="$2"; shift 2 ;;
    --frameworks) FRAMEWORKS="$2"; shift 2 ;;
    --min-selector-matching-completion-rate) MIN_SELECTOR_MATCHING_COMPLETION_RATE="$2"; shift 2 ;;
    --max-runtime-error) MAX_RUNTIME_ERROR="$2"; shift 2 ;;
    --max-backend-preflight-failed) MAX_BACKEND_PREFLIGHT_FAILED="$2"; shift 2 ;;
    --max-run-outcome-missing-rate) MAX_RUN_OUTCOME_MISSING_RATE="$2"; shift 2 ;;
    --output) OUTPUT_PATH="$2"; shift 2 ;;
    --enforce) ENFORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$(dirname "$OUTPUT_PATH")"

python3 - \
  "$MATRIX_PATH" \
  "$SUMMARY_ROOTS" \
  "$FRAMEWORKS" \
  "$MIN_SELECTOR_MATCHING_COMPLETION_RATE" \
  "$MAX_RUNTIME_ERROR" \
  "$MAX_BACKEND_PREFLIGHT_FAILED" \
  "$MAX_RUN_OUTCOME_MISSING_RATE" \
  "$OUTPUT_PATH" \
  "$ENFORCE" <<'PY'
import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


def as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


matrix_path = sys.argv[1]
summary_roots = [item.strip() for item in sys.argv[2].split(",") if item.strip()]
frameworks = [item.strip() for item in sys.argv[3].split(",") if item.strip()]
min_selector_matching_completion_rate = as_float(sys.argv[4], 0.90)
max_runtime_error = as_int(sys.argv[5], 0)
max_backend_preflight_failed = as_int(sys.argv[6], 0)
max_missing_rate = as_float(sys.argv[7], 0.05)
output_path = sys.argv[8]
enforce = as_int(sys.argv[9], 0) == 1

if not os.path.isfile(matrix_path):
    raise SystemExit(f"matrix not found: {matrix_path}")

index_to_target = {}
idx = 0
in_target = False
current = {}
with open(matrix_path, "r", encoding="utf-8") as handle:
    for raw_line in handle:
        line = raw_line.rstrip("\n")
        if line.startswith("  - name: "):
            if in_target:
                index_to_target[idx] = current
            idx += 1
            in_target = True
            current = {
                "step": idx,
                "name": line.split(": ", 1)[1].strip(),
                "framework": "circom",
                "target_circuit": "",
            }
            continue
        if not in_target:
            continue
        if line.startswith("    framework: "):
            current["framework"] = line.split(": ", 1)[1].strip()
        elif line.startswith("    target_circuit: "):
            current["target_circuit"] = line.split(": ", 1)[1].strip()
    if in_target:
        index_to_target[idx] = current

selected_by_step = {}
step_pattern = re.compile(r"step_(\d+)__")
for root in summary_roots:
    summary_dir = os.path.join(root, "summary")
    for path in sorted(glob.glob(os.path.join(summary_dir, "step_*.tsv"))):
        match = step_pattern.search(os.path.basename(path))
        if not match:
            continue
        step = int(match.group(1))
        selected_by_step[step] = path

per_framework = {}
for framework in frameworks:
    per_framework[framework] = {
        "framework": framework,
        "steps": 0,
        "total_classified": 0,
        "completed": 0,
        "selector_mismatch_count": 0,
        "selector_matching_total": 0,
        "selector_matching_completion_rate": 0.0,
        "runtime_error_count": 0,
        "backend_preflight_failed_count": 0,
        "run_outcome_missing_count": 0,
        "run_outcome_missing_rate": 0.0,
        "reason_counts": {},
        "gate_failures": [],
        "gate_pass": False,
    }

step_entries = []
reason_counts_aggregate = defaultdict(int)

for step in sorted(selected_by_step):
    path = selected_by_step[step]
    meta = index_to_target.get(step)
    if not meta:
        continue
    framework = meta.get("framework", "").strip()
    if framework not in per_framework:
        continue

    step_reason_counts = defaultdict(int)
    with open(path, "r", encoding="utf-8") as handle:
        reader = csv.reader(handle, delimiter="\t")
        next(reader, None)
        for row in reader:
            if len(row) < 4:
                continue
            reason = row[2].strip() or "unknown"
            count = max(as_int(row[3], 0), 0)
            step_reason_counts[reason] += count

    total_classified = sum(step_reason_counts.values())
    run_outcome_missing_count = step_reason_counts.get("run_outcome_missing", 0)
    run_outcome_missing_rate = (
        run_outcome_missing_count / total_classified if total_classified > 0 else 0.0
    )

    step_entries.append(
        {
            "step": step,
            "name": meta.get("name", ""),
            "framework": framework,
            "target_circuit": meta.get("target_circuit", ""),
            "summary_path": path,
            "total_classified": total_classified,
            "run_outcome_missing_count": run_outcome_missing_count,
            "run_outcome_missing_rate": run_outcome_missing_rate,
            "reason_counts": dict(sorted(step_reason_counts.items())),
        }
    )

    fw = per_framework[framework]
    fw["steps"] += 1
    fw["total_classified"] += total_classified
    fw["completed"] += step_reason_counts.get("completed", 0)
    fw["selector_mismatch_count"] += step_reason_counts.get("selector_mismatch", 0)
    fw["runtime_error_count"] += step_reason_counts.get("runtime_error", 0)
    fw["backend_preflight_failed_count"] += step_reason_counts.get(
        "backend_preflight_failed", 0
    )
    fw["run_outcome_missing_count"] += run_outcome_missing_count
    for reason, count in step_reason_counts.items():
        fw["reason_counts"][reason] = fw["reason_counts"].get(reason, 0) + count
        reason_counts_aggregate[reason] += count

for fw in per_framework.values():
    total = fw["total_classified"]
    completed = fw["completed"]
    selector_mismatch_count = fw["selector_mismatch_count"]
    selector_matching_total = max(total - selector_mismatch_count, 0)
    selector_matching_completion_rate = (
        completed / selector_matching_total if selector_matching_total > 0 else 1.0
    )
    missing = fw["run_outcome_missing_count"]
    fw["run_outcome_missing_rate"] = (missing / total) if total > 0 else 0.0
    fw["selector_matching_total"] = selector_matching_total
    fw["selector_matching_completion_rate"] = selector_matching_completion_rate
    fw["reason_counts"] = dict(sorted(fw["reason_counts"].items()))
    gate_failures = []
    if fw["steps"] == 0:
        gate_failures.append("no framework step summaries found")
    if selector_matching_completion_rate < min_selector_matching_completion_rate:
        gate_failures.append(
            "selector_matching_completion_rate "
            f"{selector_matching_completion_rate:.3f} < {min_selector_matching_completion_rate:.3f}"
        )
    if fw["runtime_error_count"] > max_runtime_error:
        gate_failures.append(
            f"runtime_error_count {fw['runtime_error_count']} > {max_runtime_error}"
        )
    if fw["backend_preflight_failed_count"] > max_backend_preflight_failed:
        gate_failures.append(
            "backend_preflight_failed_count "
            f"{fw['backend_preflight_failed_count']} > {max_backend_preflight_failed}"
        )
    fw["gate_failures"] = gate_failures
    fw["gate_pass"] = len(gate_failures) == 0

aggregate_total = sum(fw["total_classified"] for fw in per_framework.values())
aggregate_missing = sum(fw["run_outcome_missing_count"] for fw in per_framework.values())
aggregate_missing_rate = aggregate_missing / aggregate_total if aggregate_total > 0 else 0.0

gate_failures = []
if not step_entries:
    gate_failures.append("no non-circom step summaries found")
if aggregate_missing_rate > max_missing_rate:
    gate_failures.append(
        f"aggregate_run_outcome_missing_rate {aggregate_missing_rate:.3f} > {max_missing_rate:.3f}"
    )
framework_gate_failures = []
for framework in frameworks:
    fw = per_framework.get(framework, {})
    failures = fw.get("gate_failures", [])
    if failures:
        framework_gate_failures.append({"framework": framework, "failures": failures})
        for failure in failures:
            gate_failures.append(f"{framework}: {failure}")

overall_pass = len(gate_failures) == 0

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "matrix_path": matrix_path,
    "summary_roots": summary_roots,
    "frameworks": frameworks,
    "thresholds": {
        "min_selector_matching_completion_rate": min_selector_matching_completion_rate,
        "max_runtime_error": max_runtime_error,
        "max_backend_preflight_failed": max_backend_preflight_failed,
        "max_run_outcome_missing_rate": max_missing_rate,
    },
    "steps": step_entries,
    "per_framework": [per_framework[name] for name in frameworks],
    "aggregate": {
        "total_classified": aggregate_total,
        "run_outcome_missing_count": aggregate_missing,
        "run_outcome_missing_rate": aggregate_missing_rate,
        "reason_counts": dict(sorted(reason_counts_aggregate.items())),
        "framework_gate_failures": framework_gate_failures,
        "gate_failures": gate_failures,
    },
    "overall_pass": overall_pass,
}

with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")

for fw in payload["per_framework"]:
    print(
        f"[{fw['framework']}] steps={fw['steps']} total={fw['total_classified']} "
        f"selector_completion={fw['selector_matching_completion_rate']:.3f} "
        f"run_outcome_missing={fw['run_outcome_missing_count']} "
        f"rate={fw['run_outcome_missing_rate']:.3f} "
        f"runtime_error={fw['runtime_error_count']} "
        f"backend_preflight_failed={fw['backend_preflight_failed_count']}"
    )
    if fw["gate_failures"]:
        for failure in fw["gate_failures"]:
            print(f"  - {failure}")

print(
    "Aggregate non-Circom run_outcome_missing_rate="
    f"{aggregate_missing_rate:.3f} (count={aggregate_missing}, total={aggregate_total})"
)
if gate_failures:
    for failure in gate_failures:
        print(f"  - {failure}")
print(f"Follow-up gate report: {output_path}")
print(f"Overall follow-up gate: {'PASS' if overall_pass else 'FAIL'}")

if enforce and not overall_pass:
    sys.exit(1)
PY
