#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX_PATH="$ROOT_DIR/targets/zk0d_matrix_breadth.yaml"
SUMMARY_ROOTS="${SUMMARY_ROOTS:-$ROOT_DIR/artifacts/roadmap_step_tests_recheck3,$ROOT_DIR/artifacts/roadmap_step_tests_recheck4,$ROOT_DIR/artifacts/roadmap_step_tests_recheck5}"
FRAMEWORKS="${FRAMEWORKS:-noir,cairo,halo2}"
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
max_missing_rate = as_float(sys.argv[4], 0.05)
output_path = sys.argv[5]
enforce = as_int(sys.argv[6], 0) == 1

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
        "run_outcome_missing_count": 0,
        "run_outcome_missing_rate": 0.0,
        "reason_counts": {},
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
    fw["run_outcome_missing_count"] += run_outcome_missing_count
    for reason, count in step_reason_counts.items():
        fw["reason_counts"][reason] = fw["reason_counts"].get(reason, 0) + count
        reason_counts_aggregate[reason] += count

for fw in per_framework.values():
    total = fw["total_classified"]
    missing = fw["run_outcome_missing_count"]
    fw["run_outcome_missing_rate"] = (missing / total) if total > 0 else 0.0
    fw["reason_counts"] = dict(sorted(fw["reason_counts"].items()))

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

overall_pass = len(gate_failures) == 0

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "matrix_path": matrix_path,
    "summary_roots": summary_roots,
    "frameworks": frameworks,
    "thresholds": {
        "max_run_outcome_missing_rate": max_missing_rate,
    },
    "steps": step_entries,
    "per_framework": [per_framework[name] for name in frameworks],
    "aggregate": {
        "total_classified": aggregate_total,
        "run_outcome_missing_count": aggregate_missing,
        "run_outcome_missing_rate": aggregate_missing_rate,
        "reason_counts": dict(sorted(reason_counts_aggregate.items())),
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
        f"run_outcome_missing={fw['run_outcome_missing_count']} "
        f"rate={fw['run_outcome_missing_rate']:.3f}"
    )

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
