#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/non_circom_collision_stress}"
REGISTRY="${REGISTRY:-$ROOT_DIR/targets/fuzzer_registry.prod.yaml}"
TARGET_COUNT="${TARGET_COUNT:-54}"
JOBS="${JOBS:-12}"
BATCH_JOBS="${BATCH_JOBS:-1}"
WORKERS="${WORKERS:-1}"
ITERATIONS="${ITERATIONS:-1}"
TIMEOUT="${TIMEOUT:-6}"
TEMPLATE="${TEMPLATE:-cveX10_maci_underconstrained_circuit.yaml}"
MAX_OUTPUT_DIR_LOCKED="${MAX_OUTPUT_DIR_LOCKED:-0}"
MAX_RUN_OUTCOME_MISSING_RATE="${MAX_RUN_OUTCOME_MISSING_RATE:-0.05}"
MAX_NONE_RATE="${MAX_NONE_RATE:-0.0}"
ENFORCE=0

usage() {
  cat <<'USAGE'
Usage: scripts/run_non_circom_collision_stress.sh [options]

Run a 50+ target non-Circom matrix stress pass to validate collision-safe run-root allocation.

Options:
  --output-dir <path>                    Output directory (default: artifacts/non_circom_collision_stress)
  --registry <path>                      Registry YAML (default: targets/fuzzer_registry.prod.yaml)
  --target-count <N>                     Number of synthetic targets (default: 54)
  --jobs <N>                             Matrix parallel jobs (default: 12)
  --batch-jobs <N>                       Per-target batch jobs (default: 1)
  --workers <N>                          Per-scan workers (default: 1)
  --iterations <N>                       Iterations per target run (default: 1)
  --timeout <sec>                        Timeout per target run in seconds (default: 6)
  --template <name>                      Template filename to execute (default: cveX10_maci_underconstrained_circuit.yaml)
  --max-output-dir-locked <N>            Max allowed output_dir_locked count (default: 0)
  --max-run-outcome-missing-rate <float> Max allowed run_outcome_missing ratio (default: 0.05)
  --max-none-rate <float>                Max allowed reason_code=none ratio (default: 0.0)
  --enforce                              Exit non-zero on threshold failure
  -h, --help                             Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --target-count) TARGET_COUNT="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --batch-jobs) BATCH_JOBS="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --template) TEMPLATE="$2"; shift 2 ;;
    --max-output-dir-locked) MAX_OUTPUT_DIR_LOCKED="$2"; shift 2 ;;
    --max-run-outcome-missing-rate) MAX_RUN_OUTCOME_MISSING_RATE="$2"; shift 2 ;;
    --max-none-rate) MAX_NONE_RATE="$2"; shift 2 ;;
    --enforce) ENFORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$OUTPUT_DIR"
STAMP="$(date -u +"%Y%m%d_%H%M%S")"
MATRIX_PATH="$OUTPUT_DIR/matrix_${STAMP}.yaml"
SUMMARY_TSV="$OUTPUT_DIR/summary_${STAMP}.tsv"
LOG_PATH="$OUTPUT_DIR/run_${STAMP}.log"
REPORT_PATH="$OUTPUT_DIR/latest_report.json"
STRESS_HOME="$OUTPUT_DIR/stress_home"
STRESS_SIGNAL_DIR="$STRESS_HOME/ZkFuzz"
HOST_HOME="${HOST_HOME:-${HOME:-$ROOT_DIR}}"
STRESS_RUSTUP_HOME="${STRESS_RUSTUP_HOME:-${RUSTUP_HOME:-$HOST_HOME/.rustup}}"
STRESS_CARGO_HOME="${STRESS_CARGO_HOME:-${CARGO_HOME:-$HOST_HOME/.cargo}}"
STRESS_BUILD_CACHE_DIR="${STRESS_BUILD_CACHE_DIR:-$ROOT_DIR/ZkFuzz/_build_cache}"
mkdir -p "$STRESS_SIGNAL_DIR" "$STRESS_BUILD_CACHE_DIR"

if ! [[ "$TARGET_COUNT" =~ ^[0-9]+$ ]] || [ "$TARGET_COUNT" -lt 50 ]; then
  echo "target-count must be an integer >= 50 (got '$TARGET_COUNT')" >&2
  exit 2
fi

{
  echo "version: 1"
  echo
  echo "targets:"
  for ((i=1; i<=TARGET_COUNT; i++)); do
    idx="$(printf "%03d" "$i")"
    case $(( (i - 1) % 3 )) in
      0)
        echo "  - name: stress_noir_${idx}"
        echo "    target_circuit: tests/noir_projects/multiplier/Nargo.toml"
        echo "    main_component: main"
        echo "    framework: noir"
        echo "    enabled: true"
        ;;
      1)
        echo "  - name: stress_cairo_${idx}"
        echo "    target_circuit: tests/cairo_programs/multiplier.cairo"
        echo "    main_component: main"
        echo "    framework: cairo"
        echo "    enabled: true"
        ;;
      2)
        echo "  - name: stress_halo2_${idx}"
        echo "    target_circuit: tests/halo2_specs/minimal.json"
        echo "    main_component: main"
        echo "    framework: halo2"
        echo "    enabled: true"
        ;;
    esac
    echo
  done
} > "$MATRIX_PATH"

RUN_CMD=(
  cargo run --release --bin zk0d_matrix --
  --matrix "$MATRIX_PATH"
  --registry "$REGISTRY"
  --template "$TEMPLATE"
  --jobs "$JOBS"
  --batch-jobs "$BATCH_JOBS"
  --workers "$WORKERS"
  --iterations "$ITERATIONS"
  --timeout "$TIMEOUT"
  --summary-tsv "$SUMMARY_TSV"
  --allow-oversubscription
)

set +e
HOME="$STRESS_HOME" \
  ZKF_RUN_SIGNAL_DIR="$STRESS_SIGNAL_DIR" \
  ZKF_BUILD_CACHE_DIR="$STRESS_BUILD_CACHE_DIR" \
  RUSTUP_HOME="$STRESS_RUSTUP_HOME" \
  CARGO_HOME="$STRESS_CARGO_HOME" \
  "${RUN_CMD[@]}" >"$LOG_PATH" 2>&1
MATRIX_EXIT=$?
set -e

python3 - \
  "$SUMMARY_TSV" \
  "$MATRIX_PATH" \
  "$LOG_PATH" \
  "$REPORT_PATH" \
  "$TARGET_COUNT" \
  "$MAX_OUTPUT_DIR_LOCKED" \
  "$MAX_RUN_OUTCOME_MISSING_RATE" \
  "$MAX_NONE_RATE" \
  "$MATRIX_EXIT" <<'PY'
import csv
import json
import sys
from collections import defaultdict
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


summary_tsv = sys.argv[1]
matrix_path = sys.argv[2]
log_path = sys.argv[3]
report_path = sys.argv[4]
target_count = as_int(sys.argv[5], 0)
max_output_dir_locked = as_int(sys.argv[6], 0)
max_run_outcome_missing_rate = as_float(sys.argv[7], 0.05)
max_none_rate = as_float(sys.argv[8], 0.0)
matrix_exit = as_int(sys.argv[9], 1)

reason_counts = defaultdict(int)
framework_reason_counts = {
    "noir": defaultdict(int),
    "cairo": defaultdict(int),
    "halo2": defaultdict(int),
}
row_count = 0

with open(summary_tsv, "r", encoding="utf-8") as handle:
    reader = csv.DictReader(handle, delimiter="\t")
    for row in reader:
        reason = str(row.get("reason_code", "unknown") or "unknown")
        count = max(as_int(row.get("reason_count", 0), 0), 0)
        target_name = str(row.get("target", ""))
        row_count += 1
        reason_counts[reason] += count
        if target_name.startswith("stress_noir_"):
            framework_reason_counts["noir"][reason] += count
        elif target_name.startswith("stress_cairo_"):
            framework_reason_counts["cairo"][reason] += count
        elif target_name.startswith("stress_halo2_"):
            framework_reason_counts["halo2"][reason] += count

total_classified = sum(reason_counts.values())
output_dir_locked_count = reason_counts.get("output_dir_locked", 0)
run_outcome_missing_count = reason_counts.get("run_outcome_missing", 0)
none_count = reason_counts.get("none", 0)
run_outcome_missing_rate = (
    run_outcome_missing_count / total_classified if total_classified > 0 else 0.0
)
none_rate = none_count / total_classified if total_classified > 0 else 0.0

gate_failures = []
if matrix_exit != 0:
    gate_failures.append(f"matrix_exit_code={matrix_exit}")
if target_count < 50:
    gate_failures.append(f"target_count {target_count} < 50")
if output_dir_locked_count > max_output_dir_locked:
    gate_failures.append(
        f"output_dir_locked_count {output_dir_locked_count} > {max_output_dir_locked}"
    )
if run_outcome_missing_rate > max_run_outcome_missing_rate:
    gate_failures.append(
        f"run_outcome_missing_rate {run_outcome_missing_rate:.3f} > {max_run_outcome_missing_rate:.3f}"
    )
if none_rate > max_none_rate:
    gate_failures.append(f"none_rate {none_rate:.3f} > {max_none_rate:.3f}")

overall_pass = len(gate_failures) == 0

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "matrix_path": matrix_path,
    "summary_tsv": summary_tsv,
    "log_path": log_path,
    "target_count": target_count,
    "row_count": row_count,
    "matrix_exit_code": matrix_exit,
    "thresholds": {
        "max_output_dir_locked": max_output_dir_locked,
        "max_run_outcome_missing_rate": max_run_outcome_missing_rate,
        "max_none_rate": max_none_rate,
    },
    "reason_counts": dict(sorted(reason_counts.items())),
    "framework_reason_counts": {
        name: dict(sorted(counts.items()))
        for name, counts in framework_reason_counts.items()
    },
    "metrics": {
        "total_classified": total_classified,
        "output_dir_locked_count": output_dir_locked_count,
        "run_outcome_missing_count": run_outcome_missing_count,
        "run_outcome_missing_rate": run_outcome_missing_rate,
        "none_count": none_count,
        "none_rate": none_rate,
    },
    "gate_failures": gate_failures,
    "overall_pass": overall_pass,
}

with open(report_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")

print(
    f"Collision stress metrics: total={total_classified} "
    f"output_dir_locked={output_dir_locked_count} "
    f"run_outcome_missing_rate={run_outcome_missing_rate:.3f} "
    f"none_rate={none_rate:.3f}"
)
print(f"Collision stress report: {report_path}")
print(f"Collision stress gate: {'PASS' if overall_pass else 'FAIL'}")
if gate_failures:
    for failure in gate_failures:
        print(f"  - {failure}")

if not overall_pass:
    sys.exit(1)
PY

if [[ "$ENFORCE" -eq 1 ]]; then
  exit 0
fi

exit 0
