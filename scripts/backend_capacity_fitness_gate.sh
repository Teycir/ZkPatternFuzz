#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="$ROOT_DIR/artifacts/backend_capacity_fitness/latest_report.json"
THROUGHPUT_OUTPUT_DIR="$ROOT_DIR/artifacts/backend_throughput"
MEMORY_OUTPUT_DIR="$ROOT_DIR/artifacts/memory_profiles"
THROUGHPUT_REPORT=""
MEMORY_REPORT=""
REQUIRED_BACKENDS="${REQUIRED_BACKENDS:-noir,cairo,halo2}"
MIN_MEDIAN_COMPLETED_PER_SEC="${MIN_MEDIAN_COMPLETED_PER_SEC:-0.005}"
PER_BACKEND_MIN_MEDIAN_COMPLETED_PER_SEC="${PER_BACKEND_MIN_MEDIAN_COMPLETED_PER_SEC:-}"
MAX_RSS_KB="${MAX_RSS_KB:-262144}"
THROUGHPUT_RUNS="${THROUGHPUT_RUNS:-1}"
THROUGHPUT_ITERATIONS="${THROUGHPUT_ITERATIONS:-20}"
THROUGHPUT_TIMEOUT="${THROUGHPUT_TIMEOUT:-20}"
THROUGHPUT_WORKERS="${THROUGHPUT_WORKERS:-2}"
THROUGHPUT_BATCH_JOBS="${THROUGHPUT_BATCH_JOBS:-1}"
MEMORY_ITERATIONS="${MEMORY_ITERATIONS:-20}"
MEMORY_TIMEOUT="${MEMORY_TIMEOUT:-20}"
MEMORY_WORKERS="${MEMORY_WORKERS:-2}"
MEMORY_BATCH_JOBS="${MEMORY_BATCH_JOBS:-1}"
SKIP_THROUGHPUT_RUN=0
SKIP_MEMORY_RUN=0
ENFORCE=0
THROUGHPUT_RUN_EXIT_CODE=0
MEMORY_RUN_EXIT_CODE=0

usage() {
  cat <<'USAGE'
Usage: scripts/backend_capacity_fitness_gate.sh [options]

Run and enforce large-circuit memory + cross-backend throughput fitness gates
for release validation.

Options:
  --output <path>                               Output report path
                                                (default: artifacts/backend_capacity_fitness/latest_report.json)
  --throughput-output-dir <path>                Throughput harness output root
                                                (default: artifacts/backend_throughput)
  --memory-output-dir <path>                    Memory harness output root
                                                (default: artifacts/memory_profiles)
  --throughput-report <path>                    Precomputed throughput report JSON
                                                (default: <throughput-output-dir>/latest_report.json)
  --memory-report <path>                        Precomputed memory report JSON
                                                (default: <memory-output-dir>/latest_report.json)
  --required-backends <csv>                     Required backends for throughput thresholds
                                                (default: noir,cairo,halo2)
  --min-median-completed-per-sec <float>        Global min median completed/sec threshold
                                                (default: 0.005)
  --per-backend-min-median-completed-per-sec <csv>
                                                Optional per-backend thresholds (e.g. noir=0.01,cairo=0.01)
  --max-rss-kb <int>                            Max allowed RSS (kB) across profiled large-circuit runs
                                                (default: 262144)
  --throughput-runs <n>                         Throughput runs per backend (default: 1)
  --throughput-iterations <n>                   Throughput iterations per run (default: 20)
  --throughput-timeout <sec>                    Throughput timeout per run (default: 20)
  --throughput-workers <n>                      Throughput workers (default: 2)
  --throughput-batch-jobs <n>                   Throughput batch jobs (default: 1)
  --memory-iterations <n>                       Memory profile iterations per run (default: 20)
  --memory-timeout <sec>                        Memory profile timeout per run (default: 20)
  --memory-workers <n>                          Memory profile workers (default: 2)
  --memory-batch-jobs <n>                       Memory profile batch jobs (default: 1)
  --skip-throughput-run                         Do not run throughput harness; require --throughput-report
  --skip-memory-run                             Do not run memory harness; require --memory-report
  --enforce                                     Exit non-zero when gate fails
  -h, --help                                    Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT_PATH="$2"; shift 2 ;;
    --throughput-output-dir) THROUGHPUT_OUTPUT_DIR="$2"; shift 2 ;;
    --memory-output-dir) MEMORY_OUTPUT_DIR="$2"; shift 2 ;;
    --throughput-report) THROUGHPUT_REPORT="$2"; shift 2 ;;
    --memory-report) MEMORY_REPORT="$2"; shift 2 ;;
    --required-backends) REQUIRED_BACKENDS="$2"; shift 2 ;;
    --min-median-completed-per-sec) MIN_MEDIAN_COMPLETED_PER_SEC="$2"; shift 2 ;;
    --per-backend-min-median-completed-per-sec) PER_BACKEND_MIN_MEDIAN_COMPLETED_PER_SEC="$2"; shift 2 ;;
    --max-rss-kb) MAX_RSS_KB="$2"; shift 2 ;;
    --throughput-runs) THROUGHPUT_RUNS="$2"; shift 2 ;;
    --throughput-iterations) THROUGHPUT_ITERATIONS="$2"; shift 2 ;;
    --throughput-timeout) THROUGHPUT_TIMEOUT="$2"; shift 2 ;;
    --throughput-workers) THROUGHPUT_WORKERS="$2"; shift 2 ;;
    --throughput-batch-jobs) THROUGHPUT_BATCH_JOBS="$2"; shift 2 ;;
    --memory-iterations) MEMORY_ITERATIONS="$2"; shift 2 ;;
    --memory-timeout) MEMORY_TIMEOUT="$2"; shift 2 ;;
    --memory-workers) MEMORY_WORKERS="$2"; shift 2 ;;
    --memory-batch-jobs) MEMORY_BATCH_JOBS="$2"; shift 2 ;;
    --skip-throughput-run) SKIP_THROUGHPUT_RUN=1; shift ;;
    --skip-memory-run) SKIP_MEMORY_RUN=1; shift ;;
    --enforce) ENFORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for value in \
  "$MAX_RSS_KB" \
  "$THROUGHPUT_RUNS" \
  "$THROUGHPUT_ITERATIONS" \
  "$THROUGHPUT_TIMEOUT" \
  "$THROUGHPUT_WORKERS" \
  "$THROUGHPUT_BATCH_JOBS" \
  "$MEMORY_ITERATIONS" \
  "$MEMORY_TIMEOUT" \
  "$MEMORY_WORKERS" \
  "$MEMORY_BATCH_JOBS"; do
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "Expected integer numeric value but got: $value" >&2
    exit 2
  fi
done

python3 - "$MIN_MEDIAN_COMPLETED_PER_SEC" <<'PY'
import sys
try:
    value = float(sys.argv[1])
except ValueError:
    print(f"Invalid --min-median-completed-per-sec: {sys.argv[1]}", file=sys.stderr)
    raise SystemExit(2)
if value < 0:
    print(f"--min-median-completed-per-sec must be >= 0 (got {value})", file=sys.stderr)
    raise SystemExit(2)
PY

if [[ "$SKIP_THROUGHPUT_RUN" -eq 1 && -z "$THROUGHPUT_REPORT" ]]; then
  echo "--skip-throughput-run requires --throughput-report" >&2
  exit 2
fi
if [[ "$SKIP_MEMORY_RUN" -eq 1 && -z "$MEMORY_REPORT" ]]; then
  echo "--skip-memory-run requires --memory-report" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
mkdir -p "$THROUGHPUT_OUTPUT_DIR" "$MEMORY_OUTPUT_DIR"

if [[ "$SKIP_THROUGHPUT_RUN" -eq 0 && -z "$THROUGHPUT_REPORT" ]]; then
  set +e
  "$ROOT_DIR/scripts/benchmark_cross_backend_throughput.sh" \
    --output-dir "$THROUGHPUT_OUTPUT_DIR" \
    --runs "$THROUGHPUT_RUNS" \
    --iterations "$THROUGHPUT_ITERATIONS" \
    --timeout "$THROUGHPUT_TIMEOUT" \
    --workers "$THROUGHPUT_WORKERS" \
    --batch-jobs "$THROUGHPUT_BATCH_JOBS" \
    --enforce
  THROUGHPUT_RUN_EXIT_CODE=$?
  set -e
fi

if [[ "$SKIP_MEMORY_RUN" -eq 0 && -z "$MEMORY_REPORT" ]]; then
  set +e
  "$ROOT_DIR/scripts/profile_large_circuit_memory.sh" \
    --output-dir "$MEMORY_OUTPUT_DIR" \
    --iterations "$MEMORY_ITERATIONS" \
    --timeout "$MEMORY_TIMEOUT" \
    --workers "$MEMORY_WORKERS" \
    --batch-jobs "$MEMORY_BATCH_JOBS" \
    --max-rss-kb "$MAX_RSS_KB" \
    --enforce
  MEMORY_RUN_EXIT_CODE=$?
  set -e
fi

if [[ -z "$THROUGHPUT_REPORT" ]]; then
  THROUGHPUT_REPORT="$THROUGHPUT_OUTPUT_DIR/latest_report.json"
fi
if [[ -z "$MEMORY_REPORT" ]]; then
  MEMORY_REPORT="$MEMORY_OUTPUT_DIR/latest_report.json"
fi

python3 - "$THROUGHPUT_REPORT" "$MEMORY_REPORT" "$OUTPUT_PATH" "$REQUIRED_BACKENDS" "$MIN_MEDIAN_COMPLETED_PER_SEC" "$PER_BACKEND_MIN_MEDIAN_COMPLETED_PER_SEC" "$MAX_RSS_KB" "$ENFORCE" "$THROUGHPUT_OUTPUT_DIR" "$MEMORY_OUTPUT_DIR" "$SKIP_THROUGHPUT_RUN" "$SKIP_MEMORY_RUN" "$THROUGHPUT_RUN_EXIT_CODE" "$MEMORY_RUN_EXIT_CODE" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

(
    throughput_report_raw,
    memory_report_raw,
    output_raw,
    required_backends_raw,
    min_completed_raw,
    per_backend_min_raw,
    max_rss_kb_raw,
    enforce_raw,
    throughput_output_dir,
    memory_output_dir,
    skip_throughput_run_raw,
    skip_memory_run_raw,
    throughput_run_exit_code_raw,
    memory_run_exit_code_raw,
) = sys.argv[1:]

throughput_report_path = pathlib.Path(throughput_report_raw)
memory_report_path = pathlib.Path(memory_report_raw)
output_path = pathlib.Path(output_raw)
required_backends = [item.strip().lower() for item in required_backends_raw.split(",") if item.strip()]
min_completed = float(min_completed_raw)
max_rss_kb = int(max_rss_kb_raw)
enforce = enforce_raw == "1"
skip_throughput_run = skip_throughput_run_raw == "1"
skip_memory_run = skip_memory_run_raw == "1"
throughput_run_exit_code = int(throughput_run_exit_code_raw)
memory_run_exit_code = int(memory_run_exit_code_raw)

per_backend_thresholds = {}
if per_backend_min_raw.strip():
    for part in per_backend_min_raw.split(","):
        item = part.strip()
        if not item:
            continue
        if "=" not in item:
            raise SystemExit(f"Invalid threshold pair '{item}', expected backend=value")
        key, value = item.split("=", 1)
        key = key.strip().lower()
        try:
            parsed = float(value.strip())
        except ValueError:
            raise SystemExit(f"Invalid numeric threshold for '{key}': {value}")
        if parsed < 0:
            raise SystemExit(f"Threshold for '{key}' must be >= 0")
        per_backend_thresholds[key] = parsed

gate_failures = []

if not skip_throughput_run and throughput_run_exit_code != 0:
    gate_failures.append(f"throughput harness exited non-zero: {throughput_run_exit_code}")
if not skip_memory_run and memory_run_exit_code != 0:
    gate_failures.append(f"memory harness exited non-zero: {memory_run_exit_code}")

if not throughput_report_path.is_file():
    gate_failures.append(f"throughput report not found: {throughput_report_path}")
    throughput_report = {}
else:
    throughput_report = json.loads(throughput_report_path.read_text(encoding="utf-8"))

if not memory_report_path.is_file():
    gate_failures.append(f"memory report not found: {memory_report_path}")
    memory_report = {}
else:
    memory_report = json.loads(memory_report_path.read_text(encoding="utf-8"))

throughput_overall_pass = bool(throughput_report.get("overall_pass", False))
if throughput_report and not throughput_overall_pass:
    gate_failures.append("throughput harness overall_pass=false")

throughput_backends = {
    str(entry.get("backend", "")).lower(): entry for entry in throughput_report.get("backends", []) or []
}
throughput_backend_metrics = {}
for backend in required_backends:
    entry = throughput_backends.get(backend)
    if entry is None:
        gate_failures.append(f"throughput report missing required backend: {backend}")
        continue
    median_completed = float(entry.get("median_completed_per_sec", 0.0) or 0.0)
    threshold = per_backend_thresholds.get(backend, min_completed)
    throughput_backend_metrics[backend] = {
        "median_completed_per_sec": median_completed,
        "required_min_completed_per_sec": threshold,
        "backend_overall_pass": bool(entry.get("overall_pass", False)),
    }
    if not bool(entry.get("overall_pass", False)):
        gate_failures.append(f"throughput backend '{backend}' reported overall_pass=false")
    if median_completed < threshold:
        gate_failures.append(
            f"throughput backend '{backend}' median_completed_per_sec {median_completed:.6f} < required {threshold:.6f}"
        )

memory_overall_pass = bool(memory_report.get("overall_pass", False))
if memory_report and not memory_overall_pass:
    gate_failures.append("memory profile overall_pass=false")

observed_max_rss_kb = -1
framework_stats = memory_report.get("framework_stats", []) or []
for stat in framework_stats:
    try:
        value = int(stat.get("max_rss_kb", -1))
    except Exception:
        value = -1
    observed_max_rss_kb = max(observed_max_rss_kb, value)

if observed_max_rss_kb < 0:
    top_targets = memory_report.get("top_targets_by_rss", []) or []
    for row in top_targets:
        try:
            value = int(row.get("max_rss_kb", -1))
        except Exception:
            value = -1
        observed_max_rss_kb = max(observed_max_rss_kb, value)

if max_rss_kb > 0 and observed_max_rss_kb > max_rss_kb:
    gate_failures.append(
        f"observed max_rss_kb {observed_max_rss_kb} exceeds threshold {max_rss_kb}"
    )

overall_pass = len(gate_failures) == 0

report = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "overall_pass": overall_pass,
    "gate_failures": gate_failures,
    "config": {
        "required_backends": required_backends,
        "min_median_completed_per_sec": min_completed,
        "per_backend_min_median_completed_per_sec": per_backend_thresholds,
        "max_rss_kb": max_rss_kb,
        "throughput_output_dir": throughput_output_dir,
        "memory_output_dir": memory_output_dir,
        "skip_throughput_run": skip_throughput_run,
        "skip_memory_run": skip_memory_run,
        "throughput_run_exit_code": throughput_run_exit_code,
        "memory_run_exit_code": memory_run_exit_code,
    },
    "inputs": {
        "throughput_report_path": str(throughput_report_path),
        "memory_report_path": str(memory_report_path),
    },
    "throughput": {
        "overall_pass": throughput_overall_pass,
        "backend_metrics": throughput_backend_metrics,
    },
    "memory": {
        "overall_pass": memory_overall_pass,
        "observed_max_rss_kb": observed_max_rss_kb,
        "framework_stats": framework_stats,
    },
}

output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

print(f"Backend capacity fitness gate: {'PASS' if overall_pass else 'FAIL'}")
print(f"Report: {output_path}")
for failure in gate_failures:
    print(f"- {failure}")

if enforce and not overall_pass:
    raise SystemExit(1)
PY
