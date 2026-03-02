#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/artifacts/backend_throughput"
RUNS=1
ITERATIONS=20
TIMEOUT=20
WORKERS=2
BATCH_JOBS=1
INCLUDE_INTEGRATION_TESTS=false
BUILD_IF_MISSING=true
ENFORCE=false

usage() {
  cat <<'EOF'
Run cross-backend throughput comparison (Noir/Cairo/Halo2) using readiness lanes.

Usage:
  scripts/benchmark_cross_backend_throughput.sh [options]

Options:
  --output-dir <path>                 Output root (default: artifacts/backend_throughput)
  --runs <N>                          Number of repeated runs per backend (default: 1)
  --iterations <N>                    Iterations per scan (default: 20)
  --timeout <sec>                     Timeout per scan in seconds (default: 20)
  --workers <N>                       Workers per scan (default: 2)
  --batch-jobs <N>                    Template jobs passed to zk0d_batch (default: 1)
  --include-integration-tests         Include backend integration tests in lane runtime
  --no-build-if-missing               Do not build zk0d_batch when missing
  --enforce                           Exit non-zero if any backend run fails
  -h, --help                          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --batch-jobs) BATCH_JOBS="$2"; shift 2 ;;
    --include-integration-tests) INCLUDE_INTEGRATION_TESTS=true; shift ;;
    --no-build-if-missing) BUILD_IF_MISSING=false; shift ;;
    --enforce) ENFORCE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! "$RUNS" =~ ^[0-9]+$ ]] || [[ "$RUNS" -lt 1 ]]; then
  echo "Invalid --runs: $RUNS" >&2
  exit 1
fi

if [[ ! "$ITERATIONS" =~ ^[0-9]+$ ]] || [[ "$ITERATIONS" -lt 1 ]]; then
  echo "Invalid --iterations: $ITERATIONS" >&2
  exit 1
fi

if [[ ! "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 1 ]]; then
  echo "Invalid --timeout: $TIMEOUT" >&2
  exit 1
fi

if [[ ! "$WORKERS" =~ ^[0-9]+$ ]] || [[ "$WORKERS" -lt 1 ]]; then
  echo "Invalid --workers: $WORKERS" >&2
  exit 1
fi

if [[ ! "$BATCH_JOBS" =~ ^[0-9]+$ ]] || [[ "$BATCH_JOBS" -lt 1 ]]; then
  echo "Invalid --batch-jobs: $BATCH_JOBS" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR/raw"
RUN_METRICS_JSONL="$OUTPUT_DIR/raw/run_metrics.jsonl"
: > "$RUN_METRICS_JSONL"

run_lane() {
  local backend="$1"
  local run_index="$2"
  local run_output="$OUTPUT_DIR/raw/$backend/run_${run_index}"
  local lane_log="$run_output/lane.log"
  local report_path="$run_output/latest_report.json"
  local cmd=()

  mkdir -p "$run_output"

  case "$backend" in
    noir)
      cmd=(
        "$ROOT_DIR/scripts/run_noir_readiness.sh"
        --output-dir "$run_output"
        --iterations "$ITERATIONS"
        --timeout "$TIMEOUT"
        --workers "$WORKERS"
        --batch-jobs "$BATCH_JOBS"
      )
      if ! $INCLUDE_INTEGRATION_TESTS; then
        cmd+=(
          --skip-integration-test
          --skip-constraint-coverage-test
          --skip-constraint-edge-cases-test
          --skip-external-smoke-test
          --skip-external-parity-test
        )
      fi
      ;;
    cairo)
      cmd=(
        "$ROOT_DIR/scripts/run_cairo_readiness.sh"
        --output-dir "$run_output"
        --iterations "$ITERATIONS"
        --timeout "$TIMEOUT"
        --workers "$WORKERS"
        --batch-jobs "$BATCH_JOBS"
      )
      if ! $INCLUDE_INTEGRATION_TESTS; then
        cmd+=(--skip-integration-test --skip-regression-test)
      fi
      ;;
    halo2)
      cmd=(
        "$ROOT_DIR/scripts/run_halo2_readiness.sh"
        --output-dir "$run_output"
        --iterations "$ITERATIONS"
        --timeout "$TIMEOUT"
        --workers "$WORKERS"
        --batch-jobs "$BATCH_JOBS"
      )
      if ! $INCLUDE_INTEGRATION_TESTS; then
        cmd+=(
          --skip-json-integration-test
          --skip-real-circuit-test
          --skip-stability-test
        )
      fi
      ;;
    *)
      echo "Unsupported backend: $backend" >&2
      return 1
      ;;
  esac

  if ! $BUILD_IF_MISSING; then
    cmd+=(--no-build-if-missing)
  fi

  echo "[$backend] run $run_index/$RUNS ..."
  local start_ns
  local end_ns
  local lane_exit
  start_ns="$(date +%s%N)"
  set +e
  "${cmd[@]}" >"$lane_log" 2>&1
  lane_exit=$?
  set -e
  end_ns="$(date +%s%N)"

  python3 - "$RUN_METRICS_JSONL" "$backend" "$run_index" "$lane_exit" "$start_ns" "$end_ns" "$report_path" "$lane_log" <<'PY'
import json
import pathlib
import sys

out_path = pathlib.Path(sys.argv[1])
backend = sys.argv[2]
run_index = int(sys.argv[3])
lane_exit = int(sys.argv[4])
start_ns = int(sys.argv[5])
end_ns = int(sys.argv[6])
report_path = pathlib.Path(sys.argv[7])
lane_log = pathlib.Path(sys.argv[8])

elapsed_seconds = max(0.0, (end_ns - start_ns) / 1_000_000_000.0)
reason_counts = {}
integration_statuses = []
matrix_exit_code = None

if report_path.exists():
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception:
        report = {}
    reason_counts = report.get("matrix", {}).get("reason_counts", {}) or {}
    matrix_exit_code = report.get("matrix", {}).get("exit_code")
    integration_tests = report.get("integration_tests", []) or []
    integration_statuses = [str(test.get("status", "unknown")) for test in integration_tests]

total_classified = 0
for value in reason_counts.values():
    try:
        total_classified += int(value)
    except Exception:
        pass

completed = int(reason_counts.get("completed", 0) or 0)
selector_mismatch = int(reason_counts.get("selector_mismatch", 0) or 0)
selector_matching_total = max(total_classified - selector_mismatch, 0)
selector_matching_completion_rate = (
    completed / selector_matching_total if selector_matching_total > 0 else 1.0
)

classified_per_sec = total_classified / elapsed_seconds if elapsed_seconds > 0 else 0.0
completed_per_sec = completed / elapsed_seconds if elapsed_seconds > 0 else 0.0
selector_matching_total_per_sec = (
    selector_matching_total / elapsed_seconds if elapsed_seconds > 0 else 0.0
)

integration_failed = any(status == "fail" for status in integration_statuses)
run_pass = lane_exit == 0 and not integration_failed and (matrix_exit_code in (0, None))

row = {
    "backend": backend,
    "run_index": run_index,
    "lane_exit_code": lane_exit,
    "matrix_exit_code": matrix_exit_code,
    "run_pass": run_pass,
    "report_path": str(report_path),
    "lane_log": str(lane_log),
    "elapsed_seconds": elapsed_seconds,
    "reason_counts": reason_counts,
    "total_classified": total_classified,
    "completed": completed,
    "selector_mismatch": selector_mismatch,
    "selector_matching_total": selector_matching_total,
    "selector_matching_completion_rate": selector_matching_completion_rate,
    "classified_per_sec": classified_per_sec,
    "completed_per_sec": completed_per_sec,
    "selector_matching_total_per_sec": selector_matching_total_per_sec,
    "integration_statuses": integration_statuses,
}

with out_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(row, sort_keys=True))
    fh.write("\n")
PY
}

for backend in noir cairo halo2; do
  for run_index in $(seq 1 "$RUNS"); do
    run_lane "$backend" "$run_index"
  done
done

LATEST_REPORT="$OUTPUT_DIR/latest_report.json"
LATEST_MARKDOWN="$OUTPUT_DIR/latest_report.md"

python3 - "$RUN_METRICS_JSONL" "$LATEST_REPORT" "$LATEST_MARKDOWN" "$RUNS" "$ITERATIONS" "$TIMEOUT" "$WORKERS" "$BATCH_JOBS" "$INCLUDE_INTEGRATION_TESTS" "$BUILD_IF_MISSING" <<'PY'
import json
import pathlib
import statistics
import sys
from datetime import datetime, timezone

run_metrics_path = pathlib.Path(sys.argv[1])
latest_report_path = pathlib.Path(sys.argv[2])
latest_markdown_path = pathlib.Path(sys.argv[3])
runs_config = int(sys.argv[4])
iterations = int(sys.argv[5])
timeout = int(sys.argv[6])
workers = int(sys.argv[7])
batch_jobs = int(sys.argv[8])
include_integration_tests = sys.argv[9].lower() == "true"
build_if_missing = sys.argv[10].lower() == "true"

runs = []
for line in run_metrics_path.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line:
        continue
    runs.append(json.loads(line))

by_backend = {}
for row in runs:
    by_backend.setdefault(row["backend"], []).append(row)

backend_summaries = []
ranking_rows = []
overall_pass = True

for backend in ("noir", "cairo", "halo2"):
    rows = by_backend.get(backend, [])
    if not rows:
        overall_pass = False
        backend_summaries.append(
            {
                "backend": backend,
                "runs": 0,
                "pass_runs": 0,
                "overall_pass": False,
                "gate_failures": ["missing_runs"],
            }
        )
        continue

    pass_runs = sum(1 for row in rows if row.get("run_pass"))
    if pass_runs != len(rows):
        overall_pass = False

    elapsed = [float(row.get("elapsed_seconds", 0.0) or 0.0) for row in rows]
    classified = [float(row.get("classified_per_sec", 0.0) or 0.0) for row in rows]
    completed = [float(row.get("completed_per_sec", 0.0) or 0.0) for row in rows]
    selector_matching_total = [
        float(row.get("selector_matching_total_per_sec", 0.0) or 0.0) for row in rows
    ]
    selector_matching_rates = [
        float(row.get("selector_matching_completion_rate", 0.0) or 0.0) for row in rows
    ]

    reason_counts_total = {}
    for row in rows:
        for key, value in (row.get("reason_counts") or {}).items():
            reason_counts_total[key] = reason_counts_total.get(key, 0) + int(value)

    median_completed_per_sec = statistics.median(completed)
    ranking_rows.append((backend, median_completed_per_sec))

    backend_summaries.append(
        {
            "backend": backend,
            "runs": len(rows),
            "pass_runs": pass_runs,
            "overall_pass": pass_runs == len(rows),
            "median_elapsed_seconds": statistics.median(elapsed),
            "median_classified_per_sec": statistics.median(classified),
            "median_completed_per_sec": median_completed_per_sec,
            "median_selector_matching_total_per_sec": statistics.median(
                selector_matching_total
            ),
            "median_selector_matching_completion_rate": statistics.median(
                selector_matching_rates
            ),
            "total_classified": sum(int(row.get("total_classified", 0) or 0) for row in rows),
            "total_completed": sum(int(row.get("completed", 0) or 0) for row in rows),
            "total_selector_matching": sum(
                int(row.get("selector_matching_total", 0) or 0) for row in rows
            ),
            "reason_counts_total": reason_counts_total,
            "latest_report_path": rows[-1].get("report_path"),
            "latest_log_path": rows[-1].get("lane_log"),
        }
    )

ranking_rows.sort(key=lambda row: row[1], reverse=True)
ranking = [backend for backend, _ in ranking_rows]

report = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "config": {
        "runs_per_backend": runs_config,
        "iterations": iterations,
        "timeout_seconds": timeout,
        "workers": workers,
        "batch_jobs": batch_jobs,
        "include_integration_tests": include_integration_tests,
        "build_if_missing": build_if_missing,
    },
    "backends": backend_summaries,
    "ranking_by_median_completed_per_sec": ranking,
    "overall_pass": overall_pass,
    "run_metrics_path": str(run_metrics_path),
}

latest_report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

header = [
    "| Backend | Runs | Pass | Median Elapsed (s) | Median Completed/s | Median Classified/s | Selector-Matching Completion |",
    "|---|---:|---:|---:|---:|---:|---:|",
]
rows = []
for backend in backend_summaries:
    if backend.get("runs", 0) == 0:
        rows.append(
            f"| {backend['backend']} | 0 | 0 | n/a | n/a | n/a | n/a |"
        )
        continue
    rows.append(
        "| {backend} | {runs} | {pass_runs} | {elapsed:.3f} | {completed:.3f} | {classified:.3f} | {sel_rate:.3f} |".format(
            backend=backend["backend"],
            runs=backend["runs"],
            pass_runs=backend["pass_runs"],
            elapsed=backend["median_elapsed_seconds"],
            completed=backend["median_completed_per_sec"],
            classified=backend["median_classified_per_sec"],
            sel_rate=backend["median_selector_matching_completion_rate"],
        )
    )

md = [
    "# Cross-Backend Throughput Report",
    "",
    f"- Generated (UTC): {report['generated_utc']}",
    f"- Overall pass: {'PASS' if report['overall_pass'] else 'FAIL'}",
    f"- Ranking (median completed/sec): {', '.join(report['ranking_by_median_completed_per_sec']) if report['ranking_by_median_completed_per_sec'] else 'n/a'}",
    "",
    *header,
    *rows,
    "",
    f"- Raw metrics: `{run_metrics_path}`",
]

latest_markdown_path.write_text("\n".join(md) + "\n", encoding="utf-8")
print(f"Cross-backend throughput report: {latest_report_path}")
print(f"Cross-backend throughput markdown: {latest_markdown_path}")
print(f"Overall pass: {'PASS' if overall_pass else 'FAIL'}")
PY

if $ENFORCE; then
  if ! python3 - "$LATEST_REPORT" <<'PY'
import json
import pathlib
import sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
sys.exit(0 if report.get("overall_pass") else 1)
PY
  then
    echo "[FAIL] Cross-backend throughput harness enforcement failed" >&2
    exit 1
  fi
fi

