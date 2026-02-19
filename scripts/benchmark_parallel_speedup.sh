#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_ROOT="$ROOT_DIR/artifacts/benchmark_runs_speedup"
SUITE="safe_regression,vulnerable_ground_truth"
TRIALS=1
BATCH_JOBS=1
WORKERS=1
ITERATIONS=50
TIMEOUT=10
SERIAL_JOBS=1
PARALLEL_JOBS=2
SPEEDUP_THRESHOLD=1.7
ENFORCE_SPEEDUP=0

usage() {
  cat <<'USAGE'
Usage: scripts/benchmark_parallel_speedup.sh [options]

Run serial and parallel benchmark passes and compute wall-clock speedup plus
filesystem collision indicators.

Options:
  --output-root <path>        Output root directory (default: artifacts/benchmark_runs_speedup)
  --suite <names>             Suites to benchmark (default: safe_regression,vulnerable_ground_truth)
  --trials <n>                Trials per target (default: 1)
  --batch-jobs <n>            Batch jobs per run (default: 1)
  --workers <n>               Workers per run (default: 1)
  --iterations <n>            Iterations per run (default: 50)
  --timeout <seconds>         Timeout per run (default: 10)
  --serial-jobs <n>           Serial benchmark jobs value (default: 1)
  --parallel-jobs <n>         Parallel benchmark jobs value (default: 2)
  --speedup-threshold <f>     Minimum desired speedup ratio (default: 1.7)
  --enforce-speedup           Exit non-zero when speedup is below threshold
  -h, --help                  Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-root)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --suite)
      SUITE="$2"
      shift 2
      ;;
    --trials)
      TRIALS="$2"
      shift 2
      ;;
    --batch-jobs)
      BATCH_JOBS="$2"
      shift 2
      ;;
    --workers)
      WORKERS="$2"
      shift 2
      ;;
    --iterations)
      ITERATIONS="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    --serial-jobs)
      SERIAL_JOBS="$2"
      shift 2
      ;;
    --parallel-jobs)
      PARALLEL_JOBS="$2"
      shift 2
      ;;
    --speedup-threshold)
      SPEEDUP_THRESHOLD="$2"
      shift 2
      ;;
    --enforce-speedup)
      ENFORCE_SPEEDUP=1
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

mkdir -p "$OUTPUT_ROOT/serial" "$OUTPUT_ROOT/parallel"

run_case() {
  local label="$1"
  local jobs="$2"
  local outdir="$3"

  local start_ns
  local end_ns
  start_ns="$(date +%s%N)"
  cargo run --release --bin zk0d_benchmark -- \
    --config-profile dev \
    --suite "$SUITE" \
    --trials "$TRIALS" \
    --jobs "$jobs" \
    --batch-jobs "$BATCH_JOBS" \
    --workers "$WORKERS" \
    --iterations "$ITERATIONS" \
    --timeout "$TIMEOUT" \
    --output-dir "$outdir" >/tmp/zkfuzz_speedup_"$label".log 2>&1
  end_ns="$(date +%s%N)"

  local duration_s
  duration_s="$(python3 - "$start_ns" "$end_ns" <<'PY'
import sys
start_ns = int(sys.argv[1])
end_ns = int(sys.argv[2])
print(f"{(end_ns - start_ns) / 1_000_000_000:.3f}")
PY
)"

  local summary_path outcomes_path
  summary_path="$(find "$outdir" -type f -path '*/benchmark_*/summary.json' | sort | tail -n 1)"
  outcomes_path="$(find "$outdir" -type f -path '*/benchmark_*/outcomes.json' | sort | tail -n 1)"
  if [[ -z "$summary_path" || -z "$outcomes_path" ]]; then
    echo "Missing benchmark artifacts for $label run" >&2
    exit 1
  fi

  local collisions attack_stage
  read -r collisions attack_stage <<<"$(python3 - "$summary_path" "$outcomes_path" <<'PY'
import json
import sys

summary_path, outcomes_path = sys.argv[1], sys.argv[2]
with open(summary_path, "r", encoding="utf-8") as f:
    summary = json.load(f)
with open(outcomes_path, "r", encoding="utf-8") as f:
    outcomes = json.load(f)

collisions = 0
for row in outcomes:
    collisions += int(row.get("reason_counts", {}).get("output_dir_locked", 0))
attack_stage = float(summary.get("overall_attack_stage_reach_rate", 0.0))
print(collisions, f"{attack_stage:.6f}")
PY
)"

  echo "$duration_s|$summary_path|$outcomes_path|$collisions|$attack_stage"
}

echo "Running serial benchmark (jobs=$SERIAL_JOBS)..."
serial_result="$(run_case serial "$SERIAL_JOBS" "$OUTPUT_ROOT/serial")"
IFS='|' read -r serial_duration serial_summary serial_outcomes serial_collisions serial_attack_stage <<<"$serial_result"

echo "Running parallel benchmark (jobs=$PARALLEL_JOBS)..."
parallel_result="$(run_case parallel "$PARALLEL_JOBS" "$OUTPUT_ROOT/parallel")"
IFS='|' read -r parallel_duration parallel_summary parallel_outcomes parallel_collisions parallel_attack_stage <<<"$parallel_result"

speedup="$(python3 - "$serial_duration" "$parallel_duration" <<'PY'
import sys
serial = float(sys.argv[1])
parallel = float(sys.argv[2])
if parallel <= 0:
    print("0.000")
else:
    print(f"{serial / parallel:.3f}")
PY
)"

report_path="$OUTPUT_ROOT/speedup_report.json"
python3 - "$report_path" "$serial_duration" "$parallel_duration" "$speedup" \
  "$serial_summary" "$parallel_summary" "$serial_outcomes" "$parallel_outcomes" \
  "$serial_collisions" "$parallel_collisions" "$serial_attack_stage" "$parallel_attack_stage" \
  "$SPEEDUP_THRESHOLD" <<'PY'
import json
import sys
from datetime import datetime, timezone

(
    report_path,
    serial_duration,
    parallel_duration,
    speedup,
    serial_summary,
    parallel_summary,
    serial_outcomes,
    parallel_outcomes,
    serial_collisions,
    parallel_collisions,
    serial_attack_stage,
    parallel_attack_stage,
    threshold,
) = sys.argv[1:]

payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "serial": {
        "duration_seconds": float(serial_duration),
        "summary_path": serial_summary,
        "outcomes_path": serial_outcomes,
        "output_dir_locked": int(serial_collisions),
        "attack_stage_reach_rate": float(serial_attack_stage),
    },
    "parallel": {
        "duration_seconds": float(parallel_duration),
        "summary_path": parallel_summary,
        "outcomes_path": parallel_outcomes,
        "output_dir_locked": int(parallel_collisions),
        "attack_stage_reach_rate": float(parallel_attack_stage),
    },
    "speedup": float(speedup),
    "speedup_threshold": float(threshold),
    "passes_speedup_threshold": float(speedup) >= float(threshold),
}
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
PY

echo "Serial duration: ${serial_duration}s (collisions=$serial_collisions, attack_stage=${serial_attack_stage})"
echo "Parallel duration: ${parallel_duration}s (collisions=$parallel_collisions, attack_stage=${parallel_attack_stage})"
echo "Speedup: ${speedup}x (threshold ${SPEEDUP_THRESHOLD}x)"
echo "Report: $report_path"

if [[ "$serial_collisions" -ne 0 || "$parallel_collisions" -ne 0 ]]; then
  echo "Filesystem collision check failed (output_dir_locked > 0)" >&2
  exit 1
fi

if [[ "$ENFORCE_SPEEDUP" -eq 1 ]]; then
  python3 - "$speedup" "$SPEEDUP_THRESHOLD" <<'PY'
import sys
speedup = float(sys.argv[1])
threshold = float(sys.argv[2])
if speedup < threshold:
    print(f"Speedup gate failed: {speedup:.3f} < {threshold:.3f}")
    sys.exit(1)
PY
fi

echo "Parallel speedup benchmark completed."
