#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITES_PATH="${SUITES_PATH:-$ROOT_DIR/targets/benchmark_suites.multibackend.dev.yaml}"
SUITE_NAMES="${SUITE_NAMES:-safe_regression_multibackend,vulnerable_ground_truth_multibackend}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/benchmark_runs_multibackend_sample}"
TRIALS="${TRIALS:-1}"
JOBS="${JOBS:-1}"
BATCH_JOBS="${BATCH_JOBS:-1}"
WORKERS="${WORKERS:-1}"
ITERATIONS="${ITERATIONS:-20}"
TIMEOUT="${TIMEOUT:-12}"
REPORT_OUT="${REPORT_OUT:-$ROOT_DIR/artifacts/backend_effectiveness/latest_multibackend_report.json}"
ENFORCE="${ENFORCE:-0}"
PTAU_SOURCE="${PTAU_SOURCE:-$ROOT_DIR/tests/circuits/build/pot12_final.ptau}"
BENCH_HOME="$OUTPUT_DIR/benchmark_home"
PTAU_DIR="$BENCH_HOME/.snarkjs"

if [[ -f "$PTAU_SOURCE" ]]; then
  mkdir -p "$PTAU_DIR"
  cp -f "$PTAU_SOURCE" "$PTAU_DIR/$(basename "$PTAU_SOURCE")"
  echo "seeded benchmark ptau: $PTAU_DIR/$(basename "$PTAU_SOURCE")"
else
  echo "warning: ptau source missing ($PTAU_SOURCE); Circom rows may fail preflight" >&2
fi

cargo run --quiet --bin zk0d_benchmark -- \
  --suites "$SUITES_PATH" \
  --suite "$SUITE_NAMES" \
  --trials "$TRIALS" \
  --jobs "$JOBS" \
  --batch-jobs "$BATCH_JOBS" \
  --workers "$WORKERS" \
  --iterations "$ITERATIONS" \
  --timeout "$TIMEOUT" \
  --output-dir "$OUTPUT_DIR"

latest_summary="$(find "$OUTPUT_DIR" -type f | rg '/benchmark_[0-9]{8}_[0-9]{6}/summary\.json$' | sort | tail -n 1)"
if [[ -z "$latest_summary" ]]; then
  echo "no summary.json found under $OUTPUT_DIR" >&2
  exit 1
fi
latest_outcomes="${latest_summary%/summary.json}/outcomes.json"

cmd=(
  python3 "$ROOT_DIR/scripts/build_backend_effectiveness_report.py"
  --summary "$latest_summary"
  --outcomes "$latest_outcomes"
  --output "$REPORT_OUT"
)
if [[ "$ENFORCE" == "1" ]]; then
  cmd+=(--enforce)
fi
"${cmd[@]}"

echo "multibackend sample benchmark summary: $latest_summary"
echo "multibackend effectiveness report: $REPORT_OUT"
