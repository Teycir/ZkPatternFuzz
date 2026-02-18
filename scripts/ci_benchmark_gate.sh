#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_ROOT="${1:-$ROOT_DIR/artifacts/benchmark_runs}"

MIN_COMPLETION_RATE="${MIN_COMPLETION_RATE:-0.95}"
MIN_VULNERABLE_RECALL="${MIN_VULNERABLE_RECALL:-0.20}"
MIN_PRECISION="${MIN_PRECISION:-0.20}"
MAX_SAFE_FPR="${MAX_SAFE_FPR:-0.20}"

if [ ! -d "$BENCH_ROOT" ]; then
  echo "::error::Benchmark output directory not found: $BENCH_ROOT"
  exit 1
fi

SUMMARY_PATH="$(find "$BENCH_ROOT" -type f -path '*/benchmark_*/summary.json' | sort | tail -n 1)"
if [ -z "$SUMMARY_PATH" ]; then
  echo "::error::No benchmark summary.json found under $BENCH_ROOT"
  exit 1
fi

echo "Using benchmark summary: $SUMMARY_PATH"
echo "Thresholds: completion>=$MIN_COMPLETION_RATE recall>=$MIN_VULNERABLE_RECALL precision>=$MIN_PRECISION safe_fpr<=$MAX_SAFE_FPR"

python3 - "$SUMMARY_PATH" "$MIN_COMPLETION_RATE" "$MIN_VULNERABLE_RECALL" "$MIN_PRECISION" "$MAX_SAFE_FPR" <<'PY'
import json
import sys

summary_path = sys.argv[1]
min_completion = float(sys.argv[2])
min_recall = float(sys.argv[3])
min_precision = float(sys.argv[4])
max_safe_fpr = float(sys.argv[5])

with open(summary_path, "r", encoding="utf-8") as f:
    summary = json.load(f)

completion = float(summary.get("overall_completion_rate", 0.0))
recall = float(summary.get("vulnerable_recall", 0.0))
precision = float(summary.get("precision", 0.0))
safe_fpr = float(summary.get("safe_false_positive_rate", 1.0))
total_runs = int(summary.get("total_runs", 0))
total_detected = int(summary.get("total_detected", 0))

print(f"Metrics: total_runs={total_runs} total_detected={total_detected} completion={completion:.4f} recall={recall:.4f} precision={precision:.4f} safe_fpr={safe_fpr:.4f}")

failures = []
if total_runs <= 0:
    failures.append("total_runs must be > 0")
if completion < min_completion:
    failures.append(f"overall_completion_rate {completion:.4f} < {min_completion:.4f}")
if recall < min_recall:
    failures.append(f"vulnerable_recall {recall:.4f} < {min_recall:.4f}")
if precision < min_precision:
    failures.append(f"precision {precision:.4f} < {min_precision:.4f}")
if safe_fpr > max_safe_fpr:
    failures.append(f"safe_false_positive_rate {safe_fpr:.4f} > {max_safe_fpr:.4f}")

if failures:
    print("::error::Benchmark regression gate failed:")
    for item in failures:
        print(f"  - {item}")
    sys.exit(1)

print("Benchmark regression gate passed.")
PY

