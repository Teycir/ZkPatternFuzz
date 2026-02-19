#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_ROOT="$ROOT_DIR/artifacts/benchmark_runs"
REQUIRED_PASSES=2
STABLE_REF=""

usage() {
  cat <<'USAGE'
Usage: scripts/release_candidate_gate.sh [options]

Validate that the last N benchmark summaries all pass ci_benchmark_gate thresholds.

Options:
  --bench-root <path>        Benchmark root directory (default: artifacts/benchmark_runs)
  --required-passes <n>      Number of latest summaries that must pass (default: 2)
  --stable-ref <git-ref>     Optional rollback validation target (runs rollback_validate on pass)
  -h, --help                 Show this help

Thresholds are inherited from scripts/ci_benchmark_gate.sh env vars:
  MIN_COMPLETION_RATE
  MIN_VULNERABLE_RECALL
  MIN_PRECISION
  MAX_SAFE_FPR
  MAX_SAFE_HIGH_CONF_FPR
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bench-root)
      BENCH_ROOT="$2"
      shift 2
      ;;
    --required-passes)
      REQUIRED_PASSES="$2"
      shift 2
      ;;
    --stable-ref)
      STABLE_REF="$2"
      shift 2
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

if ! [[ "$REQUIRED_PASSES" =~ ^[0-9]+$ ]] || [ "$REQUIRED_PASSES" -lt 1 ]; then
  echo "required-passes must be a positive integer (got '$REQUIRED_PASSES')" >&2
  exit 2
fi

if [ ! -d "$BENCH_ROOT" ]; then
  echo "::error::Benchmark output directory not found: $BENCH_ROOT"
  exit 1
fi

mapfile -t summaries < <(
  find "$BENCH_ROOT" -type f \
    | rg '/benchmark_[0-9]{8}_[0-9]{6}/summary\.json$' \
    | sort
)
summary_count="${#summaries[@]}"

if [ "$summary_count" -lt "$REQUIRED_PASSES" ]; then
  echo "::error::Need at least $REQUIRED_PASSES benchmark summaries, found $summary_count in $BENCH_ROOT"
  exit 1
fi

start_idx=$((summary_count - REQUIRED_PASSES))
failures=0
echo "Checking last $REQUIRED_PASSES benchmark summaries under: $BENCH_ROOT"

for ((i=start_idx; i<summary_count; i++)); do
  summary="${summaries[$i]}"
  echo "==> Gate check: $summary"
  if ! "$ROOT_DIR/scripts/ci_benchmark_gate.sh" "$BENCH_ROOT" "$summary"; then
    failures=$((failures + 1))
  fi
done

if [ "$failures" -ne 0 ]; then
  echo "::error::Release candidate gate failed: $failures / $REQUIRED_PASSES summaries did not pass."
  exit 1
fi

echo "Release candidate gate passed: last $REQUIRED_PASSES benchmark summaries passed."

if [ -n "$STABLE_REF" ]; then
  echo "Running rollback validation against stable ref: $STABLE_REF"
  "$ROOT_DIR/scripts/rollback_validate.sh" --stable-ref "$STABLE_REF"
fi
