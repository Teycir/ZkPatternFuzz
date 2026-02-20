#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_ROOT="$ROOT_DIR/artifacts/benchmark_runs"
REQUIRED_PASSES=2
STABLE_REF=""
BACKEND_READINESS_ROOT="$ROOT_DIR/artifacts/backend_readiness"
BACKEND_READINESS_DASHBOARD="$BACKEND_READINESS_ROOT/latest_report.json"
BACKEND_REQUIRED_LIST="${BACKEND_REQUIRED_LIST:-noir,cairo,halo2}"
MIN_BACKEND_COMPLETION_RATE="${MIN_BACKEND_COMPLETION_RATE:-0.90}"
MAX_BACKEND_RUNTIME_ERROR="${MAX_BACKEND_RUNTIME_ERROR:-0}"
MAX_BACKEND_PREFLIGHT_FAILED="${MAX_BACKEND_PREFLIGHT_FAILED:-0}"
SKIP_BACKEND_READINESS_GATE=0

usage() {
  cat <<'USAGE'
Usage: scripts/release_candidate_gate.sh [options]

Validate that the last N benchmark summaries all pass ci_benchmark_gate thresholds.

Options:
  --bench-root <path>        Benchmark root directory (default: artifacts/benchmark_runs)
  --required-passes <n>      Number of latest summaries that must pass (default: 2)
  --stable-ref <git-ref>     Optional rollback validation target (runs rollback_validate on pass)
  --backend-readiness-root <path>
                             Backend readiness root (default: artifacts/backend_readiness)
  --backend-readiness-dashboard <path>
                             Aggregated backend dashboard output path (default: artifacts/backend_readiness/latest_report.json)
  --required-backends <csv>  Backends required by readiness gate (default: noir,cairo,halo2)
  --min-backend-completion-rate <float>
                             Minimum per-backend completion ratio (default: 0.90)
  --max-backend-runtime-error <int>
                             Maximum per-backend runtime_error count (default: 0)
  --max-backend-preflight-failed <int>
                             Maximum per-backend backend_preflight_failed count (default: 0)
  --skip-backend-readiness-gate
                             Publish dashboard artifact but do not fail release gate on backend readiness
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
    --backend-readiness-root)
      BACKEND_READINESS_ROOT="$2"
      shift 2
      ;;
    --backend-readiness-dashboard)
      BACKEND_READINESS_DASHBOARD="$2"
      shift 2
      ;;
    --required-backends)
      BACKEND_REQUIRED_LIST="$2"
      shift 2
      ;;
    --min-backend-completion-rate)
      MIN_BACKEND_COMPLETION_RATE="$2"
      shift 2
      ;;
    --max-backend-runtime-error)
      MAX_BACKEND_RUNTIME_ERROR="$2"
      shift 2
      ;;
    --max-backend-preflight-failed)
      MAX_BACKEND_PREFLIGHT_FAILED="$2"
      shift 2
      ;;
    --skip-backend-readiness-gate)
      SKIP_BACKEND_READINESS_GATE=1
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

backend_gate_cmd=(
  "$ROOT_DIR/scripts/backend_readiness_dashboard.sh"
  --readiness-root "$BACKEND_READINESS_ROOT"
  --output "$BACKEND_READINESS_DASHBOARD"
  --required-backends "$BACKEND_REQUIRED_LIST"
  --min-completion-rate "$MIN_BACKEND_COMPLETION_RATE"
  --max-runtime-error "$MAX_BACKEND_RUNTIME_ERROR"
  --max-backend-preflight-failed "$MAX_BACKEND_PREFLIGHT_FAILED"
)

if [ "$SKIP_BACKEND_READINESS_GATE" -eq 1 ]; then
  echo "Publishing backend readiness dashboard (gate disabled)..."
  "${backend_gate_cmd[@]}"
else
  echo "Running backend readiness gate..."
  "${backend_gate_cmd[@]}" --enforce
fi

if [ -n "$STABLE_REF" ]; then
  echo "Running rollback validation against stable ref: $STABLE_REF"
  "$ROOT_DIR/scripts/rollback_validate.sh" --stable-ref "$STABLE_REF"
fi
