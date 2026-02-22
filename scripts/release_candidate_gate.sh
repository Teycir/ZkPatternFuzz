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
MIN_BACKEND_SELECTOR_MATCHING_TOTAL="${MIN_BACKEND_SELECTOR_MATCHING_TOTAL:-4}"
MIN_BACKEND_SELECTOR_MATCHING_TOTALS="${MIN_BACKEND_SELECTOR_MATCHING_TOTALS:-noir=25,cairo=4,halo2=4}"
MIN_BACKEND_OVERALL_COMPLETION_RATE="${MIN_BACKEND_OVERALL_COMPLETION_RATE:-0.40}"
MAX_BACKEND_SELECTOR_MISMATCH_RATE="${MAX_BACKEND_SELECTOR_MISMATCH_RATE:-0.70}"
MAX_BACKEND_RUNTIME_ERROR="${MAX_BACKEND_RUNTIME_ERROR:-0}"
MAX_BACKEND_PREFLIGHT_FAILED="${MAX_BACKEND_PREFLIGHT_FAILED:-0}"
MAX_BACKEND_RUN_OUTCOME_MISSING_RATE="${MAX_BACKEND_RUN_OUTCOME_MISSING_RATE:-0.05}"
MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL="${MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL:-12}"
MIN_BACKEND_ENABLED_TARGETS="${MIN_BACKEND_ENABLED_TARGETS:-5}"
BACKEND_MATURITY_SCORECARD="$ROOT_DIR/artifacts/backend_maturity/latest_scorecard.json"
BACKEND_MATURITY_REQUIRED_LIST="${BACKEND_MATURITY_REQUIRED_LIST:-}"
MIN_BACKEND_MATURITY_SCORE="${MIN_BACKEND_MATURITY_SCORE:-4.5}"
KEYGEN_PREFLIGHT_REPORT="$ROOT_DIR/artifacts/keygen_preflight/latest_report.json"
RELEASE_CANDIDATE_REPORT="$ROOT_DIR/artifacts/release_candidate_validation/release_candidate_report.json"
SKIP_BACKEND_READINESS_GATE=0
SKIP_BACKEND_MATURITY_GATE=0

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
  --backend-maturity-scorecard <path>
                             Backend maturity scorecard output path (default: artifacts/backend_maturity/latest_scorecard.json)
  --required-backends <csv>  Backends required by readiness gate (default: noir,cairo,halo2)
  --required-maturity-backends <csv>
                             Backends required by maturity gate (default: circom + required-backends)
  --min-backend-completion-rate <float>
                             Minimum per-backend selector-matching completion ratio (default: 0.90)
  --min-backend-selector-matching-total <int>
                             Minimum per-backend selector-matching classified runs (default: 4)
  --min-backend-selector-matching-total-per-backend <csv>
                             Optional per-backend selector-matching thresholds
                             (default: noir=25,cairo=4,halo2=4)
  --min-backend-overall-completion-rate <float>
                             Minimum per-backend overall completion ratio (default: 0.40)
  --max-backend-selector-mismatch-rate <float>
                             Maximum per-backend selector_mismatch ratio (default: 0.70)
  --max-backend-runtime-error <int>
                             Maximum per-backend runtime_error count (default: 0)
  --max-backend-preflight-failed <int>
                             Maximum per-backend backend_preflight_failed count (default: 0)
  --max-backend-run-outcome-missing-rate <float>
                             Maximum per-backend and aggregate run_outcome_missing ratio (default: 0.05)
  --min-aggregate-selector-matching-total <int>
                             Minimum aggregate selector-matching classified runs across required backends (default: 12)
  --min-backend-enabled-targets <int>
                             Minimum enabled matrix targets required per backend (default: 5)
  --min-backend-maturity-score <float>
                             Minimum maturity score required per backend (default: 4.5)
  --keygen-preflight-report <path>
                             Circom keygen preflight report consumed by maturity scorecard
                             (default: artifacts/keygen_preflight/latest_report.json)
  --release-candidate-report <path>
                             Release candidate report consumed by maturity scorecard
                             (default: artifacts/release_candidate_validation/release_candidate_report.json)
  --skip-backend-readiness-gate
                             Publish dashboard artifact but do not fail release gate on backend readiness
  --skip-backend-maturity-gate
                             Publish maturity scorecard but do not fail release gate on backend maturity
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
    --backend-maturity-scorecard)
      BACKEND_MATURITY_SCORECARD="$2"
      shift 2
      ;;
    --required-backends)
      BACKEND_REQUIRED_LIST="$2"
      shift 2
      ;;
    --required-maturity-backends)
      BACKEND_MATURITY_REQUIRED_LIST="$2"
      shift 2
      ;;
    --min-backend-completion-rate)
      MIN_BACKEND_COMPLETION_RATE="$2"
      shift 2
      ;;
    --min-backend-selector-matching-total)
      MIN_BACKEND_SELECTOR_MATCHING_TOTAL="$2"
      shift 2
      ;;
    --min-backend-selector-matching-total-per-backend)
      MIN_BACKEND_SELECTOR_MATCHING_TOTALS="$2"
      shift 2
      ;;
    --min-backend-overall-completion-rate)
      MIN_BACKEND_OVERALL_COMPLETION_RATE="$2"
      shift 2
      ;;
    --max-backend-selector-mismatch-rate)
      MAX_BACKEND_SELECTOR_MISMATCH_RATE="$2"
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
    --max-backend-run-outcome-missing-rate)
      MAX_BACKEND_RUN_OUTCOME_MISSING_RATE="$2"
      shift 2
      ;;
    --min-aggregate-selector-matching-total)
      MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL="$2"
      shift 2
      ;;
    --min-backend-enabled-targets)
      MIN_BACKEND_ENABLED_TARGETS="$2"
      shift 2
      ;;
    --min-backend-maturity-score)
      MIN_BACKEND_MATURITY_SCORE="$2"
      shift 2
      ;;
    --keygen-preflight-report)
      KEYGEN_PREFLIGHT_REPORT="$2"
      shift 2
      ;;
    --release-candidate-report)
      RELEASE_CANDIDATE_REPORT="$2"
      shift 2
      ;;
    --skip-backend-readiness-gate)
      SKIP_BACKEND_READINESS_GATE=1
      shift
      ;;
    --skip-backend-maturity-gate)
      SKIP_BACKEND_MATURITY_GATE=1
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

if [ -z "$BACKEND_MATURITY_REQUIRED_LIST" ]; then
  BACKEND_MATURITY_REQUIRED_LIST="circom,$BACKEND_REQUIRED_LIST"
fi

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
  --min-selector-matching-total "$MIN_BACKEND_SELECTOR_MATCHING_TOTAL"
  --per-backend-min-selector-matching-total "$MIN_BACKEND_SELECTOR_MATCHING_TOTALS"
  --min-overall-completion-rate "$MIN_BACKEND_OVERALL_COMPLETION_RATE"
  --max-selector-mismatch-rate "$MAX_BACKEND_SELECTOR_MISMATCH_RATE"
  --max-runtime-error "$MAX_BACKEND_RUNTIME_ERROR"
  --max-backend-preflight-failed "$MAX_BACKEND_PREFLIGHT_FAILED"
  --max-run-outcome-missing-rate "$MAX_BACKEND_RUN_OUTCOME_MISSING_RATE"
  --min-aggregate-selector-matching-total "$MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL"
  --min-enabled-targets "$MIN_BACKEND_ENABLED_TARGETS"
)

if [ "$SKIP_BACKEND_READINESS_GATE" -eq 1 ]; then
  echo "Publishing backend readiness dashboard (gate disabled)..."
  "${backend_gate_cmd[@]}"
else
  echo "Running backend readiness gate..."
  "${backend_gate_cmd[@]}" --enforce
fi

maturity_gate_cmd=(
  "$ROOT_DIR/scripts/backend_maturity_scorecard.sh"
  --readiness-dashboard "$BACKEND_READINESS_DASHBOARD"
  --benchmark-root "$BENCH_ROOT"
  --keygen-preflight "$KEYGEN_PREFLIGHT_REPORT"
  --release-candidate-report "$RELEASE_CANDIDATE_REPORT"
  --output "$BACKEND_MATURITY_SCORECARD"
  --required-backends "$BACKEND_MATURITY_REQUIRED_LIST"
  --min-score "$MIN_BACKEND_MATURITY_SCORE"
)

if [ "$SKIP_BACKEND_MATURITY_GATE" -eq 1 ]; then
  echo "Publishing backend maturity scorecard (gate disabled)..."
  "${maturity_gate_cmd[@]}"
else
  echo "Running backend maturity gate..."
  "${maturity_gate_cmd[@]}" --enforce
fi

if [ -n "$STABLE_REF" ]; then
  echo "Running rollback validation against stable ref: $STABLE_REF"
  "$ROOT_DIR/scripts/rollback_validate.sh" --stable-ref "$STABLE_REF"
fi
