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
BACKEND_MATURITY_HISTORY="$ROOT_DIR/artifacts/backend_maturity/history.json"
BACKEND_MATURITY_REQUIRED_LIST="${BACKEND_MATURITY_REQUIRED_LIST:-}"
MIN_BACKEND_MATURITY_SCORE="${MIN_BACKEND_MATURITY_SCORE:-4.5}"
BACKEND_MATURITY_CONSECUTIVE_DAYS="${BACKEND_MATURITY_CONSECUTIVE_DAYS:-0}"
BACKEND_MATURITY_CONSECUTIVE_TARGET_SCORE="${BACKEND_MATURITY_CONSECUTIVE_TARGET_SCORE:-5.0}"
BACKEND_MATURITY_CONSECUTIVE_REQUIRED_LIST="${BACKEND_MATURITY_CONSECUTIVE_REQUIRED_LIST:-}"
KEYGEN_PREFLIGHT_REPORT="$ROOT_DIR/artifacts/keygen_preflight/latest_report.json"
RELEASE_CANDIDATE_REPORT="$ROOT_DIR/artifacts/release_candidate_validation/release_candidate_report.json"
CIRCOM_FLAKE_REPORT="$ROOT_DIR/artifacts/circom_flake/latest_report.json"
CIRCOM_FLAKE_HISTORY="$ROOT_DIR/artifacts/circom_flake/history.json"
CIRCOM_FLAKE_CONSECUTIVE_DAYS="${CIRCOM_FLAKE_CONSECUTIVE_DAYS:-0}"
CIRCOM_HERMETIC_REPORT="$ROOT_DIR/artifacts/circom_hermetic/latest_report.json"
BACKEND_CAPACITY_FITNESS_REPORT="$ROOT_DIR/artifacts/backend_capacity_fitness/latest_report.json"
BACKEND_CAPACITY_FITNESS_THROUGHPUT_OUTPUT_DIR="$ROOT_DIR/artifacts/backend_throughput"
BACKEND_CAPACITY_FITNESS_MEMORY_OUTPUT_DIR="$ROOT_DIR/artifacts/memory_profiles"
BACKEND_CAPACITY_FITNESS_REQUIRED_BACKENDS="${BACKEND_CAPACITY_FITNESS_REQUIRED_BACKENDS:-noir,cairo,halo2}"
BACKEND_CAPACITY_FITNESS_MIN_MEDIAN_COMPLETED_PER_SEC="${BACKEND_CAPACITY_FITNESS_MIN_MEDIAN_COMPLETED_PER_SEC:-0.005}"
BACKEND_CAPACITY_FITNESS_PER_BACKEND_MIN_MEDIAN_COMPLETED_PER_SEC="${BACKEND_CAPACITY_FITNESS_PER_BACKEND_MIN_MEDIAN_COMPLETED_PER_SEC:-}"
BACKEND_CAPACITY_FITNESS_MAX_RSS_KB="${BACKEND_CAPACITY_FITNESS_MAX_RSS_KB:-262144}"
BACKEND_CAPACITY_FITNESS_THROUGHPUT_RUNS="${BACKEND_CAPACITY_FITNESS_THROUGHPUT_RUNS:-1}"
BACKEND_CAPACITY_FITNESS_ITERATIONS="${BACKEND_CAPACITY_FITNESS_ITERATIONS:-20}"
BACKEND_CAPACITY_FITNESS_TIMEOUT="${BACKEND_CAPACITY_FITNESS_TIMEOUT:-20}"
BACKEND_CAPACITY_FITNESS_WORKERS="${BACKEND_CAPACITY_FITNESS_WORKERS:-2}"
BACKEND_CAPACITY_FITNESS_BATCH_JOBS="${BACKEND_CAPACITY_FITNESS_BATCH_JOBS:-1}"
SKIP_BACKEND_READINESS_GATE=0
SKIP_BACKEND_MATURITY_GATE=0
SKIP_CIRCOM_FLAKE_GATE=0
SKIP_CIRCOM_HERMETIC_GATE=0
SKIP_BACKEND_CAPACITY_FITNESS_GATE=0

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
  --backend-maturity-history <path>
                             Backend maturity history output path (default: artifacts/backend_maturity/history.json)
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
  --backend-maturity-consecutive-days <int>
                             Require N consecutive UTC daily maturity scorecards (default: 0, disabled)
  --backend-maturity-consecutive-target-score <float>
                             Target score required for consecutive-day maturity gate (default: 5.0)
  --backend-maturity-consecutive-backends <csv>
                             Backends required by consecutive maturity gate (default: required-maturity-backends)
  --keygen-preflight-report <path>
                             Circom keygen preflight report consumed by maturity scorecard
                             (default: artifacts/keygen_preflight/latest_report.json)
  --release-candidate-report <path>
                             Release candidate report consumed by maturity scorecard
                             (default: artifacts/release_candidate_validation/release_candidate_report.json)
  --circom-flake-report <path>
                             Circom long-horizon flake gate report output path
                             (default: artifacts/circom_flake/latest_report.json)
  --circom-flake-history <path>
                             Circom long-horizon flake gate history output path
                             (default: artifacts/circom_flake/history.json)
  --circom-flake-consecutive-days <int>
                             Require N consecutive UTC daily keygen+compile/prove/verify passes
                             for Circom lane flake gate (default: 0, disabled)
  --circom-hermetic-report <path>
                             Circom hermetic include/toolchain report output path
                             (default: artifacts/circom_hermetic/latest_report.json)
  --backend-capacity-fitness-report <path>
                             Backend capacity fitness report output path
                             (default: artifacts/backend_capacity_fitness/latest_report.json)
  --backend-capacity-fitness-throughput-output-dir <path>
                             Throughput harness output dir
                             (default: artifacts/backend_throughput)
  --backend-capacity-fitness-memory-output-dir <path>
                             Memory profile output dir
                             (default: artifacts/memory_profiles)
  --backend-capacity-fitness-required-backends <csv>
                             Required backends for capacity fitness thresholds
                             (default: noir,cairo,halo2)
  --backend-capacity-fitness-min-median-completed-per-sec <float>
                             Global minimum median completed/sec threshold (default: 0.005)
  --backend-capacity-fitness-per-backend-min-median-completed-per-sec <csv>
                             Optional per-backend completed/sec thresholds (e.g. noir=0.01,cairo=0.01)
  --backend-capacity-fitness-max-rss-kb <int>
                             Max allowed RSS kB for large-circuit memory profile (default: 262144)
  --backend-capacity-fitness-throughput-runs <int>
                             Throughput runs per backend for fitness gate (default: 1)
  --backend-capacity-fitness-iterations <int>
                             Iterations used by throughput/memory fitness lanes (default: 20)
  --backend-capacity-fitness-timeout <int>
                             Timeout seconds used by throughput/memory fitness lanes (default: 20)
  --backend-capacity-fitness-workers <int>
                             Worker count used by throughput/memory fitness lanes (default: 2)
  --backend-capacity-fitness-batch-jobs <int>
                             Batch jobs used by throughput/memory fitness lanes (default: 1)
  --skip-backend-readiness-gate
                             Publish dashboard artifact but do not fail release gate on backend readiness
  --skip-backend-maturity-gate
                             Publish maturity scorecard but do not fail release gate on backend maturity
  --skip-circom-flake-gate
                             Publish Circom flake report but do not fail release gate on it
  --skip-circom-hermetic-gate
                             Publish Circom hermetic report but do not fail release gate on it
  --skip-backend-capacity-fitness-gate
                             Publish backend capacity fitness report but do not fail release gate on it
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
    --backend-maturity-history)
      BACKEND_MATURITY_HISTORY="$2"
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
    --backend-maturity-consecutive-days)
      BACKEND_MATURITY_CONSECUTIVE_DAYS="$2"
      shift 2
      ;;
    --backend-maturity-consecutive-target-score)
      BACKEND_MATURITY_CONSECUTIVE_TARGET_SCORE="$2"
      shift 2
      ;;
    --backend-maturity-consecutive-backends)
      BACKEND_MATURITY_CONSECUTIVE_REQUIRED_LIST="$2"
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
    --circom-flake-report)
      CIRCOM_FLAKE_REPORT="$2"
      shift 2
      ;;
    --circom-flake-history)
      CIRCOM_FLAKE_HISTORY="$2"
      shift 2
      ;;
    --circom-flake-consecutive-days)
      CIRCOM_FLAKE_CONSECUTIVE_DAYS="$2"
      shift 2
      ;;
    --circom-hermetic-report)
      CIRCOM_HERMETIC_REPORT="$2"
      shift 2
      ;;
    --backend-capacity-fitness-report)
      BACKEND_CAPACITY_FITNESS_REPORT="$2"
      shift 2
      ;;
    --backend-capacity-fitness-throughput-output-dir)
      BACKEND_CAPACITY_FITNESS_THROUGHPUT_OUTPUT_DIR="$2"
      shift 2
      ;;
    --backend-capacity-fitness-memory-output-dir)
      BACKEND_CAPACITY_FITNESS_MEMORY_OUTPUT_DIR="$2"
      shift 2
      ;;
    --backend-capacity-fitness-required-backends)
      BACKEND_CAPACITY_FITNESS_REQUIRED_BACKENDS="$2"
      shift 2
      ;;
    --backend-capacity-fitness-min-median-completed-per-sec)
      BACKEND_CAPACITY_FITNESS_MIN_MEDIAN_COMPLETED_PER_SEC="$2"
      shift 2
      ;;
    --backend-capacity-fitness-per-backend-min-median-completed-per-sec)
      BACKEND_CAPACITY_FITNESS_PER_BACKEND_MIN_MEDIAN_COMPLETED_PER_SEC="$2"
      shift 2
      ;;
    --backend-capacity-fitness-max-rss-kb)
      BACKEND_CAPACITY_FITNESS_MAX_RSS_KB="$2"
      shift 2
      ;;
    --backend-capacity-fitness-throughput-runs)
      BACKEND_CAPACITY_FITNESS_THROUGHPUT_RUNS="$2"
      shift 2
      ;;
    --backend-capacity-fitness-iterations)
      BACKEND_CAPACITY_FITNESS_ITERATIONS="$2"
      shift 2
      ;;
    --backend-capacity-fitness-timeout)
      BACKEND_CAPACITY_FITNESS_TIMEOUT="$2"
      shift 2
      ;;
    --backend-capacity-fitness-workers)
      BACKEND_CAPACITY_FITNESS_WORKERS="$2"
      shift 2
      ;;
    --backend-capacity-fitness-batch-jobs)
      BACKEND_CAPACITY_FITNESS_BATCH_JOBS="$2"
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
    --skip-circom-flake-gate)
      SKIP_CIRCOM_FLAKE_GATE=1
      shift
      ;;
    --skip-circom-hermetic-gate)
      SKIP_CIRCOM_HERMETIC_GATE=1
      shift
      ;;
    --skip-backend-capacity-fitness-gate)
      SKIP_BACKEND_CAPACITY_FITNESS_GATE=1
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
if [ -z "$BACKEND_MATURITY_CONSECUTIVE_REQUIRED_LIST" ]; then
  BACKEND_MATURITY_CONSECUTIVE_REQUIRED_LIST="$BACKEND_MATURITY_REQUIRED_LIST"
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
LATEST_SUMMARY="${summaries[$((summary_count - 1))]}"
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

circom_flake_cmd=(
  "$ROOT_DIR/scripts/circom_flake_gate.sh"
  --benchmark-root "$BENCH_ROOT"
  --benchmark-summary "$LATEST_SUMMARY"
  --keygen-preflight "$KEYGEN_PREFLIGHT_REPORT"
  --output "$CIRCOM_FLAKE_REPORT"
  --history-path "$CIRCOM_FLAKE_HISTORY"
  --required-consecutive-days "$CIRCOM_FLAKE_CONSECUTIVE_DAYS"
)

if [ "$SKIP_CIRCOM_FLAKE_GATE" -eq 1 ]; then
  echo "Publishing Circom long-horizon flake report (gate disabled)..."
  "${circom_flake_cmd[@]}"
else
  echo "Running Circom long-horizon flake gate..."
  "${circom_flake_cmd[@]}" --enforce
fi

circom_hermetic_cmd=(
  "$ROOT_DIR/scripts/circom_hermetic_gate.sh"
  --output "$CIRCOM_HERMETIC_REPORT"
)

if [ "$SKIP_CIRCOM_HERMETIC_GATE" -eq 1 ]; then
  echo "Publishing Circom hermetic include/toolchain report (gate disabled)..."
  "${circom_hermetic_cmd[@]}"
else
  echo "Running Circom hermetic include/toolchain gate..."
  "${circom_hermetic_cmd[@]}" --enforce
fi

capacity_fitness_cmd=(
  "$ROOT_DIR/scripts/backend_capacity_fitness_gate.sh"
  --output "$BACKEND_CAPACITY_FITNESS_REPORT"
  --throughput-output-dir "$BACKEND_CAPACITY_FITNESS_THROUGHPUT_OUTPUT_DIR"
  --memory-output-dir "$BACKEND_CAPACITY_FITNESS_MEMORY_OUTPUT_DIR"
  --required-backends "$BACKEND_CAPACITY_FITNESS_REQUIRED_BACKENDS"
  --min-median-completed-per-sec "$BACKEND_CAPACITY_FITNESS_MIN_MEDIAN_COMPLETED_PER_SEC"
  --max-rss-kb "$BACKEND_CAPACITY_FITNESS_MAX_RSS_KB"
  --throughput-runs "$BACKEND_CAPACITY_FITNESS_THROUGHPUT_RUNS"
  --throughput-iterations "$BACKEND_CAPACITY_FITNESS_ITERATIONS"
  --throughput-timeout "$BACKEND_CAPACITY_FITNESS_TIMEOUT"
  --throughput-workers "$BACKEND_CAPACITY_FITNESS_WORKERS"
  --throughput-batch-jobs "$BACKEND_CAPACITY_FITNESS_BATCH_JOBS"
  --memory-iterations "$BACKEND_CAPACITY_FITNESS_ITERATIONS"
  --memory-timeout "$BACKEND_CAPACITY_FITNESS_TIMEOUT"
  --memory-workers "$BACKEND_CAPACITY_FITNESS_WORKERS"
  --memory-batch-jobs "$BACKEND_CAPACITY_FITNESS_BATCH_JOBS"
)

if [ -n "$BACKEND_CAPACITY_FITNESS_PER_BACKEND_MIN_MEDIAN_COMPLETED_PER_SEC" ]; then
  capacity_fitness_cmd+=(
    --per-backend-min-median-completed-per-sec
    "$BACKEND_CAPACITY_FITNESS_PER_BACKEND_MIN_MEDIAN_COMPLETED_PER_SEC"
  )
fi

if [ "$SKIP_BACKEND_CAPACITY_FITNESS_GATE" -eq 1 ]; then
  echo "Publishing backend capacity fitness report (gate disabled)..."
  "${capacity_fitness_cmd[@]}"
else
  echo "Running backend capacity fitness gate..."
  "${capacity_fitness_cmd[@]}" --enforce
fi

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
  --history-path "$BACKEND_MATURITY_HISTORY"
  --required-backends "$BACKEND_MATURITY_REQUIRED_LIST"
  --min-score "$MIN_BACKEND_MATURITY_SCORE"
  --consecutive-days "$BACKEND_MATURITY_CONSECUTIVE_DAYS"
  --consecutive-target-score "$BACKEND_MATURITY_CONSECUTIVE_TARGET_SCORE"
  --consecutive-required-backends "$BACKEND_MATURITY_CONSECUTIVE_REQUIRED_LIST"
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
