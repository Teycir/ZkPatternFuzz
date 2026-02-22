#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE_SCRIPT_DIR="${ZKFUZZ_RELEASE_GATE_SCRIPT_DIR:-$ROOT_DIR/scripts}"
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
EVIDENCE_ARCHIVE_ROOT="$ROOT_DIR/artifacts/release_candidate_validation/evidence_bundles"
EVIDENCE_MANIFEST_PATH="$ROOT_DIR/artifacts/release_candidate_validation/evidence_bundle_manifest.json"
BACKEND_BLOCKERS_REPORT="$ROOT_DIR/artifacts/release_candidate_validation/backend_release_blockers.json"
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
  --evidence-archive-root <path>
                             Root directory for archived release evidence bundle snapshots
                             (default: artifacts/release_candidate_validation/evidence_bundles)
  --evidence-manifest <path>
                             Output JSON manifest for release evidence bundle coverage
                             (default: artifacts/release_candidate_validation/evidence_bundle_manifest.json)
  --backend-blockers-report <path>
                             Output JSON report for unresolved backend-specific release blockers
                             (default: artifacts/release_candidate_validation/backend_release_blockers.json)
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
    --evidence-archive-root)
      EVIDENCE_ARCHIVE_ROOT="$2"
      shift 2
      ;;
    --evidence-manifest)
      EVIDENCE_MANIFEST_PATH="$2"
      shift 2
      ;;
    --backend-blockers-report)
      BACKEND_BLOCKERS_REPORT="$2"
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

if [ ! -d "$GATE_SCRIPT_DIR" ]; then
  echo "gate script directory not found: $GATE_SCRIPT_DIR" >&2
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
  if ! "$GATE_SCRIPT_DIR/ci_benchmark_gate.sh" "$BENCH_ROOT" "$summary"; then
    failures=$((failures + 1))
  fi
done

if [ "$failures" -ne 0 ]; then
  echo "::error::Release candidate gate failed: $failures / $REQUIRED_PASSES summaries did not pass."
  exit 1
fi

echo "Release candidate gate passed: last $REQUIRED_PASSES benchmark summaries passed."

circom_flake_cmd=(
  "$GATE_SCRIPT_DIR/circom_flake_gate.sh"
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
  "$GATE_SCRIPT_DIR/circom_hermetic_gate.sh"
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
  "$GATE_SCRIPT_DIR/backend_capacity_fitness_gate.sh"
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
  "$GATE_SCRIPT_DIR/backend_readiness_dashboard.sh"
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
  "$GATE_SCRIPT_DIR/backend_maturity_scorecard.sh"
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

python3 - \
  "$EVIDENCE_ARCHIVE_ROOT" \
  "$EVIDENCE_MANIFEST_PATH" \
  "$BACKEND_BLOCKERS_REPORT" \
  "$BACKEND_READINESS_DASHBOARD" \
  "$BACKEND_MATURITY_SCORECARD" \
  "$CIRCOM_FLAKE_REPORT" \
  "$CIRCOM_HERMETIC_REPORT" \
  "$BACKEND_CAPACITY_FITNESS_REPORT" \
  "$SKIP_BACKEND_READINESS_GATE" \
  "$SKIP_BACKEND_MATURITY_GATE" \
  "$SKIP_CIRCOM_FLAKE_GATE" \
  "$SKIP_CIRCOM_HERMETIC_GATE" \
  "$SKIP_BACKEND_CAPACITY_FITNESS_GATE" \
  "$BACKEND_MATURITY_CONSECUTIVE_DAYS" \
  "$BACKEND_MATURITY_CONSECUTIVE_TARGET_SCORE" \
  "$CIRCOM_FLAKE_CONSECUTIVE_DAYS" \
  "$BACKEND_REQUIRED_LIST" \
  "$BACKEND_MATURITY_REQUIRED_LIST" \
  "$BACKEND_CAPACITY_FITNESS_REQUIRED_BACKENDS" <<'PY'
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

(
    archive_root_raw,
    manifest_path_raw,
    blockers_path_raw,
    readiness_report_raw,
    maturity_report_raw,
    circom_flake_report_raw,
    circom_hermetic_report_raw,
    capacity_report_raw,
    skip_readiness_raw,
    skip_maturity_raw,
    skip_flake_raw,
    skip_hermetic_raw,
    skip_capacity_raw,
    maturity_consecutive_days_raw,
    maturity_consecutive_target_raw,
    flake_consecutive_days_raw,
    readiness_required_backends_raw,
    maturity_required_backends_raw,
    capacity_required_backends_raw,
) = sys.argv[1:]


def as_bool_int(value: str) -> bool:
    try:
        return int(value) == 1
    except Exception:
        return False


def as_int(value: str, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def as_float(value: str, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def parse_csv_list(raw: str) -> List[str]:
    values = []
    for part in raw.split(","):
        value = part.strip().lower()
        if value and value not in values:
            values.append(value)
    return values


def parse_failures(payload: dict) -> List[str]:
    candidates = []
    for key in ("gate_failures", "failures"):
        value = payload.get(key)
        if isinstance(value, list):
            for entry in value:
                candidates.append(str(entry))
    return candidates


def load_json(path: Path):
    if not path.is_file():
        return None, f"missing report: {path}"
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return None, f"invalid report payload (expected object): {path}"
        return payload, None
    except Exception as exc:
        return None, f"failed to parse report JSON {path}: {exc}"


def unique_archive_dir(base_root: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    candidate = base_root / f"release_gate_{timestamp}"
    suffix = 0
    while candidate.exists():
        suffix += 1
        candidate = base_root / f"release_gate_{timestamp}_{suffix}"
    return candidate


archive_root = Path(archive_root_raw)
manifest_path = Path(manifest_path_raw)
blockers_path = Path(blockers_path_raw)

skip_flags = {
    "backend_readiness": as_bool_int(skip_readiness_raw),
    "backend_maturity": as_bool_int(skip_maturity_raw),
    "circom_flake": as_bool_int(skip_flake_raw),
    "circom_hermetic": as_bool_int(skip_hermetic_raw),
    "backend_capacity_fitness": as_bool_int(skip_capacity_raw),
}

maturity_consecutive_days = as_int(maturity_consecutive_days_raw, 0)
maturity_consecutive_target = as_float(maturity_consecutive_target_raw, 5.0)
flake_consecutive_days = as_int(flake_consecutive_days_raw, 0)

readiness_required_backends = parse_csv_list(readiness_required_backends_raw)
maturity_required_backends = parse_csv_list(maturity_required_backends_raw)
capacity_required_backends = parse_csv_list(capacity_required_backends_raw)

bundle_specs = [
    {
        "id": "backend_readiness",
        "path": Path(readiness_report_raw),
        "required": not skip_flags["backend_readiness"],
    },
    {
        "id": "backend_maturity",
        "path": Path(maturity_report_raw),
        "required": not skip_flags["backend_maturity"],
    },
    {
        "id": "circom_flake",
        "path": Path(circom_flake_report_raw),
        "required": not skip_flags["circom_flake"],
    },
    {
        "id": "circom_hermetic",
        "path": Path(circom_hermetic_report_raw),
        "required": not skip_flags["circom_hermetic"],
    },
    {
        "id": "backend_capacity_fitness",
        "path": Path(capacity_report_raw),
        "required": not skip_flags["backend_capacity_fitness"],
    },
]

release_failures: List[str] = []
unresolved_blockers: List[dict] = []
bundle_entries: List[dict] = []


def add_backend_blocker(bundle_id: str, backend: str, message: str, report_path: Path):
    unresolved_blockers.append(
        {
            "bundle": bundle_id,
            "backend": backend,
            "severity": "release_blocker",
            "message": message,
            "evidence_path": str(report_path),
        }
    )


for spec in bundle_specs:
    bundle_id = spec["id"]
    report_path: Path = spec["path"]
    required = bool(spec["required"])

    payload, load_error = load_json(report_path)
    present = payload is not None
    overall_pass = bool(payload.get("overall_pass", False)) if payload else False
    gate_failures = parse_failures(payload) if payload else []
    threshold_failures: List[str] = []

    if load_error:
        gate_failures.append(load_error)

    if required and not present:
        release_failures.append(f"{bundle_id}: report missing ({report_path})")
        add_backend_blocker(bundle_id, "aggregate", "report missing", report_path)

    if required and present and not overall_pass:
        release_failures.append(f"{bundle_id}: overall_pass=false")

    if required and present and bundle_id == "backend_maturity" and maturity_consecutive_days > 0:
        thresholds = payload.get("thresholds", {})
        consecutive_gate = payload.get("consecutive_gate", {})
        if int(thresholds.get("consecutive_days", -1) or -1) != maturity_consecutive_days:
            threshold_failures.append(
                "maturity consecutive_days threshold mismatch "
                f"(expected {maturity_consecutive_days}, got {thresholds.get('consecutive_days')})"
            )
        if not bool(consecutive_gate.get("enabled", False)):
            threshold_failures.append("maturity consecutive gate expected enabled=true")
        if int(consecutive_gate.get("target_days", -1) or -1) != maturity_consecutive_days:
            threshold_failures.append(
                "maturity consecutive gate target_days mismatch "
                f"(expected {maturity_consecutive_days}, got {consecutive_gate.get('target_days')})"
            )
        target_score = as_float(str(consecutive_gate.get("target_score", "")), float("nan"))
        if target_score != target_score or abs(target_score - maturity_consecutive_target) > 1e-9:
            threshold_failures.append(
                "maturity consecutive gate target_score mismatch "
                f"(expected {maturity_consecutive_target:.3f}, got {consecutive_gate.get('target_score')})"
            )

    if required and present and bundle_id == "circom_flake" and flake_consecutive_days > 0:
        if int(payload.get("required_consecutive_days", -1) or -1) != flake_consecutive_days:
            threshold_failures.append(
                "circom flake required_consecutive_days mismatch "
                f"(expected {flake_consecutive_days}, got {payload.get('required_consecutive_days')})"
            )
        if not bool(payload.get("required_gate_enabled", False)):
            threshold_failures.append("circom flake required_gate_enabled expected true")

    if required and threshold_failures:
        for failure in threshold_failures:
            release_failures.append(f"{bundle_id}: {failure}")
            add_backend_blocker(bundle_id, "aggregate", failure, report_path)

    if required and present and bundle_id == "backend_readiness":
        for entry in payload.get("backends", []) or []:
            backend = str(entry.get("backend", "unknown")).lower()
            if bool(entry.get("gate_pass", False)):
                continue
            failures = entry.get("gate_failures", []) or ["gate_pass=false"]
            for failure in failures:
                add_backend_blocker(bundle_id, backend, str(failure), report_path)
        for failure in payload.get("aggregate", {}).get("gate_failures", []) or []:
            add_backend_blocker(bundle_id, "aggregate", str(failure), report_path)

    if required and present and bundle_id == "backend_maturity":
        failure_list = payload.get("gate_failures", []) or []
        for failure in failure_list:
            text = str(failure)
            match = re.match(r"^([a-zA-Z0-9_-]+):\s+", text)
            backend = match.group(1).lower() if match else "aggregate"
            add_backend_blocker(bundle_id, backend, text, report_path)

    if required and present and bundle_id == "backend_capacity_fitness":
        failure_list = payload.get("gate_failures", []) or []
        for failure in failure_list:
            text = str(failure)
            backend = "aggregate"
            for name in capacity_required_backends:
                if re.search(rf"\b{name}\b", text, flags=re.IGNORECASE):
                    backend = name
                    break
            add_backend_blocker(bundle_id, backend, text, report_path)

    if required and present and bundle_id in {"circom_flake", "circom_hermetic"}:
        failure_list = parse_failures(payload)
        if not failure_list and not overall_pass:
            failure_list = ["overall_pass=false"]
        for failure in failure_list:
            add_backend_blocker(bundle_id, "circom", str(failure), report_path)

    bundle_entries.append(
        {
            "bundle_id": bundle_id,
            "required": required,
            "report_path": str(report_path),
            "present": present,
            "overall_pass": overall_pass,
            "gate_failures": gate_failures,
            "threshold_failures": threshold_failures,
            "archived_path": None,
        }
    )

archive_dir = unique_archive_dir(archive_root)
archive_dir.mkdir(parents=True, exist_ok=True)

for entry in bundle_entries:
    source = Path(entry["report_path"])
    if not source.is_file():
        continue
    destination = archive_dir / f"{entry['bundle_id']}.json"
    shutil.copy2(source, destination)
    entry["archived_path"] = str(destination)

required_total = sum(1 for entry in bundle_entries if entry["required"])
required_present = sum(1 for entry in bundle_entries if entry["required"] and entry["present"])
required_passing = sum(
    1
    for entry in bundle_entries
    if entry["required"]
    and entry["present"]
    and entry["overall_pass"]
    and len(entry["threshold_failures"]) == 0
)

coverage_ok = required_total == required_passing
blockers_ok = len(unresolved_blockers) == 0
overall_pass = coverage_ok and blockers_ok and len(release_failures) == 0

manifest_payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "archive_dir": str(archive_dir),
    "overall_pass": overall_pass,
    "required_bundle_total": required_total,
    "required_bundle_present": required_present,
    "required_bundle_passing": required_passing,
    "bundle_coverage_ok": coverage_ok,
    "bundle_count_total": len(bundle_entries),
    "release_failures": release_failures,
    "consecutive_thresholds": {
        "backend_maturity_consecutive_days": maturity_consecutive_days,
        "backend_maturity_consecutive_target_score": maturity_consecutive_target,
        "circom_flake_consecutive_days": flake_consecutive_days,
    },
    "required_backends": {
        "readiness": readiness_required_backends,
        "maturity": maturity_required_backends,
        "capacity_fitness": capacity_required_backends,
    },
    "bundles": bundle_entries,
    "backend_release_blockers_report": str(blockers_path),
}

blockers_payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "overall_pass": blockers_ok,
    "unresolved_backend_blockers_count": len(unresolved_blockers),
    "unresolved_backend_blockers": unresolved_blockers,
}

manifest_path.parent.mkdir(parents=True, exist_ok=True)
manifest_path.write_text(json.dumps(manifest_payload, indent=2) + "\n", encoding="utf-8")
(archive_dir / "evidence_bundle_manifest.json").write_text(
    json.dumps(manifest_payload, indent=2) + "\n",
    encoding="utf-8",
)

blockers_path.parent.mkdir(parents=True, exist_ok=True)
blockers_path.write_text(json.dumps(blockers_payload, indent=2) + "\n", encoding="utf-8")
(archive_dir / "backend_release_blockers.json").write_text(
    json.dumps(blockers_payload, indent=2) + "\n",
    encoding="utf-8",
)

print(f"Release evidence bundle archive: {archive_dir}")
print(
    "Release evidence bundle coverage: "
    f"required={required_passing}/{required_total} "
    f"status={'PASS' if coverage_ok else 'FAIL'}"
)
print(
    "Backend-specific release blockers: "
    f"{len(unresolved_blockers)} "
    f"status={'PASS' if blockers_ok else 'FAIL'}"
)
print(f"Evidence manifest: {manifest_path}")
print(f"Blockers report: {blockers_path}")

if not overall_pass:
    raise SystemExit(1)
PY

if [ -n "$STABLE_REF" ]; then
  echo "Running rollback validation against stable ref: $STABLE_REF"
  "$GATE_SCRIPT_DIR/rollback_validate.sh" --stable-ref "$STABLE_REF"
fi
