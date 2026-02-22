#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
READINESS_ROOT="$ROOT_DIR/artifacts/backend_readiness"
REGISTRY="$ROOT_DIR/targets/fuzzer_registry.prod.yaml"
BATCH_BIN="$ROOT_DIR/target/release/zk0d_batch"
NOIR_MATRIX="$ROOT_DIR/targets/zk0d_matrix_noir_readiness.yaml"
CAIRO_MATRIX="$ROOT_DIR/targets/zk0d_matrix_cairo_readiness.yaml"
HALO2_MATRIX="$ROOT_DIR/targets/zk0d_matrix_halo2_readiness.yaml"
BATCH_JOBS=1
WORKERS=2
ITERATIONS=250
TIMEOUT=30
SKIP_NOIR_INTEGRATION_TEST=0
SKIP_NOIR_CONSTRAINT_COVERAGE_TEST=0
SKIP_NOIR_CONSTRAINT_EDGE_CASES_TEST=0
SKIP_NOIR_EXTERNAL_SMOKE_TEST=0
SKIP_NOIR_EXTERNAL_PARITY_TEST=0
SKIP_CAIRO_INTEGRATION_TEST=0
SKIP_CAIRO_REGRESSION_TEST=0
SKIP_HALO2_JSON_INTEGRATION_TEST=0
SKIP_HALO2_REAL_CIRCUIT_TEST=0
SKIP_HALO2_STABILITY_TEST=0
SKIP_HALO2_THROUGHPUT_TEST=0
NO_BUILD_IF_MISSING=0
ENFORCE_DASHBOARD=0
REQUIRED_BACKENDS="${BACKEND_REQUIRED_LIST:-noir,cairo,halo2}"
MIN_COMPLETION_RATE="${MIN_BACKEND_COMPLETION_RATE:-0.90}"
MIN_SELECTOR_MATCHING_TOTAL="${MIN_BACKEND_SELECTOR_MATCHING_TOTAL:-4}"
PER_BACKEND_MIN_SELECTOR_MATCHING_TOTAL="${MIN_BACKEND_SELECTOR_MATCHING_TOTALS:-noir=25,cairo=4,halo2=4}"
MIN_OVERALL_COMPLETION_RATE="${MIN_BACKEND_OVERALL_COMPLETION_RATE:-0.40}"
MAX_SELECTOR_MISMATCH_RATE="${MAX_BACKEND_SELECTOR_MISMATCH_RATE:-0.70}"
MAX_RUNTIME_ERROR="${MAX_BACKEND_RUNTIME_ERROR:-0}"
MAX_BACKEND_PREFLIGHT_FAILED="${MAX_BACKEND_PREFLIGHT_FAILED:-0}"
MAX_RUN_OUTCOME_MISSING_RATE="${MAX_BACKEND_RUN_OUTCOME_MISSING_RATE:-0.05}"
MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL="${MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL:-12}"
MIN_ENABLED_TARGETS="${MIN_BACKEND_ENABLED_TARGETS:-5}"
ENFORCE_TOOL_SANDBOX=0

usage() {
  cat <<'USAGE'
Usage: scripts/run_backend_readiness_lanes.sh [options]

Run Noir/Cairo/Halo2 readiness lanes and publish an aggregated dashboard.

Options:
  --readiness-root <path>               Backend readiness output root (default: artifacts/backend_readiness)
  --registry <path>                     Registry YAML (default: targets/fuzzer_registry.prod.yaml)
  --batch-bin <path>                    zk0d_batch binary (default: target/release/zk0d_batch)
  --noir-matrix <path>                  Noir matrix YAML (default: targets/zk0d_matrix_noir_readiness.yaml)
  --cairo-matrix <path>                 Cairo matrix YAML (default: targets/zk0d_matrix_cairo_readiness.yaml)
  --halo2-matrix <path>                 Halo2 matrix YAML (default: targets/zk0d_matrix_halo2_readiness.yaml)
  --batch-jobs <N>                      Template jobs passed to zk0d_batch (default: 1)
  --workers <N>                         Workers per scan (default: 2)
  --iterations <N>                      Iterations per scan (default: 250)
  --timeout <sec>                       Timeout per scan in seconds (default: 30)
  --required-backends <csv>             Backends required in dashboard gate (default: noir,cairo,halo2)
  --min-completion-rate <float>         Dashboard gate minimum selector-matching completion ratio (default: 0.90)
  --min-selector-matching-total <int>   Dashboard gate minimum selector-matching classified runs per backend (default: 4)
  --per-backend-min-selector-matching-total <csv>
                                        Dashboard per-backend selector-matching thresholds (default: noir=25,cairo=4,halo2=4)
  --min-overall-completion-rate <f>     Dashboard gate minimum overall completion ratio per backend (default: 0.40)
  --max-selector-mismatch-rate <f>      Dashboard gate maximum selector_mismatch ratio per backend (default: 0.70)
  --max-runtime-error <int>             Dashboard gate max runtime_error count (default: 0)
  --max-backend-preflight-failed <int>  Dashboard gate max backend_preflight_failed count (default: 0)
  --max-run-outcome-missing-rate <f>    Dashboard gate max run_outcome_missing ratio (default: 0.05)
  --min-aggregate-selector-matching-total <int>
                                        Dashboard gate minimum aggregate selector-matching classified runs (default: 12)
  --min-enabled-targets <int>           Dashboard gate minimum enabled targets per backend (default: 5)
  --skip-noir-integration-test          Skip test_noir_integration
  --skip-noir-constraint-coverage-test  Skip test_noir_constraint_coverage
  --skip-noir-constraint-edge-cases-test
                                        Skip test_noir_constraint_coverage_edge_cases
  --skip-noir-external-smoke-test       Skip test_noir_external_nargo_prove_verify_smoke
  --skip-noir-external-parity-test      Skip test_noir_external_nargo_fuzz_parity
  --skip-cairo-integration-test         Skip test_cairo_integration
  --skip-cairo-regression-test          Skip test_cairo_full_capacity_regression_suite
  --skip-halo2-json-integration-test    Skip test_halo2_json_integration
  --skip-halo2-real-circuit-test        Skip test_halo2_real_circuit_constraint_coverage
  --skip-halo2-stability-test           Skip test_halo2_scaffold_execution_stability
  --skip-halo2-throughput-test          Skip test_halo2_scaffold_production_throughput
  --no-build-if-missing                 Do not build zk0d_batch when missing
  --enforce-dashboard                   Exit non-zero if aggregated readiness gate fails
  --enforce-tool-sandbox               Require backend external-tool sandbox mode (bwrap) for lanes
  -h, --help                            Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --readiness-root) READINESS_ROOT="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --batch-bin) BATCH_BIN="$2"; shift 2 ;;
    --noir-matrix) NOIR_MATRIX="$2"; shift 2 ;;
    --cairo-matrix) CAIRO_MATRIX="$2"; shift 2 ;;
    --halo2-matrix) HALO2_MATRIX="$2"; shift 2 ;;
    --batch-jobs) BATCH_JOBS="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --required-backends) REQUIRED_BACKENDS="$2"; shift 2 ;;
    --min-completion-rate) MIN_COMPLETION_RATE="$2"; shift 2 ;;
    --min-selector-matching-total) MIN_SELECTOR_MATCHING_TOTAL="$2"; shift 2 ;;
    --per-backend-min-selector-matching-total) PER_BACKEND_MIN_SELECTOR_MATCHING_TOTAL="$2"; shift 2 ;;
    --min-overall-completion-rate) MIN_OVERALL_COMPLETION_RATE="$2"; shift 2 ;;
    --max-selector-mismatch-rate) MAX_SELECTOR_MISMATCH_RATE="$2"; shift 2 ;;
    --max-runtime-error) MAX_RUNTIME_ERROR="$2"; shift 2 ;;
    --max-backend-preflight-failed) MAX_BACKEND_PREFLIGHT_FAILED="$2"; shift 2 ;;
    --max-run-outcome-missing-rate) MAX_RUN_OUTCOME_MISSING_RATE="$2"; shift 2 ;;
    --min-aggregate-selector-matching-total) MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL="$2"; shift 2 ;;
    --min-enabled-targets) MIN_ENABLED_TARGETS="$2"; shift 2 ;;
    --skip-noir-integration-test) SKIP_NOIR_INTEGRATION_TEST=1; shift ;;
    --skip-noir-constraint-coverage-test) SKIP_NOIR_CONSTRAINT_COVERAGE_TEST=1; shift ;;
    --skip-noir-constraint-edge-cases-test) SKIP_NOIR_CONSTRAINT_EDGE_CASES_TEST=1; shift ;;
    --skip-noir-external-smoke-test) SKIP_NOIR_EXTERNAL_SMOKE_TEST=1; shift ;;
    --skip-noir-external-parity-test) SKIP_NOIR_EXTERNAL_PARITY_TEST=1; shift ;;
    --skip-cairo-integration-test) SKIP_CAIRO_INTEGRATION_TEST=1; shift ;;
    --skip-cairo-regression-test) SKIP_CAIRO_REGRESSION_TEST=1; shift ;;
    --skip-halo2-json-integration-test) SKIP_HALO2_JSON_INTEGRATION_TEST=1; shift ;;
    --skip-halo2-real-circuit-test) SKIP_HALO2_REAL_CIRCUIT_TEST=1; shift ;;
    --skip-halo2-stability-test) SKIP_HALO2_STABILITY_TEST=1; shift ;;
    --skip-halo2-throughput-test) SKIP_HALO2_THROUGHPUT_TEST=1; shift ;;
    --no-build-if-missing) NO_BUILD_IF_MISSING=1; shift ;;
    --enforce-dashboard) ENFORCE_DASHBOARD=1; shift ;;
    --enforce-tool-sandbox) ENFORCE_TOOL_SANDBOX=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$READINESS_ROOT"

if [[ "$ENFORCE_TOOL_SANDBOX" -eq 1 ]]; then
  command -v bwrap >/dev/null 2>&1 || {
    echo "bwrap is required for --enforce-tool-sandbox but was not found in PATH" >&2
    exit 2
  }
  export ZKFUZZ_EXTERNAL_TOOL_SANDBOX=required
  export ZKFUZZ_EXTERNAL_TOOL_SANDBOX_BIN="${ZKFUZZ_EXTERNAL_TOOL_SANDBOX_BIN:-bwrap}"
  echo "Backend external-tool sandbox: required (${ZKFUZZ_EXTERNAL_TOOL_SANDBOX_BIN})"
fi

run_lane() {
  local lane_name="$1"
  shift
  echo "Running ${lane_name} readiness lane..."
  set +e
  "$@"
  local lane_exit=$?
  set -e
  if [[ "$lane_exit" -eq 0 ]]; then
    echo "[PASS] ${lane_name} lane"
  else
    echo "[FAIL] ${lane_name} lane (exit=${lane_exit})"
  fi
  return "$lane_exit"
}

no_build_arg=()
if [[ "$NO_BUILD_IF_MISSING" -eq 1 ]]; then
  no_build_arg+=(--no-build-if-missing)
fi

noir_cmd=(
  "$ROOT_DIR/scripts/run_noir_readiness.sh"
  --matrix "$NOIR_MATRIX"
  --registry "$REGISTRY"
  --batch-bin "$BATCH_BIN"
  --batch-jobs "$BATCH_JOBS"
  --workers "$WORKERS"
  --iterations "$ITERATIONS"
  --timeout "$TIMEOUT"
  --output-dir "$READINESS_ROOT/noir"
  "${no_build_arg[@]}"
)
if [[ "$SKIP_NOIR_INTEGRATION_TEST" -eq 1 ]]; then
  noir_cmd+=(--skip-integration-test)
fi
if [[ "$SKIP_NOIR_CONSTRAINT_COVERAGE_TEST" -eq 1 ]]; then
  noir_cmd+=(--skip-constraint-coverage-test)
fi
if [[ "$SKIP_NOIR_CONSTRAINT_EDGE_CASES_TEST" -eq 1 ]]; then
  noir_cmd+=(--skip-constraint-edge-cases-test)
fi
if [[ "$SKIP_NOIR_EXTERNAL_SMOKE_TEST" -eq 1 ]]; then
  noir_cmd+=(--skip-external-smoke-test)
fi
if [[ "$SKIP_NOIR_EXTERNAL_PARITY_TEST" -eq 1 ]]; then
  noir_cmd+=(--skip-external-parity-test)
fi

cairo_cmd=(
  "$ROOT_DIR/scripts/run_cairo_readiness.sh"
  --matrix "$CAIRO_MATRIX"
  --registry "$REGISTRY"
  --batch-bin "$BATCH_BIN"
  --batch-jobs "$BATCH_JOBS"
  --workers "$WORKERS"
  --iterations "$ITERATIONS"
  --timeout "$TIMEOUT"
  --output-dir "$READINESS_ROOT/cairo"
  "${no_build_arg[@]}"
)
if [[ "$SKIP_CAIRO_INTEGRATION_TEST" -eq 1 ]]; then
  cairo_cmd+=(--skip-integration-test)
fi
if [[ "$SKIP_CAIRO_REGRESSION_TEST" -eq 1 ]]; then
  cairo_cmd+=(--skip-regression-test)
fi

halo2_cmd=(
  "$ROOT_DIR/scripts/run_halo2_readiness.sh"
  --matrix "$HALO2_MATRIX"
  --registry "$REGISTRY"
  --batch-bin "$BATCH_BIN"
  --batch-jobs "$BATCH_JOBS"
  --workers "$WORKERS"
  --iterations "$ITERATIONS"
  --timeout "$TIMEOUT"
  --output-dir "$READINESS_ROOT/halo2"
  "${no_build_arg[@]}"
)
if [[ "$SKIP_HALO2_JSON_INTEGRATION_TEST" -eq 1 ]]; then
  halo2_cmd+=(--skip-json-integration-test)
fi
if [[ "$SKIP_HALO2_REAL_CIRCUIT_TEST" -eq 1 ]]; then
  halo2_cmd+=(--skip-real-circuit-test)
fi
if [[ "$SKIP_HALO2_STABILITY_TEST" -eq 1 ]]; then
  halo2_cmd+=(--skip-stability-test)
fi
if [[ "$SKIP_HALO2_THROUGHPUT_TEST" -eq 1 ]]; then
  halo2_cmd+=(--skip-throughput-test)
fi

lane_failures=0
if ! run_lane "noir" "${noir_cmd[@]}"; then
  lane_failures=1
fi
if ! run_lane "cairo" "${cairo_cmd[@]}"; then
  lane_failures=1
fi
if ! run_lane "halo2" "${halo2_cmd[@]}"; then
  lane_failures=1
fi

dashboard_cmd=(
  "$ROOT_DIR/scripts/backend_readiness_dashboard.sh"
  --readiness-root "$READINESS_ROOT"
  --output "$READINESS_ROOT/latest_report.json"
  --required-backends "$REQUIRED_BACKENDS"
  --min-completion-rate "$MIN_COMPLETION_RATE"
  --min-selector-matching-total "$MIN_SELECTOR_MATCHING_TOTAL"
  --per-backend-min-selector-matching-total "$PER_BACKEND_MIN_SELECTOR_MATCHING_TOTAL"
  --min-overall-completion-rate "$MIN_OVERALL_COMPLETION_RATE"
  --max-selector-mismatch-rate "$MAX_SELECTOR_MISMATCH_RATE"
  --max-runtime-error "$MAX_RUNTIME_ERROR"
  --max-backend-preflight-failed "$MAX_BACKEND_PREFLIGHT_FAILED"
  --max-run-outcome-missing-rate "$MAX_RUN_OUTCOME_MISSING_RATE"
  --min-aggregate-selector-matching-total "$MIN_AGGREGATE_SELECTOR_MATCHING_TOTAL"
  --min-enabled-targets "$MIN_ENABLED_TARGETS"
)
if [[ "$ENFORCE_DASHBOARD" -eq 1 ]]; then
  dashboard_cmd+=(--enforce)
fi

echo "Publishing aggregated backend readiness dashboard..."
set +e
"${dashboard_cmd[@]}"
dashboard_exit=$?
set -e

if [[ "$dashboard_exit" -ne 0 ]]; then
  echo "[FAIL] Aggregated backend readiness dashboard gate"
elif [[ "$ENFORCE_DASHBOARD" -eq 1 ]]; then
  echo "[PASS] Aggregated backend readiness dashboard gate"
else
  echo "[INFO] Aggregated backend readiness dashboard published (non-enforcing mode)"
fi

if [[ "$lane_failures" -ne 0 || "$dashboard_exit" -ne 0 ]]; then
  exit 1
fi

exit 0
