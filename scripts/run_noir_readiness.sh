#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Run Noir full-capacity readiness checks (integration + matrix run).

Usage:
  scripts/run_noir_readiness.sh [options]

Options:
  --matrix <path>                     Matrix YAML (default: targets/zk0d_matrix_noir_readiness.yaml)
  --registry <path>                   Registry YAML (default: targets/fuzzer_registry.prod.yaml)
  --batch-bin <path>                  zk0d_batch binary (default: target/release/zk0d_batch)
  --batch-jobs <N>                    Template jobs passed to zk0d_batch (default: 1)
  --workers <N>                       Workers per scan (default: 2)
  --iterations <N>                    Iterations per scan (default: 250)
  --timeout <sec>                     Timeout per scan in seconds (default: 30)
  --output-dir <path>                 Output directory (default: artifacts/backend_readiness/noir)
  --skip-integration-test             Skip test_noir_integration
  --skip-local-prove-verify-test      Skip test_noir_local_prove_verify_smoke
  --skip-constraint-coverage-test     Skip test_noir_constraint_coverage
  --skip-constraint-edge-cases-test   Skip test_noir_constraint_coverage_edge_cases
  --skip-external-smoke-test          Skip test_noir_external_nargo_prove_verify_smoke
  --skip-external-parity-test         Skip test_noir_external_nargo_fuzz_parity
  --no-build-if-missing               Do not build zk0d_batch when missing
  -h, --help                          Show this help
EOF
}

MATRIX="targets/zk0d_matrix_noir_readiness.yaml"
REGISTRY="targets/fuzzer_registry.prod.yaml"
BATCH_BIN="target/release/zk0d_batch"
BATCH_JOBS=1
WORKERS=2
ITERATIONS=250
TIMEOUT=30
OUTPUT_DIR="artifacts/backend_readiness/noir"
SKIP_INTEGRATION_TEST=false
SKIP_LOCAL_PROVE_VERIFY_TEST=false
SKIP_CONSTRAINT_COVERAGE_TEST=false
SKIP_CONSTRAINT_EDGE_CASES_TEST=false
SKIP_EXTERNAL_SMOKE_TEST=false
SKIP_EXTERNAL_PARITY_TEST=false
BUILD_IF_MISSING=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix) MATRIX="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --batch-bin) BATCH_BIN="$2"; shift 2 ;;
    --batch-jobs) BATCH_JOBS="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --skip-integration-test) SKIP_INTEGRATION_TEST=true; shift ;;
    --skip-local-prove-verify-test) SKIP_LOCAL_PROVE_VERIFY_TEST=true; shift ;;
    --skip-constraint-coverage-test) SKIP_CONSTRAINT_COVERAGE_TEST=true; shift ;;
    --skip-constraint-edge-cases-test) SKIP_CONSTRAINT_EDGE_CASES_TEST=true; shift ;;
    --skip-external-smoke-test) SKIP_EXTERNAL_SMOKE_TEST=true; shift ;;
    --skip-external-parity-test) SKIP_EXTERNAL_PARITY_TEST=true; shift ;;
    --no-build-if-missing) BUILD_IF_MISSING=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -f "$MATRIX" ]]; then
  echo "Matrix not found: $MATRIX" >&2
  exit 1
fi

if [[ ! -f "$REGISTRY" ]]; then
  echo "Registry not found: $REGISTRY" >&2
  exit 1
fi

if [[ ! -x "$BATCH_BIN" ]]; then
  if ! $BUILD_IF_MISSING; then
    echo "zk0d_batch binary not found/executable: $BATCH_BIN" >&2
    exit 1
  fi
  cargo build --release --bin zk0d_batch
fi

mkdir -p "$OUTPUT_DIR"
READINESS_HOME="${READINESS_HOME:-$OUTPUT_DIR/readiness_home}"
READINESS_SIGNAL_DIR="${READINESS_SIGNAL_DIR:-$READINESS_HOME/ZkFuzz}"
HOST_HOME="${HOST_HOME:-${HOME:-$ROOT_DIR}}"
READINESS_RUSTUP_HOME="${READINESS_RUSTUP_HOME:-${RUSTUP_HOME:-$HOST_HOME/.rustup}}"
READINESS_CARGO_HOME="${READINESS_CARGO_HOME:-${CARGO_HOME:-$HOST_HOME/.cargo}}"
READINESS_BUILD_CACHE_DIR="${READINESS_BUILD_CACHE_DIR:-$ROOT_DIR/ZkFuzz/_build_cache}"
mkdir -p "$READINESS_SIGNAL_DIR"
mkdir -p "$READINESS_BUILD_CACHE_DIR"

STAMP="$(date -u +"%Y%m%d_%H%M%S")"
INTEGRATION_LOG="$OUTPUT_DIR/integration_${STAMP}.log"
LOCAL_PROVE_VERIFY_LOG="$OUTPUT_DIR/local_prove_verify_${STAMP}.log"
CONSTRAINT_COVERAGE_LOG="$OUTPUT_DIR/constraint_coverage_${STAMP}.log"
CONSTRAINT_EDGE_CASES_LOG="$OUTPUT_DIR/constraint_edge_cases_${STAMP}.log"
EXTERNAL_SMOKE_LOG="$OUTPUT_DIR/external_smoke_${STAMP}.log"
EXTERNAL_PARITY_LOG="$OUTPUT_DIR/external_parity_${STAMP}.log"
MATRIX_LOG="$OUTPUT_DIR/matrix_${STAMP}.log"
SUMMARY_TSV="$OUTPUT_DIR/summary_${STAMP}.tsv"
LATEST_JSON="$OUTPUT_DIR/latest_report.json"

INTEGRATION_EXIT=0
INTEGRATION_STATUS="skipped"
if ! $SKIP_INTEGRATION_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_integration -- --exact \
    >"$INTEGRATION_LOG" 2>&1
  INTEGRATION_EXIT=$?
  set -e
  if [[ "$INTEGRATION_EXIT" -eq 0 ]]; then
    INTEGRATION_STATUS="pass"
  else
    INTEGRATION_STATUS="fail"
  fi
fi

LOCAL_PROVE_VERIFY_EXIT=0
LOCAL_PROVE_VERIFY_STATUS="skipped"
if ! $SKIP_LOCAL_PROVE_VERIFY_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_local_prove_verify_smoke -- --exact \
    >"$LOCAL_PROVE_VERIFY_LOG" 2>&1
  LOCAL_PROVE_VERIFY_EXIT=$?
  set -e
  if [[ "$LOCAL_PROVE_VERIFY_EXIT" -eq 0 ]]; then
    LOCAL_PROVE_VERIFY_STATUS="pass"
  else
    LOCAL_PROVE_VERIFY_STATUS="fail"
  fi
fi

CONSTRAINT_COVERAGE_EXIT=0
CONSTRAINT_COVERAGE_STATUS="skipped"
if ! $SKIP_CONSTRAINT_COVERAGE_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_constraint_coverage -- --exact \
    >"$CONSTRAINT_COVERAGE_LOG" 2>&1
  CONSTRAINT_COVERAGE_EXIT=$?
  set -e
  if [[ "$CONSTRAINT_COVERAGE_EXIT" -eq 0 ]]; then
    CONSTRAINT_COVERAGE_STATUS="pass"
  else
    CONSTRAINT_COVERAGE_STATUS="fail"
  fi
fi

CONSTRAINT_EDGE_CASES_EXIT=0
CONSTRAINT_EDGE_CASES_STATUS="skipped"
if ! $SKIP_CONSTRAINT_EDGE_CASES_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_constraint_coverage_edge_cases -- --exact \
    >"$CONSTRAINT_EDGE_CASES_LOG" 2>&1
  CONSTRAINT_EDGE_CASES_EXIT=$?
  set -e
  if [[ "$CONSTRAINT_EDGE_CASES_EXIT" -eq 0 ]]; then
    CONSTRAINT_EDGE_CASES_STATUS="pass"
  else
    CONSTRAINT_EDGE_CASES_STATUS="fail"
  fi
fi

EXTERNAL_SMOKE_EXIT=0
EXTERNAL_SMOKE_STATUS="skipped"
if ! $SKIP_EXTERNAL_SMOKE_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_external_nargo_prove_verify_smoke -- --exact \
    >"$EXTERNAL_SMOKE_LOG" 2>&1
  EXTERNAL_SMOKE_EXIT=$?
  set -e
  if [[ "$EXTERNAL_SMOKE_EXIT" -eq 0 ]]; then
    EXTERNAL_SMOKE_STATUS="pass"
  else
    EXTERNAL_SMOKE_STATUS="fail"
  fi
fi

EXTERNAL_PARITY_EXIT=0
EXTERNAL_PARITY_STATUS="skipped"
if ! $SKIP_EXTERNAL_PARITY_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_noir_external_nargo_fuzz_parity -- --exact \
    >"$EXTERNAL_PARITY_LOG" 2>&1
  EXTERNAL_PARITY_EXIT=$?
  set -e
  if [[ "$EXTERNAL_PARITY_EXIT" -eq 0 ]]; then
    EXTERNAL_PARITY_STATUS="pass"
  else
    EXTERNAL_PARITY_STATUS="fail"
  fi
fi

mapfile -t TARGET_ROWS < <(
  awk '
    /^  - name: / {
      if (in_target && enabled == "true") {
        printf("%s\t%s\t%s\t%s\t%s\n", name, target_circuit, main_component, framework, alias);
      }
      in_target = 1;
      name = $3;
      target_circuit = "";
      main_component = "main";
      framework = "circom";
      alias = "always";
      enabled = "true";
      next;
    }
    in_target && /^    target_circuit: / { sub(/^    target_circuit: /, "", $0); target_circuit = $0; next; }
    in_target && /^    main_component: / { sub(/^    main_component: /, "", $0); main_component = $0; next; }
    in_target && /^    framework: / { sub(/^    framework: /, "", $0); framework = $0; next; }
    in_target && /^    alias: / { sub(/^    alias: /, "", $0); alias = $0; next; }
    in_target && /^    enabled: / { sub(/^    enabled: /, "", $0); enabled = $0; next; }
    END {
      if (in_target && enabled == "true") {
        printf("%s\t%s\t%s\t%s\t%s\n", name, target_circuit, main_component, framework, alias);
      }
    }
  ' "$MATRIX"
)

if [[ "${#TARGET_ROWS[@]}" -eq 0 ]]; then
  echo "No enabled targets found in matrix: $MATRIX" >&2
  exit 1
fi

echo -e "target\texit_code\treason_code\treason_count" > "$SUMMARY_TSV"
MATRIX_EXIT=0

for row in "${TARGET_ROWS[@]}"; do
  IFS=$'\t' read -r TARGET_NAME TARGET_CIRCUIT MAIN_COMPONENT FRAMEWORK ALIAS <<< "$row"

  TARGET_LOG="$(mktemp)"
  RUN_CMD=(
    "$BATCH_BIN"
    --registry "$REGISTRY"
    --alias "$ALIAS"
    --target-circuit "$TARGET_CIRCUIT"
    --main-component "$MAIN_COMPONENT"
    --framework "$FRAMEWORK"
    --jobs "$BATCH_JOBS"
    --workers "$WORKERS"
    --seed 42
    --iterations "$ITERATIONS"
    --timeout "$TIMEOUT"
    --emit-reason-tsv
  )

  set +e
  HOME="$READINESS_HOME" \
    ZKF_RUN_SIGNAL_DIR="$READINESS_SIGNAL_DIR" \
    ZKF_BUILD_CACHE_DIR="$READINESS_BUILD_CACHE_DIR" \
    RUSTUP_HOME="$READINESS_RUSTUP_HOME" \
    CARGO_HOME="$READINESS_CARGO_HOME" \
    "${RUN_CMD[@]}" >"$TARGET_LOG" 2>&1
  TARGET_EXIT=$?
  set -e

  cat "$TARGET_LOG" >> "$MATRIX_LOG"

  if [[ "$TARGET_EXIT" -ne 0 ]]; then
    MATRIX_EXIT=1
  fi

  mapfile -t TARGET_REASON_ROWS < <(
    awk -F'\t' '
      $0 == "REASON_TSV_START" { in_block = 1; next; }
      $0 == "REASON_TSV_END" { in_block = 0; next; }
      in_block && $0 !~ /^template\t/ && NF >= 3 {
        reason = $3;
        counts[reason] += 1;
      }
      END {
        for (reason in counts) {
          printf("%s\t%d\n", reason, counts[reason]);
        }
      }
    ' "$TARGET_LOG" | sort
  )

  if [[ "${#TARGET_REASON_ROWS[@]}" -eq 0 ]]; then
    echo -e "${TARGET_NAME}\t${TARGET_EXIT}\tnone\t1" >> "$SUMMARY_TSV"
  else
    for reason_row in "${TARGET_REASON_ROWS[@]}"; do
      IFS=$'\t' read -r reason_code reason_count <<< "$reason_row"
      echo -e "${TARGET_NAME}\t${TARGET_EXIT}\t${reason_code}\t${reason_count}" >> "$SUMMARY_TSV"
    done
  fi

  rm -f "$TARGET_LOG"
done

if [[ -f "$SUMMARY_TSV" ]]; then
  REASONS_JSON="$(awk -F'\t' 'NR > 1 { if (seen[$3]++ == 0) order[++n]=$3; counts[$3]+=$4 } END { for (i=1; i<=n; i++) { key=order[i]; printf("%s\"%s\":%d", (i>1?",":""), key, counts[key]); } }' "$SUMMARY_TSV")"
else
  REASONS_JSON="\"summary_missing\":1"
fi

cat > "$LATEST_JSON" <<EOF
{
  "backend": "noir",
  "generated_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "matrix": {
    "path": "$MATRIX",
    "summary_tsv": "$SUMMARY_TSV",
    "log": "$MATRIX_LOG",
    "exit_code": $MATRIX_EXIT,
    "reason_counts": {${REASONS_JSON}}
  },
  "integration_tests": [
    {
      "name": "test_noir_integration",
      "status": "$INTEGRATION_STATUS",
      "exit_code": $INTEGRATION_EXIT,
      "log": "$INTEGRATION_LOG"
    },
    {
      "name": "test_noir_local_prove_verify_smoke",
      "status": "$LOCAL_PROVE_VERIFY_STATUS",
      "exit_code": $LOCAL_PROVE_VERIFY_EXIT,
      "log": "$LOCAL_PROVE_VERIFY_LOG"
    },
    {
      "name": "test_noir_constraint_coverage",
      "status": "$CONSTRAINT_COVERAGE_STATUS",
      "exit_code": $CONSTRAINT_COVERAGE_EXIT,
      "log": "$CONSTRAINT_COVERAGE_LOG"
    },
    {
      "name": "test_noir_constraint_coverage_edge_cases",
      "status": "$CONSTRAINT_EDGE_CASES_STATUS",
      "exit_code": $CONSTRAINT_EDGE_CASES_EXIT,
      "log": "$CONSTRAINT_EDGE_CASES_LOG"
    },
    {
      "name": "test_noir_external_nargo_prove_verify_smoke",
      "status": "$EXTERNAL_SMOKE_STATUS",
      "exit_code": $EXTERNAL_SMOKE_EXIT,
      "log": "$EXTERNAL_SMOKE_LOG"
    },
    {
      "name": "test_noir_external_nargo_fuzz_parity",
      "status": "$EXTERNAL_PARITY_STATUS",
      "exit_code": $EXTERNAL_PARITY_EXIT,
      "log": "$EXTERNAL_PARITY_LOG"
    }
  ]
}
EOF

echo "Noir readiness report: $LATEST_JSON"
if [[ "$MATRIX_EXIT" -ne 0 || "$INTEGRATION_EXIT" -ne 0 || "$LOCAL_PROVE_VERIFY_EXIT" -ne 0 || "$CONSTRAINT_COVERAGE_EXIT" -ne 0 || "$CONSTRAINT_EDGE_CASES_EXIT" -ne 0 || "$EXTERNAL_SMOKE_EXIT" -ne 0 || "$EXTERNAL_PARITY_EXIT" -ne 0 ]]; then
  exit 1
fi

exit 0
