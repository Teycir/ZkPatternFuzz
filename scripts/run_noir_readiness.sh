#!/usr/bin/env bash
set -euo pipefail

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
  --skip-constraint-coverage-test     Skip test_noir_constraint_coverage
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
SKIP_CONSTRAINT_COVERAGE_TEST=false
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
    --skip-constraint-coverage-test) SKIP_CONSTRAINT_COVERAGE_TEST=true; shift ;;
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

STAMP="$(date -u +"%Y%m%d_%H%M%S")"
INTEGRATION_LOG="$OUTPUT_DIR/integration_${STAMP}.log"
CONSTRAINT_COVERAGE_LOG="$OUTPUT_DIR/constraint_coverage_${STAMP}.log"
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
      "name": "test_noir_constraint_coverage",
      "status": "$CONSTRAINT_COVERAGE_STATUS",
      "exit_code": $CONSTRAINT_COVERAGE_EXIT,
      "log": "$CONSTRAINT_COVERAGE_LOG"
    }
  ]
}
EOF

echo "Noir readiness report: $LATEST_JSON"
if [[ "$MATRIX_EXIT" -ne 0 || "$INTEGRATION_EXIT" -ne 0 || "$CONSTRAINT_COVERAGE_EXIT" -ne 0 ]]; then
  exit 1
fi

exit 0
