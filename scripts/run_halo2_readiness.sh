#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Run Halo2 full-capacity readiness checks (integration + matrix run).

Usage:
  scripts/run_halo2_readiness.sh [options]

Options:
  --matrix <path>              Matrix YAML (default: targets/zk0d_matrix_halo2_readiness.yaml)
  --registry <path>            Registry YAML (default: targets/fuzzer_registry.prod.yaml)
  --batch-bin <path>           zk0d_batch binary (default: target/release/zk0d_batch)
  --batch-jobs <N>             Template jobs passed to zk0d_batch (default: 1)
  --workers <N>                Workers per scan (default: 2)
  --iterations <N>             Iterations per scan (default: 100)
  --timeout <sec>              Timeout per scan in seconds (default: 20)
  --output-dir <path>          Output directory (default: artifacts/backend_readiness/halo2)
  --skip-json-integration-test Skip test_halo2_json_integration
  --skip-real-circuit-test     Skip test_halo2_real_circuit_constraint_coverage
  --skip-stability-test        Skip test_halo2_scaffold_execution_stability
  --skip-throughput-test       Skip test_halo2_scaffold_production_throughput
  --no-build-if-missing        Do not build zk0d_batch when missing
  -h, --help                   Show this help
EOF
}

MATRIX="targets/zk0d_matrix_halo2_readiness.yaml"
REGISTRY="targets/fuzzer_registry.prod.yaml"
BATCH_BIN="target/release/zk0d_batch"
BATCH_JOBS=1
WORKERS=2
ITERATIONS=100
TIMEOUT=20
OUTPUT_DIR="artifacts/backend_readiness/halo2"
SKIP_JSON_INTEGRATION_TEST=false
SKIP_REAL_CIRCUIT_TEST=false
SKIP_STABILITY_TEST=false
SKIP_THROUGHPUT_TEST=false
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
    --skip-json-integration-test) SKIP_JSON_INTEGRATION_TEST=true; shift ;;
    --skip-real-circuit-test) SKIP_REAL_CIRCUIT_TEST=true; shift ;;
    --skip-stability-test) SKIP_STABILITY_TEST=true; shift ;;
    --skip-throughput-test) SKIP_THROUGHPUT_TEST=true; shift ;;
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
JSON_INTEGRATION_LOG="$OUTPUT_DIR/integration_json_${STAMP}.log"
REAL_CIRCUIT_LOG="$OUTPUT_DIR/integration_real_${STAMP}.log"
STABILITY_LOG="$OUTPUT_DIR/integration_stability_${STAMP}.log"
THROUGHPUT_LOG="$OUTPUT_DIR/integration_throughput_${STAMP}.log"
MATRIX_LOG="$OUTPUT_DIR/matrix_${STAMP}.log"
SUMMARY_TSV="$OUTPUT_DIR/summary_${STAMP}.tsv"
LATEST_JSON="$OUTPUT_DIR/latest_report.json"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"

JSON_INTEGRATION_EXIT=0
JSON_INTEGRATION_STATUS="skipped"
if ! $SKIP_JSON_INTEGRATION_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_json_integration -- --exact \
    >"$JSON_INTEGRATION_LOG" 2>&1
  JSON_INTEGRATION_EXIT=$?
  set -e
  if [[ "$JSON_INTEGRATION_EXIT" -eq 0 ]]; then
    JSON_INTEGRATION_STATUS="pass"
  else
    JSON_INTEGRATION_STATUS="fail"
  fi
fi

REAL_CIRCUIT_EXIT=0
REAL_CIRCUIT_STATUS="skipped"
if ! $SKIP_REAL_CIRCUIT_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_real_circuit_constraint_coverage -- --exact \
    >"$REAL_CIRCUIT_LOG" 2>&1
  REAL_CIRCUIT_EXIT=$?
  set -e
  if [[ "$REAL_CIRCUIT_EXIT" -eq 0 ]]; then
    REAL_CIRCUIT_STATUS="pass"
  else
    REAL_CIRCUIT_STATUS="fail"
  fi
fi

STABILITY_EXIT=0
STABILITY_STATUS="skipped"
if ! $SKIP_STABILITY_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_scaffold_execution_stability -- --exact \
    >"$STABILITY_LOG" 2>&1
  STABILITY_EXIT=$?
  set -e
  if [[ "$STABILITY_EXIT" -eq 0 ]]; then
    STABILITY_STATUS="pass"
  else
    STABILITY_STATUS="fail"
  fi
fi

THROUGHPUT_EXIT=0
THROUGHPUT_STATUS="skipped"
if ! $SKIP_THROUGHPUT_TEST; then
  set +e
  ZKFUZZ_REAL_BACKENDS=1 cargo test -q --test backend_integration_tests test_halo2_scaffold_production_throughput -- --exact \
    >"$THROUGHPUT_LOG" 2>&1
  THROUGHPUT_EXIT=$?
  set -e
  if [[ "$THROUGHPUT_EXIT" -eq 0 ]]; then
    THROUGHPUT_STATUS="pass"
  else
    THROUGHPUT_STATUS="fail"
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
  "backend": "halo2",
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
      "name": "test_halo2_json_integration",
      "status": "$JSON_INTEGRATION_STATUS",
      "exit_code": $JSON_INTEGRATION_EXIT,
      "log": "$JSON_INTEGRATION_LOG"
    },
    {
      "name": "test_halo2_real_circuit_constraint_coverage",
      "status": "$REAL_CIRCUIT_STATUS",
      "exit_code": $REAL_CIRCUIT_EXIT,
      "log": "$REAL_CIRCUIT_LOG"
    },
    {
      "name": "test_halo2_scaffold_execution_stability",
      "status": "$STABILITY_STATUS",
      "exit_code": $STABILITY_EXIT,
      "log": "$STABILITY_LOG"
    },
    {
      "name": "test_halo2_scaffold_production_throughput",
      "status": "$THROUGHPUT_STATUS",
      "exit_code": $THROUGHPUT_EXIT,
      "log": "$THROUGHPUT_LOG"
    }
  ]
}
EOF

echo "Halo2 readiness report: $LATEST_JSON"
if [[ "$MATRIX_EXIT" -ne 0 || "$JSON_INTEGRATION_EXIT" -ne 0 || "$REAL_CIRCUIT_EXIT" -ne 0 || "$STABILITY_EXIT" -ne 0 || "$THROUGHPUT_EXIT" -ne 0 ]]; then
  exit 1
fi

exit 0
