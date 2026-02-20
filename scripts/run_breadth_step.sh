#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Step-by-step breadth testing runner (one target per step).

Usage:
  scripts/run_breadth_step.sh --list
  scripts/run_breadth_step.sh --step <N> [options]

Options:
  --matrix <path>        Matrix YAML (default: targets/zk0d_matrix_breadth.yaml)
  --registry <path>      Registry YAML (default: targets/fuzzer_registry.prod.yaml)
  --step <N>             1-based target index to execute
  --workers <N>          Workers per scan (default: 2)
  --iterations <N>       Iterations per scan (default: 1500)
  --timeout <sec>        Timeout per scan in seconds (default: 90)
  --output-dir <path>    Output root for step artifacts (default: artifacts/roadmap_step_tests)
  --list                 Print indexed target list and exit
  -h, --help             Show this help
EOF
}

MATRIX="targets/zk0d_matrix_breadth.yaml"
REGISTRY="targets/fuzzer_registry.prod.yaml"
STEP=""
WORKERS=2
ITERATIONS=1500
TIMEOUT=90
OUTPUT_DIR="artifacts/roadmap_step_tests"
LIST_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix) MATRIX="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --step) STEP="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --list) LIST_ONLY=true; shift ;;
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

if $LIST_ONLY; then
  awk '
    /^  - name: / {
      idx += 1
      name = $3
    }
    /^    target_circuit: / {
      path = $0
      sub(/^    target_circuit: /, "", path)
    }
    /^    framework: / {
      framework = $0
      sub(/^    framework: /, "", framework)
      printf("%03d\t%s\t%s\t%s\n", idx, name, framework, path)
    }
  ' "$MATRIX"
  exit 0
fi

if [[ -z "$STEP" ]]; then
  echo "Missing --step <N> (or use --list)." >&2
  exit 1
fi

if ! [[ "$STEP" =~ ^[0-9]+$ ]]; then
  echo "--step must be a positive integer" >&2
  exit 1
fi

STEP_NUM=$((10#$STEP))

TARGET_COUNT="$(awk '/^  - name: / { c += 1 } END { print c + 0 }' "$MATRIX")"
if (( STEP_NUM < 1 || STEP_NUM > TARGET_COUNT )); then
  echo "--step out of range: $STEP_NUM (valid: 1..$TARGET_COUNT)" >&2
  exit 1
fi

TMP_SINGLE_MATRIX="$(mktemp)"
trap 'rm -f "$TMP_SINGLE_MATRIX"' EXIT

{
  echo "version: 1"
  echo
  echo "targets:"
  awk -v wanted="$STEP_NUM" '
    /^  - name: / {
      idx += 1
      in_target = (idx == wanted)
    }
    in_target {
      print
    }
  ' "$MATRIX"
} > "$TMP_SINGLE_MATRIX"

TARGET_NAME="$(awk '/^  - name: / { print $3; exit }' "$TMP_SINGLE_MATRIX")"
TARGET_CIRCUIT="$(sed -n 's/^    target_circuit: //p' "$TMP_SINGLE_MATRIX" | head -n1)"
TARGET_FRAMEWORK="$(sed -n 's/^    framework: //p' "$TMP_SINGLE_MATRIX" | head -n1)"
SAFE_TARGET_NAME="$(echo "$TARGET_NAME" | tr -cs 'A-Za-z0-9._-' '_')"
STEP_ID="$(printf "%03d" "$STEP_NUM")"

mkdir -p "$OUTPUT_DIR/logs" "$OUTPUT_DIR/summary" "$OUTPUT_DIR/observations"

SUMMARY_TSV="$OUTPUT_DIR/summary/step_${STEP_ID}__${SAFE_TARGET_NAME}.tsv"
LOG_FILE="$OUTPUT_DIR/logs/step_${STEP_ID}__${SAFE_TARGET_NAME}.log"
OBS_FILE="$OUTPUT_DIR/observations/step_${STEP_ID}__${SAFE_TARGET_NAME}.md"

RUN_CMD=(
  cargo run --release --bin zk0d_matrix --
  --matrix "$TMP_SINGLE_MATRIX"
  --registry "$REGISTRY"
  --jobs 1
  --batch-jobs 1
  --workers "$WORKERS"
  --iterations "$ITERATIONS"
  --timeout "$TIMEOUT"
  --summary-tsv "$SUMMARY_TSV"
)

echo "Step:        $STEP_ID/$TARGET_COUNT"
echo "Target:      $TARGET_NAME"
echo "Framework:   $TARGET_FRAMEWORK"
echo "Circuit:     $TARGET_CIRCUIT"
echo "Workers:     $WORKERS"
echo "Iterations:  $ITERATIONS"
echo "Timeout(sec):$TIMEOUT"
echo "Summary TSV: $SUMMARY_TSV"
echo "Log file:    $LOG_FILE"
echo

set +e
"${RUN_CMD[@]}" 2>&1 | tee "$LOG_FILE"
RUN_EXIT="${PIPESTATUS[0]}"
set -e

RUN_STATUS="PASS"
if [[ "$RUN_EXIT" -ne 0 ]]; then
  RUN_STATUS="FAIL"
fi

REASON_LINES="(summary file missing)"
if [[ -f "$SUMMARY_TSV" ]]; then
  REASON_LINES="$(awk -F'\t' 'NR > 1 { printf("- %s: %s\n", $3, $4) }' "$SUMMARY_TSV")"
  if [[ -z "$REASON_LINES" ]]; then
    REASON_LINES="(no reason rows)"
  fi
fi

{
  echo "# Step ${STEP_ID} Observation"
  echo
  echo "- Date (UTC): $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "- Step index: ${STEP_NUM}/${TARGET_COUNT}"
  echo "- Target: \`${TARGET_NAME}\`"
  echo "- Framework: \`${TARGET_FRAMEWORK}\`"
  echo "- Circuit: \`${TARGET_CIRCUIT}\`"
  echo "- Status: \`${RUN_STATUS}\`"
  echo "- Exit code: \`${RUN_EXIT}\`"
  echo "- Summary TSV: \`${SUMMARY_TSV}\`"
  echo "- Log file: \`${LOG_FILE}\`"
  echo
  echo "## Command"
  echo '```bash'
  printf '%q ' "${RUN_CMD[@]}"
  echo
  echo '```'
  echo
  echo "## Reason Summary"
  echo "${REASON_LINES}"
  echo
  echo "## Observations"
  echo "- [ ] What happened on this target?"
  echo "- [ ] Did selectors match as expected?"
  echo "- [ ] Any high-confidence findings?"
  echo "- [ ] Any setup/runtime/timeout issues?"
  echo
  echo "## Next Action"
  echo "- [ ] Update row in \`docs/ROADMAP_TARGET_TESTS.md\` for this target."
  echo "- [ ] Run next target step."
} > "$OBS_FILE"

echo
echo "Observation template written: $OBS_FILE"
echo "Run result: $RUN_STATUS (exit=$RUN_EXIT)"

exit "$RUN_EXIT"
