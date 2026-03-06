#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

OUTPUT_DIR="${ZKF_SEMANTIC_OUTPUT_ROOT:-$ROOT_DIR/artifacts/semantic_campaign}"
SEARCH_ROOT="${ZKF_SEMANTIC_SEARCH_ROOT:-$OUTPUT_DIR}"
REPORT_OUTPUT="${ZKF_SEMANTIC_EXIT_REPORT:-$ROOT_DIR/artifacts/semantic_exit/latest_report.json}"
RUN_ID="${ZKF_SEMANTIC_RUN_ID:-semantic-exit-sample}"
CAMPAIGN_ID="${ZKF_SEMANTIC_CAMPAIGN_ID:-semantic-exit-campaign}"
SEMANTIC_ROOTS="${ZKF_SEMANTIC_ROOTS:-tests,docs,targets/zkbugs/dataset/halo2}"
ADAPTER="${ZKF_SEMANTIC_ADAPTER:-heuristic_augmented}"
GUIDANCE_LABEL="${ZKF_SEMANTIC_GUIDANCE_LABEL:-mistral}"
SYSTEM_PROMPT="${ZKF_SEMANTIC_SYSTEM_PROMPT:-strict formal extraction for semantic security intent from docs/comments}"
EXECUTION_EVIDENCE_PATH="${ZKF_SEMANTIC_EXECUTION_EVIDENCE_PATH:-$ROOT_DIR/campaigns/semantic/semantic_exit_sample.execution_evidence.json}"
ENFORCE_EXIT="${ENFORCE_EXIT:-false}"
MIN_MANUAL_LABELS="${MIN_MANUAL_LABELS:-10}"
MANUAL_LABELS_PATH="${MANUAL_LABELS_PATH:-}"

mkdir -p "$OUTPUT_DIR" "$(dirname "$REPORT_OUTPUT")"

if [[ ! -f "$EXECUTION_EVIDENCE_PATH" ]]; then
  echo "Missing semantic execution evidence payload: $EXECUTION_EVIDENCE_PATH" >&2
  exit 1
fi

cargo run --quiet -p zk-track-semantic --example semantic_exit_campaign -- \
  --output-dir "$OUTPUT_DIR" \
  --run-id "$RUN_ID" \
  --campaign-id "$CAMPAIGN_ID" \
  --semantic-roots "$SEMANTIC_ROOTS" \
  --adapter "$ADAPTER" \
  --guidance-label "$GUIDANCE_LABEL" \
  --system-prompt "$SYSTEM_PROMPT" \
  --execution-evidence-path "$EXECUTION_EVIDENCE_PATH"

report_cmd=(
  python3
  "$ROOT_DIR/scripts/build_semantic_exit_report.py"
  --repo-root "$ROOT_DIR"
  --search-root "$SEARCH_ROOT"
  --output "$REPORT_OUTPUT"
  --min-manual-labels "$MIN_MANUAL_LABELS"
)

if [[ -n "$MANUAL_LABELS_PATH" ]]; then
  report_cmd+=(--manual-labels "$MANUAL_LABELS_PATH")
fi

if [[ "$ENFORCE_EXIT" == "true" ]]; then
  report_cmd+=(--enforce)
fi

"${report_cmd[@]}"

echo "semantic exit sample complete:"
echo "  output_root=$OUTPUT_DIR"
echo "  report=$REPORT_OUTPUT"
