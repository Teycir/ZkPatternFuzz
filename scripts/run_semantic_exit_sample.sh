#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT_DIR/artifacts/semantic_campaign}"
RUN_ID="${RUN_ID:-semantic-exit-sample}"
SEMANTIC_ROOTS="${SEMANTIC_ROOTS:-tests,docs,targets/zkbugs/dataset/halo2}"
ADAPTER="${ADAPTER:-heuristic_augmented}"
GUIDANCE_LABEL="${GUIDANCE_LABEL:-${MODEL_NAME:-mistral}}"
EXIT_REPORT_OUT="${EXIT_REPORT_OUT:-$ROOT_DIR/artifacts/semantic_exit/latest_report.json}"
MANUAL_LABELS_PATH="${MANUAL_LABELS_PATH:-}"
ENFORCE_EXIT="${ENFORCE_EXIT:-false}"
MIN_MANUAL_LABELS="${MIN_MANUAL_LABELS:-10}"

printf '[semantic-exit] running semantic campaign example\n'
cargo run -q -p zk-track-semantic --example semantic_exit_campaign -- \
  --output-dir "$OUTPUT_ROOT" \
  --run-id "$RUN_ID" \
  --semantic-roots "$SEMANTIC_ROOTS" \
  --adapter "$ADAPTER" \
  --guidance-label "$GUIDANCE_LABEL"

printf '[semantic-exit] building exit report\n'
CMD=(
  python3 "$ROOT_DIR/scripts/build_semantic_exit_report.py"
  --repo-root "$ROOT_DIR"
  --search-root "$OUTPUT_ROOT"
  --output "$EXIT_REPORT_OUT"
)
if [[ -n "$MANUAL_LABELS_PATH" ]]; then
  CMD+=(--manual-labels "$MANUAL_LABELS_PATH")
fi
if [[ "${ENFORCE_EXIT,,}" == "true" ]]; then
  CMD+=(--enforce)
fi
CMD+=(--min-manual-labels "$MIN_MANUAL_LABELS")
"${CMD[@]}"

printf '[semantic-exit] report ready: %s\n' "$EXIT_REPORT_OUT"
