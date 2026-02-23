#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/boundary/serialization_sample}"
OUTPUT_JSON="${OUTPUT_JSON:-$OUTPUT_DIR/latest_report.json}"
SEED="${SEED:-20260223}"
CASES_PER_FORMAT="${CASES_PER_FORMAT:-12}"
FORMATS="${FORMATS:-binary,hex,base64}"
VERIFIER_PROFILE="${VERIFIER_PROFILE:-strict_canonical}"

mkdir -p "$OUTPUT_DIR"
echo "[boundary] running serialization sample campaign"
cargo run -q -p zk-track-boundary --example run_serialization_fuzz_campaign -- \
  --output-json "$OUTPUT_JSON" \
  --seed "$SEED" \
  --cases-per-format "$CASES_PER_FORMAT" \
  --formats "$FORMATS" \
  --verifier-profile "$VERIFIER_PROFILE"

echo "[boundary] report: $OUTPUT_JSON"
