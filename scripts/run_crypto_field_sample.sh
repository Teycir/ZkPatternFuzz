#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/crypto/field_sample}"
OUTPUT_JSON="${OUTPUT_JSON:-$OUTPUT_DIR/latest_report.json}"
SEED="${SEED:-20260223}"
RANDOM_VALUES="${RANDOM_VALUES:-8}"
OPERATIONS="${OPERATIONS:-addition,subtraction,multiplication,division,exponentiation,modular_reduction}"
PROPERTIES="${PROPERTIES:-commutativity,associativity,distributivity,identity,inverse}"
IMPLEMENTATION_PROFILE="${IMPLEMENTATION_PROFILE:-strict_reference}"

mkdir -p "$OUTPUT_DIR"
echo "[crypto] running field arithmetic sample campaign"
cargo run -q -p zk-track-crypto --example run_field_arithmetic_fuzz_campaign -- \
  --output-json "$OUTPUT_JSON" \
  --seed "$SEED" \
  --random-values "$RANDOM_VALUES" \
  --operations "$OPERATIONS" \
  --properties "$PROPERTIES" \
  --implementation-profile "$IMPLEMENTATION_PROFILE"

echo "[crypto] field sample report: $OUTPUT_JSON"
