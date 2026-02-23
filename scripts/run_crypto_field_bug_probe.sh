#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/crypto/field_bug_probe}"
OUTPUT_JSON="${OUTPUT_JSON:-$OUTPUT_DIR/latest_report.json}"
SEED="${SEED:-20260223}"
RANDOM_VALUES="${RANDOM_VALUES:-8}"
OPERATIONS="${OPERATIONS:-addition,subtraction,multiplication,division,exponentiation,modular_reduction}"
PROPERTIES="${PROPERTIES:-commutativity,associativity,distributivity,identity,inverse}"
IMPLEMENTATION_PROFILE="${IMPLEMENTATION_PROFILE:-weak_reduction}"

mkdir -p "$OUTPUT_DIR"
echo "[crypto] running field arithmetic bug probe"
cargo run -q -p zk-track-crypto --example run_field_arithmetic_fuzz_campaign -- \
  --output-json "$OUTPUT_JSON" \
  --seed "$SEED" \
  --random-values "$RANDOM_VALUES" \
  --operations "$OPERATIONS" \
  --properties "$PROPERTIES" \
  --implementation-profile "$IMPLEMENTATION_PROFILE"

echo "[crypto] field bug probe report: $OUTPUT_JSON"
