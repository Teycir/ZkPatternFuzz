#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/backend_compile_integration_sample}"
BACKEND="${BACKEND:-halo2}"
CIRCUITS="${CIRCUITS:-20}"
SEED="${SEED:-1337}"

mkdir -p "$OUTPUT_DIR"
echo "[circuit-gen] running backend compile integration sample"
cargo run -q -p zk-circuit-gen --example run_backend_compile_integration -- \
  --backend "$BACKEND" \
  --circuits "$CIRCUITS" \
  --seed "$SEED" \
  --output-json "$OUTPUT_DIR/latest_report.json"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
