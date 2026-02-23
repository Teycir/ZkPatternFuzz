#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/structure_sample}"
DSL_FILE="${DSL_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/structure_dsl.sample.yaml}"
BACKEND="${BACKEND:-circom}"

mkdir -p "$OUTPUT_DIR"
echo "[circuit-gen] compiling DSL + extracting structure metrics"
cargo run -q -p zk-circuit-gen --example compile_and_extract_structure -- \
  --dsl-file "$DSL_FILE" \
  --backend "$BACKEND" \
  --output-json "$OUTPUT_DIR/latest_report.json"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
