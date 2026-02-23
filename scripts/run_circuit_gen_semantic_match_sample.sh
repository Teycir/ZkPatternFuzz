#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/semantic_constraint_match_sample}"
SOURCE_FILE="${SOURCE_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/semantic_source.sample.circom}"
DOC_FILE="${DOC_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/semantic_doc.sample.md}"
DSL_FILE="${DSL_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/structure_dsl.sample.yaml}"
BACKEND="${BACKEND:-circom}"

mkdir -p "$OUTPUT_DIR"
echo "[circuit-gen] verifying semantic intent against compiled constraints"
cargo run -q -p zk-circuit-gen --example verify_semantic_constraint_match -- \
  --source-file "$SOURCE_FILE" \
  --doc-file "$DOC_FILE" \
  --dsl-file "$DSL_FILE" \
  --backend "$BACKEND" \
  --output-json "$OUTPUT_DIR/latest_report.json"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
