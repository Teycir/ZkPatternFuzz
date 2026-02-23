#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/semantic_intent_sample}"
SOURCE_FILE="${SOURCE_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/semantic_source.sample.circom}"
DOC_FILE="${DOC_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/semantic_doc.sample.md}"

mkdir -p "$OUTPUT_DIR"
echo "[circuit-gen] extracting semantic intent from source/docs"
cargo run -q -p zk-circuit-gen --example extract_semantic_intent -- \
  --backend circom \
  --source-file "$SOURCE_FILE" \
  --doc-file "$DOC_FILE" \
  --output-json "$OUTPUT_DIR/latest_report.json"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
