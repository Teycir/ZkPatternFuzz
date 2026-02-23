#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/semantic_violation_sample}"
SOURCE_FILE="${SOURCE_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/semantic_source.no_intent.sample.circom}"
DOC_FILE="${DOC_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/semantic_doc.boundary_violations.sample.md}"
DSL_FILE="${DSL_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/structure_dsl.sample.yaml}"
BACKEND="${BACKEND:-circom}"

mkdir -p "$OUTPUT_DIR"
echo "[circuit-gen] running semantic violation sample"
cargo run -q -p zk-circuit-gen --example verify_semantic_constraint_match -- \
  --source-file "$SOURCE_FILE" \
  --doc-file "$DOC_FILE" \
  --dsl-file "$DSL_FILE" \
  --backend "$BACKEND" \
  --output-json "$OUTPUT_DIR/latest_report.json" \
  --output-markdown "$OUTPUT_DIR/latest_report.md"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
