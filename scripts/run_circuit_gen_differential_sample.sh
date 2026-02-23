#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/differential_sample}"
DSL_FILE="${DSL_FILE:-$ROOT_DIR/tests/datasets/circuit_gen/structure_dsl.sample.yaml}"
BACKENDS="${BACKENDS:-circom,noir}"
COMPILER_IDS="${COMPILER_IDS:-circom_v2_0,circom_v2_1}"

mkdir -p "$OUTPUT_DIR"
echo "[circuit-gen] running differential compiler matrix"
cargo run -q -p zk-circuit-gen --example run_differential_compiler_matrix -- \
  --dsl-file "$DSL_FILE" \
  --backends "$BACKENDS" \
  --compiler-ids "$COMPILER_IDS" \
  --output-json "$OUTPUT_DIR/latest_report.json"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
