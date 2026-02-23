#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/differential_version_matrix_sample}"
CIRCUITS="${CIRCUITS:-120}"
SEED="${SEED:-42}"
BACKENDS="${BACKENDS:-circom}"
COMPILER_IDS="${COMPILER_IDS:-circom_v2_0,circom_v2_1,circom_v2_2}"

echo "[circuit-gen] running differential version matrix campaign"
cargo run -q -p zk-circuit-gen --example run_differential_version_matrix -- \
  --output-dir "$OUTPUT_DIR" \
  --circuits "$CIRCUITS" \
  --seed "$SEED" \
  --backends "$BACKENDS" \
  --compiler-ids "$COMPILER_IDS"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
