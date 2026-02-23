#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/bulk_latest}"
CIRCUITS_PER_BACKEND="${CIRCUITS_PER_BACKEND:-1000}"
SEED="${SEED:-1337}"
BACKENDS="${BACKENDS:-circom,noir,halo2,cairo}"

echo "[circuit-gen] generating bulk corpus"
cargo run -q -p zk-circuit-gen --example generate_bulk_corpus -- \
  --output-dir "$OUTPUT_DIR" \
  --circuits-per-backend "$CIRCUITS_PER_BACKEND" \
  --seed "$SEED" \
  --backends "$BACKENDS"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
