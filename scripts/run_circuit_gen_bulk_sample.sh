#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/bulk_latest}"
CIRCUITS_PER_BACKEND="${CIRCUITS_PER_BACKEND:-1000}"
SEED="${SEED:-1337}"
BACKENDS="${BACKENDS:-circom,noir,halo2,cairo}"
MUTATION_STRATEGIES="${MUTATION_STRATEGIES:-}"
MUTATION_INTENSITY="${MUTATION_INTENSITY:-3}"

echo "[circuit-gen] generating bulk corpus"
CMD=(
  cargo run -q -p zk-circuit-gen --example generate_bulk_corpus --
  --output-dir "$OUTPUT_DIR"
  --circuits-per-backend "$CIRCUITS_PER_BACKEND"
  --seed "$SEED"
  --backends "$BACKENDS"
  --mutation-intensity "$MUTATION_INTENSITY"
)
if [[ -n "$MUTATION_STRATEGIES" ]]; then
  CMD+=(--mutation-strategies "$MUTATION_STRATEGIES")
fi
"${CMD[@]}"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
