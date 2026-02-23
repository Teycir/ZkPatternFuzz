#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/adversarial_top10_sample}"
PATTERNS_JSON="${PATTERNS_JSON:-$ROOT_DIR/tests/datasets/circuit_gen/external_ai_patterns.top10.sample.json}"
SEED="${SEED:-7331}"

echo "[circuit-gen] generating 10-pattern adversarial corpus from external AI bundle"
cargo run -q -p zk-circuit-gen --example generate_adversarial_corpus -- \
  --patterns-json "$PATTERNS_JSON" \
  --output-dir "$OUTPUT_DIR" \
  --seed "$SEED"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
