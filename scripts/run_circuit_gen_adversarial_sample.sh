#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/adversarial_sample}"
PATTERNS_JSON="${PATTERNS_JSON:-$ROOT_DIR/tests/datasets/circuit_gen/external_ai_patterns.sample.json}"
FEEDBACK_JSON="${FEEDBACK_JSON:-$ROOT_DIR/tests/datasets/circuit_gen/external_ai_feedback.sample.json}"
SEED="${SEED:-7331}"

echo "[circuit-gen] generating adversarial corpus from external AI pattern bundle"
cargo run -q -p zk-circuit-gen --example generate_adversarial_corpus -- \
  --patterns-json "$PATTERNS_JSON" \
  --feedback-json "$FEEDBACK_JSON" \
  --output-dir "$OUTPUT_DIR" \
  --seed "$SEED"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
