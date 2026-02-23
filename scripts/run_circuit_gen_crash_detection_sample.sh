#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/circuit_gen/crash_detection_sample}"
PROBE_JSON="${PROBE_JSON:-$ROOT_DIR/tests/datasets/circuit_gen/compiler_probe_cases.sample.json}"

echo "[circuit-gen] running compiler crash detection sample"
cargo run -q -p zk-circuit-gen --example run_compiler_crash_detector -- \
  --probe-json "$PROBE_JSON" \
  --output-dir "$OUTPUT_DIR"

echo "[circuit-gen] report: $OUTPUT_DIR/latest_report.json"
