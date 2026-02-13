#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="reports/validation/safe"
mkdir -p "$OUT_DIR"

echo "Running safe-circuits benchmark smoke pass..."
cargo test --test false_positive_analysis -- --nocapture

echo "Collecting summary..."
python3 tests/scripts/calculate_fpr.py "$OUT_DIR" > reports/validation/false_positive_report.md || true

echo "Safe-circuits benchmark complete."
