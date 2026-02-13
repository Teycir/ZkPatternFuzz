#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="reports/validation/ground_truth"
mkdir -p "$OUT_DIR"

echo "Running ground-truth validation smoke pass..."
cargo test --test ground_truth_test ground_truth_infrastructure_smoke_test -- --nocapture

echo "Generating ground-truth summary..."
python3 tests/scripts/validate_findings.py "$OUT_DIR" tests/ground_truth_circuits > reports/validation/ground_truth_report.md || true

echo "Ground-truth validation complete."
