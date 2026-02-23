#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/boundary/cross_component_sample}"
OUTPUT_JSON="${OUTPUT_JSON:-$OUTPUT_DIR/latest_report.json}"
SEED="${SEED:-20260223}"
COMBINATIONS="${COMBINATIONS:-60}"
PUBLIC_INPUTS_PER_CASE="${PUBLIC_INPUTS_PER_CASE:-3}"
FAULT_STAGES="${FAULT_STAGES:-circuit_stage,prover_stage,verifier_stage,transport_boundary}"
MISMATCH_CASES="${MISMATCH_CASES:-prover_verifier_version_mismatch,circuit_verifier_flag_mismatch,trusted_setup_mismatch,curve_parameter_mismatch}"
VERIFIER_PROFILE="${VERIFIER_PROFILE:-strict_compatibility}"

mkdir -p "$OUTPUT_DIR"
echo "[boundary] running cross-component sample campaign"
cargo run -q -p zk-track-boundary --example run_cross_component_fuzz_campaign -- \
  --output-json "$OUTPUT_JSON" \
  --seed "$SEED" \
  --combinations "$COMBINATIONS" \
  --public-inputs-per-case "$PUBLIC_INPUTS_PER_CASE" \
  --fault-stages "$FAULT_STAGES" \
  --mismatch-cases "$MISMATCH_CASES" \
  --verifier-profile "$VERIFIER_PROFILE"

echo "[boundary] report: $OUTPUT_JSON"
