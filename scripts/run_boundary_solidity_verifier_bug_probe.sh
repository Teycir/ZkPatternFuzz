#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/boundary/solidity_verifier_bug_probe}"
OUTPUT_JSON="${OUTPUT_JSON:-$OUTPUT_DIR/latest_report.json}"
SEED="${SEED:-20260223}"
PROOFS="${PROOFS:-500}"
PUBLIC_INPUTS_PER_PROOF="${PUBLIC_INPUTS_PER_PROOF:-3}"
INPUT_MUTATIONS="${INPUT_MUTATIONS:-proof_byte_mutation,public_input_edge_case,malformed_calldata,gas_limit_stress,revert_condition_probe}"
PAIRING_CASES="${PAIRING_CASES:-pairing_equation_tamper,invalid_curve_point,wrong_subgroup_point,malformed_pairing_input}"
EDGE_CASES="${EDGE_CASES:-gas_calculation_overflow,public_input_array_bounds,memory_allocation_edge,calldata_memory_confusion,reentrancy_callback_probe}"
OPTIMIZED_PROFILE="${OPTIMIZED_PROFILE:-weak_gas_optimization}"

mkdir -p "$OUTPUT_DIR"
echo "[boundary] running solidity verifier bug probe"
cargo run -q -p zk-track-boundary --example run_solidity_verifier_fuzz_campaign -- \
  --output-json "$OUTPUT_JSON" \
  --seed "$SEED" \
  --proofs "$PROOFS" \
  --public-inputs-per-proof "$PUBLIC_INPUTS_PER_PROOF" \
  --input-mutations "$INPUT_MUTATIONS" \
  --pairing-cases "$PAIRING_CASES" \
  --edge-cases "$EDGE_CASES" \
  --optimized-profile "$OPTIMIZED_PROFILE"

echo "[boundary] bug probe report: $OUTPUT_JSON"
