#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/crypto/curve_bug_probe}"
OUTPUT_JSON="${OUTPUT_JSON:-$OUTPUT_DIR/latest_report.json}"
SEED="${SEED:-20260223}"
ITERATIONS="${ITERATIONS:-50}"
POINT_TYPES="${POINT_TYPES:-identity,generator,random_valid,random_valid_alt,low_order_proxy,invalid_not_on_curve,infinity_alt_representation}"
OPERATIONS="${OPERATIONS:-point_addition,point_doubling,scalar_multiplication,multi_scalar_multiplication,point_negation,point_validation}"
EDGE_CASES="${EDGE_CASES:-adding_identity,adding_inverse,doubling_identity,zero_scalar,one_scalar,large_scalar_wraparound,invalid_point_rejection}"
IMPLEMENTATION_PROFILE="${IMPLEMENTATION_PROFILE:-weak_invalid_handling}"

mkdir -p "$OUTPUT_DIR"
echo "[crypto] running curve operation bug probe"
cargo run -q -p zk-track-crypto --example run_curve_operation_fuzz_campaign -- \
  --output-json "$OUTPUT_JSON" \
  --seed "$SEED" \
  --iterations "$ITERATIONS" \
  --point-types "$POINT_TYPES" \
  --operations "$OPERATIONS" \
  --edge-cases "$EDGE_CASES" \
  --implementation-profile "$IMPLEMENTATION_PROFILE"

echo "[crypto] curve bug probe report: $OUTPUT_JSON"
