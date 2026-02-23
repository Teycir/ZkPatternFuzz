#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/crypto/pairing_sample}"
OUTPUT_JSON="${OUTPUT_JSON:-$OUTPUT_DIR/latest_report.json}"
SEED="${SEED:-20260223}"
G1_INPUTS="${G1_INPUTS:-identity,generator,random_valid,low_order_proxy,invalid}"
G2_INPUTS="${G2_INPUTS:-identity,generator,random_valid,low_order_proxy,invalid}"
PROPERTIES="${PROPERTIES:-bilinearity,non_degeneracy,identity,linearity_g1,linearity_g2}"
IMPLEMENTATION_PROFILE="${IMPLEMENTATION_PROFILE:-strict_subgroup_checks}"

mkdir -p "$OUTPUT_DIR"
echo "[crypto] running pairing sample campaign"
cargo run -q -p zk-track-crypto --example run_pairing_fuzz_campaign -- \
  --output-json "$OUTPUT_JSON" \
  --seed "$SEED" \
  --g1-inputs "$G1_INPUTS" \
  --g2-inputs "$G2_INPUTS" \
  --properties "$PROPERTIES" \
  --implementation-profile "$IMPLEMENTATION_PROFILE"

echo "[crypto] pairing sample report: $OUTPUT_JSON"
