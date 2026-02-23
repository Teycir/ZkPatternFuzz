#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/artifacts/boundary/public_input_bug_probe}"
OUTPUT_JSON="${OUTPUT_JSON:-$OUTPUT_DIR/latest_report.json}"
SEED="${SEED:-13370}"
PROOFS="${PROOFS:-1000}"
PUBLIC_INPUTS_PER_PROOF="${PUBLIC_INPUTS_PER_PROOF:-3}"
MUTATION_STRATEGIES="${MUTATION_STRATEGIES:-bit_flip,field_boundary,reordering,truncation,duplication,type_confusion}"
ATTACK_SCENARIOS="${ATTACK_SCENARIOS:-identity_swap,value_inflation,merkle_root_swap}"
VERIFIER_PROFILE="${VERIFIER_PROFILE:-weak_first_input_binding}"

mkdir -p "$OUTPUT_DIR"
echo "[boundary] running public input bug probe"
cargo run -q -p zk-track-boundary --example run_public_input_manipulation_campaign -- \
  --output-json "$OUTPUT_JSON" \
  --seed "$SEED" \
  --proofs "$PROOFS" \
  --public-inputs-per-proof "$PUBLIC_INPUTS_PER_PROOF" \
  --mutation-strategies "$MUTATION_STRATEGIES" \
  --attack-scenarios "$ATTACK_SCENARIOS" \
  --verifier-profile "$VERIFIER_PROFILE"

echo "[boundary] bug probe report: $OUTPUT_JSON"
