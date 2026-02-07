#!/usr/bin/env bash
set -euo pipefail

# Batch runner for zk0d target list
# Usage: scripts/run_ai_campaign.sh [--targets targets/zk0d_targets.yaml] [--dry-run]

cargo run --release --bin zk0d_batch -- "$@"
