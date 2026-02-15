#!/usr/bin/env bash
set -euo pipefail

# Skimmer for zk0d (hints only)
# Default depth: --max-files 1200 --min-confidence 0.15 --top 40
# Usage: scripts/run_skimmer.sh [--root $ZK0D_BASE] [--root-placeholder '${TARGET_REPO}'] [--max-files 1200]
# Note: --root must be a single repo root (contains .git), not a parent of multiple repos.

cargo run --release --bin zk0d_skimmer -- "$@"
