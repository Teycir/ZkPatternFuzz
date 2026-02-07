#!/usr/bin/env bash
set -euo pipefail

# Skimmer for zk0d (hints only)
# Usage: scripts/run_skimmer.sh [--root /media/elements/Repos/zk0d] [--max-files 200]
# Note: --root must be a single repo root (contains .git), not a parent of multiple repos.

cargo run --release --bin zk0d_skimmer -- "$@"
