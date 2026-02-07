#!/usr/bin/env bash
set -euo pipefail

# Skimmer for zk0d (hints only)
# Usage: scripts/run_skimmer.sh [--root /media/elements/Repos/zk0d] [--max-files 200]

cargo run --release --bin zk0d_skimmer -- "$@"
