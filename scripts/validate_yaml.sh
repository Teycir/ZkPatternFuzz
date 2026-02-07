#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: scripts/validate_yaml.sh <campaign.yaml>"
  exit 1
fi

cargo run --release --bin validate_yaml -- "$@"
