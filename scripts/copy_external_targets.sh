#!/usr/bin/env bash
# Script to copy external validation targets to workspace
# Run this from a terminal with access to both paths

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$PROJECT_ROOT/scripts/load_env_master.sh"
load_env_master "$PROJECT_ROOT"

SOURCE_DIR="${SOURCE_DIR:-}"
if [[ -z "$SOURCE_DIR" && -n "${ZK0D_BASE:-}" ]]; then
  SOURCE_DIR="${ZK0D_BASE%/}/cat3_privacy"
fi
TARGET_DIR="${TARGET_DIR:-}"

if [[ -z "$SOURCE_DIR" ]]; then
  echo "Missing SOURCE_DIR. Set SOURCE_DIR or ZK0D_BASE." >&2
  echo "Example: SOURCE_DIR=/path/to/zk0d/cat3_privacy $0" >&2
  exit 1
fi

if [[ -z "$TARGET_DIR" ]]; then
  echo "Missing TARGET_DIR. Set TARGET_DIR in env master or shell environment." >&2
  echo "Example: TARGET_DIR=/path/to/workspace/targets/zk0d/cat3_privacy $0" >&2
  exit 1
fi

echo "Copying validation targets from external drive..."
echo "Source: $SOURCE_DIR"
echo "Target: $TARGET_DIR"

# Create target directory
mkdir -p "$TARGET_DIR"

# Copy all data
echo "Copying circuits..."
rsync -avh --progress "$SOURCE_DIR/" "$TARGET_DIR/"

echo ""
echo "Copy complete!"
echo ""
echo "Verifying contents:"
ls -la "$TARGET_DIR/"
