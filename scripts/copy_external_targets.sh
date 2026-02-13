#!/bin/bash
# Script to copy external validation targets to workspace
# Run this from a terminal with access to both paths

set -e

SOURCE_DIR="/media/elements/Repos/zk0d/cat3_privacy"
TARGET_DIR="/home/teycir/Repos/ZkPatternFuzz/targets/zk0d/cat3_privacy"

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
