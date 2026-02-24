#!/usr/bin/env bash
# Baseline Verification Script
# Verifies that the fuzzer produces consistent results for CI regression testing
set -e

SEED=42
WORKERS=1
CONFIG="tests/campaigns/baseline.yaml"
EXPECTED_HASH="${EXPECTED_BASELINE_HASH:-}"

echo "=== ZkPatternFuzz Baseline Verification ==="
echo "Config: $CONFIG"
echo "Seed: $SEED"
echo "Workers: $WORKERS"
echo ""

# Run the fuzzer with deterministic settings
OUTPUT=$(cargo run --release -- --config "$CONFIG" --seed "$SEED" --workers "$WORKERS" 2>&1)

# Compute hash of key output metrics (filter for deterministic parts)
HASH=$(echo "$OUTPUT" | grep -E "(Coverage:|Findings:|Total Findings:)" | sha256sum | cut -d' ' -f1)

echo "Output Hash: $HASH"

if [ -n "$EXPECTED_HASH" ]; then
    if [ "$HASH" = "$EXPECTED_HASH" ]; then
        echo "✅ Baseline verification PASSED"
        exit 0
    else
        echo "❌ Baseline verification FAILED"
        echo "Expected: $EXPECTED_HASH"
        echo "Got: $HASH"
        exit 1
    fi
else
    echo "ℹ️  No expected hash set. Current hash: $HASH"
    echo "   Set EXPECTED_BASELINE_HASH=$HASH for future verification"
    exit 0
fi
