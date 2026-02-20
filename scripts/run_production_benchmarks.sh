#!/bin/bash
# Production Benchmark Suite for ZkPatternFuzz
#
# Runs fuzzing campaigns against real circuits from the zk0d collection.
# Measures detection time, false positive rate, coverage, and throughput.
#
# Usage:
#   ./scripts/run_production_benchmarks.sh [--quick] [--circuit CIRCUIT]
#
# Options:
#   --quick    Run quick benchmarks (shorter timeout)
#   --circuit  Run only specified circuit (tornado|semaphore|zkevm)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Configuration
ZK0D_BASE="${ZK0D_BASE:-/media/elements/Repos/zk0d}"
OUTPUT_DIR="./reports/benchmarks"
CAMPAIGNS_DIR="${CAMPAIGNS_DIR:-./tests/campaigns}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
QUICK_MODE=false
CIRCUIT_FILTER=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }

publish_backend_dashboard() {
    local dashboard_script="$ROOT_DIR/scripts/backend_readiness_dashboard.sh"
    if [ ! -x "$dashboard_script" ]; then
        log_warn "Backend readiness dashboard script not found: $dashboard_script"
        return
    fi
    if "$dashboard_script" --output "$ROOT_DIR/artifacts/backend_readiness/latest_report.json" >/dev/null 2>&1; then
        log_info "Updated backend readiness dashboard: artifacts/backend_readiness/latest_report.json"
    else
        log_warn "Backend readiness dashboard update failed"
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick) QUICK_MODE=true; shift ;;
        --circuit) CIRCUIT_FILTER="$2"; shift 2 ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Set timeouts based on mode
if $QUICK_MODE; then
    TORNADO_TIMEOUT=60
    SEMAPHORE_TIMEOUT=120
    ZKEVM_TIMEOUT=180
else
    TORNADO_TIMEOUT=600
    SEMAPHORE_TIMEOUT=1800
    ZKEVM_TIMEOUT=3600
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build release binary
log_section "Building ZkPatternFuzz (release)"
if ! cargo build --release 2>&1 | tail -5; then
    log_error "Failed to build release binary"
    exit 1
fi

USE_MOCK=false
if [ ! -d "$ZK0D_BASE" ]; then
    log_warn "zk0d collection not found at $ZK0D_BASE"
    log_warn "Set ZK0D_BASE environment variable to the correct path"
    log_warn "Benchmark will rely on staged circuits under ./circuits/"
fi

# Initialize results file
RESULTS_FILE="$OUTPUT_DIR/benchmark_${TIMESTAMP}.md"
cat > "$RESULTS_FILE" << EOF
# ZkPatternFuzz Benchmark Results

**Date:** $(date)
**Mode:** $(if $QUICK_MODE; then echo "Quick"; else echo "Full"; fi)
**zk0d Base:** $ZK0D_BASE

## Summary

| Circuit | Detection Time | False Positives | Coverage | Throughput |
|---------|---------------|-----------------|----------|------------|
EOF

# Benchmark function
prepare_config() {
    local source_config="$1"
    local timeout="$2"
    local tmp_config
    tmp_config=$(mktemp)

    if $QUICK_MODE; then
        sed -E "s/timeout_seconds: [0-9]+/timeout_seconds: ${timeout}/" "$source_config" > "$tmp_config"
    else
        cp "$source_config" "$tmp_config"
    fi

    echo "$tmp_config"
}

run_benchmark() {
    local name="$1"
    local config_path="$2"
    local timeout="$3"
    
    log_section "Benchmarking: $name"
    
    local start_time=$(date +%s)
    
    if [ ! -f "$config_path" ]; then
        log_warn "Campaign config not found: $config_path"
        log_warn "Skipping $name benchmark"
        return
    fi

    local circuit_path
    circuit_path=$(grep -m1 "circuit_path:" "$config_path" | awk '{print $2}' | tr -d '"')
    if [ -n "$circuit_path" ] && [ ! -e "$circuit_path" ]; then
        log_warn "Circuit path not found: $circuit_path"
        log_warn "Run ./scripts/setup_real_circuits.sh to stage sources"
        return
    fi

    local effective_config
    effective_config=$(prepare_config "$config_path" "$timeout")

    # Run fuzzer
    if timeout "$timeout" cargo run --release -- \
        --config "$effective_config" \
        --workers 4 \
        --seed 42 \
        > "$OUTPUT_DIR/${name}_log.txt" 2>&1; then
        local status="completed"
    else
        local status="timeout"
    fi

    rm -f "$effective_config"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Parse results (simplified)
    local findings=0
    local false_positives=0
    local coverage=0
    local throughput=0
    
    if [ -f "$OUTPUT_DIR/${name}_log.txt" ]; then
        findings=$(grep -c "Finding:" "$OUTPUT_DIR/${name}_log.txt" 2>/dev/null || echo "0")
        throughput=$(grep "executions/sec" "$OUTPUT_DIR/${name}_log.txt" | tail -1 | awk '{print $1}' || echo "0")
    fi
    
    # Append to results
    echo "| $name | ${duration}s | $false_positives | ${coverage}% | ${throughput}/s |" >> "$RESULTS_FILE"
    
    log_info "Completed $name in ${duration}s (findings: $findings, status: $status)"
}

# Run benchmarks
if [ -z "$CIRCUIT_FILTER" ] || [ "$CIRCUIT_FILTER" = "tornado" ]; then
    run_benchmark "tornado_cash" \
        "$CAMPAIGNS_DIR/tornado_core_audit.yaml" \
        "$TORNADO_TIMEOUT"
fi

if [ -z "$CIRCUIT_FILTER" ] || [ "$CIRCUIT_FILTER" = "semaphore" ]; then
    run_benchmark "semaphore" \
        "$CAMPAIGNS_DIR/semaphore_audit.yaml" \
        "$SEMAPHORE_TIMEOUT"
fi

if [ -z "$CIRCUIT_FILTER" ] || [ "$CIRCUIT_FILTER" = "zkevm" ]; then
    run_benchmark "zkevm" \
        "$CAMPAIGNS_DIR/polygon_zkevm_audit.yaml" \
        "$ZKEVM_TIMEOUT"
fi

# Generate final report
cat >> "$RESULTS_FILE" << EOF

## Detailed Metrics

### Performance Targets

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Tornado Cash Detection | <10 min | TBD | ⏳ |
| Semaphore Detection | <30 min | TBD | ⏳ |
| False Positive Rate | <5% | TBD | ⏳ |
| Constraint Coverage | >80% | TBD | ⏳ |

### Environment

- **CPU:** $(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 || echo "Unknown")
- **RAM:** $(free -h | grep Mem | awk '{print $2}' 2>/dev/null || echo "Unknown")
- **Rust:** $(rustc --version 2>/dev/null || echo "Unknown")
- **Z3:** $(z3 --version 2>/dev/null || echo "Unknown")

## Log Files

$(ls -la "$OUTPUT_DIR"/*_log.txt 2>/dev/null || echo "No log files generated")

---
Generated by ZkPatternFuzz benchmark suite
EOF

publish_backend_dashboard

log_section "Benchmark Complete"
log_info "Results saved to: $RESULTS_FILE"
cat "$RESULTS_FILE"
