#!/bin/bash
# ZkPatternFuzz Benchmark Runner
#
# Runs the known-bug benchmark suite and generates reports.
#
# Usage:
#   ./scripts/run_benchmarks.sh [OPTIONS]
#
# Options:
#   --quick       Quick mode (1 run per benchmark, shorter timeout)
#   --full        Full mode (5 runs per benchmark, standard timeout)
#   --ci          CI mode (optimized for GitHub Actions)
#   --output DIR  Output directory for results (default: reports/benchmarks)
#   --help        Show this help

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REBUILD_SCRIPT="$ROOT_DIR/scripts/rebuild_release_binaries.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"; }

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

# Configuration
QUICK_MODE=false
FULL_MODE=false
CI_MODE=false
OUTPUT_DIR="reports/benchmarks"
KNOWN_BUGS_DIR="tests/bench/known_bugs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SEED=42
WORKERS=4
RUNS=3
TIMEOUT=300

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_MODE=true
            RUNS=1
            TIMEOUT=60
            shift
            ;;
        --full)
            FULL_MODE=true
            RUNS=5
            TIMEOUT=600
            shift
            ;;
        --ci)
            CI_MODE=true
            RUNS=1
            TIMEOUT=120
            shift
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help)
            echo "ZkPatternFuzz Benchmark Runner"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick       Quick mode (1 run, 60s timeout)"
            echo "  --full        Full mode (5 runs, 600s timeout)"
            echo "  --ci          CI mode (1 run, 120s timeout, optimized output)"
            echo "  --output DIR  Output directory (default: reports/benchmarks)"
            echo "  --help        Show this help"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Print banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           ZkPatternFuzz Benchmark Suite                   ║"
echo "║                                                           ║"
echo "║  Testing known-bug detection capabilities                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

log_section "Configuration"
echo "  Mode: $(if $QUICK_MODE; then echo 'Quick'; elif $FULL_MODE; then echo 'Full'; elif $CI_MODE; then echo 'CI'; else echo 'Standard'; fi)"
echo "  Runs per benchmark: $RUNS"
echo "  Timeout: ${TIMEOUT}s"
echo "  Workers: $WORKERS"
echo "  Output: $OUTPUT_DIR"
echo "  Seed: $SEED"

# Check prerequisites
log_section "Prerequisites Check"

if ! command -v cargo &> /dev/null; then
    log_error "cargo not found. Please install Rust."
    exit 1
fi
log_info "cargo: $(cargo --version)"

if [ ! -d "$KNOWN_BUGS_DIR" ]; then
    log_error "Known bugs directory not found: $KNOWN_BUGS_DIR"
    exit 1
fi
log_info "Known bugs directory: $KNOWN_BUGS_DIR"

# Count benchmarks
BENCHMARK_COUNT=$(find "$KNOWN_BUGS_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)
log_info "Found $BENCHMARK_COUNT benchmarks"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build release binary
log_section "Building ZkPatternFuzz"
if [[ ! -x "$REBUILD_SCRIPT" ]]; then
    log_error "Rebuild script not found or not executable: $REBUILD_SCRIPT"
    exit 1
fi
if "$REBUILD_SCRIPT" --project-root "$ROOT_DIR" --if-changed >/dev/null 2>&1; then
    log_info "Build successful"
else
    log_error "Build failed"
    exit 1
fi

# Initialize results
RESULTS_JSON="$OUTPUT_DIR/benchmark_${TIMESTAMP}.json"
RESULTS_MD="$OUTPUT_DIR/benchmark_${TIMESTAMP}.md"
SCOREBOARD="$OUTPUT_DIR/scoreboard.json"

# Initialize JSON results
cat > "$RESULTS_JSON" << EOF
{
  "version": "$(cargo pkgid | cut -d'#' -f2)",
  "timestamp": "$(date -Iseconds)",
  "config": {
    "runs": $RUNS,
    "timeout": $TIMEOUT,
    "workers": $WORKERS,
    "seed": $SEED
  },
  "benchmarks": [
EOF

# Initialize Markdown results
cat > "$RESULTS_MD" << EOF
# ZkPatternFuzz Benchmark Results

**Date:** $(date)
**Version:** $(cargo pkgid | cut -d'#' -f2 2>/dev/null || echo "dev")
**Mode:** $(if $QUICK_MODE; then echo 'Quick'; elif $FULL_MODE; then echo 'Full'; elif $CI_MODE; then echo 'CI'; else echo 'Standard'; fi)

## Summary

| Benchmark | Expected Bug | Detection Time | Status |
|-----------|-------------|----------------|--------|
EOF

# Run benchmarks
log_section "Running Benchmarks"

PASSED=0
FAILED=0
FIRST=true

for BENCHMARK_DIR in "$KNOWN_BUGS_DIR"/*/; do
    BENCHMARK_NAME=$(basename "$BENCHMARK_DIR")
    
    if [ ! -f "$BENCHMARK_DIR/expected_finding.json" ]; then
        log_warn "Skipping $BENCHMARK_NAME: no expected_finding.json"
        continue
    fi

    log_info "Running: $BENCHMARK_NAME"

    EXPECTED_TYPE=$(jq -r '.attack_type' "$BENCHMARK_DIR/expected_finding.json" 2>/dev/null || echo "Unknown")
    EXPECTED_TIME=$(jq -r '.expected_time_seconds' "$BENCHMARK_DIR/expected_finding.json" 2>/dev/null || echo "30")

    # Run the benchmark (simulate for now - integrate with actual fuzzer)
    START_TIME=$(date +%s%N)
    
    # For demonstration, we'll simulate running the harness test
    # In production, this would call the actual fuzzer
    DETECTION_TIME="N/A"
    STATUS="⏳"
    
    if cargo test --test harness "$BENCHMARK_NAME" -- --nocapture 2>&1 | tee "$OUTPUT_DIR/${BENCHMARK_NAME}_log.txt" | tail -20; then
        END_TIME=$(date +%s%N)
        ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
        
        # Check if bug was found
        if grep -q "VULNERABILITY CONFIRMED\|expected_bug_found: true\|passed: true" "$OUTPUT_DIR/${BENCHMARK_NAME}_log.txt" 2>/dev/null; then
            DETECTION_TIME="${ELAPSED_MS}ms"
            STATUS="✅"
            ((PASSED++)) || true
        else
            DETECTION_TIME="timeout"
            STATUS="❌"
            ((FAILED++)) || true
        fi
    else
        STATUS="❌"
        ((FAILED++)) || true
    fi

    # Append to JSON
    if ! $FIRST; then
        echo "," >> "$RESULTS_JSON"
    fi
    FIRST=false
    
    cat >> "$RESULTS_JSON" << EOF
    {
      "name": "$BENCHMARK_NAME",
      "expected_type": "$EXPECTED_TYPE",
      "detection_time_ms": ${ELAPSED_MS:-null},
      "status": "$(if [ "$STATUS" = "✅" ]; then echo 'passed'; else echo 'failed'; fi)"
    }
EOF

    # Append to Markdown
    echo "| $BENCHMARK_NAME | $EXPECTED_TYPE | $DETECTION_TIME | $STATUS |" >> "$RESULTS_MD"

    echo "  $BENCHMARK_NAME: $STATUS ($DETECTION_TIME)"
done

# Close JSON array
cat >> "$RESULTS_JSON" << EOF
  ],
  "summary": {
    "total": $BENCHMARK_COUNT,
    "passed": $PASSED,
    "failed": $FAILED,
    "pass_rate": $(echo "scale=2; $PASSED / $BENCHMARK_COUNT * 100" | bc 2>/dev/null || echo "0")
  }
}
EOF

# Finish Markdown
cat >> "$RESULTS_MD" << EOF

## Statistics

- **Total Benchmarks:** $BENCHMARK_COUNT
- **Passed:** $PASSED
- **Failed:** $FAILED
- **Pass Rate:** $(echo "scale=1; $PASSED / $BENCHMARK_COUNT * 100" | bc 2>/dev/null || echo "N/A")%

---
*Generated by ZkPatternFuzz benchmark suite*
EOF

# Copy to scoreboard
cp "$RESULTS_JSON" "$SCOREBOARD"

# Print summary
log_section "Results Summary"

echo -e "  Total:  ${BLUE}$BENCHMARK_COUNT${NC}"
echo -e "  Passed: ${GREEN}$PASSED${NC}"
echo -e "  Failed: ${RED}$FAILED${NC}"

PASS_RATE=$(echo "scale=1; $PASSED / $BENCHMARK_COUNT * 100" | bc 2>/dev/null || echo "0")
echo -e "  Rate:   ${CYAN}${PASS_RATE}%${NC}"
echo ""
echo "  Results saved to:"
echo "    - $RESULTS_JSON"
echo "    - $RESULTS_MD"
echo "    - $SCOREBOARD"

publish_backend_dashboard

# Exit code based on results
if [ "$FAILED" -gt 0 ]; then
    if $CI_MODE; then
        log_warn "Some benchmarks failed (CI mode - not failing build)"
        exit 0
    else
        log_error "Some benchmarks failed"
        exit 1
    fi
else
    log_info "All benchmarks passed!"
    exit 0
fi
