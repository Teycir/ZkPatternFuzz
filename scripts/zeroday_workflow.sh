#!/bin/bash
# =============================================================================
# ZkPatternFuzz 0-Day Discovery Workflow
# =============================================================================
# This script orchestrates the complete workflow for finding 0-day vulnerabilities
# in ZK circuits following the AI_PENTEST_RULES.md guidelines.
#
# Phases:
#   1. SKIM    - Rapid heuristic scan (hints only)
#   2. ANALYZE - Manual invariant analysis (human step)
#   3. EVIDENCE - Bounded deterministic fuzzing with invariants
#   4. VERIFY  - Formal verification with Picus (optional)
#   5. TRIAGE  - Review findings and confirm/reject
#   6. DEEP    - Targeted edge-case fuzzing
#
# Usage:
#   ./scripts/zeroday_workflow.sh skim    <repo_path>
#   ./scripts/zeroday_workflow.sh evidence <campaign.yaml> [--iterations N] [--timeout S]
#   ./scripts/zeroday_workflow.sh verify  <circuit.circom> [--timeout MS]
#   ./scripts/zeroday_workflow.sh deep    <campaign.yaml> [--seed S]
#   ./scripts/zeroday_workflow.sh report  <output_dir>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FUZZER="$PROJECT_ROOT/target/release/zk-fuzzer"
SKIMMER="$PROJECT_ROOT/target/release/zk0d_skimmer"
PICUS_DIR="${PICUS_DIR:-/tmp/Picus}"
PICUS_BIN="${PICUS_BIN:-}"

# Default values
DEFAULT_ITERATIONS=50000
DEFAULT_TIMEOUT=1800
DEFAULT_SEED=42
DEFAULT_WORKERS=$(nproc 2>/dev/null || echo 4)
DEFAULT_PICUS_TIMEOUT=60000  # 60 seconds for Picus SMT solver

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

resolve_picus_bin() {
    # Priority:
    # 1) Explicit PICUS_BIN
    # 2) PICUS_DIR/run-picus
    # 3) run-picus on PATH
    # 4) picus on PATH (wrapper style install)
    if [[ -n "${PICUS_BIN:-}" && -x "${PICUS_BIN:-}" ]]; then
        printf '%s\n' "$PICUS_BIN"
        return 0
    fi

    if [[ -n "${PICUS_DIR:-}" && -x "${PICUS_DIR:-}/run-picus" ]]; then
        printf '%s\n' "${PICUS_DIR}/run-picus"
        return 0
    fi

    if command -v run-picus >/dev/null 2>&1; then
        command -v run-picus
        return 0
    fi

    if command -v picus >/dev/null 2>&1; then
        command -v picus
        return 0
    fi

    return 1
}

# Ensure release build exists
ensure_build() {
    if [[ ! -f "$FUZZER" ]]; then
        log_info "Building release version..."
        cd "$PROJECT_ROOT" && cargo build --release
    fi
}

# Phase 1: SKIM
phase_skim() {
    local repo_path="$1"
    local output_dir="${2:-reports/zk0d/skimmer}"
    
    log_info "=== PHASE 1: SKIM (Hints Only) ==="
    log_info "Target: $repo_path"
    log_warn "This phase produces HINTS, not confirmed findings."
    
    ensure_build
    
    if [[ ! -d "$repo_path/.git" ]]; then
        log_error "Repository must contain .git directory: $repo_path"
        exit 1
    fi
    
    "$SKIMMER" \
        --root "$repo_path" \
        --max-files 1200 \
        --min-confidence 0.15 \
        --top 40 \
        --output-dir "$output_dir" \
        --save-configs
    
    log_success "Skimmer complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Review: $output_dir/skimmer_summary.md"
    echo "  2. Fill invariants: $output_dir/candidate_invariants.yaml"
    echo "  3. Run evidence mode: ./scripts/zeroday_workflow.sh evidence <campaign.yaml>"
}

# Phase 2: Validate campaign before evidence run
validate_campaign() {
    local campaign="$1"
    
    log_info "Validating campaign: $campaign"
    
    if [[ ! -f "$campaign" ]]; then
        log_error "Campaign file not found: $campaign"
        exit 1
    fi
    
    "$FUZZER" validate "$campaign"
    
    # Check for invariants
    if ! grep -q "invariants:" "$campaign"; then
        log_warn "Campaign has no invariants section - evidence mode may not produce confirmed findings"
    else
        local inv_count=$(grep -c "name:" "$campaign" | head -1 || echo "0")
        log_info "Found invariants in campaign"
    fi
}

# Phase 3: EVIDENCE
phase_evidence() {
    local campaign="$1"
    shift
    
    local iterations=$DEFAULT_ITERATIONS
    local timeout=$DEFAULT_TIMEOUT
    local seed=$DEFAULT_SEED
    local workers=$DEFAULT_WORKERS
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --iterations|-i)
                iterations="$2"
                shift 2
                ;;
            --timeout|-t)
                timeout="$2"
                shift 2
                ;;
            --seed|-s)
                seed="$2"
                shift 2
                ;;
            --workers|-w)
                workers="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    log_info "=== PHASE 3: EVIDENCE (Deterministic Fuzzing) ==="
    log_info "Campaign: $campaign"
    log_info "Iterations: $iterations"
    log_info "Timeout: ${timeout}s"
    log_info "Seed: $seed"
    log_info "Workers: $workers"
    
    ensure_build
    validate_campaign "$campaign"
    
    log_info "Starting evidence run..."
    
    "$FUZZER" evidence "$campaign" \
        --seed "$seed" \
        --iterations "$iterations" \
        --timeout "$timeout" \
        --workers "$workers" \
        --simple-progress
    
    log_success "Evidence run complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Review findings in reports directory"
    echo "  2. For each finding, verify reproduction"
    echo "  3. If needed, run deep fuzz: ./scripts/zeroday_workflow.sh deep <campaign.yaml>"
}

# Phase 4: VERIFY (Formal Verification with Picus)
phase_verify() {
    local circuit="$1"
    shift
    
    local timeout=$DEFAULT_PICUS_TIMEOUT
    local output_json=""
    local solver="cvc5"
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout|-t)
                timeout="$2"
                shift 2
                ;;
            --output|-o)
                output_json="$2"
                shift 2
                ;;
            --solver)
                solver="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    log_info "=== PHASE 4: VERIFY (Formal Verification with Picus) ==="
    log_info "Circuit: $circuit"
    log_info "Solver timeout: ${timeout}ms"
    log_info "Solver: $solver"
    
    if [[ ! -f "$circuit" ]]; then
        log_error "Circuit file not found: $circuit"
        exit 1
    fi
    
    local picus_bin=""
    if ! picus_bin="$(resolve_picus_bin)"; then
        log_error "Picus not found via PICUS_BIN, PICUS_DIR/run-picus, run-picus PATH, or picus PATH"
        log_error "Set PICUS_BIN explicitly or PICUS_DIR to your Picus installation"
        log_error "See: VERIDISE_INTEGRATION.md"
        exit 1
    fi

    log_info "Using Picus binary: $picus_bin"
    log_info "Running Picus formal verification..."
    
    local picus_args=(--timeout "$timeout" --solver "$solver")
    
    if [[ -n "$output_json" ]]; then
        picus_args+=(--json "$output_json")
    fi
    
    local picus_tmp
    picus_tmp="$(mktemp)"
    set +e
    "$picus_bin" "${picus_args[@]}" "$circuit" 2>&1 | tee "$picus_tmp"
    local result=${PIPESTATUS[0]}
    set -e
    local picus_output
    picus_output="$(cat "$picus_tmp")"
    rm -f "$picus_tmp"

    # Some Picus builds print an inconclusive message while returning 0.
    # Treat this as UNKNOWN to avoid misclassifying ambiguous proofs as SAFE.
    if [[ "$picus_output" == *"Cannot determine whether the circuit is properly constrained"* ]]; then
        result=10
    fi
    
    echo ""
    case $result in
        0)
            log_success "Picus result: SAFE (no under-constraint found)"
            log_info "If ZkPatternFuzz found issues, they may be false positives."
            ;;
        9)
            log_warn "Picus result: UNSAFE (under-constraint detected!)"
            log_info "This is a FORMALLY CONFIRMED vulnerability (zero false positive)."
            ;;
        10)
            log_warn "Picus result: UNKNOWN (solver timeout or inconclusive)"
            log_info "Consider increasing --timeout or manual review."
            ;;
        *)
            log_error "Picus exited with unexpected code: $result"
            ;;
    esac
    
    echo ""
    log_info "Next steps:"
    echo "  1. Compare with ZkPatternFuzz findings"
    echo "  2. Update finding confidence levels based on Picus result"
    echo "  3. If UNSAFE, extract counterexample for PoC"
}

# Phase 6: DEEP (Edge Case Hunting)
phase_deep() {
    local campaign="$1"
    shift
    
    local iterations=100000
    local timeout=3600
    local seed=1337
    local workers=$DEFAULT_WORKERS
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --iterations|-i)
                iterations="$2"
                shift 2
                ;;
            --timeout|-t)
                timeout="$2"
                shift 2
                ;;
            --seed|-s)
                seed="$2"
                shift 2
                ;;
            --workers|-w)
                workers="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    log_info "=== PHASE 5: DEEP CUSTOM FUZZ (Edge Cases) ==="
    log_info "Campaign: $campaign"
    log_info "Iterations: $iterations"
    log_info "Timeout: ${timeout}s"
    log_info "Seed: $seed"
    
    ensure_build
    validate_campaign "$campaign"
    
    log_info "Starting deep fuzzing run..."
    
    "$FUZZER" evidence "$campaign" \
        --seed "$seed" \
        --iterations "$iterations" \
        --timeout "$timeout" \
        --workers "$workers" \
        --simple-progress
    
    log_success "Deep fuzz complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Review deep fuzzing findings"
    echo "  2. Consider running Picus verification on new findings"
}

# Generate summary report
phase_report() {
    local output_dir="$1"
    
    log_info "=== GENERATING SUMMARY REPORT ==="
    
    if [[ ! -d "$output_dir" ]]; then
        log_error "Output directory not found: $output_dir"
        exit 1
    fi
    
    local report_file="$output_dir/0day_summary.md"
    
    echo "# 0-Day Discovery Summary" > "$report_file"
    echo "" >> "$report_file"
    echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$report_file"
    echo "" >> "$report_file"
    
    # Count findings
    local json_files=$(find "$output_dir" -name "report.json" 2>/dev/null || true)
    
    if [[ -n "$json_files" ]]; then
        echo "## Findings Overview" >> "$report_file"
        echo "" >> "$report_file"
        for json in $json_files; do
            local dir=$(dirname "$json")
            local name=$(basename "$dir")
            local count=$(grep -c '"severity"' "$json" 2>/dev/null || echo "0")
            echo "- **$name**: $count findings" >> "$report_file"
        done
    else
        echo "No report.json files found in $output_dir" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "## Classification" >> "$report_file"
    echo "" >> "$report_file"
    echo "| Finding | Status | Evidence |" >> "$report_file"
    echo "|---------|--------|----------|" >> "$report_file"
    echo "| (Review findings and update) | PENDING | |" >> "$report_file"
    
    log_success "Report generated: $report_file"
}

# Show help
show_help() {
    echo "ZkPatternFuzz 0-Day Discovery Workflow"
    echo ""
    echo "Usage:"
    echo "  $0 skim <repo_path>                     Phase 1: Rapid heuristic scan"
    echo "  $0 evidence <campaign.yaml> [options]   Phase 3: Bounded evidence run"
    echo "  $0 verify <circuit.circom> [options]    Phase 4: Formal verification (Picus)"
    echo "  $0 deep <campaign.yaml> [options]       Phase 6: Deep edge-case fuzzing"
    echo "  $0 report <output_dir>                  Generate summary report"
    echo ""
    echo "Options for evidence/deep:"
    echo "  --iterations, -i N    Number of fuzzing iterations (default: $DEFAULT_ITERATIONS)"
    echo "  --timeout, -t S       Timeout in seconds (default: $DEFAULT_TIMEOUT)"
    echo "  --seed, -s S          Random seed for reproducibility (default: $DEFAULT_SEED)"
    echo "  --workers, -w W       Number of parallel workers (default: $DEFAULT_WORKERS)"
    echo ""
    echo "Options for verify:"
    echo "  --timeout, -t MS      SMT solver timeout in milliseconds (default: $DEFAULT_PICUS_TIMEOUT)"
    echo "  --output, -o FILE     Output JSON report path (optional)"
    echo "  --solver SOLVER       SMT solver: cvc5 | z3 (default: cvc5)"
    echo ""
    echo "Workflow:"
    echo "  1. skim      - Scan repo for candidate vulnerabilities (hints only)"
    echo "  2. (manual)  - Review hints, write invariants in YAML"
    echo "  3. evidence  - Run fuzzer with invariants, collect PoCs"
    echo "  4. verify    - Formal proof with Picus (OPTIONAL, eliminates false positives)"
    echo "  5. (manual)  - Triage findings, confirm/reject each"
    echo "  6. deep      - Targeted edge-case hunting"
    echo ""
    echo "Environment Variables:"
    echo "  PICUS_BIN    Absolute path to Picus executable (highest priority)"
    echo "  PICUS_DIR    Path to Picus installation (expects PICUS_DIR/run-picus; default: /tmp/Picus)"
    echo ""
    echo "See docs/AI_PENTEST_RULES.md for classification rules."
    echo "See VERIDISE_INTEGRATION.md for Picus installation."
}

# Main entry point
main() {
    if [[ $# -lt 1 ]]; then
        show_help
        exit 1
    fi
    
    local command="$1"
    shift
    
    case "$command" in
        skim)
            [[ $# -lt 1 ]] && { log_error "Missing repo_path"; show_help; exit 1; }
            phase_skim "$@"
            ;;
        evidence)
            [[ $# -lt 1 ]] && { log_error "Missing campaign.yaml"; show_help; exit 1; }
            phase_evidence "$@"
            ;;
        verify)
            [[ $# -lt 1 ]] && { log_error "Missing circuit.circom"; show_help; exit 1; }
            phase_verify "$@"
            ;;
        deep)
            [[ $# -lt 1 ]] && { log_error "Missing campaign.yaml"; show_help; exit 1; }
            phase_deep "$@"
            ;;
        report)
            [[ $# -lt 1 ]] && { log_error "Missing output_dir"; show_help; exit 1; }
            phase_report "$@"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
