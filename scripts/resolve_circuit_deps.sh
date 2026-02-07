#!/bin/bash
# Resolve Circuit Dependencies for zk0d Collection (uses ${ZK0D_BASE:-/media/elements/Repos/zk0d})
#
# Installs npm dependencies required for circuit compilation.
# Creates a ready-to-use environment for fuzzing real ZK circuits.
#
# Usage:
#   ./scripts/resolve_circuit_deps.sh [--check-only] [--circuit CIRCUIT]
#
# Options:
#   --check-only  Only check dependencies, don't install
#   --circuit     Process only specified circuit directory

set -euo pipefail

ZK0D_BASE="${ZK0D_BASE:-/media/elements/Repos/zk0d}"
CHECK_ONLY=false
CIRCUIT_FILTER=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --check-only) CHECK_ONLY=true; shift ;;
        --circuit) CIRCUIT_FILTER="$2"; shift 2 ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing=()
    
    if ! command -v node &> /dev/null; then
        missing+=("node")
    else
        local node_version=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$node_version" -lt 18 ]; then
            log_warn "Node.js version $node_version detected. Recommend v18+"
        fi
    fi
    
    if ! command -v npm &> /dev/null; then
        missing+=("npm")
    fi
    
    if ! command -v circom &> /dev/null; then
        log_warn "circom not found globally. Will use npx or install."
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing prerequisites: ${missing[*]}"
        log_error "Please install: Node.js v18+, npm"
        exit 1
    fi
    
    log_info "Prerequisites OK"
}

# Check if directory has node dependencies
has_node_deps() {
    local dir="$1"
    [ -f "$dir/package.json" ]
}

# Check if dependencies are installed
deps_installed() {
    local dir="$1"
    [ -d "$dir/node_modules" ]
}

# Install dependencies for a circuit
install_deps() {
    local name="$1"
    local dir="$2"
    
    if ! has_node_deps "$dir"; then
        return 0
    fi
    
    if deps_installed "$dir"; then
        log_info "[$name] Dependencies already installed"
        return 0
    fi
    
    if $CHECK_ONLY; then
        log_warn "[$name] Dependencies missing: $dir"
        return 1
    fi
    
    log_info "[$name] Installing dependencies..."
    if ! (cd "$dir" && npm install --legacy-peer-deps 2>&1); then
        log_warn "[$name] npm install failed, trying with --force"
        if ! (cd "$dir" && npm install --force 2>&1); then
            log_error "[$name] Failed to install dependencies"
            return 1
        fi
    fi
    
    if [ ! -d "$dir/node_modules" ]; then
        log_error "[$name] node_modules directory not created after install"
        return 1
    fi
    
    log_info "[$name] Dependencies installed successfully"
}

# Compile a circuit
compile_circuit() {
    local name="$1"
    local circom_file="$2"
    local output_dir="$3"
    
    if [ ! -f "$circom_file" ]; then
        log_warn "[$name] Circuit file not found: $circom_file"
        return 1
    fi
    
    local circuit_dir=$(dirname "$circom_file")
    
    # Check for circomlib dependency
    if ! [ -d "$circuit_dir/node_modules/circomlib" ]; then
        if [ -d "$circuit_dir/../node_modules/circomlib" ]; then
            log_info "[$name] Using parent circomlib"
        else
            log_warn "[$name] circomlib not found, may fail to compile"
        fi
    fi
    
    log_info "[$name] Compiling: $circom_file"
    mkdir -p "$output_dir"
    
    if command -v circom &> /dev/null; then
        circom "$circom_file" --r1cs --sym -o "$output_dir" 2>&1 || {
            log_warn "[$name] Compilation failed"
            return 1
        }
    else
        npx circom "$circom_file" --r1cs --sym -o "$output_dir" 2>&1 || {
            log_warn "[$name] Compilation with npx failed"
            return 1
        }
    fi
    
    log_info "[$name] Compiled successfully to $output_dir"
}

# Process circuits
process_circuits() {
    local circuits=(
        "tornado-core:cat3_privacy/tornado-core"
        "semaphore:cat3_privacy/semaphore"
        "railgun:cat3_privacy/railgun-contract"
        "aztec:cat3_privacy/aztec-packages"
        "email-wallet:cat3_privacy/email-wallet"
    )
    
    local success=0
    local failed=0
    local skipped=0
    
    for circuit_entry in "${circuits[@]}"; do
        local name="${circuit_entry%%:*}"
        local path="${circuit_entry#*:}"
        local full_path="$ZK0D_BASE/$path"
        
        # Apply filter if specified
        if [ -n "$CIRCUIT_FILTER" ] && [ "$name" != "$CIRCUIT_FILTER" ]; then
            continue
        fi
        
        if [ ! -d "$full_path" ]; then
            log_warn "[$name] Directory not found: $full_path"
            ((skipped++))
            continue
        fi
        
        if install_deps "$name" "$full_path"; then
            ((success++))
        else
            ((failed++))
        fi
        
        # Check for nested packages (monorepo structure)
        if [ -d "$full_path/packages" ]; then
            for pkg in "$full_path/packages"/*; do
                if [ -d "$pkg" ]; then
                    local pkg_name="$name/$(basename "$pkg")"
                    if install_deps "$pkg_name" "$pkg"; then
                        ((success++))
                    else
                        ((failed++))
                    fi
                fi
            done
        fi
    done
    
    echo ""
    log_info "=== Summary ==="
    log_info "Success: $success"
    log_info "Failed: $failed"
    log_info "Skipped: $skipped"
    
    if [ $failed -gt 0 ]; then
        return 1
    fi
}

# Install global tools
install_global_tools() {
    if $CHECK_ONLY; then
        return 0
    fi
    
    log_info "Checking global tools..."
    
    if ! command -v circom &> /dev/null; then
        log_info "Installing circom globally..."
        npm install -g circom@latest 2>&1 || log_warn "Failed to install circom globally"
    fi
    
    if ! command -v snarkjs &> /dev/null; then
        log_info "Installing snarkjs globally..."
        npm install -g snarkjs@latest 2>&1 || log_warn "Failed to install snarkjs globally"
    fi
}

# Main
main() {
    echo "========================================"
    echo "  ZK Circuit Dependency Resolver"
    echo "========================================"
    echo ""
    
    if [ ! -d "$ZK0D_BASE" ]; then
        log_error "zk0d collection not found at: $ZK0D_BASE"
        log_error "Set ZK0D_BASE environment variable to the correct path"
        exit 1
    fi
    
    check_prerequisites
    install_global_tools
    process_circuits
}

main
