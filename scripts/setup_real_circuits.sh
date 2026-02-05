#!/bin/bash
# Setup Real ZK Circuits for Integration Testing
#
# This script compiles real-world ZK circuits for testing with ZkPatternFuzz.
# It uses circuits from the zk0d collection at /media/elements/Repos/zk0d
#
# Prerequisites:
#   - Node.js v18+ 
#   - npm
#   - circom compiler (installed globally or via npm)
#
# Usage:
#   ./scripts/setup_real_circuits.sh

set -euo pipefail

ZK0D_BASE="${ZK0D_BASE:-/media/elements/Repos/zk0d}"
OUTPUT_DIR="./circuits/compiled"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v node &> /dev/null; then
        log_error "Node.js is not installed. Please install Node.js v18+"
        exit 1
    fi
    
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        log_warn "Node.js version $NODE_VERSION detected. Recommend v18+"
    fi
    
    if ! command -v npm &> /dev/null; then
        log_error "npm is not installed"
        exit 1
    fi
    
    # Check for circom
    if command -v circom &> /dev/null; then
        CIRCOM_VERSION=$(circom --version 2>/dev/null || echo "unknown")
        log_info "Found circom: $CIRCOM_VERSION"
    else
        log_warn "circom not found globally, will use npx"
    fi
    
    log_info "Prerequisites check passed"
}

# Create output directory
setup_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    log_info "Output directory: $OUTPUT_DIR"
}

# Compile a single circuit
compile_circuit() {
    local name="$1"
    local circom_path="$2"
    local output_subdir="$OUTPUT_DIR/$name"
    
    log_info "Compiling $name..."
    
    if [ ! -f "$circom_path" ]; then
        log_warn "Circuit file not found: $circom_path"
        return 1
    fi
    
    mkdir -p "$output_subdir"
    
    # Try to compile with circom
    if command -v circom &> /dev/null; then
        circom "$circom_path" --r1cs --sym -o "$output_subdir" 2>&1 || {
            log_warn "Failed to compile $name with global circom"
            return 1
        }
    else
        npx circom "$circom_path" --r1cs --sym -o "$output_subdir" 2>&1 || {
            log_warn "Failed to compile $name with npx circom"
            return 1
        }
    fi
    
    log_info "✓ Compiled $name"
    return 0
}

# Compile snarkjs test circuits (already compiled, just copy)
setup_snarkjs_circuits() {
    log_info "Setting up snarkjs test circuits..."
    
    local snarkjs_test="$ZK0D_BASE/cat5_frameworks/snarkjs/test"
    
    if [ ! -d "$snarkjs_test" ]; then
        log_warn "snarkjs test directory not found at $snarkjs_test"
        return
    fi
    
    # Copy pre-compiled circuits
    for circuit_dir in "$snarkjs_test"/*/; do
        local circuit_name=$(basename "$circuit_dir")
        local r1cs_file="$circuit_dir/circuit.r1cs"
        
        if [ -f "$r1cs_file" ]; then
            mkdir -p "$OUTPUT_DIR/snarkjs_$circuit_name"
            cp "$r1cs_file" "$OUTPUT_DIR/snarkjs_$circuit_name/"
            
            if [ -f "$circuit_dir/circuit.sym" ]; then
                cp "$circuit_dir/circuit.sym" "$OUTPUT_DIR/snarkjs_$circuit_name/"
            fi
            
            log_info "✓ Copied snarkjs $circuit_name"
        fi
    done
}

# Setup Tornado Cash circuits
setup_tornado_circuits() {
    log_info "Setting up Tornado Cash circuits..."
    
    local tornado_dir="$ZK0D_BASE/cat3_privacy/tornado-core"
    
    if [ ! -d "$tornado_dir" ]; then
        log_warn "Tornado Cash directory not found at $tornado_dir"
        return
    fi
    
    # Check if node_modules exists
    if [ ! -d "$tornado_dir/node_modules" ]; then
        log_info "Installing Tornado Cash dependencies..."
        (cd "$tornado_dir" && npm install --legacy-peer-deps 2>&1 | tail -5) || {
            log_warn "Failed to install Tornado dependencies"
            return
        }
    fi
    
    # Compile circuits
    for circuit in "$tornado_dir/circuits"/*.circom; do
        local circuit_name=$(basename "$circuit" .circom)
        compile_circuit "tornado_$circuit_name" "$circuit" || true
    done
}

# Setup Semaphore circuits  
setup_semaphore_circuits() {
    log_info "Setting up Semaphore circuits..."
    
    local semaphore_dir="$ZK0D_BASE/cat3_privacy/semaphore"
    
    if [ ! -d "$semaphore_dir" ]; then
        log_warn "Semaphore directory not found at $semaphore_dir"
        return
    fi
    
    # Find semaphore.circom
    local semaphore_circuit="$semaphore_dir/packages/circuits/src/semaphore.circom"
    
    if [ -f "$semaphore_circuit" ]; then
        compile_circuit "semaphore" "$semaphore_circuit" || true
    else
        log_warn "Semaphore circuit not found at $semaphore_circuit"
    fi
}

# Setup Iden3 circuits
setup_iden3_circuits() {
    log_info "Setting up Iden3 circuits..."
    
    local iden3_dir="$ZK0D_BASE/cat3_privacy/circuits"
    
    if [ ! -d "$iden3_dir" ]; then
        log_warn "Iden3 circuits directory not found at $iden3_dir"
        return
    fi
    
    # Install dependencies
    if [ ! -d "$iden3_dir/node_modules" ]; then
        log_info "Installing Iden3 dependencies..."
        (cd "$iden3_dir" && npm install --legacy-peer-deps 2>&1 | tail -5) || {
            log_warn "Failed to install Iden3 dependencies"
            return
        }
    fi
    
    # Compile main circuits
    for circuit in "$iden3_dir/circuits"/*.circom; do
        local circuit_name=$(basename "$circuit" .circom)
        # Skip template circuits (those with parameters)
        if [[ "$circuit_name" != *"-"* ]]; then
            compile_circuit "iden3_$circuit_name" "$circuit" || true
        fi
    done
}

# Generate summary
print_summary() {
    echo ""
    log_info "========== COMPILATION SUMMARY =========="
    
    if [ -d "$OUTPUT_DIR" ]; then
        local count=$(find "$OUTPUT_DIR" -name "*.r1cs" | wc -l)
        log_info "Total R1CS files compiled: $count"
        
        echo ""
        echo "Compiled circuits:"
        for r1cs in "$OUTPUT_DIR"/*/*.r1cs; do
            if [ -f "$r1cs" ]; then
                local size=$(stat -c%s "$r1cs" 2>/dev/null || stat -f%z "$r1cs" 2>/dev/null)
                local name=$(dirname "$r1cs" | xargs basename)
                printf "  %-30s %10d bytes\n" "$name" "$size"
            fi
        done
    else
        log_warn "No circuits compiled"
    fi
    
    echo ""
    log_info "Run tests with: cargo test --test real_circuit_integration"
}

# Main
main() {
    echo "================================================="
    echo "   ZkPatternFuzz Real Circuit Setup"
    echo "================================================="
    echo ""
    
    check_prerequisites
    setup_output_dir
    
    # Setup circuits from zk0d collection
    setup_snarkjs_circuits
    setup_tornado_circuits
    setup_semaphore_circuits
    setup_iden3_circuits
    
    print_summary
}

main "$@"
