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
SUBMODULE_BASE="${SUBMODULE_BASE:-./circuits/real}"
OUTPUT_DIR="./circuits/compiled"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TORNADO_BASE_OVERRIDE="${TORNADO_BASE:-}"
SEMAPHORE_BASE_OVERRIDE="${SEMAPHORE_BASE:-}"
IDEN3_BASE_OVERRIDE="${IDEN3_BASE:-}"
ZKEVM_BASE_OVERRIDE="${ZKEVM_BASE:-}"
SNARKJS_BASE_OVERRIDE="${SNARKJS_BASE:-}"

SOURCE_MODE="${SOURCE_MODE:-auto}" # auto|zk0d|submodules
LINK_MODE=false
SKIP_COMPILE=false
INIT_SUBMODULES=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

append_unique_root() {
    local root="$1"
    local existing

    if [ -z "$root" ]; then
        return
    fi

    for existing in "${include_roots[@]}"; do
        if [ "$existing" = "$root" ]; then
            return
        fi
    done

    include_roots+=("$root")
}

add_circomlib_root() {
    local root="$1"

    if [ -z "$root" ] || [ ! -d "$root" ]; then
        return
    fi

    if [ -d "$root/circomlib/circuits" ]; then
        append_unique_root "$root"
        return
    fi

    if [ "$(basename "$root")" = "circomlib" ] && [ -d "$root/circuits" ]; then
        append_unique_root "$(dirname "$root")"
        append_unique_root "$root"
    fi
}

usage() {
    cat << EOF
Usage: ./scripts/setup_real_circuits.sh [options]

Options:
  --source <auto|zk0d|submodules>  Select circuit source (default: auto)
  --link                           Symlink sources into ./circuits (default: copy)
  --skip-compile                   Skip circom compilation (stage sources only)
  --init-submodules                Run git submodule update --init --recursive
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --source) SOURCE_MODE="$2"; shift 2 ;;
            --link) LINK_MODE=true; shift ;;
            --skip-compile) SKIP_COMPILE=true; shift ;;
            --init-submodules) INIT_SUBMODULES=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) log_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

resolve_source_mode() {
    local mode="$SOURCE_MODE"

    if [ "$mode" = "auto" ]; then
        if [ -d "$ZK0D_BASE" ]; then
            mode="zk0d"
        elif [ -d "$SUBMODULE_BASE/tornado-core" ] || [ -d "$SUBMODULE_BASE/semaphore" ]; then
            mode="submodules"
        else
            log_error "No circuit sources found."
            log_error "Expected zk0d at $ZK0D_BASE or submodules under $SUBMODULE_BASE"
            exit 1
        fi
    fi

    if [ "$mode" = "zk0d" ]; then
        log_info "Using zk0d dataset at $ZK0D_BASE"
        SNARKJS_BASE="$ZK0D_BASE/cat5_frameworks/snarkjs/test"
        TORNADO_BASE="$ZK0D_BASE/cat3_privacy/tornado-core"
        SEMAPHORE_BASE="$ZK0D_BASE/cat3_privacy/semaphore"
        IDEN3_BASE="$ZK0D_BASE/cat3_privacy/circuits"
        ZKEVM_BASE="$ZK0D_BASE/cat2_rollups/zkevm-circuits"
    elif [ "$mode" = "submodules" ]; then
        log_info "Using submodules under $SUBMODULE_BASE"
        SNARKJS_BASE=""
        TORNADO_BASE="$SUBMODULE_BASE/tornado-core"
        SEMAPHORE_BASE="$SUBMODULE_BASE/semaphore"
        IDEN3_BASE="$SUBMODULE_BASE/iden3-auth"
        ZKEVM_BASE="$SUBMODULE_BASE/zkevm-circuits"
    else
        log_error "Invalid --source value: $mode"
        exit 1
    fi

    if [ -n "$SNARKJS_BASE_OVERRIDE" ]; then
        log_info "Overriding SNARKJS_BASE: $SNARKJS_BASE_OVERRIDE"
        SNARKJS_BASE="$SNARKJS_BASE_OVERRIDE"
    fi

    if [ -n "$TORNADO_BASE_OVERRIDE" ]; then
        log_info "Overriding TORNADO_BASE: $TORNADO_BASE_OVERRIDE"
        TORNADO_BASE="$TORNADO_BASE_OVERRIDE"
    fi

    if [ -n "$SEMAPHORE_BASE_OVERRIDE" ]; then
        log_info "Overriding SEMAPHORE_BASE: $SEMAPHORE_BASE_OVERRIDE"
        SEMAPHORE_BASE="$SEMAPHORE_BASE_OVERRIDE"
    fi

    if [ -n "$IDEN3_BASE_OVERRIDE" ]; then
        log_info "Overriding IDEN3_BASE: $IDEN3_BASE_OVERRIDE"
        IDEN3_BASE="$IDEN3_BASE_OVERRIDE"
    fi

    if [ -n "$ZKEVM_BASE_OVERRIDE" ]; then
        log_info "Overriding ZKEVM_BASE: $ZKEVM_BASE_OVERRIDE"
        ZKEVM_BASE="$ZKEVM_BASE_OVERRIDE"
    fi
}

init_submodules() {
    if ! $INIT_SUBMODULES; then
        return 0
    fi

    log_info "Initializing git submodules..."
    git submodule update --init --recursive
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v node &> /dev/null; then
        log_error "Node.js is not installed. Please install Node.js v18+"
        exit 1
    fi
    
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ -z "$NODE_VERSION" ] || [ "$NODE_VERSION" -lt 18 ]; then
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

stage_file() {
    local source="$1"
    local target="$2"

    if [ ! -f "$source" ]; then
        log_warn "Source not found: $source"
        return 1
    fi

    mkdir -p "$(dirname "$target")"

    if $LINK_MODE; then
        ln -sf "$source" "$target"
    else
        cp "$source" "$target"
    fi

    log_info "Staged: $target"
}

stage_dir() {
    local source="$1"
    local target="$2"

    if [ ! -d "$source" ]; then
        log_warn "Source directory not found: $source"
        return 1
    fi

    if $LINK_MODE; then
        ln -sfn "$source" "$target"
    else
        rm -rf "$target"
        cp -R "$source" "$target"
    fi

    log_info "Staged directory: $target"
}

# Compile a single circuit
compile_circuit() {
    local name="$1"
    local circom_path="$2"
    local output_subdir="$OUTPUT_DIR/$name"
    local -a include_roots=()
    local -a include_args=()
    
    log_info "Compiling $name..."
    
    if [ ! -f "$circom_path" ]; then
        log_warn "Circuit file not found: $circom_path"
        return 1
    fi
    
    mkdir -p "$output_subdir"

    add_circomlib_root "$PROJECT_ROOT/third_party"
    add_circomlib_root "$PROJECT_ROOT/node_modules"
    add_circomlib_root "$ZK0D_BASE/cat3_privacy/circuits/node_modules"
    add_circomlib_root "$TORNADO_BASE/node_modules"
    add_circomlib_root "$SEMAPHORE_BASE/node_modules"
    add_circomlib_root "$IDEN3_BASE/node_modules"

    if [ -n "$circom_path" ]; then
        local circuit_dir
        circuit_dir="$(cd "$(dirname "$circom_path")" && pwd)"
        while [ "$circuit_dir" != "/" ]; do
            if [ -d "$circuit_dir/node_modules/circomlib/circuits" ]; then
                add_circomlib_root "$circuit_dir/node_modules"
                break
            fi
            circuit_dir="$(dirname "$circuit_dir")"
        done
    fi

    for root in "${include_roots[@]}"; do
        include_args+=("-l" "$root")
    done

    # Try to compile with circom
    if command -v circom &> /dev/null; then
        if ! circom "$circom_path" --r1cs --sym -o "$output_subdir" "${include_args[@]}" 2>&1 | tee "$output_subdir/compile.log"; then
            log_warn "Failed to compile $name with global circom (see $output_subdir/compile.log)"
            return 1
        fi
    else
        if ! npx circom "$circom_path" --r1cs --sym -o "$output_subdir" "${include_args[@]}" 2>&1 | tee "$output_subdir/compile.log"; then
            log_warn "Failed to compile $name with npx circom (see $output_subdir/compile.log)"
            return 1
        fi
    fi
    
    log_info "✓ Compiled $name"
    return 0
}

# Compile snarkjs test circuits (already compiled, just copy)
setup_snarkjs_circuits() {
    log_info "Setting up snarkjs test circuits..."
    
    if [ -z "${SNARKJS_BASE:-}" ]; then
        log_warn "snarkjs base not available for selected source"
        return
    fi

    local snarkjs_test="$SNARKJS_BASE"
    
    if [ ! -d "$snarkjs_test" ]; then
        log_warn "snarkjs test directory not found at $snarkjs_test"
        return
    fi
    
    # Copy pre-compiled circuits
    for circuit_dir in "$snarkjs_test"/*/; do
        [ -d "$circuit_dir" ] || continue
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
    
    local tornado_dir="$TORNADO_BASE"
    
    if [ ! -d "$tornado_dir" ]; then
        log_warn "Tornado Cash directory not found at $tornado_dir"
        return
    fi
    
    # Check if node_modules exists
    if ! $SKIP_COMPILE && [ ! -d "$tornado_dir/node_modules" ]; then
        log_info "Installing Tornado Cash dependencies..."
        (cd "$tornado_dir" && npm install --legacy-peer-deps 2>&1 | tail -5) || {
            log_warn "Failed to install Tornado dependencies"
            return
        }
    fi
    
    # Compile circuits
    for circuit in "$tornado_dir/circuits"/*.circom; do
        [ -f "$circuit" ] || continue
        local circuit_name=$(basename "$circuit" .circom)
        if ! $SKIP_COMPILE; then
            compile_circuit "tornado_$circuit_name" "$circuit" || true
        fi
    done

    # Stage withdraw circuit for campaign configs
    local withdraw_circuit="$tornado_dir/circuits/withdraw.circom"
    stage_file "$withdraw_circuit" "./circuits/withdraw.circom" || true
}

# Setup Semaphore circuits  
setup_semaphore_circuits() {
    log_info "Setting up Semaphore circuits..."
    
    local semaphore_dir="$SEMAPHORE_BASE"
    
    if [ ! -d "$semaphore_dir" ]; then
        log_warn "Semaphore directory not found at $semaphore_dir"
        return
    fi
    
    # Find semaphore.circom
    local semaphore_circuit="$semaphore_dir/packages/circuits/src/semaphore.circom"
    
    if [ -f "$semaphore_circuit" ]; then
        if ! $SKIP_COMPILE; then
            compile_circuit "semaphore" "$semaphore_circuit" || true
        fi
        stage_file "$semaphore_circuit" "./circuits/semaphore.circom" || true
    else
        log_warn "Semaphore circuit not found at $semaphore_circuit"
    fi
}

# Setup Iden3 circuits
setup_iden3_circuits() {
    log_info "Setting up Iden3 circuits..."
    
    local iden3_dir="$IDEN3_BASE"
    
    if [ ! -d "$iden3_dir" ]; then
        log_warn "Iden3 circuits directory not found at $iden3_dir"
        return
    fi
    
    # Install dependencies
    if ! $SKIP_COMPILE && [ ! -d "$iden3_dir/node_modules" ]; then
        log_info "Installing Iden3 dependencies..."
        (cd "$iden3_dir" && npm install --legacy-peer-deps 2>&1 | tail -5) || {
            log_warn "Failed to install Iden3 dependencies"
            return
        }
    fi
    
    # Compile main circuits
    for circuit in "$iden3_dir/circuits"/*.circom; do
        [ -f "$circuit" ] || continue
        local circuit_name=$(basename "$circuit" .circom)
        # Skip template circuits (those with parameters)
        if [[ "$circuit_name" != *"-"* ]]; then
            if ! $SKIP_COMPILE; then
                compile_circuit "iden3_$circuit_name" "$circuit" || true
            fi
        fi
    done

    # Stage auth circuit for campaign configs
    local auth_circuit
    auth_circuit=$(find "$iden3_dir" -name "authV3.circom" 2>/dev/null | head -n1 || true)
    if [ -n "$auth_circuit" ]; then
        stage_file "$auth_circuit" "./circuits/auth/authV3.circom" || true
    else
        log_warn "authV3.circom not found under $iden3_dir"
    fi
}

setup_zkevm_circuits() {
    log_info "Setting up zkEVM circuits..."

    local zkevm_dir="$ZKEVM_BASE"
    if [ -z "${zkevm_dir:-}" ] || [ ! -d "$zkevm_dir" ]; then
        log_warn "zkEVM circuits directory not found at ${zkevm_dir:-<unset>}"
        return
    fi

    stage_dir "$zkevm_dir" "./circuits/zkevm-circuits" || true
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
            [ -f "$r1cs" ] || continue
            local size=$(stat -c%s "$r1cs" 2>/dev/null || stat -f%z "$r1cs" 2>/dev/null)
            local name=$(dirname "$r1cs" | xargs basename)
            printf "  %-30s %10d bytes\n" "$name" "$size"
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
    
    parse_args "$@"
    resolve_source_mode
    init_submodules

    if ! $SKIP_COMPILE; then
        check_prerequisites
    fi

    setup_output_dir
    
    # Setup circuits from zk0d collection
    setup_snarkjs_circuits
    setup_tornado_circuits
    setup_semaphore_circuits
    setup_iden3_circuits
    setup_zkevm_circuits
    
    print_summary
}

main "$@"
