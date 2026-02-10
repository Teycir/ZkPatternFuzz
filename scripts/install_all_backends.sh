#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║     ZkPatternFuzz Backend Installation Suite          ║"
echo "║     Installing Cairo 2.x + Halo2                       ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check prerequisites
echo "🔍 Checking prerequisites..."
command -v curl >/dev/null 2>&1 || { echo "❌ curl not found. Install: sudo apt install curl"; exit 1; }
command -v git >/dev/null 2>&1 || { echo "❌ git not found. Install: sudo apt install git"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "❌ cargo not found. Install Rust first"; exit 1; }
echo "✅ Prerequisites OK"
echo ""

# 1. Install Cairo
echo "════════════════════════════════════════════════════════"
echo "  Step 1/2: Installing Cairo 2.x"
echo "════════════════════════════════════════════════════════"
bash "$SCRIPT_DIR/install_cairo.sh"
echo ""

# 2. Install Halo2
echo "════════════════════════════════════════════════════════"
echo "  Step 2/2: Installing Halo2 Circuits"
echo "════════════════════════════════════════════════════════"
bash "$SCRIPT_DIR/install_halo2.sh"
echo ""

# 3. Verify all backends
echo "════════════════════════════════════════════════════════"
echo "  Final Verification"
echo "════════════════════════════════════════════════════════"
echo ""

check_backend() {
    local name=$1
    local cmd=$2
    local expected=$3
    
    echo -n "  $name: "
    if command -v "$cmd" >/dev/null 2>&1; then
        version=$($cmd --version 2>&1 | head -1)
        if echo "$version" | grep -q "$expected"; then
            echo "✅ $version"
            return 0
        else
            echo "⚠️  $version (expected $expected)"
            return 1
        fi
    else
        echo "❌ Not found"
        return 1
    fi
}

echo "Backend Status:"
check_backend "Circom" "circom" "2\."
check_backend "Noir" "nargo" "1\."
check_backend "Cairo" "scarb" "2\." || check_backend "Cairo" "cairo-compile" "2\."

echo ""
echo -n "  Halo2: "
if [ -d "/media/elements/Repos/zk0d/cat3_privacy/halo2-test-circuits" ]; then
    echo "✅ Test circuits available"
else
    echo "❌ Test circuits not found"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Installation Complete!"
echo "════════════════════════════════════════════════════════"
echo ""
echo "📝 Next Steps:"
echo ""
echo "1. Reload your shell:"
echo "   source ~/.bashrc"
echo ""
echo "2. Test ZkPatternFuzz backends:"
echo "   cd /home/teycir/Repos/ZkPatternFuzz"
echo "   cargo test --package zk-backends --lib"
echo ""
echo "3. Run full backend verification:"
echo "   bash scripts/verify_backends.sh"
echo ""
echo "4. Start fuzzing with all backends:"
echo "   cargo run --release --features all-backends -- --config <campaign.yaml>"
echo ""
