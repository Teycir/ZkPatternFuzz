#!/bin/bash
set -e

echo "=== Installing Cairo 2.x Backend ==="

# Detect architecture
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

if [ "$ARCH" = "x86_64" ]; then
    ARCH_NAME="x86_64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH_NAME="aarch64"
else
    echo "❌ Unsupported architecture: $ARCH"
    exit 1
fi

echo "Detected: $OS-$ARCH_NAME"

# Install Scarb (Cairo package manager)
echo ""
echo "📦 Installing Scarb (Cairo 2.x toolchain)..."
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh

# Add to PATH for current session
export PATH="$HOME/.local/bin:$PATH"

# Verify installation
echo ""
echo "✅ Verifying Scarb installation..."
if command -v scarb &> /dev/null; then
    scarb --version
else
    echo "⚠️  Scarb not in PATH. Add this to ~/.bashrc:"
    echo 'export PATH="$HOME/.local/bin:$PATH"'
    exit 1
fi

# Install Cairo 2.x directly (optional, Scarb includes it)
echo ""
echo "📦 Installing Cairo 2.x compiler..."
CAIRO_VERSION="2.6.3"
CAIRO_URL="https://github.com/starkware-libs/cairo/releases/download/v${CAIRO_VERSION}/cairo-${CAIRO_VERSION}-${ARCH_NAME}-unknown-${OS}-gnu.tar.gz"

cd /tmp
curl -L "$CAIRO_URL" -o cairo.tar.gz
tar xzf cairo.tar.gz
sudo mv "cairo-${CAIRO_VERSION}-${ARCH_NAME}-unknown-${OS}-gnu/bin/"* /usr/local/bin/ 2>/dev/null || {
    echo "⚠️  Sudo failed, installing to ~/.local/bin"
    mkdir -p ~/.local/bin
    mv "cairo-${CAIRO_VERSION}-${ARCH_NAME}-unknown-${OS}-gnu/bin/"* ~/.local/bin/
}
rm -rf cairo.tar.gz "cairo-${CAIRO_VERSION}-${ARCH_NAME}-unknown-${OS}-gnu"

# Verify Cairo
echo ""
echo "✅ Verifying Cairo installation..."
cairo-compile --version || echo "⚠️  Cairo not in PATH"

# Test with a simple Cairo program
echo ""
echo "🧪 Testing Cairo backend..."
cat > /tmp/test.cairo << 'EOF'
fn main() -> felt252 {
    42
}
EOF

if scarb cairo-run /tmp/test.cairo 2>/dev/null; then
    echo "✅ Cairo backend working!"
else
    echo "⚠️  Cairo test failed (may need project setup)"
fi

rm -f /tmp/test.cairo

echo ""
echo "=== Cairo 2.x Installation Complete ==="
echo ""
echo "📝 Add to ~/.bashrc if not already present:"
echo 'export PATH="$HOME/.local/bin:$PATH"'
echo ""
echo "🔄 Reload shell: source ~/.bashrc"
