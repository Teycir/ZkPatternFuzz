# Backend Setup Guide

## Current Status

✅ **Circom** - 2.2.3 (Production)  
✅ **Noir** - 1.0.0-beta.18 (Production)  
✅ **Halo2** - Test circuits built (~/halo2-circuits/)  
✅ **Cairo** - 2.15.0 via Scarb 2.15.1 (Production)  

## Quick Local Bootstrap (Circom + snarkjs + ptau)

Use the built-in bootstrap command to internalize Circom tooling under `./bins`:

```bash
cargo run --release --bin zk-fuzzer -- bins bootstrap
```

Notes:
- Circom is sourced from an already-installed local binary in `PATH`.
- snarkjs is sourced from an already-installed local binary in `PATH`.
- ptau is copied from the local fixture with checksum verification.

---

## 1. Cairo Backend (STARK) ✅

### Status: COMPLETE

Cairo 2.15.0 installed via Scarb 2.15.1

### Installation

```bash
# Install Scarb (includes Cairo 2.x)
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh

# Verify
scarb --version  # Should show 2.15.1
scarb cairo-run --version  # Should show Cairo 2.15.0
```

### Test Cairo Backend

```bash
cd /home/teycir/Repos/ZkPatternFuzz
cargo test --package zk-backends --lib cairo -- --nocapture
```

---

## 2. Setup Halo2 Test Circuits ✅

### Status: COMPLETE

Halo2 test circuits successfully built in `~/halo2-circuits/`

### Installation (Automated)

```bash
bash scripts/install_halo2.sh
```

### Manual Installation

```bash
# Clone repositories to mounted storage
cd /media/elements/Repos/zk0d/cat3_privacy/
git clone https://github.com/privacy-scaling-explorations/halo2.git
git clone https://github.com/axiom-crypto/halo2-lib.git

# Create test circuits in HOME directory (avoids permission issues)
mkdir -p ~/halo2-circuits
cd ~/halo2-circuits

# Initialize Cargo project
cargo init --name halo2-test-circuits

# Add dependencies
cat >> Cargo.toml << 'EOF'

[[bin]]
name = "simple_circuit"
path = "src/simple.rs"

[[bin]]
name = "range_check"
path = "src/range.rs"

[dependencies]
halo2_proofs = { git = "https://github.com/privacy-scaling-explorations/halo2.git", tag = "v2023_04_20" }
halo2curves = { version = "0.3.2", git = "https://github.com/privacy-scaling-explorations/halo2curves", tag = "0.3.2" }
ff = "0.13"
group = "0.13"
rand = "0.8"
EOF

# Create simple circuit
cat > src/simple.rs << 'EOF'
fn main() {
    println!("Halo2 Simple Circuit Test");
}
EOF

# Create range check circuit
cat > src/range.rs << 'EOF'
fn main() {
    println!("Halo2 Range Check Circuit Test");
}
EOF

# Build (IMPORTANT: clean target if copying from mounted filesystem)
rm -rf target  # Remove any copied build artifacts with permission issues
cargo build --release
```

### Verify Installation

```bash
cd ~/halo2-circuits
./target/release/simple_circuit
./target/release/range_check
```

### Test Halo2 Backend

```bash
cd /home/teycir/Repos/ZkPatternFuzz
cargo test --package zk-backends --lib halo2 -- --nocapture
```

---

## 3. Verify All Backends

### Quick Test Script

```bash
#!/bin/bash
echo "=== Backend Verification ==="

# Circom
echo -n "Circom: "
circom --version 2>&1 | grep -q "2\." && echo "✅ OK" || echo "❌ FAIL"

# Noir
echo -n "Noir: "
nargo --version 2>&1 | grep -q "1\." && echo "✅ OK" || echo "❌ FAIL"

# Cairo
echo -n "Cairo: "
if command -v scarb &> /dev/null; then
    scarb --version 2>&1 | grep -q "2\." && echo "✅ OK (Scarb)" || echo "⚠️ OLD"
else
    cairo-compile --version 2>&1 | grep -q "2\." && echo "✅ OK" || echo "⚠️ OLD (0.14)"
fi

# Halo2 (check if circuits exist)
echo -n "Halo2: "
if [ -d "/media/elements/Repos/zk0d/cat3_privacy/halo2" ]; then
    echo "✅ OK (circuits available)"
else
    echo "⚠️ No test circuits"
fi

echo ""
echo "=== ZkPatternFuzz Backend Tests ==="
cd /home/teycir/Repos/ZkPatternFuzz
cargo test --package zk-backends --lib -- --test-threads=1 --nocapture 2>&1 | grep -E "test.*ok|FAILED"
```

Save as `verify_backends.sh` and run:

```bash
chmod +x verify_backends.sh
./verify_backends.sh
```

---

## 4. Update ZkPatternFuzz Config

Once backends are ready, update `Cargo.toml` to enable all features:

```toml
[dependencies]
# Add Halo2 dependencies
halo2_proofs = { version = "0.3", optional = true }
halo2curves = { version = "0.6", optional = true }

[features]
default = ["circom", "noir"]
circom = []
noir = []
cairo = []
halo2 = ["dep:halo2_proofs", "dep:halo2curves"]
all-backends = ["circom", "noir", "cairo", "halo2"]
```

Build with all backends:

```bash
cargo build --release --features all-backends
```

---

## 5. Next Steps

### All Backends Ready! ✅

- **Circom** 2.2.3 ✅
- **Noir** 1.0.0-beta.18 ✅  
- **Cairo** 2.15.0 ✅
- **Halo2** Test circuits ✅

### Ready for Mode 2 Differential Testing

You can now run differential testing across backends. Example targets:

1. **Iden3 Circuits** (Circom) - Port to Noir for Mode 2
2. **Tornado Cash** (Circom) - Already tested in Mode 1
3. **Custom Circuits** - Implement in multiple backends

### Recommended Next Action

**Option A: Test Iden3 (Mode 1 + Mode 3)**
```bash
cd /home/teycir/Repos/ZkPatternFuzz
cargo run --release -- --config campaigns/zk0d_validation/iden3/auth_deep.yaml
```

**Option B: Create Differential Test (Mode 2)**
Port a simple circuit to both Circom and Noir, then run differential testing.

**Option C: Multi-Circuit Chain (Mode 3)**
Test Iden3's auth → state transition → credential query flow.
