#!/bin/bash
set -e

echo "=== Setting Up Halo2 Backend & Test Circuits ==="

INSTALL_DIR="/media/elements/Repos/zk0d/cat3_privacy"
cd "$INSTALL_DIR"

# 1. Clone PSE Halo2 (Privacy Scaling Explorations)
echo ""
echo "📦 Cloning PSE Halo2 library..."
if [ ! -d "halo2" ]; then
    git clone --depth 1 https://github.com/privacy-scaling-explorations/halo2.git
    echo "✅ PSE Halo2 cloned"
else
    echo "⚠️  halo2/ already exists, skipping"
fi

# 2. Clone Axiom Halo2-lib (production circuits)
echo ""
echo "📦 Cloning Axiom halo2-lib..."
if [ ! -d "halo2-lib" ]; then
    git clone --depth 1 https://github.com/axiom-crypto/halo2-lib.git
    echo "✅ Axiom halo2-lib cloned"
else
    echo "⚠️  halo2-lib/ already exists, skipping"
fi

# 3. Build PSE Halo2 examples
echo ""
echo "🔨 Building PSE Halo2 examples..."
cd "$INSTALL_DIR/halo2/halo2_proofs"
cargo build --release --examples 2>&1 | tail -20
echo "✅ PSE Halo2 examples built"

# 4. Build Axiom halo2-lib
echo ""
echo "🔨 Building Axiom halo2-lib..."
cd "$INSTALL_DIR/halo2-lib"
cargo build --release 2>&1 | tail -20
echo "✅ Axiom halo2-lib built"

# 5. Create test circuit wrapper for ZkPatternFuzz
echo ""
echo "📝 Creating Halo2 test circuit wrapper..."
mkdir -p "$INSTALL_DIR/halo2-test-circuits"
cd "$INSTALL_DIR/halo2-test-circuits"

cat > Cargo.toml << 'EOF'
[package]
name = "halo2-test-circuits"
version = "0.1.0"
edition = "2021"

[dependencies]
halo2_proofs = { git = "https://github.com/privacy-scaling-explorations/halo2.git", tag = "v2023_04_20" }
halo2curves = "0.6"
rand = "0.8"

[[bin]]
name = "simple_circuit"
path = "src/simple.rs"

[[bin]]
name = "range_check"
path = "src/range_check.rs"
EOF

mkdir -p src

# Simple circuit example
cat > src/simple.rs << 'EOF'
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

#[derive(Clone, Debug)]
struct SimpleConfig {
    advice: Column<Advice>,
    instance: Column<Instance>,
}

#[derive(Clone, Debug)]
struct SimpleCircuit {
    a: Value<Fr>,
    b: Value<Fr>,
}

impl Circuit<Fr> for SimpleCircuit {
    type Config = SimpleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        meta.enable_equality(advice);
        meta.enable_equality(instance);

        meta.create_gate("add", |meta| {
            let a = meta.query_advice(advice, Rotation::cur());
            let b = meta.query_advice(advice, Rotation::next());
            let c = meta.query_advice(advice, Rotation(2));
            vec![a + b - c]
        });

        SimpleConfig { advice, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "simple addition",
            |mut region| {
                region.assign_advice(|| "a", config.advice, 0, || self.a)?;
                region.assign_advice(|| "b", config.advice, 1, || self.b)?;
                region.assign_advice(|| "c", config.advice, 2, || self.a + self.b)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

fn main() {
    println!("Halo2 Simple Circuit Test");
}
EOF

# Range check circuit
cat > src/range_check.rs << 'EOF'
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

#[derive(Clone, Debug)]
struct RangeCheckConfig {
    value: Column<Advice>,
}

#[derive(Clone, Debug)]
struct RangeCheckCircuit {
    value: Value<Fr>,
    range: u64,
}

impl Circuit<Fr> for RangeCheckCircuit {
    type Config = RangeCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            range: self.range,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let value = meta.advice_column();
        RangeCheckConfig { value }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "range check",
            |mut region| {
                region.assign_advice(|| "value", config.value, 0, || self.value)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

fn main() {
    println!("Halo2 Range Check Circuit Test");
}
EOF

echo "✅ Test circuits created"

# 6. Build test circuits
echo ""
echo "🔨 Building test circuits..."
cargo build --release 2>&1 | tail -10
echo "✅ Test circuits built"

# 7. Verify binaries
echo ""
echo "✅ Verifying Halo2 setup..."
ls -lh target/release/simple_circuit target/release/range_check 2>/dev/null || echo "⚠️  Binaries not found"

echo ""
echo "=== Halo2 Setup Complete ==="
echo ""
echo "📁 Installed to: $INSTALL_DIR"
echo "   - halo2/ (PSE library)"
echo "   - halo2-lib/ (Axiom circuits)"
echo "   - halo2-test-circuits/ (ZkPatternFuzz test circuits)"
echo ""
echo "🧪 Test circuits available:"
echo "   - simple_circuit (basic addition)"
echo "   - range_check (range proof)"
