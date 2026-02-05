# Quick Start: Week 1 Implementation Plan

**Goal:** Implement the critical path to finding your first real bug in 7 days

---

## Day 1: Setup Real Circuit Infrastructure

### Step 1: Add Real Circuits as Git Submodules

```bash
# From project root
mkdir -p circuits/real

# Add Tornado Cash (most audited, good test case)
git submodule add https://github.com/tornadocash/tornado-core.git \
    circuits/real/tornado-core

# Add Semaphore
git submodule add https://github.com/semaphore-protocol/semaphore.git \
    circuits/real/semaphore

# Initialize and update
git submodule update --init --recursive
```

### Step 2: Install ZK Tooling

```bash
# Install Node.js dependencies
npm install -g snarkjs@latest circom@2.1.5

# Install Z3 SMT solver
sudo apt-get install -y z3  # Ubuntu/Debian
# or
brew install z3  # macOS

# Verify installations
circom --version  # Should be 2.1.5+
snarkjs --version
z3 --version
```

### Step 3: Compile Test Circuit

```bash
cd circuits/real/tornado-core
npm install

# Compile the Merkle tree circuit (smaller, faster to test)
mkdir -p build
circom circuits/merkleTree.circom \
    --r1cs build/merkleTree.r1cs \
    --wasm build/merkleTree_js/merkleTree.wasm \
    --sym build/merkleTree.sym

# Verify output
ls -lh build/
# Should see: merkleTree.r1cs, merkleTree_js/, merkleTree.sym

cd ../../..
```

**Deliverable:** Real circuit compiled and ready for fuzzing

---

## Day 2: Implement R1CS Binary Parser

### File: `src/analysis/r1cs_parser.rs`

Create the new file with this starter code:

```rust
//! R1CS Binary Format Parser
//! Spec: https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md

use anyhow::{anyhow, Context, Result};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// R1CS constraint: (A·w) * (B·w) = (C·w)
#[derive(Debug, Clone)]
pub struct R1CSConstraint {
    pub a: Vec<(usize, BigUint)>,
    pub b: Vec<(usize, BigUint)>,
    pub c: Vec<(usize, BigUint)>,
}

#[derive(Debug)]
pub struct R1CS {
    pub field_size: BigUint,
    pub num_wires: usize,
    pub num_public_outputs: usize,
    pub num_public_inputs: usize,
    pub num_private_inputs: usize,
    pub constraints: Vec<R1CSConstraint>,
    pub wire_names: Vec<String>,
}

impl R1CS {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open {}", path.as_ref().display()))?;
        let mut reader = BufReader::new(file);

        // Read and verify magic number
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"r1cs" {
            return Err(anyhow!("Invalid R1CS file: bad magic {:?}", magic));
        }

        // Read version
        let version = read_u32_le(&mut reader)?;
        if version != 1 {
            return Err(anyhow!("Unsupported R1CS version: {}", version));
        }

        // Read number of sections
        let num_sections = read_u32_le(&mut reader)?;
        tracing::debug!("R1CS file has {} sections", num_sections);

        let mut r1cs = R1CS {
            field_size: BigUint::from(0u32),
            num_wires: 0,
            num_public_outputs: 0,
            num_public_inputs: 0,
            num_private_inputs: 0,
            constraints: Vec::new(),
            wire_names: Vec::new(),
        };

        // Parse each section
        for section_idx in 0..num_sections {
            let section_type = read_u32_le(&mut reader)?;
            let section_size = read_u64_le(&mut reader)?;

            tracing::debug!(
                "Section {}: type={}, size={}",
                section_idx,
                section_type,
                section_size
            );

            match section_type {
                1 => parse_header(&mut reader, &mut r1cs)?,
                2 => parse_constraints(&mut reader, &mut r1cs)?,
                3 => parse_wire_names(&mut reader, &mut r1cs)?,
                _ => {
                    tracing::warn!("Skipping unknown section type {}", section_type);
                    skip_bytes(&mut reader, section_size as usize)?;
                }
            }
        }

        tracing::info!(
            "Parsed R1CS: {} wires, {} constraints, {} public inputs, {} private inputs",
            r1cs.num_wires,
            r1cs.constraints.len(),
            r1cs.num_public_inputs,
            r1cs.num_private_inputs
        );

        Ok(r1cs)
    }

    pub fn total_inputs(&self) -> usize {
        self.num_public_outputs + self.num_public_inputs + self.num_private_inputs
    }
}

// Helper functions
fn read_u32_le<R: Read>(reader: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le<R: Read>(reader: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_bigint<R: Read>(reader: &mut R, n_bytes: usize) -> Result<BigUint> {
    let mut buf = vec![0u8; n_bytes];
    reader.read_exact(&mut buf)?;
    Ok(BigUint::from_bytes_le(&buf))
}

fn skip_bytes<R: Read>(reader: &mut R, n: usize) -> Result<()> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(())
}

fn parse_header<R: Read>(reader: &mut R, r1cs: &mut R1CS) -> Result<()> {
    // Field size (32 bytes for BN254)
    r1cs.field_size = read_bigint(reader, 32)?;

    // Wire counts
    r1cs.num_wires = read_u32_le(reader)? as usize;
    r1cs.num_public_outputs = read_u32_le(reader)? as usize;
    r1cs.num_public_inputs = read_u32_le(reader)? as usize;
    r1cs.num_private_inputs = read_u32_le(reader)? as usize;

    // Number of labels (u64)
    let _num_labels = read_u64_le(reader)?;

    // Number of constraints (u32)
    let num_constraints = read_u32_le(reader)? as usize;
    r1cs.constraints = Vec::with_capacity(num_constraints);

    Ok(())
}

fn parse_constraints<R: Read>(reader: &mut R, r1cs: &mut R1CS) -> Result<()> {
    let num_constraints = read_u32_le(reader)? as usize;

    for i in 0..num_constraints {
        let a = read_sparse_vec(reader)?;
        let b = read_sparse_vec(reader)?;
        let c = read_sparse_vec(reader)?;

        r1cs.constraints.push(R1CSConstraint { a, b, c });

        if (i + 1) % 1000 == 0 {
            tracing::debug!("Parsed {}/{} constraints", i + 1, num_constraints);
        }
    }

    Ok(())
}

fn read_sparse_vec<R: Read>(reader: &mut R) -> Result<Vec<(usize, BigUint)>> {
    let num_elements = read_u32_le(reader)? as usize;
    let mut vec = Vec::with_capacity(num_elements);

    for _ in 0..num_elements {
        let wire_idx = read_u32_le(reader)? as usize;
        let coeff = read_bigint(reader, 32)?;
        vec.push((wire_idx, coeff));
    }

    Ok(vec)
}

fn parse_wire_names<R: Read>(reader: &mut R, r1cs: &mut R1CS) -> Result<()> {
    // Wire names are stored as null-terminated strings
    for wire_idx in 0..r1cs.num_wires {
        let name_len = read_u32_le(reader)? as usize;
        let mut name_bytes = vec![0u8; name_len];
        reader.read_exact(&mut name_bytes)?;

        let name = String::from_utf8(name_bytes)
            .unwrap_or_else(|_| format!("wire_{}", wire_idx));

        r1cs.wire_names.push(name);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tornado_merkle() {
        let path = "circuits/real/tornado-core/build/merkleTree.r1cs";
        
        if !Path::new(path).exists() {
            eprintln!("Skipping test: {} not found", path);
            return;
        }

        let r1cs = R1CS::from_file(path).expect("Failed to parse R1CS");

        assert!(r1cs.constraints.len() > 0);
        assert!(r1cs.num_wires > 0);
        
        println!("Tornado Merkle Tree:");
        println!("  Constraints: {}", r1cs.constraints.len());
        println!("  Wires: {}", r1cs.num_wires);
        println!("  Public inputs: {}", r1cs.num_public_inputs);
        println!("  Private inputs: {}", r1cs.num_private_inputs);
    }
}
```

### Update `Cargo.toml`

Add `num-bigint` dependency if not already present:

```toml
[dependencies]
num-bigint = "0.4"
```

### Update module exports

In `src/analysis/mod.rs`:

```rust
pub mod r1cs_parser;
pub use r1cs_parser::{R1CS, R1CSConstraint};
```

### Test it

```bash
cargo test --test r1cs_parser -- --nocapture
```

**Deliverable:** Parse real Tornado R1CS file and extract constraint count

---

## Day 3: Integrate R1CS into CircomTarget

### Update `src/targets/circom.rs`

Add R1CS constraint inspection:

```rust
use crate::analysis::r1cs_parser::R1CS;

impl CircomTarget {
    /// Get parsed R1CS for constraint analysis
    pub fn get_r1cs(&self) -> Result<R1CS> {
        let r1cs_path = self.build_dir.join(format!("{}.r1cs", self.main_component));
        R1CS::from_file(r1cs_path)
    }
}

impl TargetCircuit for CircomTarget {
    fn constraint_inspector(&self) -> Option<Box<dyn ConstraintInspector>> {
        // Return R1CS-based inspector
        match self.get_r1cs() {
            Ok(r1cs) => Some(Box::new(R1CSInspector::new(r1cs))),
            Err(e) => {
                tracing::warn!("Failed to load R1CS: {}", e);
                None
            }
        }
    }
}
```

### Create R1CS Inspector

In `src/executor/mod.rs`:

```rust
pub struct R1CSInspector {
    r1cs: R1CS,
}

impl R1CSInspector {
    pub fn new(r1cs: R1CS) -> Self {
        Self { r1cs }
    }
}

impl ConstraintInspector for R1CSInspector {
    fn get_constraints(&self) -> Vec<ConstraintEquation> {
        // Convert R1CS constraints to generic format
        self.r1cs.constraints.iter()
            .map(|c| ConstraintEquation {
                // Simplified conversion
                id: 0,
                terms: Vec::new(),
            })
            .collect()
    }
    
    fn num_constraints(&self) -> usize {
        self.r1cs.constraints.len()
    }
}
```

**Deliverable:** CircomTarget exposes real R1CS constraints

---

## Day 4: Implement First Semantic Oracle (Nullifier)

### File: `src/fuzzer/oracles/nullifier.rs`

```rust
//! Nullifier Collision Oracle - Detects double-spending vulnerabilities

use crate::fuzzer::{BugOracle, Finding, TestCase, FieldElement};
use crate::config::{AttackType, Severity};
use std::collections::HashMap;

pub struct NullifierOracle {
    // Map: nullifier -> (secret, test_id)
    seen_nullifiers: HashMap<Vec<u8>, (FieldElement, usize)>,
    test_counter: usize,
}

impl NullifierOracle {
    pub fn new() -> Self {
        Self {
            seen_nullifiers: HashMap::new(),
            test_counter: 0,
        }
    }
    
    fn hash_field(&self, fe: &FieldElement) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&fe.0);
        hasher.finalize().to_vec()
    }
}

impl BugOracle for NullifierOracle {
    fn check(&mut self, test_case: &TestCase, output: &[FieldElement]) -> Option<Finding> {
        self.test_counter += 1;
        
        // For privacy protocols, nullifier is typically:
        // - output[1] (after root)
        // - or computed as hash(secret, nullifier_preimage)
        
        let nullifier = if output.len() >= 2 {
            self.hash_field(&output[1])
        } else {
            return None;
        };
        
        // Extract secret from inputs (typically first private input)
        let secret = test_case.inputs.first()?.clone();
        
        // Check for collision with different secret
        if let Some((prev_secret, prev_test)) = self.seen_nullifiers.get(&nullifier) {
            if prev_secret != &secret {
                return Some(Finding {
                    attack_type: AttackType::InformationLeakage,
                    severity: Severity::Critical,
                    description: format!(
                        "🚨 NULLIFIER COLLISION DETECTED 🚨\n\
                         \n\
                         Two different secrets produce identical nullifier!\n\
                         This enables DOUBLE-SPENDING attacks.\n\
                         \n\
                         Secret A (test {}): 0x{}...\n\
                         Secret B (test {}): 0x{}...\n\
                         Nullifier: 0x{}...\n\
                         \n\
                         Impact: Attacker can spend same commitment multiple times.",
                        prev_test,
                        hex::encode(&prev_secret.0[..4]),
                        self.test_counter,
                        hex::encode(&secret.0[..4]),
                        hex::encode(&nullifier[..4]),
                    ),
                    poc: crate::fuzzer::ProofOfConcept {
                        witness_a: test_case.inputs.clone(),
                        witness_b: None,
                        public_inputs: output.to_vec(),
                        proof: None,
                    },
                    location: Some(format!("test_{}", self.test_counter)),
                });
            }
        }
        
        // Record this nullifier
        self.seen_nullifiers.insert(nullifier, (secret, self.test_counter));
        
        None
    }
    
    fn name(&self) -> &str {
        "nullifier_collision_oracle"
    }
}

impl Default for NullifierOracle {
    fn default() -> Self {
        Self::new()
    }
}
```

### Register Oracle in Engine

Update `src/fuzzer/engine.rs`:

```rust
use super::oracle::{
    BugOracle, 
    UnderconstrainedOracle, 
    ArithmeticOverflowOracle,
    NullifierOracle,  // Add this
};

impl FuzzingEngine {
    pub fn new(...) -> Result<Self> {
        // ...existing code...
        
        // Initialize bug oracles
        let oracles: Vec<Box<dyn BugOracle>> = vec![
            Box::new(UnderconstrainedOracle::new()),
            Box::new(ArithmeticOverflowOracle::new()),
            Box::new(NullifierOracle::new()),  // Add this
        ];
        
        // ...rest of code...
    }
}
```

Update `src/fuzzer/oracle.rs` to export:

```rust
mod nullifier;
pub use nullifier::NullifierOracle;
```

**Deliverable:** Detect nullifier collisions during fuzzing

---

## Day 5: Add Campaign for Tornado Cash

### File: `tests/campaigns/tornado_real.yaml`

```yaml
campaign:
  name: "Tornado Cash Real Circuit Audit"
  version: "1.0"
  target:
    framework: "circom"
    circuit_path: "./circuits/real/tornado-core/build/merkleTree.circom"
    main_component: "MerkleTree"
  
  parameters:
    field: "bn254"
    max_constraints: 100000
    timeout_seconds: 3600

attacks:
  - type: "underconstrained"
    description: "Check for degree-of-freedom issues"
    config:
      witness_pairs: 100
  
  - type: "soundness"
    description: "Attempt proof forgery"
    config:
      forge_attempts: 1000
  
  - type: "witness_fuzzing"
    description: "Fuzz witness generation with nullifier oracle"
    config:
      determinism_tests: 1000
      timing_tests: 100

inputs:
  - name: "root"
    type: "field"
    fuzz_strategy: "random"
  
  - name: "nullifierHash"
    type: "field"
    fuzz_strategy: "random"
  
  - name: "recipient"
    type: "field"
    fuzz_strategy: "random"
  
  - name: "relayer"
    type: "field"
    fuzz_strategy: "random"
  
  - name: "fee"
    type: "field"
    fuzz_strategy: "interesting_values"
    interesting:
      - "0x0"
      - "0x1"
  
  - name: "nullifier"
    type: "field"
    fuzz_strategy: "random"
  
  - name: "secret"
    type: "field"
    fuzz_strategy: "random"
  
  - name: "pathElements"
    type: "array<field>"
    length: 20
    fuzz_strategy: "mutation"
  
  - name: "pathIndices"
    type: "array<field>"
    length: 20
    fuzz_strategy: "mutation"

reporting:
  output_dir: "./reports/tornado_real"
  formats: ["json", "markdown"]
  include_poc: true
```

**Deliverable:** Ready-to-run campaign against real Tornado circuit

---

## Day 6: Run First Real Fuzzing Campaign

### Baseline Run

```bash
# Set up logging
export RUST_LOG=info

# Run 1-hour campaign
cargo run --release -- \
    --config tests/campaigns/tornado_real.yaml \
    --workers 4 \
    --seed 12345 \
    --verbose

# Check results
ls -lh reports/tornado_real/
cat reports/tornado_real/report.md
```

### Monitor Progress

```bash
# In another terminal, watch live stats
watch -n 5 'tail -20 reports/tornado_real/fuzzing.log'
```

### Expected Output

```
Starting fuzzing campaign: Tornado Cash Real Circuit Audit
Circuit: MerkleTree (Circom)
Workers: 4
Constraint count: 1234 constraints

[00:01:30] Executions: 1500, Coverage: 45.2%, Findings: 0
[00:05:00] Executions: 5000, Coverage: 67.8%, Findings: 0
[00:15:00] Executions: 15000, Coverage: 82.1%, Findings: 1 ⚠️

🚨 Finding: Nullifier collision detected!
   Severity: Critical
   Description: Two different secrets produce same nullifier
   PoC: See reports/tornado_real/finding_001.json
```

**Deliverable:** First fuzzing run against real ZK circuit

---

## Day 7: Analyze Results & Iterate

### Triage Findings

```bash
# View all findings
cat reports/tornado_real/findings.json | jq '.findings[] | {severity, description}'

# Check coverage
cat reports/tornado_real/report.json | jq '.statistics.coverage_percentage'
```

### Validate Findings

For each finding:

1. **Extract PoC**
   ```bash
   # Get witness from finding
   cat reports/tornado_real/finding_001.json | jq '.poc'
   ```

2. **Manually Verify**
   ```bash
   # Run witness through original circuit
   cd circuits/real/tornado-core
   node --input finding_001_witness.json --circuit build/merkleTree_js/
   ```

3. **Confirm Bug**
   - Is it a real vulnerability?
   - Or a false positive?
   - Or a limitation of the oracle?

### Iterate

Based on results:

- **If no findings:** Increase iterations, improve oracles
- **If false positives:** Refine oracle logic
- **If real bugs:** 🎉 Report to Tornado team, claim bounty!

---

## Week 1 Checklist

- [ ] Real circuits compiled (tornado-core, semaphore)
- [ ] R1CS parser working on real .r1cs files
- [ ] CircomTarget exposing R1CS constraints
- [ ] Nullifier oracle detecting collisions
- [ ] Campaign config for Tornado Cash
- [ ] 1-hour fuzzing run completed
- [ ] Results analyzed and documented

---

## Week 2 Preview: SMT Integration

Next steps to boost effectiveness:

1. **R1CS → Z3 Translation**
   - Convert constraints to SMT formulas
   - Generate constraint-guided inputs
   
2. **Coverage-Guided Seed Generation**
   - Use SMT to generate inputs targeting uncovered constraints
   - Compare coverage: random vs SMT-guided
   
3. **Second Oracle: Merkle Proof Soundness**
   - Detect path length bypasses
   - Test sibling order validation

---

## Common Issues & Solutions

### Issue: "circom: command not found"

```bash
npm install -g circom@latest
export PATH="$PATH:$HOME/.npm-global/bin"
```

### Issue: "R1CS parse error: bad magic"

The file might be corrupted or use a different format. Verify:

```bash
hexdump -C build/merkleTree.r1cs | head -1
# Should start with: 72 31 63 73 (r1cs in ASCII)
```

### Issue: "No findings after 1 hour"

This is **expected** for well-audited circuits like Tornado! Try:

- Artificially inject a bug for testing
- Run on less-audited circuits
- Increase iterations (run overnight)

### Issue: "Out of memory"

Large circuits can exhaust memory. Reduce:

```yaml
corpus:
  max_size: 1000  # Down from 10000
```

---

## Success Criteria for Week 1

**Minimum Viable:**
- ✅ Parse real R1CS file
- ✅ Run fuzzing on Tornado circuit
- ✅ Generate report with coverage stats

**Stretch Goals:**
- 🎯 Find at least one finding (even if false positive)
- 🎯 Achieve >70% constraint coverage
- 🎯 Compare performance vs. existing tools

---

**Ready to Start?**

```bash
# Let's go!
git checkout -b feature/real-circuit-fuzzing
./scripts/setup_real_circuits.sh
cargo test r1cs_parser
```

📧 Questions? Open an issue or discussion on GitHub.

**Next:** [Full 12-Month Roadmap](ZERO_DAY_ROADMAP.md)
